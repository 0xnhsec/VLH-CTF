// VLH-CTF — ASLV M0 collector (aslv-core).
//
// Shared foundation service. NO vulnerabilities of its own by design:
// it is the organization's activity sink + event-verified flag minter for the
// ASLV product line (CORS / CSRF dual-check, mirroring dsltv/base/runtime.js).
//
// Endpoints (all on :8090, env COLLECTOR_PORT):
//   POST /ingest             — activity row(s): single JSON object, JSON array, or NDJSON body
//   GET  /internal/activity  — NDJSON of stored rows (latest first, cap 5000)
//   POST /exfil              — record {origin, referer, payload} exfil hit (CORS verifier input)
//   GET  /verify             — dual-check mint for ASLV{CORS-...} / ASLV{CSRF-...}
//   GET  /healthz
//
// Storage: NDJSON files under DATA_DIR (default /data) only.
// Postgres: the compose file keeps a Postgres service for the organization
// narrative, but v1 of the collector does NOT archive to it — stdlib Go has no
// Postgres driver and adding one (lib/pq) is deliberately deferred. See README.
package main

import (
	"bufio"
	"bytes"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"
)

/* ------------------------------------------------------------------ config */

type conf struct {
	port         string
	dataDir      string
	registryDir  string
	registryFile string
	attackerHost string
	portalURL    string
	bootNonce    string // fallback secret material when the portal is unreachable
}

func envOr(key, def string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return def
}

var cfg conf

const ringCap = 5000

/* ------------------------------------------------------------- tiny helpers */

func nowIso() string { return time.Now().UTC().Format(time.RFC3339Nano) }

func randHex(n int) string {
	b := make([]byte, (n+1)/2)
	_, _ = rand.Read(b)
	return hex.EncodeToString(b)[:n]
}

// flagDigits derives the deterministic 9-digit numeric part of an event-verified
// flag from the innocent secret + tag (same scheme as dsltv/base/runtime.js).
func flagDigits(secret, tag string) string {
	sum := sha256.Sum256([]byte(secret + ":" + tag))
	h := hex.EncodeToString(sum[:])
	v, err := strconv.ParseUint(h[:12], 16, 64)
	if err != nil {
		v = 0
	}
	return fmt.Sprintf("%09d", v%1000000000)
}

/* ------------------------------------------------------------------ stores */

type activityStore struct {
	mu   sync.Mutex
	ring []string // compact JSON rows, oldest -> newest
}

var activity activityStore

func (a *activityStore) append(rows []string) {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.ring = append(a.ring, rows...)
	if len(a.ring) > ringCap {
		a.ring = a.ring[len(a.ring)-ringCap:]
	}
}

func (a *activityStore) snapshotLatestFirst() []string {
	a.mu.Lock()
	defer a.mu.Unlock()
	out := make([]string, 0, len(a.ring))
	for i := len(a.ring) - 1; i >= 0; i-- {
		out = append(out, a.ring[i])
	}
	return out
}

func appendFile(path string, lines []string) error {
	f, err := os.OpenFile(path, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o644)
	if err != nil {
		return err
	}
	defer f.Close()
	for _, l := range lines {
		if _, err := f.WriteString(l + "\n"); err != nil {
			return err
		}
	}
	return nil
}

// lastFileLine returns the last non-empty line of a file ("" if none).
func lastFileLine(path string) string {
	f, err := os.Open(path)
	if err != nil {
		return ""
	}
	defer f.Close()
	last := ""
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 0, 64*1024), 8*1024*1024)
	for sc.Scan() {
		if t := strings.TrimSpace(sc.Text()); t != "" {
			last = t
		}
	}
	return last
}

/* ---------------------------------------------------------------- registry */

func registryAppend(obj map[string]any) {
	b, err := json.Marshal(obj)
	if err != nil {
		return
	}
	_ = appendFile(cfg.registryFile, []string{string(b)})
}

/* ------------------------------------------------------- minted flag state */

type mintEntry struct {
	Flag     string `json:"flag"`
	MintedAt string `json:"minted_at"`
}

var (
	mintMu   sync.Mutex
	minted   = map[string]mintEntry{}
	mintPath string
)

func loadMinted() {
	b, err := os.ReadFile(mintPath)
	if err != nil {
		return
	}
	_ = json.Unmarshal(b, &minted)
}

func saveMinted() {
	b, err := json.MarshalIndent(minted, "", "  ")
	if err != nil {
		return
	}
	_ = os.WriteFile(mintPath, b, 0o644)
}

// mint returns the (stable per boot) flag for a category, minting + registering
// it on first pass. secret feeds the deterministic digits derivation.
func mint(category, secret string) mintEntry {
	mintMu.Lock()
	defer mintMu.Unlock()
	if e, ok := minted[category]; ok {
		return e
	}
	flag := "ASLV{" + category + "-" + flagDigits(secret, category) + "}"
	e := mintEntry{Flag: flag, MintedAt: nowIso()}
	minted[category] = e
	saveMinted()
	registryAppend(map[string]any{
		"flag":      flag,
		"category":  category,
		"unit":      "m2", // ASLV CORS/CSRF flags belong to the M2 surface
		"archetype": "event-verified",
		"minted_at": e.MintedAt,
		"note":      "minted",
	})
	return e
}

/* --------------------------------------------------------- portal lookups */

var (
	secretMu        sync.Mutex
	cachedSecret    string
	cachedFetchedAt time.Time
)

func fetchJSON(url string, out any) error {
	client := &http.Client{Timeout: 5 * time.Second}
	resp, err := client.Get(url)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("GET %s -> %s", url, resp.Status)
	}
	return json.NewDecoder(io.LimitReader(resp.Body, 1<<20)).Decode(out)
}

// innocentSecret fetches (and caches) the innocent session-bound secret from the
// portal internal endpoint: GET {PORTAL_INTERNAL_URL}/_internal/innocent-secret
// -> {"api_key":"<32-hex>"}. In full mode the portal is M2 (aslv-portal); in
// standalone modes it is the M0 stub-portal.
func innocentSecret() (string, error) {
	secretMu.Lock()
	defer secretMu.Unlock()
	if cachedSecret != "" && time.Since(cachedFetchedAt) < time.Minute {
		return cachedSecret, nil
	}
	var out struct {
		APIKey string `json:"api_key"`
		Secret string `json:"secret"`
	}
	if err := fetchJSON(cfg.portalURL+"/_internal/innocent-secret", &out); err != nil {
		return "", err
	}
	s := out.APIKey
	if s == "" {
		s = out.Secret
	}
	if s == "" {
		return "", errors.New("portal returned an empty innocent secret")
	}
	cachedSecret = s
	cachedFetchedAt = time.Now()
	return s, nil
}

/* ------------------------------------------------------------ HTTP handlers */

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

// handleIngest accepts a single activity row (JSON object), a JSON array of
// rows, or an NDJSON body. Rows are normalized (ts defaulted) and appended to
// the activity file + in-memory ring.
func handleIngest(w http.ResponseWriter, r *http.Request) {
	body, err := io.ReadAll(io.LimitReader(r.Body, 8<<20))
	if err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]any{"error": "cannot read body"})
		return
	}
	trimmed := bytes.TrimSpace(body)
	if len(trimmed) == 0 {
		writeJSON(w, http.StatusBadRequest, map[string]any{"error": "empty body"})
		return
	}

	var rows []map[string]any
	appendRow := func(raw []byte) bool {
		var m map[string]any
		if !json.Valid(raw) {
			return false
		}
		if err := json.Unmarshal(raw, &m); err != nil || m == nil {
			return false
		}
		if _, ok := m["ts"]; !ok {
			m["ts"] = nowIso()
		}
		rows = append(rows, m)
		return true
	}

	if trimmed[0] == '[' {
		var arr []map[string]any
		if err := json.Unmarshal(trimmed, &arr); err != nil {
			writeJSON(w, http.StatusBadRequest, map[string]any{"error": "invalid JSON array"})
			return
		}
		rows = arr
		for _, m := range rows {
			if m == nil {
				continue
			}
			if _, ok := m["ts"]; !ok {
				m["ts"] = nowIso()
			}
		}
	} else if trimmed[0] == '{' {
		if !appendRow(trimmed) {
			writeJSON(w, http.StatusBadRequest, map[string]any{"error": "invalid JSON object"})
			return
		}
	} else {
		// NDJSON
		for _, line := range strings.Split(string(trimmed), "\n") {
			line = strings.TrimSpace(line)
			if line == "" {
				continue
			}
			if !appendRow([]byte(line)) {
				writeJSON(w, http.StatusBadRequest, map[string]any{"error": "invalid NDJSON line", "line": line})
				return
			}
		}
	}
	if len(rows) == 0 {
		writeJSON(w, http.StatusBadRequest, map[string]any{"error": "no valid rows"})
		return
	}

	lines := make([]string, 0, len(rows))
	for _, m := range rows {
		if m == nil {
			continue
		}
		b, err := json.Marshal(m)
		if err != nil {
			continue
		}
		lines = append(lines, string(b))
	}
	if err := appendFile(filepath.Join(cfg.dataDir, "activity.jsonl"), lines); err != nil {
		log.Printf("[collector] activity file append failed: %v", err)
	}
	activity.append(lines)
	writeJSON(w, http.StatusOK, map[string]any{"ingested": len(lines)})
}

func handleInternalActivity(w http.ResponseWriter, r *http.Request) {
	rows := activity.snapshotLatestFirst()
	w.Header().Set("Content-Type", "application/x-ndjson")
	for _, l := range rows {
		_, _ = io.WriteString(w, l+"\n")
	}
}

// exfilHit mirrors dsltv/base exfil_hits rows.
type exfilHit struct {
	TS           string `json:"ts"`
	Origin       string `json:"origin"`
	Referer      string `json:"referer"`
	SecFetchSite string `json:"sec_fetch_site"`
	Payload      string `json:"payload"`
	IP           string `json:"ip"`
}

func handleExfil(w http.ResponseWriter, r *http.Request) {
	var in struct {
		Origin       string          `json:"origin"`
		Referer      string          `json:"referer"`
		SecFetchSite string          `json:"sec_fetch_site"`
		Payload      json.RawMessage `json:"payload"`
	}
	_ = json.NewDecoder(io.LimitReader(r.Body, 4<<20)).Decode(&in)

	payload := ""
	if len(in.Payload) > 0 {
		var s string
		if err := json.Unmarshal(in.Payload, &s); err == nil {
			payload = s
		} else {
			payload = string(bytes.TrimSpace(in.Payload))
		}
	}
	if payload == "" {
		payload = "{}"
	}
	if len(payload) > 16384 {
		payload = payload[:16384]
	}

	hit := exfilHit{
		TS:           nowIso(),
		Origin:       in.Origin,
		Referer:      in.Referer,
		SecFetchSite: in.SecFetchSite,
		Payload:      payload,
		IP:           r.RemoteAddr,
	}
	if hit.Origin == "" {
		hit.Origin = r.Header.Get("Origin")
	}
	if hit.Referer == "" {
		hit.Referer = r.Header.Get("Referer")
	}
	if hit.SecFetchSite == "" {
		hit.SecFetchSite = r.Header.Get("Sec-Fetch-Site")
	}
	b, _ := json.Marshal(hit)
	if err := appendFile(filepath.Join(cfg.dataDir, "exfil.jsonl"), []string{string(b)}); err != nil {
		log.Printf("[collector] exfil file append failed: %v", err)
	}
	writeJSON(w, http.StatusOK, map[string]any{"recorded": true})
}

type checkResult struct {
	Verified bool   `json:"verified"`
	Flag     string `json:"flag"`
	Reason   string `json:"reason"`
}

func mintedOnce(category string) (mintEntry, bool) {
	mintMu.Lock()
	defer mintMu.Unlock()
	e, ok := minted[category]
	return e, ok
}

// corsCheck copies the semantics of dsltv/base/runtime.js collectorRouter
// GET /verify (CORS branch): the latest exfil hit must carry an attacker
// cross-site context AND a payload bound to the innocent session secret.
func corsCheck() checkResult {
	if e, ok := mintedOnce("CORS"); ok {
		return checkResult{Verified: true, Flag: e.Flag, Reason: "already minted"}
	}
	secret, err := innocentSecret()
	if err != nil {
		return checkResult{Reason: "innocent secret unavailable: " + err.Error()}
	}
	last := lastFileLine(filepath.Join(cfg.dataDir, "exfil.jsonl"))
	if last == "" {
		return checkResult{Reason: "no exfil hit received"}
	}
	var hit exfilHit
	if err := json.Unmarshal([]byte(last), &hit); err != nil {
		return checkResult{Reason: "cannot parse latest exfil hit"}
	}
	crossSite := strings.Contains(hit.Origin, cfg.attackerHost) ||
		strings.Contains(hit.Referer, cfg.attackerHost) ||
		hit.SecFetchSite == "cross-site"
	secretMatch := strings.Contains(hit.Payload, secret)
	if crossSite && secretMatch {
		e := mint("CORS", secret)
		return checkResult{Verified: true, Flag: e.Flag, Reason: "dual check passed: cross-site context + session-bound secret match"}
	}
	return checkResult{Reason: fmt.Sprintf("dual check failed (cross-site=%v, secret-match=%v)", crossSite, secretMatch)}
}

// csrfCheck: the portal reports whether the innocent row state changed
// (recovery_email differs from seed) — mirrors the base runtime CSRF checker.
// Best-effort: if the portal does not expose /_internal/csrf-state yet, the
// check reports not-verified with a reason (see README coordination note).
func csrfCheck() checkResult {
	if e, ok := mintedOnce("CSRF"); ok {
		return checkResult{Verified: true, Flag: e.Flag, Reason: "already minted"}
	}
	var state struct {
		Changed bool `json:"changed"`
	}
	if err := fetchJSON(cfg.portalURL+"/_internal/csrf-state", &state); err != nil {
		return checkResult{Reason: "portal csrf-state unavailable: " + err.Error()}
	}
	if !state.Changed {
		return checkResult{Reason: "no innocent-row state change observed yet"}
	}
	secret, err := innocentSecret()
	if err != nil {
		secret = cfg.bootNonce // deterministic-per-boot fallback digits material
	}
	e := mint("CSRF", secret)
	return checkResult{Verified: true, Flag: e.Flag, Reason: "innocent row state change observed"}
}

func handleVerify(w http.ResponseWriter, r *http.Request) {
	cors := corsCheck()
	csrf := csrfCheck()
	out := map[string]any{
		"checked_at": nowIso(),
		"cors":       cors,
		"csrf":       csrf,
	}
	out["verified"] = cors.Verified || csrf.Verified
	flag := ""
	if cors.Verified {
		flag = cors.Flag
	}
	if csrf.Verified {
		flag = csrf.Flag
	}
	out["flag"] = flag
	writeJSON(w, http.StatusOK, out)
}

func handleHealthz(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, map[string]any{"ok": true, "service": "aslv-collector"})
}

/* -------------------------------------------------------------------- main */

func main() {
	cfg = conf{
		port:         envOr("COLLECTOR_PORT", "8090"),
		dataDir:      envOr("DATA_DIR", "/data"),
		registryDir:  envOr("REGISTRY_DIR", "/registry"),
		attackerHost: envOr("ATTACKER_HOST", "attacker.aslv.lab"),
		portalURL:    strings.TrimRight(envOr("PORTAL_INTERNAL_URL", "http://portal:3000"), "/"),
		bootNonce:    "boot:" + randHex(16),
	}
	if err := os.MkdirAll(cfg.dataDir, 0o755); err != nil {
		log.Fatalf("[collector] cannot create DATA_DIR %s: %v", cfg.dataDir, err)
	}
	_ = os.MkdirAll(cfg.registryDir, 0o755)

	// registry file with graceful fallback (read-only registry volume etc.)
	regPath := filepath.Join(cfg.registryDir, "flags.ndjson")
	if err := appendFile(regPath, nil); err != nil {
		regPath = filepath.Join(cfg.dataDir, "registry-fallback.ndjson")
		log.Printf("[collector] registry dir not writable, falling back to %s", regPath)
	}
	cfg.registryFile = regPath

	mintPath = filepath.Join(cfg.dataDir, "minted.json")
	loadMinted()

	mux := http.NewServeMux()
	mux.HandleFunc("POST /ingest", handleIngest)
	mux.HandleFunc("GET /internal/activity", handleInternalActivity)
	mux.HandleFunc("POST /exfil", handleExfil)
	mux.HandleFunc("GET /verify", handleVerify)
	mux.HandleFunc("GET /healthz", handleHealthz)
	mux.HandleFunc("GET /", func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, http.StatusOK, map[string]any{
			"service": "aslv-collector",
			"see":     []string{"/ingest", "/internal/activity", "/exfil", "/verify", "/healthz"},
		})
	})

	srv := &http.Server{
		Addr:              ":" + cfg.port,
		Handler:           mux,
		ReadHeaderTimeout: 10 * time.Second,
		ReadTimeout:       60 * time.Second,
		WriteTimeout:      60 * time.Second,
	}
	log.Printf("[collector] aslv-core collector listening on :%s (attacker-host=%s portal=%s)", cfg.port, cfg.attackerHost, cfg.portalURL)
	log.Printf("[collector] v1 archives activity to NDJSON only — see README for the honest Postgres note")
	if err := srv.ListenAndServe(); err != nil {
		log.Fatalf("[collector] server error: %v", err)
	}
}
