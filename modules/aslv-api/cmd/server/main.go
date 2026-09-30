// VLH-CTF — ASLV M4 aslv-api (cmd/server).
//
// API composite module: BOLA / BFLA / BOPLA (excessive data exposure) +
// mass assignment (role in PATCH) + shadow API version, stage-gated flags.
// Also carries the M5→M4 JWT trust edge (signature-only validation, deliberately
// loose claim trust incl. RS256/HS256 algorithm confusion) and the M2↔M4 CORS
// edge (Origin reflection + credentials on /user/v1/* and /v1/user/*).
//
// Path scheme (arch §7.2): aslv.lab/user/v1/{user}/…  — the {user} path
// parameter is trusted for data resolution WITHOUT verifying {user} == owner.
//
// This file: config, DB bootstrap + seed, flags/registry, sessions, activity
// logging, mux wiring. Handlers live in handlers.go, JWT validation in jwt.go.
package main

import (
	"crypto/rand"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"

	_ "modernc.org/sqlite"
)

/* ------------------------------------------------------------------ config */

type conf struct {
	apiPort      string
	dataDir      string
	registryFile string
	jwksURL      string
	activitySink string
	labDomain    string
	innocent     seedSpec // org-wide seed override (full mode)
}

type seedSpec struct {
	Username string
	Password string
	APIKey   string
	UUID     string
}

func envOr(key, def string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return def
}

var cfg conf

/* ------------------------------------------------------------- helpers */

func nowIso() string { return time.Now().UTC().Format(time.RFC3339Nano) }

func randHex(n int) string {
	b := make([]byte, (n+1)/2)
	_, _ = rand.Read(b)
	return hex.EncodeToString(b)[:n]
}

func randDigits(n int) string {
	b := make([]byte, n)
	_, _ = rand.Read(b)
	out := make([]byte, n)
	for i := range b {
		out[i] = byte('0') + b[i]%10
	}
	return string(out)
}

func uuidv4() string {
	b := make([]byte, 16)
	_, _ = rand.Read(b)
	b[6] = (b[6] & 0x0f) | 0x40
	b[8] = (b[8] & 0x3f) | 0x80
	return fmt.Sprintf("%x-%x-%x-%x-%x", b[0:4], b[4:6], b[6:8], b[8:10], b[10:16])
}

func sha256Hex(s string) string {
	sum := sha256.Sum256([]byte(s))
	return hex.EncodeToString(sum[:])
}

// tenantFor derives a stable tenant slug from the username (deterministic so
// the full-mode org-wide seed yields the same tenant everywhere).
func tenantFor(username string) string {
	sum := sha256.Sum256([]byte("aslv-tenant:" + username))
	return "t" + hex.EncodeToString(sum[:])[:6]
}

/* -------------------------------------------------------------------- db */

var db *sql.DB

const schema = `
CREATE TABLE IF NOT EXISTS users (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  username TEXT UNIQUE NOT NULL,
  uuid TEXT UNIQUE NOT NULL,
  password TEXT NOT NULL,
  role TEXT NOT NULL,
  original_role TEXT NOT NULL,
  email TEXT,
  tenant TEXT,
  api_key TEXT,
  created_at TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS sessions (
  sid TEXT PRIMARY KEY,
  user_id INTEGER NOT NULL,
  created_at TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS orders (
  id INTEGER PRIMARY KEY,
  user_id INTEGER NOT NULL,
  note TEXT,
  secret_note TEXT,
  total_cents INTEGER,
  created_at TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS profiles (
  user_id INTEGER PRIMARY KEY,
  full_name TEXT,
  bio TEXT,
  phone TEXT
);
CREATE TABLE IF NOT EXISTS activity (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  ts TEXT NOT NULL,
  identifier TEXT NOT NULL,
  is_authenticated INTEGER NOT NULL,
  data TEXT NOT NULL,
  latency_ms REAL NOT NULL
);
CREATE TABLE IF NOT EXISTS flags (
  category TEXT NOT NULL,
  stage TEXT NOT NULL,
  flag TEXT NOT NULL,
  state TEXT NOT NULL,
  minted_at TEXT,
  PRIMARY KEY (category, stage)
);
`

type userRow struct {
	ID           int64
	Username     string
	UUID         string
	Password     string
	Role         string
	OriginalRole string
	Email        string
	Tenant       string
	APIKey       string
	CreatedAt    string
}

func scanUser(row interface{ Scan(...any) error }) (*userRow, error) {
	u := &userRow{}
	err := row.Scan(&u.ID, &u.Username, &u.UUID, &u.Password, &u.Role, &u.OriginalRole,
		&u.Email, &u.Tenant, &u.APIKey, &u.CreatedAt)
	if err != nil {
		return nil, err
	}
	return u, nil
}

const userCols = "id, username, uuid, password, role, original_role, email, tenant, api_key, created_at"

func userByRef(ref string) *userRow {
	u, err := scanUser(db.QueryRow("SELECT "+userCols+" FROM users WHERE uuid = ? OR username = ? LIMIT 1", ref, ref))
	if err != nil {
		return nil
	}
	return u
}

func userByID(id int64) *userRow {
	u, err := scanUser(db.QueryRow("SELECT "+userCols+" FROM users WHERE id = ?", id))
	if err != nil {
		return nil
	}
	return u
}

/* ------------------------------------------------------------ flag registry */

func registryAppend(obj map[string]any) {
	b, err := json.Marshal(obj)
	if err != nil {
		return
	}
	f, err := os.OpenFile(cfg.registryFile, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o644)
	if err != nil {
		return
	}
	defer f.Close()
	_, _ = f.WriteString(string(b) + "\n")
}

var (
	flagStage1 string // ASLV{API-<digits1>} — escalation proof in own profile
	flagStage2 string // ASLV{API-<digits2>} — admin panel verifying server-side role
)

func bootstrapFlags() {
	// Flags regenerate every boot (CONTRACT §3): wipe + re-hold.
	_, _ = db.Exec("DELETE FROM flags")
	flagStage1 = "ASLV{API-" + randDigits(9) + "}"
	flagStage2 = "ASLV{API-" + randDigits(9) + "}"
	for _, s := range []struct {
		stage, flag string
	}{
		{"stage1", flagStage1},
		{"stage2", flagStage2},
	} {
		_, err := db.Exec("INSERT INTO flags (category, stage, flag, state, minted_at) VALUES (?,?,?,?,?)",
			"API", s.stage, s.flag, "held", nowIso())
		if err != nil {
			log.Fatalf("[api] cannot hold flag %s: %v", s.stage, err)
		}
		registryAppend(map[string]any{
			"flag":      s.flag,
			"category":  "API",
			"unit":      "m4",
			"archetype": "stage-gated",
			"minted_at": nowIso(),
			"note":      "held",
			"stage":     s.stage,
		})
	}
}

// earnFlag flips a stage flag to minted (first time only) and registers it.
func earnFlag(stage, flag string) {
	res, err := db.Exec("UPDATE flags SET state='minted', minted_at=? WHERE category='API' AND stage=? AND state!='minted'", nowIso(), stage)
	if err != nil {
		return
	}
	if n, _ := res.RowsAffected(); n > 0 {
		registryAppend(map[string]any{
			"flag":      flag,
			"category":  "API",
			"unit":      "m4",
			"archetype": "stage-gated",
			"minted_at": nowIso(),
			"note":      "minted",
			"stage":     stage,
		})
	}
}

/* ------------------------------------------------------------------ seed */

func seedIfEmpty() {
	var count int
	if err := db.QueryRow("SELECT COUNT(*) FROM users").Scan(&count); err != nil {
		log.Fatalf("[api] seed count failed: %v", err)
	}
	if count > 0 {
		// Org-wide seed override (full mode): keep the innocent row in sync.
		if cfg.innocent.Username != "" {
			applyInnocentOverride()
		}
		return
	}

	innocentUsername := cfg.innocent.Username
	if innocentUsername == "" {
		innocentUsername = "usr_" + randHex(4)
	}
	innocentPassword := cfg.innocent.Password
	if innocentPassword == "" {
		innocentPassword = randHex(16)
	}
	innocentAPIKey := cfg.innocent.APIKey
	if innocentAPIKey == "" {
		innocentAPIKey = randHex(32)
	}
	innocentUUID := cfg.innocent.UUID
	if innocentUUID == "" {
		innocentUUID = uuidv4()
	}

	type spec struct {
		username, password, role, email, apiKey, uuid string
	}
	users := []spec{
		{"0xnhsec", "vlh-tester-01", "tester", "0xnhsec@" + cfg.labDomain, randHex(32), uuidv4()},
		{"Noshiro", "vlh-tester-02", "tester", "noshiro@" + cfg.labDomain, randHex(32), uuidv4()},
		{innocentUsername, innocentPassword, "innocent", innocentUsername + "@" + cfg.labDomain, innocentAPIKey, innocentUUID},
		{"admin", randHex(16), "admin", "admin@" + cfg.labDomain, randHex(32), uuidv4()},
	}
	ids := map[string]int64{}
	for _, u := range users {
		res, err := db.Exec(`INSERT INTO users (username, uuid, password, role, original_role, email, tenant, api_key, created_at)
			VALUES (?,?,?,?,?,?,?,?,?)`,
			u.username, u.uuid, sha256Hex(u.password), u.role, u.role, u.email, tenantFor(u.username), u.apiKey, nowIso())
		if err != nil {
			log.Fatalf("[api] seed user %s: %v", u.username, err)
		}
		id, _ := res.LastInsertId()
		ids[u.username] = id
		if u.role == "innocent" {
			ids["innocent"] = id
		}
	}

	profiles := map[string][3]string{
		"0xnhsec":  {"Nh Sec", "Known tester account #1 (see player guide).", "+1-555-0101"},
		"Noshiro":  {"Noshiro", "Known tester account #2 (see player guide).", "+1-555-0102"},
		"innocent": {"N. Nocent", "Procurement lead, tenant-isolated account.", "+1-555-0177"},
		"admin":    {"System Administrator", "Platform operations.", "+1-555-0100"},
	}
	for name, p := range profiles {
		if _, err := db.Exec("INSERT INTO profiles (user_id, full_name, bio, phone) VALUES (?,?,?,?)", ids[name], p[0], p[1], p[2]); err != nil {
			log.Fatalf("[api] seed profile %s: %v", name, err)
		}
	}

	// Orders. The innocent's order carries the pivot material (M4→M3 edge).
	innocent := userByID(ids["innocent"])
	pivot := fmt.Sprintf("PIVOT: innocent email=%s tenant=%s.aslv.lab cross-tenant document reference=%s (see GET /api/documents/{uuid} on the tenant app)", innocent.Email, innocent.Tenant, innocent.UUID)
	orders := []struct {
		id   int64
		user string
		note string
		sec  string
	}{
		{1001, "innocent", "Q3 procurement bundle", pivot},
		{1002, "innocent", "Renewal — standard", ""},
		{1003, "0xnhsec", "Tester sample order", ""},
		{1004, "Noshiro", "Tester sample order", ""},
		{1005, "admin", "Platform license renewal", "ADMIN-ONLY note: platform license key 811911-VLH-ENT (internal)."},
	}
	for _, o := range orders {
		if _, err := db.Exec("INSERT INTO orders (id, user_id, note, secret_note, total_cents, created_at) VALUES (?,?,?,?,?,?)",
			o.id, ids[o.user], o.note, o.sec, 10000+int(o.id), nowIso()); err != nil {
			log.Fatalf("[api] seed order %d: %v", o.id, err)
		}
	}

	// Grading-only seed dump (container-internal; NEVER player-accessible).
	seedDump := map[string]any{
		"generated_at": nowIso(),
		"innocent":     map[string]string{"username": innocentUsername, "password": innocentPassword, "api_key": innocentAPIKey, "uuid": innocentUUID},
		"admin":        map[string]string{"username": "admin", "password": users[3].password},
		"flags":        map[string]string{"stage1": flagStage1, "stage2": flagStage2},
	}
	if b, err := json.MarshalIndent(seedDump, "", "  "); err == nil {
		_ = os.WriteFile(filepath.Join(cfg.dataDir, "seed.json"), b, 0o644)
	}
	log.Printf("[api] seeded users (innocent=%s tenant=%s) + orders; flags held", innocentUsername, innocent.Tenant)
}

func applyInnocentOverride() {
	u := userByRef(cfg.innocent.Username)
	if u == nil {
		u = userByRef(cfg.innocent.UUID)
	}
	if u == nil || u.Role != "innocent" {
		return
	}
	pw := cfg.innocent.Password
	if pw == "" {
		pw = randHex(16)
	}
	apiKey := cfg.innocent.APIKey
	if apiKey == "" {
		apiKey = randHex(32)
	}
	id := cfg.innocent.UUID
	if id == "" {
		id = u.UUID
	}
	_, _ = db.Exec("UPDATE users SET username=?, password=?, api_key=?, uuid=? WHERE id=?",
		cfg.innocent.Username, sha256Hex(pw), apiKey, id, u.ID)
}

/* ---------------------------------------------------------------- sessions */

func createSession(userID int64) (string, error) {
	sid := randHex(32)
	_, err := db.Exec("INSERT INTO sessions (sid, user_id, created_at) VALUES (?,?,?)", sid, userID, nowIso())
	return sid, err
}

func sessionUser(sid string) *userRow {
	var userID int64
	if err := db.QueryRow("SELECT user_id FROM sessions WHERE sid = ?", sid).Scan(&userID); err != nil {
		return nil
	}
	return userByID(userID)
}

/* ----------------------------------------------------------- activity log */

func logActivity(identifier string, authed bool, data string, latencyMs float64) {
	_, _ = db.Exec("INSERT INTO activity (ts, identifier, is_authenticated, data, latency_ms) VALUES (?,?,?,?,?)",
		nowIso(), identifier, boolInt(authed), data, latencyMs)
	if cfg.activitySink != "" {
		row := map[string]any{
			"ts":              nowIso(),
			"identifier":      identifier,
			"is_authenticated": authed,
			"data":            data,
			"latency_ms":      latencyMs,
		}
		go func(r map[string]any) {
			b, err := json.Marshal(r)
			if err != nil {
				return
			}
			client := &http.Client{Timeout: 2 * time.Second}
			resp, err := client.Post(cfg.activitySink, "application/json", strings.NewReader(string(b)))
			if err == nil {
				_, _ = io.Copy(io.Discard, resp.Body)
				_ = resp.Body.Close()
			}
		}(row)
	}
}

func boolInt(b bool) int {
	if b {
		return 1
	}
	return 0
}

/* ------------------------------------------------------------- HTTP wiring */

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

// corsWrap implements the M2↔M4 trust edge: any Origin present on
// /user/v1/* or /v1/user/* requests is REFLECTED together with
// Access-Control-Allow-Credentials: true (arch §5.2).
func corsWrap(h http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		origin := r.Header.Get("Origin")
		p := r.URL.Path
		if origin != "" && (strings.HasPrefix(p, "/user/v1/") || strings.HasPrefix(p, "/v1/user/")) {
			w.Header().Set("Access-Control-Allow-Origin", origin)
			w.Header().Set("Access-Control-Allow-Credentials", "true")
			w.Header().Add("Vary", "Origin")
			if r.Method == http.MethodOptions {
				w.Header().Set("Access-Control-Allow-Methods", "GET, POST, PATCH, OPTIONS")
				w.Header().Set("Access-Control-Allow-Headers", "Content-Type, Authorization")
				w.WriteHeader(http.StatusNoContent)
				return
			}
		}
		h.ServeHTTP(w, r)
	})
}

// trackWrap logs every request to the local activity store (+ sink).
func trackWrap(h http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()
		defer func() {
			id := resolveIdentity(r)
			identifier := "anon"
			authed := false
			if id.Authed {
				authed = true
				identifier = id.Username
			}
			data := r.Method + " " + r.URL.Path
			if r.URL.RawQuery != "" {
				data += "?" + r.URL.RawQuery
			}
			latency := float64(time.Since(start).Microseconds()) / 1000.0
			logActivity(identifier, authed, data, latency)
		}()
		h.ServeHTTP(w, r)
	})
}

func main() {
	cfg = conf{
		apiPort:      envOr("API_PORT", "8080"),
		dataDir:      envOr("DATA_DIR", "/data"),
		jwksURL:      envOr("JWKS_URL", "http://identity:3000/jwks.json"),
		activitySink: envOr("ACTIVITY_SINK", ""),
		labDomain:    envOr("LAB_DOMAIN", "aslv.lab"),
		innocent: seedSpec{
			Username: envOr("INNOCENT_USERNAME", ""),
			Password: envOr("INNOCENT_PASSWORD", ""),
			APIKey:   envOr("INNOCENT_API_KEY", ""),
			UUID:     envOr("INNOCENT_UUID", ""),
		},
	}
	if err := os.MkdirAll(cfg.dataDir, 0o755); err != nil {
		log.Fatalf("[api] cannot create DATA_DIR: %v", err)
	}
	_ = os.MkdirAll(envOr("REGISTRY_DIR", "/registry"), 0o755)

	// registry file with graceful fallback
	regPath := filepath.Join(envOr("REGISTRY_DIR", "/registry"), "flags.ndjson")
	if f, err := os.OpenFile(regPath, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o644); err == nil {
		_ = f.Close()
	} else {
		regPath = filepath.Join(cfg.dataDir, "registry-fallback.ndjson")
		log.Printf("[api] registry dir not writable, falling back to %s", regPath)
	}
	cfg.registryFile = regPath

	dsn := "file:" + filepath.Join(cfg.dataDir, "api.db") + "?_pragma=journal_mode(WAL)&_pragma=busy_timeout(5000)"
	var err error
	db, err = sql.Open("sqlite", dsn)
	if err != nil {
		log.Fatalf("[api] cannot open sqlite: %v", err)
	}
	db.SetMaxOpenConns(1)
	for _, stmt := range strings.Split(schema, ";") {
		if strings.TrimSpace(stmt) == "" {
			continue
		}
		if _, err := db.Exec(stmt); err != nil {
			log.Fatalf("[api] schema exec failed: %v", err)
		}
	}

	bootstrapFlags()
	seedIfEmpty()
	jwksInit()

	mux := http.NewServeMux()
	mux.HandleFunc("GET /healthz", handleHealthz)
	mux.HandleFunc("GET /", handleRoot)
	mux.HandleFunc("POST /user/v1/login", handleLogin)
	mux.HandleFunc("POST /user/v1/logout", handleLogout)
	mux.HandleFunc("GET /user/v1/list", handleList)
	mux.HandleFunc("GET /user/v1/{user}/profile", handleProfile)
	mux.HandleFunc("GET /user/v1/{user}/orders", handleOrders)
	mux.HandleFunc("GET /user/v1/{user}/orders/{id}", handleOrder)
	mux.HandleFunc("PATCH /user/v1/{user}", handlePatch)
	mux.HandleFunc("POST /admin/v1/restart", handleRestart)
	mux.HandleFunc("GET /admin/v1/panel", handlePanel)
	mux.HandleFunc("GET /v1/user/{user}/profile", handleShadowProfile)
	mux.HandleFunc("GET /internal/activity", handleInternalActivity)

	var handler http.Handler = mux
	handler = corsWrap(handler)
	handler = trackWrap(handler)

	srv := &http.Server{
		Addr:              ":" + cfg.apiPort,
		Handler:           handler,
		ReadHeaderTimeout: 10 * time.Second,
		ReadTimeout:       60 * time.Second,
		WriteTimeout:      60 * time.Second,
	}
	log.Printf("[api] aslv-api listening on :%s (jwks=%s sink=%s)", cfg.apiPort, cfg.jwksURL, cfg.activitySink)
	if err := srv.ListenAndServe(); err != nil {
		log.Fatalf("[api] server error: %v", err)
	}
}
