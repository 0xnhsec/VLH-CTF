// Command edgeback is the VLH-CTF M1 origin back-end.
//
// LISTENER :8081 — raw, manually parsed HTTP (NO net/http here: it would
// auto-repair the ambiguous framing the smuggling labs depend on, arch §8).
// The connection handler parses requests in a LOOP, so a pipelined or
// smuggled request that follows the first one on the same connection gets its
// own response — the response the player reads off the socket after the
// visible one.
//
// Routing (deterministic):
//
//	Host: internal.aslv.lab  →  path is prefixed with /internal/
//	                            (the internal zone's own host gate)
//	/internal/flag           →  ASLV{HTTP-...} — ONLY inside the internal
//	                            host context (403 otherwise)
//	/internal/*              →  404
//	/app/*                   →  200 simple pages (/app/vault shows the
//	                            synthetic innocent secret)
//	anything else            →  404
//
// The flag is generated at container start (entrypoint script) and stored in
// /data/flag.txt; this binary re-generates + registers it if the file is
// missing (CONTRACT §3: never hardcoded, never in env, regenerated every
// restart).
//
// LISTENER :8090 — mini collector. net/http is fine on this listener because
// it is NOT in the smuggling path:
//
//	GET  /internal/activity  NDJSON, latest 5000 activity rows (newest first)
//	POST /internal/ingest    accept forwarded activity rows (NDJSON body)
//	POST /ingest             alias
//	GET  /healthz            liveness probe
//
// Every :8081 request is logged as an activity row {ts, identifier,
// is_authenticated, data, latency_ms} to /data/activity.jsonl and, when
// ACTIVITY_SINK is set, POSTed there fire-and-forget (1s timeout).
package main

import (
	"bufio"
	"crypto/rand"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/0xnhsec/vlh-ctf/modules/aslv-edge/internal/httparse"
)

func envOr(key, def string) string {
	if v := strings.TrimSpace(os.Getenv(key)); v != "" {
		return v
	}
	return def
}

var (
	listenAddr    = envOr("LISTEN", ":8081")
	collectorAddr = envOr("COLLECTOR_LISTEN", ":8090")
	dataDir       = envOr("DATA_DIR", "/data")
	registryDir   = envOr("REGISTRY_DIR", "/registry")
	internalHost  = envOr("INTERNAL_HOST", "internal.aslv.lab")
	activitySink  = os.Getenv("ACTIVITY_SINK")
)

var (
	flagOnce sync.Once
	appFlag  string

	actMu   sync.Mutex
	actFile string
)

func main() {
	_ = os.MkdirAll(dataDir, 0o755)
	actFile = filepath.Join(dataDir, "activity.jsonl")
	_ = os.MkdirAll(registryDir, 0o755) // best effort; writes fall back to /data

	log.Printf("edgeback: flag ready (%d bytes), internal-host=%s", len(loadFlag()), internalHost)

	go runCollector()

	ln, err := net.Listen("tcp", listenAddr)
	if err != nil {
		log.Fatalf("edgeback: listen %s: %v", listenAddr, err)
	}
	log.Printf("edgeback: raw http on %s, collector on %s", listenAddr, collectorAddr)
	for {
		c, err := ln.Accept()
		if err != nil {
			log.Printf("edgeback: accept: %v", err)
			continue
		}
		go serveConn(c)
	}
}

// serveConn answers every request arriving on the connection in order. This
// loop is what turns the edge-front's re-framing into observable desync: the
// smuggled request that follows the first one gets parsed and answered like
// any other.
func serveConn(c net.Conn) {
	defer c.Close()
	br := bufio.NewReaderSize(c, 32*1024)
	for {
		_ = c.SetDeadline(time.Now().Add(75 * time.Second))
		r, err := httparse.ReadRequestHeaders(br)
		if err != nil {
			return
		}

		// Back-end framing rule: strict chunked TE when present, else CL.
		// Obfuscated TE headers (TE.TE) are NOT recognized → CL fallback.
		if r.ValidChunkedTE() {
			body, err := httparse.ReadBodyChunked(br)
			if err != nil {
				return
			}
			r.Body = body
		} else if cl, ok := r.ContentLength(); ok {
			body, err := httparse.ReadN(br, int(cl))
			if err != nil {
				return
			}
			r.Body = body
		}

		start := time.Now()
		status, reason, ctype, body := route(r)
		keepAlive := !r.WantsClose() && r.Proto != "HTTP/1.0"
		writeResponse(c, status, reason, ctype, body, keepAlive)
		logActivity(c, r, status, time.Since(start))
		if !keepAlive {
			return
		}
	}
}

func route(r *httparse.Request) (status int, reason, ctype, body string) {
	internal := false
	if httparse.HostPart(r.Authority) == internalHost {
		internal = true
	}
	for _, v := range r.HeaderValues("host") {
		if httparse.HostPart(v) == internalHost {
			internal = true
		}
	}

	path := r.Path
	if internal && !strings.HasPrefix(httparse.PathOnly(path), "/internal/") {
		path = "/internal/" + strings.TrimPrefix(path, "/")
	}
	p := httparse.PathOnly(path)

	switch {
	case p == "/internal/flag":
		if !internal {
			return 403, "Forbidden", "text/plain; charset=utf-8",
				"edge-back: the internal zone requires Host: " + internalHost + "\n"
		}
		return 200, "OK", "text/html; charset=utf-8", flagPage()
	case strings.HasPrefix(p, "/internal/"):
		return 404, "Not Found", "text/plain; charset=utf-8", "edge-back: no such internal resource\n"
	case p == "/app" || strings.HasPrefix(p, "/app/"):
		if p == "/app/vault" || strings.HasPrefix(p, "/app/vault/") {
			return 200, "OK", "text/html; charset=utf-8", vaultPage()
		}
		return 200, "OK", "text/html; charset=utf-8", appPage(p)
	case p == "/healthz":
		return 200, "OK", "application/json", `{"ok":true,"service":"edge-back"}`
	default:
		return 404, "Not Found", "text/plain; charset=utf-8", "edge-back: not found\n"
	}
}

func writeResponse(c net.Conn, status int, reason, ctype, body string, keepAlive bool) {
	conn := "keep-alive"
	if !keepAlive {
		conn = "close"
	}
	fmt.Fprintf(c, "HTTP/1.1 %d %s\r\nContent-Type: %s\r\nContent-Length: %d\r\nConnection: %s\r\n\r\n%s",
		status, reason, ctype, len(body), conn, body)
}

/* ------------------------------------------------------------ activity */

func logActivity(c net.Conn, r *httparse.Request, status int, took time.Duration) {
	remote := "unknown"
	if ra := c.RemoteAddr(); ra != nil {
		remote = ra.String()
	}
	row := map[string]any{
		"ts":               time.Now().UTC().Format("2006-01-02T15:04:05.000Z"),
		"identifier":       remote + "/edge",
		"is_authenticated": false,
		"data":             fmt.Sprintf("%s %s -> %d", r.Method, httparse.PathOnly(r.Path), status),
		"latency_ms":       float64(took.Microseconds()) / 1000.0,
		"unit":             "m1",
	}
	b, err := json.Marshal(row)
	if err != nil {
		return
	}
	appendActivity(string(b))
	sinkActivity(string(b))
}

func appendActivity(line string) {
	actMu.Lock()
	defer actMu.Unlock()
	f, err := os.OpenFile(actFile, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o644)
	if err != nil {
		return
	}
	defer f.Close()
	_, _ = f.WriteString(line + "\n")
}

func sinkActivity(line string) {
	if activitySink == "" {
		return
	}
	go func() {
		client := &http.Client{Timeout: time.Second} // fire-and-forget, 1s cap
		resp, err := client.Post(activitySink, "application/x-ndjson", strings.NewReader(line))
		if err == nil {
			_ = resp.Body.Close()
		}
	}()
}

func tailActivity(n int) []string {
	actMu.Lock()
	defer actMu.Unlock()
	b, err := os.ReadFile(actFile)
	if err != nil {
		return nil
	}
	all := strings.Split(strings.TrimRight(string(b), "\n"), "\n")
	if len(all) == 1 && all[0] == "" {
		return nil
	}
	if len(all) > n {
		all = all[len(all)-n:]
	}
	out := make([]string, 0, len(all))
	for i := len(all) - 1; i >= 0; i-- { // newest first
		out = append(out, all[i])
	}
	return out
}

/* ------------------------------------------------------------ collector */

func runCollector() {
	if collectorAddr == "" || collectorAddr == "-" {
		return
	}
	mux := http.NewServeMux()
	mux.HandleFunc("/internal/activity", handleActivity)
	mux.HandleFunc("/internal/ingest", handleIngest)
	mux.HandleFunc("/ingest", handleIngest)
	mux.HandleFunc("/healthz", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = io.WriteString(w, `{"ok":true,"service":"edge-back-collector"}`)
	})
	srv := &http.Server{Addr: collectorAddr, Handler: mux, ReadHeaderTimeout: 5 * time.Second}
	if err := srv.ListenAndServe(); err != nil {
		log.Printf("edgeback: collector %s: %v", collectorAddr, err)
	}
}

func handleActivity(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		w.WriteHeader(http.StatusMethodNotAllowed)
		return
	}
	w.Header().Set("Content-Type", "application/x-ndjson")
	for _, l := range tailActivity(5000) {
		_, _ = io.WriteString(w, l+"\n")
	}
}

func handleIngest(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		w.WriteHeader(http.StatusMethodNotAllowed)
		return
	}
	body, err := io.ReadAll(io.LimitReader(r.Body, 8<<20))
	if err != nil {
		w.WriteHeader(http.StatusBadRequest)
		return
	}
	count := 0
	for _, line := range strings.Split(strings.TrimRight(string(body), "\n"), "\n") {
		if strings.TrimSpace(line) != "" {
			appendActivity(line)
			count++
		}
	}
	w.Header().Set("Content-Type", "application/json")
	_, _ = io.WriteString(w, fmt.Sprintf(`{"ingested":%d}`, count))
}

/* ----------------------------------------------------------- flag/pages */

func loadFlag() string {
	flagOnce.Do(func() {
		p := filepath.Join(dataDir, "flag.txt")
		if b, err := os.ReadFile(p); err == nil {
			if s := strings.TrimSpace(string(b)); strings.HasPrefix(s, "ASLV{HTTP-") {
				appFlag = s
				return
			}
		}
		// Fallback: the entrypoint normally generates the flag; if the file is
		// missing (e.g. someone runs the binary directly) mint one now and
		// register it per CONTRACT §3.
		appFlag = "ASLV{HTTP-" + randomDigits(10) + "}"
		_ = os.WriteFile(p, []byte(appFlag), 0o644)
		registryAppend(registryLine(appFlag, "held"))
	})
	return appFlag
}

func loadSecret() string {
	b, err := os.ReadFile(filepath.Join(dataDir, "innocent-secret.txt"))
	if err != nil {
		return "unavailable"
	}
	return strings.TrimSpace(string(b))
}

func randomDigits(n int) string {
	buf := make([]byte, n)
	if _, err := rand.Read(buf); err != nil {
		return strings.Repeat("0", n)
	}
	out := make([]byte, n)
	for i, v := range buf {
		out[i] = byte('0') + byte(v)%10
	}
	return string(out)
}

func registryLine(flag, note string) string {
	ts := time.Now().UTC().Format("2006-01-02T15:04:05Z")
	return fmt.Sprintf(`{"flag":%q,"category":"HTTP","unit":"m1","archetype":"location-locked","minted_at":%q,"note":%q}`,
		flag, ts, note)
}

func registryAppend(line string) {
	_ = os.MkdirAll(registryDir, 0o755)
	p := filepath.Join(registryDir, "flags.ndjson")
	f, err := os.OpenFile(p, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o644)
	if err != nil {
		p = filepath.Join(dataDir, "registry-fallback.ndjson")
		if f, err = os.OpenFile(p, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o644); err != nil {
			return
		}
	}
	defer f.Close()
	_, _ = f.WriteString(line + "\n")
}

const pageStyle = `<style>
body{font-family:ui-monospace,Menlo,Consolas,monospace;background:#0a0f0a;color:#c7f0c7;margin:0;padding:2rem}
a{color:#4ade80}h1{color:#4ade80;font-size:1.2rem}.muted{color:#5c8a5c;font-size:.8rem}
.flag{color:#facc15;font-weight:700}code{background:#0f1a0f;padding:.1rem .3rem;border-radius:3px}
</style>`

func flagPage() string {
	return "<!doctype html><html><head><meta charset=\"utf-8\"><title>internal — flag</title>" + pageStyle +
		"</head><body><h1>edge-back internal zone</h1>" +
		"<p>You reached the unrouted internal zone. Your flag:</p>" +
		"<p class=\"flag\">" + loadFlag() + "</p>" +
		"<p class=\"muted\">location-locked: this page is unreachable through any gateway vhost — only a desync or an internal-Host route gets here.</p>" +
		"</body></html>"
}

func vaultPage() string {
	return "<!doctype html><html><head><meta charset=\"utf-8\"><title>app — vault</title>" + pageStyle +
		"</head><body><h1>app vault (synthetic victim page)</h1>" +
		"<p>The synthetic innocent secret for this boot:</p>" +
		"<p><code>" + loadSecret() + "</code></p>" +
		"<p class=\"muted\">M1 standalone generates this 32-hex secret at boot. It stands in for the innocent session-bound secret of M2/M3 when the edge lab is played offline.</p>" +
		"</body></html>"
}

func appPage(p string) string {
	return "<!doctype html><html><head><meta charset=\"utf-8\"><title>app</title>" + pageStyle +
		"</head><body><h1>edge-back app</h1>" +
		"<p>Requested: <code>" + p + "</code></p>" +
		"<p>Pages: <a href=\"/app\">/app</a> · <a href=\"/app/vault\">/app/vault</a></p>" +
		"<p class=\"muted\">This origin honors strict <code>Transfer-Encoding: chunked</code> when present, Content-Length otherwise.</p>" +
		"</body></html>"
}
