// Command edgefront is the VLH-CTF M1 edge front: a deliberately desync-prone
// reverse proxy that turns one client framing rule into the other on its way to
// the back-end. It is the deterministic core of the ASLV M1 "HTTP" lab.
//
// ENVIRONMENT
//
//	EDGE_MODE   cl-te (default) | te-cl | te-te
//	EDGE_BACK   back-end address (default edge-back:8081)
//	LISTEN      listen address (default :8080)
//	INTERNAL_HOST  host that routes to the back-end internal zone
//	               (default internal.aslv.lab)
//
// MODES (all deterministic, no auto-repairing)
//
//	cl-te — the front honors Content-Length, then forwards to the back-end
//	  re-framed as `Transfer-Encoding: chunked`:
//	    * if the CL body is itself complete chunked framing (starts with a
//	      chunk-size line and contains the 0-chunk terminator), it is forwarded
//	      VERBATIM — any bytes packed after the terminator inside the CL window
//	      ride through and become the back-end's NEXT request (classic CL.TE).
//	    * otherwise the body is re-encoded as one true-length chunk plus a
//	      `0\r\n\r\n` terminator.
//	  In both cases, bytes the client sent beyond its declared Content-Length
//	  (the smuggled prefix) are appended RAW after the forwarded request, and
//	  the back-end — which honors Transfer-Encoding — parses them as its next
//	  pipelined request.
//
//	te-cl — the front honors Transfer-Encoding (de-chunks the body), then
//	  forwards with a Content-Length header: the CLIENT's original
//	  Content-Length if one was supplied (trusted verbatim — that is the
//	  desync), otherwise the true de-chunked length. The back-end honors CL,
//	  stops after CL bytes, and parses the rest of the body as its next
//	  request.
//
//	te-te — like te-cl, but the forwarded request also carries an OBFUSCATED
//	  `Transfer-Encoding : chunked` header (note the space before the colon).
//	  The back-end's strict parser does not recognize the name and falls back
//	  to Content-Length — classic TE.TE via obfuscation.
//
// HOST ROUTING (the host-header quirks surface)
//
// The front re-routes its BACKEND request when the request it parsed carries
// the internal host — via a duplicate Host header, an absolute-form target, or
// a plain internal Host: `Host: internal.aslv.lab` + `GET /flag` is forwarded
// as `GET /internal/flag` with `Host: internal.aslv.lab`. The outer nginx
// gateway 404s internal.aslv.lab and rejects duplicate Host headers, so this
// rule is reachable on the edge-front port (the deterministic lab bench) and,
// best-effort, via an absolute-form mismatch request through the gateway.
//
// LOCATION LOCK
//
// Parsed requests whose path starts with /internal are refused (403) unless
// the internal-host context applies — the edge has no /internal location, so
// the flag at edge-back's /internal/flag cannot be reached with a plain
// request through any routed path. Only a desynced smuggled request (which the
// front forwards without parsing) or an internal-Host-routed request gets in.
package main

import (
	"bufio"
	"bytes"
	"fmt"
	"io"
	"log"
	"net"
	"os"
	"strings"
	"time"

	"github.com/0xnhsec/vlh-ctf/modules/aslv-edge/internal/httparse"
)

const (
	readTimeout = 45 * time.Second
	dialTimeout = 5 * time.Second
)

func envOr(key, def string) string {
	if v := strings.TrimSpace(os.Getenv(key)); v != "" {
		return v
	}
	return def
}

var (
	edgeMode     = envOr("EDGE_MODE", "cl-te")
	backAddr     = envOr("EDGE_BACK", "edge-back:8081")
	listenAddr   = envOr("LISTEN", ":8080")
	internalHost = envOr("INTERNAL_HOST", "internal.aslv.lab")
)

func main() {
	switch edgeMode {
	case "cl-te", "te-cl", "te-te":
	default:
		log.Fatalf("edgefront: invalid EDGE_MODE %q (want cl-te | te-cl | te-te)", edgeMode)
	}
	ln, err := net.Listen("tcp", listenAddr)
	if err != nil {
		log.Fatalf("edgefront: listen %s: %v", listenAddr, err)
	}
	log.Printf("edgefront: listening on %s mode=%s back=%s internal-host=%s", listenAddr, edgeMode, backAddr, internalHost)
	for {
		c, err := ln.Accept()
		if err != nil {
			log.Printf("edgefront: accept: %v", err)
			continue
		}
		go handleClient(c)
	}
}

func handleClient(c net.Conn) {
	defer c.Close()
	_ = c.SetDeadline(time.Now().Add(readTimeout))
	br := bufio.NewReaderSize(c, 32*1024)

	req, err := readRequest(br)
	if err != nil {
		respondPlain(c, 400, "Bad Request", "edgefront: parse error: "+err.Error()+"\n")
		return
	}

	// Location lock: the edge has no /internal location. Parsed requests may
	// not enter the internal zone unless the internal-host context applies.
	p := httparse.PathOnly(req.Path)
	if (p == "/internal" || strings.HasPrefix(p, "/internal/")) && !internalContext(req) {
		respondPlain(c, 403, "Forbidden", "edgefront: /internal/* is unrouted at the edge (location-locked)\n")
		return
	}

	up, err := net.DialTimeout("tcp", backAddr, dialTimeout)
	if err != nil {
		respondPlain(c, 502, "Bad Gateway", "edgefront: back-end unreachable: "+err.Error()+"\n")
		return
	}
	defer up.Close()

	if _, err := up.Write(buildForward(req)); err != nil {
		return
	}

	// After the first (re-framed) exchange, pipe both directions raw so the
	// back-end's pipelined response to the smuggled request reaches the
	// client, and so later client bytes continue to flow to the back-end.
	_ = c.SetDeadline(time.Time{})
	pipeBoth(c, br, up)
}

// readRequest parses one request per the FRONT rule for the configured mode
// and captures the smuggled prefix (bytes beyond the framing rule that are
// already buffered on the connection).
func readRequest(br *bufio.Reader) (*httparse.Request, error) {
	r, err := httparse.ReadRequestHeaders(br)
	if err != nil {
		return nil, err
	}

	switch edgeMode {
	case "cl-te":
		// CL wins: read exactly Content-Length bytes. Anything the client
		// sends beyond that is the smuggled prefix (Leftover, below).
		if n, ok := r.ContentLength(); ok {
			body, err := httparse.ReadN(br, int(n))
			if err != nil {
				return nil, err
			}
			r.Body = body
		}
	case "te-cl", "te-te":
		// TE wins when it is strict chunked; otherwise fall back to CL.
		if r.ValidChunkedTE() {
			body, err := httparse.ReadBodyChunked(br)
			if err != nil {
				return nil, err
			}
			r.Body = body
		} else if n, ok := r.ContentLength(); ok {
			body, err := httparse.ReadN(br, int(n))
			if err != nil {
				return nil, err
			}
			r.Body = body
		}
	}

	// Smuggled prefix: whatever is buffered beyond the framing rule rides
	// along raw, appended after the forwarded request. Bytes that arrive
	// later flow through the raw pipe (pipeBoth reads from br).
	if n := br.Buffered(); n > 0 {
		buf := make([]byte, n)
		if _, err := io.ReadFull(br, buf); err != nil {
			return nil, err
		}
		r.Leftover = buf
	}
	return r, nil
}

// internalContext reports whether the parsed request signals the internal
// host — through a duplicate/plain Host header or an absolute-form target.
func internalContext(r *httparse.Request) bool {
	if httparse.HostPart(r.Authority) == internalHost {
		return true
	}
	for _, v := range r.HeaderValues("host") {
		if httparse.HostPart(v) == internalHost {
			return true
		}
	}
	return false
}

// hopByHop lists headers never forwarded upstream.
func hopByHop(name string) bool {
	switch strings.ToLower(name) {
	case "host", "content-length", "transfer-encoding", "connection", "keep-alive",
		"proxy-connection", "proxy-authorization", "proxy-authenticate", "te",
		"trailer", "upgrade":
		return true
	}
	return false
}

// buildForward serializes the request to be sent to the back-end: host-rule
// path rewrite, hop-by-hop stripping, and the mode's re-framing. The smuggled
// prefix (r.Leftover) is appended RAW after the re-framed request.
func buildForward(r *httparse.Request) []byte {
	internal := internalContext(r)
	path := r.Path
	if internal && !strings.HasPrefix(httparse.PathOnly(path), "/internal/") {
		path = "/internal/" + strings.TrimPrefix(path, "/")
	}

	var b bytes.Buffer
	b.WriteString(r.Method)
	b.WriteByte(' ')
	b.WriteString(path)
	b.WriteByte(' ')
	b.WriteString(r.Proto)
	b.WriteString("\r\n")

	for _, h := range r.Headers {
		if hopByHop(h.Name) {
			continue
		}
		b.WriteString(h.Raw)
		b.WriteString("\r\n")
	}
	if internal {
		// Force a single clean internal Host so the back-end's own host gate
		// lets the request into the internal zone (duplicate-Host defense).
		b.WriteString("Host: " + internalHost + "\r\n")
	} else {
		for _, h := range r.Headers {
			if strings.EqualFold(h.Name, "host") {
				b.WriteString(h.Raw)
				b.WriteString("\r\n")
			}
		}
	}

	switch edgeMode {
	case "cl-te":
		if len(r.Body) > 0 {
			b.WriteString("Transfer-Encoding: chunked\r\n\r\n")
			if _, ok := httparse.ChunkedComplete(r.Body); ok {
				// Pre-chunked body: pass through VERBATIM. Its own 0-chunk
				// terminator ends request #1 for the back-end and anything
				// packed after the terminator inside this CL window becomes
				// the back-end's next request (classic CL.TE payload).
				b.Write(r.Body)
			} else {
				// Ordinary body: re-encode with the TRUE length and terminate
				// cleanly. The desync channel is the appended Leftover.
				fmt.Fprintf(&b, "%x\r\n", len(r.Body))
				b.Write(r.Body)
				b.WriteString("\r\n0\r\n\r\n")
			}
		} else {
			b.WriteString("\r\n")
		}
	case "te-cl", "te-te":
		// Content-Length: the client's own value when supplied (trusted
		// verbatim — the TE.CL / TE.TE desync), else the true de-chunked
		// length. Body bytes follow verbatim; the back-end stops at CL bytes
		// and parses the remainder as its next request.
		cl := int64(len(r.Body))
		if v, ok := r.ContentLength(); ok {
			cl = v
		}
		fmt.Fprintf(&b, "Content-Length: %d\r\n", cl)
		if edgeMode == "te-te" {
			// Obfuscated TE: the back-end's strict parser does not match the
			// header NAME "Transfer-Encoding " (trailing space before the
			// colon) and falls back to Content-Length.
			b.WriteString("Transfer-Encoding : chunked\r\n")
		}
		b.WriteString("\r\n")
		b.Write(r.Body)
	}

	b.Write(r.Leftover)
	return b.Bytes()
}

// pipeBoth relays raw bytes in both directions. The client side reads through
// the bufio.Reader so bytes it already buffered are not lost.
func pipeBoth(client net.Conn, br *bufio.Reader, upstream net.Conn) {
	done := make(chan struct{}, 2)
	go func() {
		_, _ = io.Copy(upstream, br) // client -> back-end (raw)
		done <- struct{}{}
	}()
	go func() {
		_, _ = io.Copy(client, upstream) // back-end -> client (raw responses)
		done <- struct{}{}
	}()
	<-done
	_ = client.Close()
	_ = upstream.Close()
}

func respondPlain(c net.Conn, status int, reason, msg string) {
	fmt.Fprintf(c, "HTTP/1.1 %d %s\r\nContent-Type: text/plain; charset=utf-8\r\nContent-Length: %d\r\nConnection: close\r\n\r\n%s",
		status, reason, len(msg), msg)
}
