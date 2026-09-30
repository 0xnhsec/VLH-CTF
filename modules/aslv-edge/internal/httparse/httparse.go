// Package httparse provides the tiny, deliberately strict HTTP/1.1 message
// parser shared by the VLH-CTF M1 edge pair (edge-front / edge-back).
//
// It is hand-written on top of net.Conn-sized buffers on purpose: framework
// parsers (net/http, Express, Laravel, ...) silently auto-repair the ambiguous
// framing that the request-smuggling labs depend on (architecture decisions
// §8: "M1 backend must not auto-repair ambiguous framing").
//
// Strictness rules that matter for the labs:
//   - Header NAMES are compared without trimming: `Transfer-Encoding : chunked`
//     (space before the colon) is NOT a Transfer-Encoding header. That
//     obfuscation is the TE.TE surface.
//   - `Transfer-Encoding` counts as chunked framing only when a single header
//     carries the exact value `chunked` (case-insensitive, OWS-trimmed).
//     `xchunked`, `chunked, identity`, stacked TEs etc. are NOT chunked.
//   - Duplicate Host headers are preserved in order and all values are exposed
//     to the caller (the duplicate-Host routing trick needs them).
package httparse

import (
        "bufio"
        "bytes"
        "fmt"
        "io"
        "strconv"
        "strings"
)

// MaxBody is the largest body (per request, after de-chunking) the pair will
// buffer. The labs never need anything close to this.
const MaxBody = 8 * 1024 * 1024

// Header is one raw header line. Name keeps the exact bytes before the colon
// (case preserved, whitespace preserved); Value is OWS-trimmed; Raw is the
// complete original line without the trailing CRLF.
type Header struct {
        Name  string
        Value string
        Raw   string
}

// Request is a parsed request head (body filled by the caller according to
// whichever framing rule that side of the edge pair honors).
type Request struct {
        Method    string
        Target    string // original request target (may be absolute-form)
        Proto     string
        Path      string // origin-form path (query included) derived from Target
        Authority string // host[:port] from an absolute-form Target, else ""
        Headers   []Header
        Body      []byte
        // Leftover holds bytes that arrived beyond the framing rule the parser
        // honored — the smuggled prefix from the front's point of view. Only the
        // edge-front populates it.
        Leftover []byte
}

// HeaderValues returns every value for the (case-insensitive) header name,
// duplicates included, in wire order.
func (r *Request) HeaderValues(name string) []string {
        var out []string
        for _, h := range r.Headers {
                if strings.EqualFold(h.Name, name) {
                        out = append(out, h.Value)
                }
        }
        return out
}

// ContentLength returns the first parseable Content-Length header.
func (r *Request) ContentLength() (int64, bool) {
        for _, h := range r.Headers {
                if strings.EqualFold(h.Name, "content-length") {
                        if n, err := strconv.ParseInt(strings.TrimSpace(h.Value), 10, 64); err == nil {
                                return n, true
                        }
                }
        }
        return 0, false
}

// ValidChunkedTE reports a strict `Transfer-Encoding: chunked` header. See the
// package comment: obfuscated or stacked forms deliberately do NOT count.
func (r *Request) ValidChunkedTE() bool {
        for _, h := range r.Headers {
                if strings.EqualFold(h.Name, "transfer-encoding") &&
                        strings.EqualFold(strings.TrimSpace(h.Value), "chunked") {
                        return true
                }
        }
        return false
}

// WantsClose reports a `Connection: close` header (token match).
func (r *Request) WantsClose() bool {
        for _, h := range r.Headers {
                if !strings.EqualFold(h.Name, "connection") {
                        continue
                }
                for _, tok := range strings.Split(h.Value, ",") {
                        if strings.EqualFold(strings.TrimSpace(tok), "close") {
                                return true
                        }
                }
        }
        return false
}

// ReadLine reads one CRLF- (or LF-) terminated line and strips the terminator.
func ReadLine(br *bufio.Reader) (string, error) {
        line, err := br.ReadString('\n')
        if err != nil {
                return "", err
        }
        return strings.TrimRight(line, "\r\n"), nil
}

// ReadN reads exactly n bytes.
func ReadN(br *bufio.Reader, n int) ([]byte, error) {
        if n < 0 || n > MaxBody {
                return nil, fmt.Errorf("refusing to read %d bytes", n)
        }
        buf := make([]byte, n)
        if _, err := io.ReadFull(br, buf); err != nil {
                return nil, err
        }
        return buf, nil
}

// ReadRequestHeaders parses the request line + header block only. The caller
// decides which framing rule (CL or TE) owns the body.
func ReadRequestHeaders(br *bufio.Reader) (*Request, error) {
        reqLine, err := ReadLine(br)
        if err != nil {
                return nil, err
        }
        if reqLine == "" {
                // tolerate a stray leading blank line
                reqLine, err = ReadLine(br)
                if err != nil {
                        return nil, err
                }
        }
        parts := strings.SplitN(reqLine, " ", 3)
        if len(parts) != 3 || parts[0] == "" || parts[2] == "" {
                return nil, fmt.Errorf("malformed request line %q", reqLine)
        }
        r := &Request{Method: parts[0], Target: parts[1], Proto: parts[2]}
        r.Path, r.Authority = SplitTarget(r.Target)

        block := 0
        for {
                h, err := ReadLine(br)
                if err != nil {
                        return nil, err
                }
                if h == "" {
                        break // end of header block
                }
                block += len(h)
                if block > 128*1024 {
                        return nil, fmt.Errorf("header block too large")
                }
                i := strings.IndexByte(h, ':')
                if i <= 0 {
                        continue // deterministically skip junk lines
                }
                r.Headers = append(r.Headers, Header{
                        Name:  h[:i],
                        Value: strings.Trim(h[i+1:], " \t"),
                        Raw:   h,
                })
        }
        return r, nil
}

// SplitTarget splits an absolute-form target into (path, authority). For an
// origin-form target it returns (target, "").
func SplitTarget(target string) (path, authority string) {
        if strings.HasPrefix(target, "http://") || strings.HasPrefix(target, "https://") {
                rest := target[strings.Index(target, "://")+3:]
                if i := strings.IndexAny(rest, "/?#"); i >= 0 {
                        return rest[i:], rest[:i]
                }
                return "/", rest
        }
        return target, ""
}

// PathOnly strips the query/fragment so prefix checks see the bare path.
func PathOnly(p string) string {
        if i := strings.IndexAny(p, "?#"); i >= 0 {
                return p[:i]
        }
        return p
}

// HostPart lowercases and strips an optional :port ("[::1]:80" and "a.b:80"
// both handled). Used for Host-header comparisons.
func HostPart(s string) string {
        s = strings.TrimSpace(strings.ToLower(s))
        if strings.HasPrefix(s, "[") {
                if i := strings.IndexByte(s, ']'); i >= 0 {
                        return s[1:i]
                }
                return s
        }
        if i := strings.LastIndexByte(s, ':'); i >= 0 {
                return s[:i]
        }
        return s
}

// ReadBodyChunked consumes a complete chunked body (terminating 0-chunk plus
// trailer section) and returns the de-chunked payload.
func ReadBodyChunked(br *bufio.Reader) ([]byte, error) {
        var body []byte
        for {
                sizeLine, err := ReadLine(br)
                if err != nil {
                        return nil, err
                }
                if i := strings.IndexByte(sizeLine, ';'); i >= 0 {
                        sizeLine = sizeLine[:i] // chunk extensions
                }
                n, err := strconv.ParseInt(strings.TrimSpace(sizeLine), 16, 64)
                if err != nil || n < 0 {
                        return nil, fmt.Errorf("bad chunk size %q", sizeLine)
                }
                if n == 0 {
                        for { // trailers until blank line
                                t, err := ReadLine(br)
                                if err != nil {
                                        return nil, err
                                }
                                if t == "" {
                                        return body, nil
                                }
                        }
                }
                if len(body)+int(n) > MaxBody {
                        return nil, fmt.Errorf("chunked body too large")
                }
                chunk, err := ReadN(br, int(n))
                if err != nil {
                        return nil, err
                }
                body = append(body, chunk...)
                crlf, err := ReadLine(br)
                if err != nil {
                        return nil, err
                }
                if crlf != "" {
                        return nil, fmt.Errorf("missing CRLF after chunk data")
                }
        }
}

// ChunkedComplete reports whether body itself is complete chunked framing that
// terminates with a 0-chunk inside body. It returns the offset just past the
// terminator. Bytes after that offset inside the body are, from a chunk-honoring
// parser's point of view, the start of the NEXT request — the classic CL.TE
// smuggling payload packs the smuggled request there. This lets edge-front pass
// pre-chunked bodies through VERBATIM (preserving the embedded terminator and
// whatever follows it) instead of re-encoding them with a true-length chunk.
func ChunkedComplete(body []byte) (int, bool) {
        pos := 0
        for {
                end := bytes.IndexByte(body[pos:], '\n')
                if end < 0 {
                        return 0, false
                }
                sizeLine := strings.TrimRight(string(body[pos:pos+end]), "\r")
                if i := strings.IndexByte(sizeLine, ';'); i >= 0 {
                        sizeLine = sizeLine[:i]
                }
                n, err := strconv.ParseInt(strings.TrimSpace(sizeLine), 16, 64)
                if err != nil || n < 0 {
                        return 0, false
                }
                pos += end + 1
                if n == 0 {
                        for {
                                e := bytes.IndexByte(body[pos:], '\n')
                                if e < 0 {
                                        return 0, false
                                }
                                line := strings.TrimRight(string(body[pos:pos+e]), "\r")
                                pos += e + 1
                                if line == "" {
                                        return pos, true
                                }
                        }
                }
                if pos+int(n)+2 > len(body) {
                        return 0, false // chunk data + CRLF not fully contained
                }
                pos += int(n)
                if body[pos] == '\r' && body[pos+1] == '\n' {
                        pos += 2
                } else {
                        return 0, false
                }
        }
}
