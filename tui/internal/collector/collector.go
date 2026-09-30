// Package collector polls the lab's collector management API
// (GET /internal/activity, NDJSON) — the FR-8 activity feed.
//
// Reachability contract (CONTRACT §2/§9 + dsltv/base/runtime.js): the mgmt
// endpoints are bound on host loopback (full=18090, m1..m5=18091..18095,
// dsltv=18119). The base URL names the collector VHOST — e.g.
// "http://collector.target.lab:18119" (DSLTV) or
// "http://collector.aslv.lab:18090" (ASLV full) — because the DSLTV runtime
// routes by Host header. PollActivity sets the Host header from the base URL's
// host part but always DIALS 127.0.0.1:<port>, so no /etc/hosts entry is
// required for the TUI.
package collector

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"strings"
	"time"
)

// ActivityRow is one line of the /internal/activity NDJSON feed.
//
// BINDING cross-agent API: field names and meaning match dsltv/base/runtime.js
// exactly (ts, identifier, is_authenticated, data, latency, unit). The ASLV M0
// collector must emit the same shape.
type ActivityRow struct {
	TS              string  `json:"ts"`              // ISO8601 UTC
	Identifier      string  `json:"identifier"`      // username or "ip/session-prefix"
	IsAuthenticated bool    `json:"is_authenticated"`
	Data            string  `json:"data"`   // e.g. "GET /api/secret"
	Latency         float64 `json:"latency"` // milliseconds
	Unit            string  `json:"unit"`   // emitting profile, e.g. "dsltv-jwt-none-alg"
}

// PollActivity GETs baseURL + "/internal/activity" and parses the NDJSON body.
// Rows arrive newest-first (runtime orders by id DESC). Timeout: 2s.
func PollActivity(baseURL string) ([]ActivityRow, error) {
	u, err := url.Parse(strings.TrimRight(baseURL, "/"))
	if err != nil {
		return nil, fmt.Errorf("collector: bad base URL %q: %w", baseURL, err)
	}
	if u.Scheme != "http" && u.Scheme != "https" {
		return nil, fmt.Errorf("collector: base URL %q must include http(s):// and name the collector vhost", baseURL)
	}
	if u.Host == "" {
		return nil, fmt.Errorf("collector: base URL %q has no host", baseURL)
	}

	req, err := http.NewRequest(http.MethodGet, u.String()+"/internal/activity", nil)
	if err != nil {
		return nil, fmt.Errorf("collector: build request: %w", err)
	}
	req.Host = u.Host // Host-header vhost routing (see package doc)

	client := &http.Client{
		Timeout: 2 * time.Second,
		Transport: &http.Transport{
			// The mgmt endpoints live on host loopback: dial 127.0.0.1, keep
			// the URL's port, ignore its hostname.
			DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
				_, port, splitErr := net.SplitHostPort(addr)
				if splitErr != nil || port == "" {
					port = "80"
				}
				d := net.Dialer{Timeout: time.Second}
				return d.DialContext(ctx, network, net.JoinHostPort("127.0.0.1", port))
			},
		},
	}

	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("collector: %w", err)
	}
	defer resp.Body.Close() //nolint:errcheck // read-only body
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("collector: HTTP %d from %s", resp.StatusCode, u.Host)
	}

	var rows []ActivityRow
	sc := bufio.NewScanner(resp.Body)
	sc.Buffer(make([]byte, 0, 64*1024), 1024*1024)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" {
			continue
		}
		var row ActivityRow
		if err := json.Unmarshal([]byte(line), &row); err != nil {
			continue // skip malformed lines — never break the feed
		}
		rows = append(rows, row)
	}
	if err := sc.Err(); err != nil {
		return nil, fmt.Errorf("collector: read activity feed: %w", err)
	}
	return rows, nil
}
