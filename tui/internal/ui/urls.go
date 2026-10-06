package ui

import (
	"os"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/charmbracelet/lipgloss"

	"github.com/0xnhsec/vlh-ctf/tui/internal/dockerops"
)

// Copyable entry points ("play URLs") for a deployed profile.
//
// The whole point is that the operator never has to guess a port or a vhost
// again: the port comes from the container that is actually publishing it
// (so FR-11 remaps via docker-compose.override.yml are reflected), and the
// vhosts are the ones the module sidecars / the full-mode gateway really
// route — restricted to names a host browser can resolve (localhost plus
// what installer.sh writes to /etc/hosts).

// hostPath is one routable vhost of a profile: host + the useful path on it.
type hostPath struct {
	host string
	path string
}

// entryHosts lists the vhosts one profile serves, in the order a player meets
// them (CONTRACT §4; source: gateway-full.conf, gateway-standalone.conf and
// the per-module sidecar templates). Wildcard tenant subdomains
// (<slug>.aslv.lab) are deliberately absent — /etc/hosts cannot express them
// (deployment.md §3), so they would never resolve from the host browser.
func entryHosts(profile string) []hostPath {
	switch {
	case profile == "full":
		return []hostPath{
			{"aslv.lab", "/"},                 // portal (M2) + /user/v1/* (M4)
			{"victim.aslv.lab", "/"},          // M2 victim origin (CORS/CSRF target)
			{"attacker.aslv.lab", "/"},        // M2 exploit server
			{"collector.aslv.lab", "/verify"}, // M2 verifier (event-minted flags)
			{"mail.aslv.lab", "/"},            // MailHog UI
			{"auth.aslv.lab", "/"},            // M5 identity
			{"client.aslv.lab", "/"},          // M5 OAuth client app
			{"edge.aslv.lab", "/"},            // M1 edge front
			{"app.aslv.lab", "/"},             // M3 app, shared origin (reserved tenant)
		}
	case profile == "m1":
		return []hostPath{
			{"edge.aslv.lab", "/"},
			{"www.aslv.lab", "/"},
			{"auth.aslv.lab", "/"},
			{"collector.aslv.lab", "/verify"},
			{"mail.aslv.lab", "/"},
		}
	case profile == "m2":
		return []hostPath{
			{"victim.aslv.lab", "/"},
			{"attacker.aslv.lab", "/"},
			{"collector.aslv.lab", "/verify"},
			{"mail.aslv.lab", "/"},
			{"www.aslv.lab", "/"},
		}
	case profile == "m3":
		return []hostPath{
			{"localhost", "/"}, // sidecar default_server → the app
			{"collector.aslv.lab", "/"},
			{"mail.aslv.lab", "/"},
		}
	case profile == "m4":
		return []hostPath{
			{"aslv.lab", "/user/v1/"},
			{"www.aslv.lab", "/user/v1/"},
			{"api.aslv.lab", "/"},
			{"auth.aslv.lab", "/"},
			{"localhost", "/"},
		}
	case profile == "m5":
		return []hostPath{
			{"auth.aslv.lab", "/"},
			{"client.aslv.lab", "/"},
			{"mail.aslv.lab", "/"},
			{"localhost", "/"},
		}
	}
	if strings.HasPrefix(profile, "dsltv-") { // every subclass: same sidecar
		return []hostPath{
			{"victim.target.lab", "/"},
			{"attacker.target.lab", "/"},
			{"collector.target.lab", "/verify"},
			{"mail.target.lab", "/"},
		}
	}
	return nil
}

// urlsFor renders the entry points of a profile on a given host port.
func urlsFor(profile string, port int) []string {
	hosts := entryHosts(profile)
	out := make([]string, 0, len(hosts))
	for _, h := range hosts {
		out = append(out, "http://"+h.host+":"+strconv.Itoa(port)+h.path)
	}
	return out
}

// firstURL is the one URL to open after deploying a profile ("" when the
// profile is unknown to the TUI).
func firstURL(profile string, port int) string {
	u := urlsFor(profile, port)
	if len(u) == 0 {
		return ""
	}
	return u[0]
}

// playPort returns the host port a profile really answers on: the port
// published by its running containers when there is one (this is what makes a
// port remap show up correctly), falling back to the config/manifest port.
func (m Model) playPort(t deployTarget) int {
	mgmt := make(map[int]bool, len(m.cfg.CollectorPorts))
	for _, p := range m.cfg.CollectorPorts {
		mgmt[p] = true // loopback collector-mgmt bindings are never play ports
	}
	fallback := 0
	for _, ci := range m.statusRows {
		if ci.State != "running" || !dockerops.ProfileMatches(ci, t.Profile) {
			continue
		}
		for _, p := range ci.PublicPorts {
			if mgmt[p] {
				continue
			}
			if p == t.Port {
				return p
			}
			if fallback == 0 {
				fallback = p
			}
		}
	}
	if fallback != 0 {
		return fallback
	}
	return t.Port
}

// activeTargets is every deployable that currently has running containers.
func (m Model) activeTargets() []deployTarget {
	all := m.allTargets()
	out := make([]deployTarget, 0, len(all))
	for _, t := range all {
		if m.isProfileActive(t) {
			out = append(out, t)
		}
	}
	return out
}

// Prefixes playLines uses so the status view can style the first line and the
// /etc/hosts hint; the continuation indent matches playPrefix.
const (
	playPrefix = "play  "
	hintPrefix = "!     "
)

// playLines renders the copyable entry points of every active profile, wrapped
// to width. First line is the primary URL of the first active profile. Returns
// nil when nothing is deployed (the caller then prints nothing).
func (m Model) playLines(width int) []string {
	active := m.activeTargets()
	if len(active) == 0 {
		return nil
	}
	if width < 40 {
		width = 40
	}
	var missing []string
	var urls []string
	for _, t := range active {
		for _, u := range urlsFor(t.Profile, m.playPort(t)) {
			urls = append(urls, u)
			if h := hostOf(u); !resolvesFromHosts(h) {
				missing = append(missing, h)
			}
		}
	}
	if len(urls) == 0 {
		return nil
	}

	indent := strings.Repeat(" ", len(playPrefix))
	lines := []string{playPrefix + urls[0]}
	rest := urls[1:]
	cur := indent
	for _, u := range rest {
		sep := ""
		if cur != indent {
			sep = "  "
		}
		if lipgloss.Width(cur)+lipgloss.Width(sep)+lipgloss.Width(u) > width {
			lines = append(lines, cur)
			cur = indent + u
			continue
		}
		cur += sep + u
	}
	if cur != indent {
		lines = append(lines, cur)
	}
	if len(missing) > 0 {
		lines = append(lines, hintPrefix+
			dupeFree(missing)+" not in /etc/hosts — run ./installer.sh --hosts (needs sudo)")
	}
	return lines
}

// hostOf extracts the hostname from an http://host:port/path URL.
func hostOf(u string) string {
	s := strings.TrimPrefix(u, "http://")
	if i := strings.IndexAny(s, ":/"); i >= 0 {
		s = s[:i]
	}
	return s
}

// dupeFree keeps order while dropping repeats.
func dupeFree(in []string) string {
	seen := map[string]bool{}
	out := in[:0:0]
	for _, s := range in {
		if seen[s] {
			continue
		}
		seen[s] = true
		out = append(out, s)
	}
	return strings.Join(out, ", ")
}

// resolvesFromHosts reports whether /etc/hosts maps host to an address.
// Unreadable file ⇒ true (no hint, we simply do not know).
func resolvesFromHosts(host string) bool {
	if host == "localhost" {
		return true
	}
	names, ok := hostFileNames()
	if !ok {
		return true
	}
	return names[host]
}

var (
	hostsMu    sync.Mutex
	hostsCache map[string]bool
	hostsAt    time.Time
)

// hostFileNames parses /etc/hosts (cached for a few seconds so the status
// screen does not re-read it on every redraw).
func hostFileNames() (map[string]bool, bool) {
	hostsMu.Lock()
	defer hostsMu.Unlock()
	if hostsCache != nil && time.Since(hostsAt) < 5*time.Second {
		return hostsCache, true
	}
	data, err := os.ReadFile("/etc/hosts")
	if err != nil {
		hostsCache = nil
		hostsAt = time.Now()
		return nil, false
	}
	names := map[string]bool{}
	for _, line := range strings.Split(string(data), "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		if i := strings.IndexAny(line, "#"); i >= 0 {
			line = strings.TrimSpace(line[:i])
		}
		fields := strings.Fields(line)
		for _, f := range fields[1:] {
			names[f] = true
		}
	}
	hostsCache = names
	hostsAt = time.Now()
	return names, true
}


