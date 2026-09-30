// Package config loads and persists the TUI configuration at
// ~/.config/aslv-dsltv/config.toml (PRD FR-11, CONTRACT §9) and generates
// docker-compose.override.yml files for host-port remapping.
package config

import (
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"

	"github.com/BurntSushi/toml"
	"gopkg.in/yaml.v3"
)

// Config mirrors ~/.config/aslv-dsltv/config.toml. Map keys are compose
// profile names ("full", "m1".."m5", "dsltv").
type Config struct {
	DefaultPorts   map[string]int `toml:"default_ports"`
	CollectorPorts map[string]int `toml:"collector_ports"`
	ExportDir      string         `toml:"export_dir"`
	ComposeFile    string         `toml:"compose_file"`
	ManifestDir    string         `toml:"manifest_dir"`
}

// DefaultPorts per CONTRACT §2 (ASLV mode ports + shared DSLTV port).
func defaultPorts() map[string]int {
	return map[string]int{
		"full":  18024,
		"m1":    18021,
		"m2":    18022,
		"m3":    18023,
		"m4":    18025,
		"m5":    18026,
		"dsltv": 8119,
	}
}

// CollectorPorts per CONTRACT §2 — collector management API on host loopback.
func collectorPorts() map[string]int {
	return map[string]int{
		"full":  18090,
		"m1":    18091,
		"m2":    18092,
		"m3":    18093,
		"m4":    18094,
		"m5":    18095,
		"dsltv": 18119,
	}
}

// Default returns a Config with all defaults filled in (CONTRACT §2/§9).
func Default() *Config {
	c := &Config{}
	c.backfill()
	return c
}

func (c *Config) backfill() {
	if c.DefaultPorts == nil {
		c.DefaultPorts = map[string]int{}
	}
	for k, v := range defaultPorts() {
		if _, ok := c.DefaultPorts[k]; !ok {
			c.DefaultPorts[k] = v
		}
	}
	if c.CollectorPorts == nil {
		c.CollectorPorts = map[string]int{}
	}
	for k, v := range collectorPorts() {
		if _, ok := c.CollectorPorts[k]; !ok {
			c.CollectorPorts[k] = v
		}
	}
	if c.ExportDir == "" {
		c.ExportDir = "./exports"
	}
	if c.ComposeFile == "" {
		c.ComposeFile = "docker-compose.yml"
	}
	if c.ManifestDir == "" {
		c.ManifestDir = "manifests"
	}
}

// Path returns the absolute config file path (~/.config/aslv-dsltv/config.toml).
func Path() (string, error) {
	home, err := os.UserHomeDir()
	if err != nil {
		return "", fmt.Errorf("resolve home dir: %w", err)
	}
	return filepath.Join(home, ".config", "aslv-dsltv", "config.toml"), nil
}

// Load reads the config file, creating it with defaults on first run. Missing
// keys are backfilled from defaults, so a partial user file is fine.
func Load() (*Config, error) {
	p, err := Path()
	if err != nil {
		return nil, err
	}
	cfg := Default()
	if _, err := os.Stat(p); err != nil {
		if os.IsNotExist(err) {
			if err := cfg.Save(); err != nil {
				return nil, fmt.Errorf("write default config to %s: %w", p, err)
			}
			return cfg, nil
		}
		return nil, fmt.Errorf("stat %s: %w", p, err)
	}
	if _, err := toml.DecodeFile(p, cfg); err != nil {
		return nil, fmt.Errorf("parse %s: %w", p, err)
	}
	cfg.backfill()
	return cfg, nil
}

// Save writes the config file (creates parent directories as needed).
func (c *Config) Save() error {
	p, err := Path()
	if err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
		return fmt.Errorf("create config dir: %w", err)
	}
	f, err := os.Create(p)
	if err != nil {
		return fmt.Errorf("create %s: %w", p, err)
	}
	if err := toml.NewEncoder(f).Encode(c); err != nil {
		return fmt.Errorf("encode config: %w", err)
	}
	return f.Close()
}

// ---------------------------------------------------------------------------
// Port overrides -> docker-compose.override.yml (PRD FR-11)
// ---------------------------------------------------------------------------

// PortMapping is one published port entry of a compose service
// ("[bindIP:]host:guest[/proto]").
type PortMapping struct {
	HostPort  int
	GuestPort int
	Protocol  string // "" => tcp
	BindIP    string // "" => no explicit bind IP
}

func (p PortMapping) String() string {
	proto := p.Protocol
	if proto == "" {
		proto = "tcp"
	}
	if p.BindIP != "" {
		return fmt.Sprintf("%s:%d:%d/%s", p.BindIP, p.HostPort, p.GuestPort, proto)
	}
	return fmt.Sprintf("%d:%d/%s", p.HostPort, p.GuestPort, proto)
}

type rawCompose struct {
	Services map[string]rawService `yaml:"services"`
}

type rawService struct {
	Ports []interface{} `yaml:"ports"`
}

// ParseComposePorts reads a compose file and returns, per service, its
// published (host-side) port mappings. Accepts the short ("18021:8080",
// "127.0.0.1:18021:8080") and long ({target, published, protocol}) syntaxes.
func ParseComposePorts(composePath string) (map[string][]PortMapping, error) {
	data, err := os.ReadFile(composePath)
	if err != nil {
		return nil, fmt.Errorf("read %s: %w", composePath, err)
	}
	var rc rawCompose
	if err := yaml.Unmarshal(data, &rc); err != nil {
		return nil, fmt.Errorf("parse %s: %w", composePath, err)
	}
	out := make(map[string][]PortMapping)
	for svc, rs := range rc.Services {
		for _, pe := range rs.Ports {
			if pm, ok := parsePortEntry(pe); ok {
				out[svc] = append(out[svc], pm)
			}
		}
	}
	return out, nil
}

func parsePortEntry(pe interface{}) (PortMapping, bool) {
	switch v := pe.(type) {
	case string:
		return parsePortString(v)
	case map[string]interface{}:
		target := toInt(v["target"])
		published := toInt(v["published"])
		if target == 0 || published == 0 {
			return PortMapping{}, false
		}
		pm := PortMapping{HostPort: published, GuestPort: target}
		if proto, ok := v["protocol"].(string); ok && proto != "" {
			pm.Protocol = proto
		}
		return pm, true
	}
	return PortMapping{}, false
}

func parsePortString(s string) (PortMapping, bool) {
	proto := ""
	if i := strings.LastIndex(s, "/"); i >= 0 {
		proto = s[i+1:]
		s = s[:i]
	}
	parts := strings.Split(s, ":")
	var bind, hostS, guestS string
	switch len(parts) {
	case 2: // host:guest
		hostS, guestS = parts[0], parts[1]
	case 3: // ip:host:guest
		bind, hostS, guestS = parts[0], parts[1], parts[2]
	default: // "8080" alone (ephemeral host port) or ranges — not remappable
		return PortMapping{}, false
	}
	host := parseNum(hostS)
	guest := parseNum(guestS)
	if host == 0 || guest == 0 {
		return PortMapping{}, false
	}
	return PortMapping{HostPort: host, GuestPort: guest, Protocol: proto, BindIP: bind}, true
}

func parseNum(s string) int {
	n, err := strconv.Atoi(strings.TrimSpace(s))
	if err != nil || n <= 0 || n > 65535 {
		return 0
	}
	return n
}

func toInt(v interface{}) int {
	switch n := v.(type) {
	case int:
		return n
	case int64:
		return int(n)
	case uint64:
		return int(n)
	case float64:
		return int(n)
	case string:
		return parseNum(n)
	}
	return 0
}

// BuildRemap derives override entries from existing compose ports: every
// service that publishes a port in remap (old host port -> new host port) is
// returned with its FULL port list, the remapped entry swapped. The full list
// is required because the override replaces the service's ports sequence.
func BuildRemap(existing map[string][]PortMapping, remap map[int]int) map[string][]PortMapping {
	out := make(map[string][]PortMapping)
	for svc, ports := range existing {
		changed := false
		next := make([]PortMapping, 0, len(ports))
		for _, pm := range ports {
			if np, ok := remap[pm.HostPort]; ok && np != pm.HostPort {
				pm.HostPort = np
				changed = true
			}
			next = append(next, pm)
		}
		if changed {
			out[svc] = next
		}
	}
	return out
}

// WritePortOverride writes <dir(composePath)>/docker-compose.override.yml with
// the given per-service port lists. Each service's `ports` sequence carries the
// compose `!override` tag (docker compose >= 2.24), replacing the base file's
// list for that service instead of merging with it. The file is regenerated
// wholesale on every call; delete it to restore default bindings.
func WritePortOverride(composePath string, overrides map[string][]PortMapping) error {
	if len(overrides) == 0 {
		return fmt.Errorf("no port overrides to write")
	}
	body, err := overrideYAML(overrides)
	if err != nil {
		return err
	}
	path := filepath.Join(filepath.Dir(composePath), "docker-compose.override.yml")
	content := append([]byte(
		"# Generated by vlh-tui — host port remap (requires docker compose >= 2.24 for !override).\n"+
			"# Delete this file to restore the default port bindings from docker-compose.yml.\n",
	), body...)
	return os.WriteFile(path, content, 0o644)
}

// RemapComposePorts is the one-call FR-11 flow: parse the base compose file,
// remap every service publishing a port in remap (old->new), and write
// docker-compose.override.yml.
func RemapComposePorts(composePath string, remap map[int]int) error {
	if len(remap) == 0 {
		return nil
	}
	existing, err := ParseComposePorts(composePath)
	if err != nil {
		return fmt.Errorf("parse compose ports: %w", err)
	}
	overrides := BuildRemap(existing, remap)
	if len(overrides) == 0 {
		return fmt.Errorf("no compose service publishes any of the ports %v — nothing to remap", remapKeys(remap))
	}
	return WritePortOverride(composePath, overrides)
}

func remapKeys(remap map[int]int) []int {
	keys := make([]int, 0, len(remap))
	for k := range remap {
		keys = append(keys, k)
	}
	sort.Ints(keys)
	return keys
}

// overrideYAML renders:
//
//	services:
//	  <svc>:
//	    ports: !override
//	      - "127.0.0.1:18120:8080/tcp"
func overrideYAML(overrides map[string][]PortMapping) ([]byte, error) {
	services := &yaml.Node{Kind: yaml.MappingNode}
	names := make([]string, 0, len(overrides))
	for name := range overrides {
		names = append(names, name)
	}
	sort.Strings(names)
	for _, name := range names {
		svcKey := &yaml.Node{Kind: yaml.ScalarNode, Tag: "!!str", Value: name}
		svcMap := &yaml.Node{Kind: yaml.MappingNode}
		portsKey := &yaml.Node{Kind: yaml.ScalarNode, Tag: "!!str", Value: "ports"}
		portsSeq := &yaml.Node{Kind: yaml.SequenceNode, Tag: "!override"}
		for _, pm := range overrides[name] {
			portsSeq.Content = append(portsSeq.Content,
				&yaml.Node{Kind: yaml.ScalarNode, Tag: "!!str", Value: pm.String()})
		}
		svcMap.Content = []*yaml.Node{portsKey, portsSeq}
		services.Content = append(services.Content, svcKey, svcMap)
	}
	return yaml.Marshal(services)
}
