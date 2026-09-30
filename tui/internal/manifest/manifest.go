// Package manifest loads the two lab manifests (CONTRACT §8) that drive every
// TUI menu. Adding an ASLV mode or DSLTV subclass is a data change in
// manifests/*.yaml — no TUI code edit (PRD FR-5 / arch §6).
package manifest

import (
	"fmt"
	"os"

	"gopkg.in/yaml.v3"
)

// ---------------------------------------------------------------------------
// ASLV (manifests/aslv-manifest.yaml)
// ---------------------------------------------------------------------------

// FlagSpec describes one flag a module mints.
type FlagSpec struct {
	Category  string `yaml:"category"`
	Archetype string `yaml:"archetype"`
}

// Mode is one deployable ASLV mode (full-chain or a standalone module).
type Mode struct {
	ID      string `yaml:"id"`
	Name    string `yaml:"name"`
	Port    int    `yaml:"port"`
	Profile string `yaml:"profile"`
}

// Module is metadata about one ASLV module (M0..M5).
type Module struct {
	ID       string     `yaml:"id"`
	Codename string     `yaml:"codename"`
	Name     string     `yaml:"name"`
	Stack    []string   `yaml:"stack"`
	Classes  []string   `yaml:"classes"`
	Port     int        `yaml:"port"`
	Profile  string     `yaml:"profile"`
	Flags    []FlagSpec `yaml:"flags"`
}

// ASLVManifest is the root of aslv-manifest.yaml.
type ASLVManifest struct {
	Version     int      `yaml:"version"`
	Project     string   `yaml:"project"`
	ProductLine string   `yaml:"product_line"`
	Modes       []Mode   `yaml:"modes"`
	Modules     []Module `yaml:"modules"`
}

// LoadASLV reads and validates the ASLV manifest.
func LoadASLV(path string) (*ASLVManifest, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var m ASLVManifest
	if err := yaml.Unmarshal(data, &m); err != nil {
		return nil, fmt.Errorf("%s: %w", path, err)
	}
	if len(m.Modes) == 0 {
		return nil, fmt.Errorf("%s: no modes defined", path)
	}
	for i := range m.Modes {
		if m.Modes[i].Profile == "" {
			m.Modes[i].Profile = m.Modes[i].ID
		}
	}
	return &m, nil
}

// ---------------------------------------------------------------------------
// DSLTV (manifests/dsltv-manifest.yaml)
// ---------------------------------------------------------------------------

// Subclass is one DSLTV lab. CategoryID/CategoryName are attached by
// DSLTVManifest.SubclassList (not present in the YAML file).
type Subclass struct {
	Slug         string `yaml:"slug"`
	Name         string `yaml:"name"`
	Archetype    string `yaml:"archetype"`
	CutCandidate bool   `yaml:"cut_candidate"`
	Difficulty   string `yaml:"difficulty"`
	Win          string `yaml:"win"`
	CategoryID   string `yaml:"-"`
	CategoryName string `yaml:"-"`
}

// Category groups DSLTV subclasses (jwt, csrf, cors, ...).
type Category struct {
	ID         string     `yaml:"id"`
	Name       string     `yaml:"name"`
	Subclasses []Subclass `yaml:"subclasses"`
}

// DSLTVManifest is the root of dsltv-manifest.yaml.
type DSLTVManifest struct {
	Version     int        `yaml:"version"`
	Project     string     `yaml:"project"`
	ProductLine string     `yaml:"product_line"`
	Port        int        `yaml:"port"`
	Categories  []Category `yaml:"categories"`
}

// LoadDSLTV reads and validates the DSLTV manifest.
func LoadDSLTV(path string) (*DSLTVManifest, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var m DSLTVManifest
	if err := yaml.Unmarshal(data, &m); err != nil {
		return nil, fmt.Errorf("%s: %w", path, err)
	}
	if len(m.Categories) == 0 {
		return nil, fmt.Errorf("%s: no categories defined", path)
	}
	if m.Port == 0 {
		m.Port = 8119
	}
	return &m, nil
}

// SubclassList returns every subclass flattened, with its category attached.
func (m *DSLTVManifest) SubclassList() []Subclass {
	out := make([]Subclass, 0, 64)
	for _, cat := range m.Categories {
		for _, sc := range cat.Subclasses {
			sc.CategoryID = cat.ID
			sc.CategoryName = cat.Name
			out = append(out, sc)
		}
	}
	return out
}

// ProfileName returns the compose profile name for a DSLTV subclass
// (CONTRACT §7): "dsltv-<category>-<slug>", e.g. "dsltv-jwt-none-alg".
func ProfileName(category, slug string) string {
	return "dsltv-" + category + "-" + slug
}
