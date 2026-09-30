// Command vlh-tui is the terminal controller for the VLH-CTF home lab
// (CONTRACT §9, PRD FR-5..FR-11). It is menu-driven from the two manifests:
// every ASLV mode and every DSLTV subclass appears automatically — adding a
// subclass to dsltv-manifest.yaml is a pure data change (no TUI code edit).
//
// Run it from the repository root (docker-compose.yml + manifests/ are
// resolved relative to the working directory unless overridden in
// ~/.config/aslv-dsltv/config.toml).
package main

import (
	"fmt"
	"os"
	"path/filepath"

	tea "github.com/charmbracelet/bubbletea"

	"github.com/0xnhsec/vlh-ctf/tui/internal/config"
	"github.com/0xnhsec/vlh-ctf/tui/internal/dockerops"
	"github.com/0xnhsec/vlh-ctf/tui/internal/manifest"
	"github.com/0xnhsec/vlh-ctf/tui/internal/ui"
)

func main() {
	cfg, err := config.Load()
	if err != nil {
		die("config: %v", err)
	}

	aslv, err := manifest.LoadASLV(filepath.Join(cfg.ManifestDir, "aslv-manifest.yaml"))
	if err != nil {
		die("ASLV manifest: %v\n  (run from the repo root, or fix manifest_dir in %s)", err, configPathHint())
	}
	dsltv, err := manifest.LoadDSLTV(filepath.Join(cfg.ManifestDir, "dsltv-manifest.yaml"))
	if err != nil {
		die("DSLTV manifest: %v\n  (run from the repo root, or fix manifest_dir in %s)", err, configPathHint())
	}

	dk, err := dockerops.NewClient()
	if err != nil {
		die("docker client: %v\n  (is the docker daemon running? DOCKER_HOST set? user in the docker group?)", err)
	}
	defer dk.Close() //nolint:errcheck // best effort on shutdown

	p := tea.NewProgram(
		ui.NewApp(cfg, aslv, dsltv, dk),
		tea.WithAltScreen(),
		tea.WithMouseCellMotion(), // FR-5: mouse + keyboard
	)
	if _, err := p.Run(); err != nil {
		die("tui: %v", err)
	}
}

func configPathHint() string {
	p, err := config.Path()
	if err != nil {
		return "~/.config/aslv-dsltv/config.toml"
	}
	return p
}

func die(format string, args ...interface{}) {
	fmt.Fprintf(os.Stderr, "vlh-tui: "+format+"\n", args...)
	os.Exit(1)
}
