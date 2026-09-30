package ui

import (
	"fmt"
	"path/filepath"
	"strings"
	"time"

	tea "github.com/charmbracelet/bubbletea"

	"github.com/0xnhsec/vlh-ctf/tui/internal/collector"
	"github.com/0xnhsec/vlh-ctf/tui/internal/config"
	"github.com/0xnhsec/vlh-ctf/tui/internal/exporter"
)

func buildExportMenu() menu {
	return menu{
		title: "export",
		items: []menuItem{
			{text: "NDJSON", desc: "one JSON object per line (stream-friendly)", action: "ndjson"},
			{text: "CSV", desc: "timestamp,identifier,is_authenticated,data,latency,unit", action: "csv"},
		},
	}
}

func (m Model) exportView() string {
	var b strings.Builder
	b.WriteString(Title.Render("Export activity") + "\n\n")
	src := m.actProfile
	if src == "" {
		src = "(none)"
	}
	b.WriteString(Dim.Render(fmt.Sprintf("  source: profile %s · %d cached rows", src, len(m.actRows))) + "\n")
	b.WriteString(Dim.Render("  target: "+filepath.Join(m.cfg.ExportDir, "activity-<unit>-<timestamp>.<ext>")) + "\n\n")
	b.WriteString(m.exportMenu.view(m.width, m.bodyHeight()-6))
	if m.exportResult != "" {
		res := m.exportResult
		if m.exportIsErr {
			res = Alert.Render(res)
		} else {
			res = Normal.Render(res)
		}
		b.WriteString("\n\n  " + res)
	}
	return b.String()
}

func (m Model) keyExport(msg tea.KeyMsg) (tea.Model, tea.Cmd) {
	switch msg.String() {
	case "up", "k":
		m.exportMenu.up()
		return m, nil
	case "down", "j":
		m.exportMenu.down()
		return m, nil
	case "enter", " ", "e":
		it := m.exportMenu.selected()
		if it.action == "ndjson" || it.action == "csv" {
			return m.runExport(it.action)
		}
		return m, nil
	case "esc", "q":
		m.screen = scrMain
		return m, nil
	}
	return m, nil
}

// runExport snapshots the cached activity rows and exports them (FR-10).
func (m Model) runExport(format string) (tea.Model, tea.Cmd) {
	rows := make([]collector.ActivityRow, len(m.actRows))
	copy(rows, m.actRows)
	m.exportResult = ""
	return m, exportCmd(m.cfg, format, rows)
}

func exportCmd(cfg *config.Config, format string, rows []collector.ActivityRow) tea.Cmd {
	return func() tea.Msg {
		if len(rows) == 0 {
			return exportDoneMsg{err: fmt.Errorf("no cached activity rows — open Activity (a) first")}
		}
		unit := rows[0].Unit
		if unit == "" {
			unit = "lab"
		}
		safe := strings.Map(func(r rune) rune {
			switch {
			case r >= 'a' && r <= 'z', r >= 'A' && r <= 'Z', r >= '0' && r <= '9', r == '-', r == '_':
				return r
			}
			return '-'
		}, unit)
		name := fmt.Sprintf("activity-%s-%s.%s", safe, time.Now().UTC().Format("20060102T150405Z"), format)
		path := filepath.Join(cfg.ExportDir, name)
		var err error
		if format == "csv" {
			err = exporter.ExportCSV(rows, path)
		} else {
			err = exporter.ExportNDJSON(rows, path)
		}
		if err != nil {
			return exportDoneMsg{err: err}
		}
		return exportDoneMsg{path: path, rows: len(rows)}
	}
}
