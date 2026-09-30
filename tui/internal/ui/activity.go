package ui

import (
        "fmt"
        "strings"

        "github.com/charmbracelet/bubbles/table"
        tea "github.com/charmbracelet/bubbletea"
        "github.com/charmbracelet/lipgloss"

        "github.com/0xnhsec/vlh-ctf/tui/internal/collector"
        "github.com/0xnhsec/vlh-ctf/tui/internal/config"
)

// activityAlertLatencyMs is the FR-8/FR-9 red-row threshold.
const activityAlertLatencyMs = 1500.0

// newActivityTable builds the FR-8 table: TS, Identifier, Auth (✓/✗), Data,
// Latency. Rows are colored green (normal) / red (data contains "alert" or
// latency > 1500ms).
func newActivityTable() table.Model {
        t := table.New(
                table.WithColumns([]table.Column{
                        {Title: "TS", Width: 20},
                        {Title: "Identifier", Width: 18},
                        {Title: "Auth", Width: 4},
                        {Title: "Data", Width: 42},
                        {Title: "Latency", Width: 10},
                }),
                table.WithRows([]table.Row{}),
                table.WithFocused(true),
                table.WithHeight(8),
        )
        st := table.DefaultStyles()
        st.Header = TableHeader
        st.Selected = lipgloss.NewStyle().Bold(true)
        t.SetStyles(st)
        return t
}

func activityTableRows(rows []collector.ActivityRow) []table.Row {
        out := make([]table.Row, 0, len(rows))
        for _, r := range rows {
                auth := "✗"
                if r.IsAuthenticated {
                        auth = "✓"
                }
                alert := strings.Contains(strings.ToLower(r.Data), "alert") || r.Latency > activityAlertLatencyMs
                // clip BEFORE styling: clipStr must never see ANSI escapes
                cells := []string{
                        clipStr(tsShort(r.TS), 19),
                        clipStr(r.Identifier, 17),
                        auth,
                        clipStr(r.Data, 41),
                        clipStr(fmt.Sprintf("%.1f ms", r.Latency), 9),
                }
                style := Normal
                if alert {
                        style = Alert
                }
                for i := range cells {
                        cells[i] = style.Render(cells[i])
                }
                out = append(out, table.Row(cells))
        }
        return out
}

// tsShort shortens "2026-01-02T15:04:05.123Z" to "01-02 15:04:05".
func tsShort(ts string) string {
        if len(ts) >= 19 && ts[4] == '-' && ts[7] == '-' && (ts[10] == 'T' || ts[10] == ' ') {
                return ts[5:10] + " " + ts[11:19]
        }
        return ts
}

// collectorURL builds the mgmt base URL for a profile (CONTRACT §2). The URL
// names the collector vhost (the Host header the runtime's vhost routing
// needs); collector.PollActivity dials 127.0.0.1 with the URL's port.
func collectorURL(cfg *config.Config, profile string) string {
        port := 0
        if p, ok := cfg.CollectorPorts[profile]; ok {
                port = p
        }
        host := "collector.aslv.lab"
        if strings.HasPrefix(profile, "dsltv-") {
                if port == 0 {
                        port = cfg.CollectorPorts["dsltv"]
                }
                host = "collector.target.lab"
        }
        if port == 0 {
                port = 18119 // unreachable fallback; every known profile is in the config
        }
        return fmt.Sprintf("http://%s:%d", host, port)
}

func activityPollCmd(cfg *config.Config, profile string) tea.Cmd {
        return func() tea.Msg {
                rows, err := collector.PollActivity(collectorURL(cfg, profile))
                return activityMsg{rows: rows, err: err}
        }
}

// startActivityPolling picks the active profile (first in manifest order) and
// starts the 2s poll cycle.
func (m *Model) startActivityPolling() tea.Cmd {
        m.actErr = nil
        ap := m.activeProfiles()
        if len(ap) == 0 {
                m.actProfile = ""
                m.actPolling = false
                return nil
        }
        m.actProfile = ap[0]
        m.actPolling = true
        return activityPollCmd(m.cfg, ap[0])
}

// cycleActivityProfile advances to the next active profile (tab).
func (m *Model) cycleActivityProfile() tea.Cmd {
        ap := m.activeProfiles()
        if len(ap) == 0 {
                return m.startActivityPolling()
        }
        idx := -1
        for i, p := range ap {
                if p == m.actProfile {
                        idx = i
                        break
                }
        }
        next := ap[0]
        if idx >= 0 {
                next = ap[(idx+1)%len(ap)]
        }
        m.actProfile = next
        m.actPolling = true
        return activityPollCmd(m.cfg, next)
}

func (m Model) activityView() string {
        var b strings.Builder
        head := Title.Render("Activity") + Dim.Render("  profile: ")
        if m.actProfile == "" {
                head += Dim.Render("(none detected)")
        } else {
                head += Normal.Render(m.actProfile)
        }
        head += Dim.Render("  ·  GET /internal/activity · 2s poll")
        b.WriteString(head + "\n")
        if m.actErr != nil {
                b.WriteString(Alert.Render("poll error: "+m.actErr.Error()) + "\n")
        }
        if len(m.actRows) == 0 {
                if m.actErr == nil {
                        b.WriteString(Dim.Render("(no rows yet — generate traffic against the lab)"))
                }
        } else {
                b.WriteString(m.activity.View())
        }
        if m.actProfile == "" {
                b.WriteString("\n" + Dim.Render("deploy a profile first; tab re-detects"))
        }
        return b.String()
}

func (m Model) keyActivity(msg tea.KeyMsg) (tea.Model, tea.Cmd) {
        switch msg.String() {
        case "up", "k", "down", "j", "pgup", "pgdown", "b", "f", " ":
                var cmd tea.Cmd
                m.activity, cmd = m.activity.Update(msg)
                return m, cmd
        case "tab":
                cmd := m.cycleActivityProfile()
                return m, cmd
        case "R":
                if m.actProfile != "" {
                        return m, activityPollCmd(m.cfg, m.actProfile)
                }
                cmd := m.startActivityPolling()
                return m, cmd
        case "e":
                m.screen = scrExport
                return m, nil
        case "esc", "q":
                m.actPolling = false
                m.screen = scrMain
                return m, nil
        case "?":
                m.screen = scrHelp
                return m, nil
        }
        return m, nil
}
