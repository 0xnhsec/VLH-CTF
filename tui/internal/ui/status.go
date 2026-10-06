package ui

import (
        "strings"

        "github.com/charmbracelet/bubbles/table"
        tea "github.com/charmbracelet/bubbletea"
        "github.com/charmbracelet/lipgloss"

        "github.com/0xnhsec/vlh-ctf/tui/internal/dockerops"
)

// newStatusTable builds the containers table: Name, State, Ports, Profile
// (green running / red stopped — FR-9).
func newStatusTable() table.Model {
        t := table.New(
                table.WithColumns([]table.Column{
                        {Title: "Name", Width: 30},
                        {Title: "State", Width: 10},
                        {Title: "Ports", Width: 34},
                        {Title: "Profile/Service", Width: 24},
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

func statusTableRows(list []dockerops.ContainerInfo) []table.Row {
        rows := make([]table.Row, 0, len(list))
        for _, ci := range list {
                state := ci.State
                if state == "running" {
                        state = Normal.Render(state)
                } else {
                        state = Alert.Render(state)
                }
                profile := strings.Join(ci.Profiles, ",")
                if profile == "" {
                        profile = ci.Service
                }
                rows = append(rows, table.Row([]string{
                        clipStr(ci.Name, 29),
                        state,
                        clipStr(ci.Ports, 33),
                        clipStr(profile, 23),
                }))
        }
        return rows
}

// statusReserve is how many body lines the status view spends below the
// container table: the "active:" summary plus the copyable play-URL block
// (and its /etc/hosts hint). The table height is body minus this.
func (m Model) statusReserve() int {
        return 1 + len(m.playLines(m.width))
}

// statusView renders the containers table plus the active-profile summary
// (part of the FR-6 pre-deploy picture) and the copyable play URLs.
func (m Model) statusView() string {
        if len(m.statusRows) == 0 {
                return Dim.Render("no lab containers found (compose project vlh-ctf / label 811911.vlh=1)") +
                        "\n\n" + Dim.Render("deploy a profile from the main menu — R refreshes")
        }
        var b strings.Builder
        b.WriteString(m.status.View())
        b.WriteString("\n")
        ap := m.activeProfiles()
        if len(ap) == 0 {
                b.WriteString(Dim.Render("active profiles: none"))
        } else {
                b.WriteString(Normal.Render("active: ") + clipStr(strings.Join(ap, ", "), maxInt(10, m.width-8)))
        }
        for _, l := range m.playLines(m.width) {
                b.WriteString("\n")
                switch {
                case strings.HasPrefix(l, playPrefix):
                        b.WriteString(Normal.Render(playPrefix) + strings.TrimPrefix(l, playPrefix))
                case strings.HasPrefix(l, hintPrefix):
                        b.WriteString(Alert.Render(hintPrefix) + strings.TrimPrefix(l, hintPrefix))
                default:
                        b.WriteString(l)
                }
        }
        return b.String()
}

func (m Model) keyStatus(msg tea.KeyMsg) (tea.Model, tea.Cmd) {
        switch msg.String() {
        case "up", "k", "down", "j", "pgup", "pgdown", "b", "f", " ":
                var cmd tea.Cmd
                m.status, cmd = m.status.Update(msg)
                return m, cmd
        case "esc", "q":
                m.screen = scrMain
                return m, nil
        case "R":
                return m, refreshCmd(m.dk)
        case "s":
                if name := m.selectedContainer(); name != "" {
                        return m, contOpCmd(m.dk, "stop", name)
                }
        case "S":
                if name := m.selectedContainer(); name != "" {
                        return m, contOpCmd(m.dk, "start", name)
                }
        case "r":
                if name := m.selectedContainer(); name != "" {
                        return m, contOpCmd(m.dk, "restart", name)
                }
        case "l", "enter":
                if name := m.selectedContainer(); name != "" {
                        cmd := m.openLogs(name)
                        return m, cmd
                }
        case "a":
                m.screen = scrActivity
                cmd := m.startActivityPolling()
                return m, cmd
        case "e":
                m.screen = scrExport
                return m, nil
        case "?":
                m.screen = scrHelp
                return m, nil
        }
        return m, nil
}

func (m Model) selectedContainer() string {
        if len(m.statusRows) == 0 {
                return ""
        }
        row := m.status.SelectedRow()
        if len(row) == 0 {
                return ""
        }
        return row[0]
}
