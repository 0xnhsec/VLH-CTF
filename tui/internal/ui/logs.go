package ui

import (
        "context"
        "strconv"
        "strings"
        "time"

        tea "github.com/charmbracelet/bubbletea"
)

// maxLogLines caps the in-memory log ring buffer (oldest lines are dropped).
const maxLogLines = 2000

// openLogs starts streaming logs for one container (FR-7) and switches to the
// stream view. The stream is cancelled cleanly on esc / view change via ctx.
func (m *Model) openLogs(name string) tea.Cmd {
        m.closeLogs()
        m.logSession++
        m.logStream = name
        m.logLines = nil
        m.logFollow = true
        m.logVP.SetContent("")
        m.logVP.GotoTop()
        ctx, cancel := context.WithCancel(context.Background())
        m.logCancel = cancel
        ch, err := m.dk.StreamLogs(ctx, name, time.Time{}) // Tail:"200" seeds the backlog
        if err != nil {
                m.closeLogs()
                m.setMsg("logs "+name+": "+err.Error(), true)
                return nil
        }
        m.logCh = ch
        m.screen = scrLogs
        sess := m.logSession
        return func() tea.Msg {
                line, ok := <-ch
                if !ok {
                        return logsEndMsg{session: sess}
                }
                return logsMsg{session: sess, line: line}
        }
}

// closeLogs cancels the active stream (if any) and resets to picker state.
func (m *Model) closeLogs() {
        if m.logCancel != nil {
                m.logCancel()
                m.logCancel = nil
        }
        m.logCh = nil
        m.logStream = ""
}

// appendLog adds one line to the ring buffer and refreshes the viewport,
// auto-scrolling while follow mode is on.
func (m *Model) appendLog(line string) {
        m.logLines = append(m.logLines, line)
        if len(m.logLines) > maxLogLines {
                m.logLines = m.logLines[len(m.logLines)-maxLogLines:]
        }
        m.logVP.SetContent(strings.Join(m.logLines, "\n"))
        if m.logFollow {
                m.logVP.GotoBottom()
        }
}

// enterLogsPicker switches to the container picker (menus → l).
func (m *Model) enterLogsPicker() tea.Cmd {
        m.closeLogs()
        m.rebuildLogPicker()
        m.screen = scrLogs
        return refreshCmd(m.dk)
}

// rebuildLogPicker (re)builds the container list, preserving the cursor.
func (m *Model) rebuildLogPicker() {
        cur := m.logs.cursor
        items := make([]menuItem, 0, len(m.statusRows))
        for _, ci := range m.statusRows {
                items = append(items, menuItem{
                        text:   ci.Name,
                        desc:   ci.Status + " · " + ci.Ports,
                        action: "container",
                        alert:  ci.State != "running",
                })
        }
        m.logs = menu{title: "logs", items: items}
        if cur >= 0 && cur < len(items) {
                m.logs.cursor = cur
        }
}

func (m Model) logsView() string {
        if m.logStream == "" {
                if len(m.logs.items) == 0 {
                        return Dim.Render("no lab containers — deploy a profile first (R refreshes)")
                }
                return m.logs.view(m.width, m.bodyHeight())
        }
        head := Title.Render("logs: " + m.logStream) + Dim.Render("  ·  follow: ")
        if m.logFollow {
                head += Normal.Render("on")
        } else {
                head += Dim.Render("off")
        }
        head += Dim.Render("  ·  " + strconv.Itoa(len(m.logLines)) + " lines")
        return head + "\n" + m.logVP.View()
}

func (m Model) keyLogs(msg tea.KeyMsg) (tea.Model, tea.Cmd) {
        if m.logStream == "" {
                // container picker
                switch msg.String() {
                case "up", "k":
                        m.logs.up()
                        return m, nil
                case "down", "j":
                        m.logs.down()
                        return m, nil
                case "enter", " ", "l":
                        it := m.logs.selected()
                        if it.action == "container" {
                                cmd := m.openLogs(it.text)
                                return m, cmd
                        }
                        return m, nil
                case "R":
                        return m, refreshCmd(m.dk)
                case "esc", "q":
                        m.screen = scrMain
                        return m, nil
                }
                return m, nil
        }
        // streaming view
        switch msg.String() {
        case "up", "k":
                m.logVP.LineUp(1)
                m.logFollow = m.logVP.AtBottom()
                return m, nil
        case "down", "j":
                m.logVP.LineDown(1)
                m.logFollow = m.logVP.AtBottom()
                return m, nil
        case "pgup", "b":
                m.logVP.LineUp(m.logVP.Height / 2)
                m.logFollow = m.logVP.AtBottom()
                return m, nil
        case "pgdown":
                m.logVP.LineDown(m.logVP.Height / 2)
                m.logFollow = m.logVP.AtBottom()
                return m, nil
        case "g", "home":
                m.logVP.GotoTop()
                m.logFollow = false
                return m, nil
        case "G", "end":
                m.logVP.GotoBottom()
                m.logFollow = true
                return m, nil
        case "f":
                m.logFollow = !m.logFollow
                if m.logFollow {
                        m.logVP.GotoBottom()
                }
                return m, nil
        case "esc", "q":
                m.closeLogs()
                m.rebuildLogPicker()
                return m, refreshCmd(m.dk)
        }
        return m, nil
}
