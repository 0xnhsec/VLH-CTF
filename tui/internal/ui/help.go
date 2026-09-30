package ui

import (
        "fmt"
        "strings"

        tea "github.com/charmbracelet/bubbletea"
)

func (m Model) helpView() string {
        var b strings.Builder
        b.WriteString(Title.Render("Help — VLH-CTF TUI") + "\n\n")

        b.WriteString(TableHeader.Render("Keys") + "\n")
        keys := [][2]string{
                {"↑/k  ↓/j  wheel", "move selection (click = select + open)"},
                {"enter / d", "menus: open deploy confirm · status: open logs"},
                {"D (confirm screen)", "force deploy even if the port is occupied (docker may still refuse)"},
                {"p / 0 (confirm)", "next free port — writes docker-compose.override.yml / clear remap"},
                {"x (confirm)", "stop the conflicting lab profile, then deploy (FR-16 switch)"},
                {"s / S (status)", "stop / start the selected container (menus: s stops the profile)"},
                {"r", "menus: restart profile · status: restart selected container"},
                {"right/middle click", "stop / restart the clicked menu item or selected container"},
                {"l", "logs — container picker from menus, selected container from status"},
                {"f (logs)", "toggle follow (auto-scroll) · g/G top/bottom"},
                {"a", "activity view — 2s poll of the active profile's collector"},
                {"tab (activity)", "cycle the active profile"},
                {"e", "export cached activity rows to NDJSON / CSV"},
                {"R", "refresh the current view"},
                {"? / esc / q", "help · back · back (quit on main) — ctrl+c quits anywhere"},
        }
        for _, k := range keys {
                b.WriteString("  " + fmt.Sprintf("%-22s", k[0]) + Dim.Render(clipStr(k[1], maxInt(10, m.width-28))) + "\n")
        }

        b.WriteString("\n" + TableHeader.Render("Ports (contract §2)") + "\n")
        b.WriteString("  ASLV: full=18024  m1=18021  m2=18022  m3=18023  m4=18025  m5=18026\n")
        b.WriteString("  DSLTV lab port: 8119 (one subclass at a time)\n")
        b.WriteString("  collector mgmt (loopback): full=18090  m1..m5=18091..18095  dsltv=18119\n")

        b.WriteString("\n" + TableHeader.Render("Config") + "\n")
        b.WriteString("  " + m.cfgPath + "\n")
        b.WriteString("  keys: default_ports, collector_ports, export_dir, compose_file, manifest_dir\n")
        b.WriteString("  (run vlh-tui from the repo root, or set compose_file/manifest_dir there)\n")

        b.WriteString("\n" + Alert.Render("WARNING (NFR-4): this tool drives the Docker socket") + "\n")
        b.WriteString("  Docker socket access is host-root-equivalent. Run it only on your\n")
        b.WriteString("  own machine; never expose the socket or this tool to untrusted users.\n")

        b.WriteString("\n" + Dim.Render("VLH-CTF v1.0.0 · github.com/0xnhsec/vlh-ctf · binary: vlh-tui"))
        return b.String()
}

func (m Model) keyHelp(msg tea.KeyMsg) (tea.Model, tea.Cmd) {
        switch msg.String() {
        case "esc", "q", "?":
                m.screen = scrMain
                return m, nil
        }
        return m, nil
}
