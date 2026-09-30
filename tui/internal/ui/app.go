// Package ui implements the bubbletea Model for the VLH-CTF TUI: the
// menu-driven state machine over both manifests (PRD FR-5..FR-11).
package ui

import (
        "context"
        "fmt"
        "strconv"
        "strings"
        "time"

        "github.com/charmbracelet/bubbles/table"
        "github.com/charmbracelet/bubbles/viewport"
        tea "github.com/charmbracelet/bubbletea"
        "github.com/charmbracelet/lipgloss"

        "github.com/0xnhsec/vlh-ctf/tui/internal/collector"
        "github.com/0xnhsec/vlh-ctf/tui/internal/config"
        "github.com/0xnhsec/vlh-ctf/tui/internal/dockerops"
        "github.com/0xnhsec/vlh-ctf/tui/internal/manifest"
)

// screen identifies the active view.
type screen int

const (
        scrMain     screen = iota // main menu
        scrASLV                   // ASLV modes
        scrDSLTV                  // DSLTV categories
        scrDSLTVSub               // DSLTV subclasses of one category
        scrStatus                 // containers table (FR-6)
        scrLogs                   // logs picker + stream (FR-7)
        scrActivity               // activity table (FR-8)
        scrExport                 // NDJSON/CSV export (FR-10)
        scrHelp                   // help + socket warning (NFR-4)
        scrConfirm                // deploy confirmation w/ port occupancy (FR-6)
)

// deployTarget is one deployable unit: an ASLV mode or a DSLTV subclass.
type deployTarget struct {
        Profile string // compose profile name
        Name    string // display name
        Port    int    // host port it binds (config value, manifest fallback)
        Kind    string // "aslv" | "dsltv"
        Note    string // win condition / module info
}

// confirmState carries the FR-6 pre-deploy occupancy check for one target.
type confirmState struct {
        target      deployTarget
        checked     bool   // occupancy info loaded
        occupied    bool   // a running lab container binds the port
        occupant    string // "<container> — <status>"
        heldByLab   string // profile label / service of the occupant ("" = unknown)
        sameProfile bool   // occupant belongs to the target profile (recreate is fine)
        portFree    bool   // dockerops.CheckPortFree result
        altPort     int    // remap candidate (0 = no remap)
}

// ---------------------------------------------------------------------------
// Messages
// ---------------------------------------------------------------------------

type (
        containersMsg struct {
                list []dockerops.ContainerInfo
        }
        refreshErrMsg struct{ err error }
        deployMsg struct {
                target deployTarget
                err    error
        }
        profileOpMsg struct {
                op      string // "stop" | "restart"
                profile string
                err     error
        }
        contOpMsg struct {
                op   string // "stop" | "restart" | "start"
                name string
                err  error
        }
        confirmInfoMsg struct{ state confirmState }
        logsMsg struct {
                session int
                line    string
        }
        logsEndMsg struct{ session int }
        activityMsg struct {
                rows []collector.ActivityRow
                err  error
        }
        activityTickMsg struct{}
        exportDoneMsg struct {
                path string
                rows int
                err  error
        }
)

// ---------------------------------------------------------------------------
// Model
// ---------------------------------------------------------------------------

// Model is the top-level bubbletea model.
type Model struct {
        cfg      *config.Config
        cfgPath  string
        aslv     *manifest.ASLVManifest
        dsltv    *manifest.DSLTVManifest
        dk       *dockerops.Client
        width    int
        height   int
        screen   screen
        confirmFrom screen

        // menus
        main       menu
        aslvM      menu
        dsltvM     menu
        subM       menu
        logs       menu // container picker (scrLogs)
        exportMenu menu

        // status view
        statusRows []dockerops.ContainerInfo
        status     table.Model
        statusH    int

        // logs view
        logStream  string // container currently streamed ("" = picker)
        logSession int    // guards stale stream messages
        logCh      <-chan string
        logCancel  context.CancelFunc
        logLines   []string // ring buffer (max maxLogLines)
        logFollow  bool
        logVP      viewport.Model

        // activity view
        activity   table.Model
        activityH  int
        actRows    []collector.ActivityRow
        actProfile string
        actPolling bool
        actErr     error

        // export view
        exportResult string
        exportIsErr  bool

        // deploy confirmation
        confirm confirmState

        // chrome
        msg      string
        msgIsErr bool
        busy     bool // a long compose op is in flight; most keys are paused
}

// NewApp wires everything up. Callers must have loaded config + manifests and
// connected the docker client.
func NewApp(cfg *config.Config, aslv *manifest.ASLVManifest, dsltv *manifest.DSLTVManifest, dk *dockerops.Client) Model {
        cfgPath, err := config.Path()
        if err != nil {
                cfgPath = "~/.config/aslv-dsltv/config.toml"
        }
        return Model{
                cfg:         cfg,
                cfgPath:     cfgPath,
                aslv:        aslv,
                dsltv:       dsltv,
                dk:          dk,
                width:       80,
                height:      24,
                screen:      scrMain,
                main:        buildMainMenu(),
                aslvM:       buildASLVMenu(cfg, aslv),
                dsltvM:      buildDSLTVMenu(dsltv),
                status:      newStatusTable(),
                activity:    newActivityTable(),
                logVP:       viewport.New(78, 10),
                exportMenu:  buildExportMenu(),
                msg:         "welcome — pick a profile to deploy, ? for help",
        }
}

// Init triggers the first container refresh.
func (m Model) Init() tea.Cmd {
        return refreshCmd(m.dk)
}

// Update dispatches messages.
func (m Model) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
        switch msg := msg.(type) {
        case tea.WindowSizeMsg:
                m.width = msg.Width
                m.height = msg.Height
                h := m.bodyHeight()
                w := msg.Width - 2
                if w < 20 {
                        w = 20 // keep tables usable on tiny terminals
                }
                m.status.SetWidth(w)
                sh := h - 3
                if sh < 1 {
                        sh = 1
                }
                m.status.SetHeight(sh)
                m.statusH = sh
                m.activity.SetWidth(w)
                ah := h - 5
                if ah < 1 {
                        ah = 1
                }
                m.activity.SetHeight(ah)
                m.activityH = ah
                m.logVP.Width = msg.Width - 2
                m.logVP.Height = h - 2
                if m.logVP.Width < 10 {
                        m.logVP.Width = 10
                }
                if m.logVP.Height < 3 {
                        m.logVP.Height = 3
                }
                return m, nil

        case tea.MouseMsg:
                // bubbletea v1.2: all mouse events arrive as MouseMsg (a MouseEvent).
                if tea.MouseEvent(msg).IsWheel() {
                        return m.handleWheel(msg)
                }
                return m.handleClick(msg)

        case tea.KeyMsg:
                return m.handleKey(msg)

        case containersMsg:
                m.statusRows = msg.list
                m.status.SetRows(statusTableRows(msg.list))
                m.refreshMenuMarks()
                var cmd tea.Cmd
                if m.screen == scrLogs && m.logStream == "" {
                        m.rebuildLogPicker()
                }
                if m.screen == scrActivity && m.actProfile == "" {
                        cmd = m.startActivityPolling()
                }
                return m, cmd

        case refreshErrMsg:
                m.setMsg("docker: "+msg.err.Error(), true)
                return m, nil

        case deployMsg:
                m.busy = false
                if msg.err != nil {
                        m.setMsg(fmt.Sprintf("deploy %s failed: %v", msg.target.Name, msg.err), true)
                        return m, nil
                }
                m.setMsg(fmt.Sprintf("deployed %s (profile %s)", msg.target.Name, msg.target.Profile), false)
                m.screen = scrStatus
                return m, refreshCmd(m.dk)

        case profileOpMsg:
                if msg.err != nil {
                        m.setMsg(fmt.Sprintf("%s %s failed: %v", msg.op, msg.profile, msg.err), true)
                } else {
                        m.setMsg(fmt.Sprintf("%s %s: ok", msg.op, msg.profile), false)
                }
                return m, refreshCmd(m.dk)

        case contOpMsg:
                if msg.err != nil {
                        m.setMsg(fmt.Sprintf("%s %s failed: %v", msg.op, msg.name, msg.err), true)
                } else {
                        m.setMsg(fmt.Sprintf("%s %s: ok", msg.op, msg.name), false)
                }
                return m, refreshCmd(m.dk)

        case confirmInfoMsg:
                m.confirm = msg.state
                return m, nil

        case logsMsg:
                if msg.session != m.logSession || m.logCh == nil {
                        return m, nil
                }
                m.appendLog(msg.line)
                ch, sess := m.logCh, m.logSession
                return m, func() tea.Msg {
                        line, ok := <-ch
                        if !ok {
                                return logsEndMsg{session: sess}
                        }
                        return logsMsg{session: sess, line: line}
                }

        case logsEndMsg:
                if msg.session == m.logSession && m.screen == scrLogs && m.logStream != "" {
                        m.setMsg("log stream ended (container stopped or feed closed)", true)
                }
                return m, nil

        case activityMsg:
                if msg.err != nil {
                        m.actErr = msg.err
                } else {
                        m.actErr = nil
                        m.actRows = msg.rows
                        m.activity.SetRows(activityTableRows(m.actRows))
                }
                if m.screen == scrActivity && m.actPolling {
                        return m, tea.Tick(2*time.Second, func(time.Time) tea.Msg {
                                return activityTickMsg{}
                        })
                }
                return m, nil

        case activityTickMsg:
                if m.screen == scrActivity && m.actPolling && m.actProfile != "" {
                        return m, activityPollCmd(m.cfg, m.actProfile)
                }
                return m, nil

        case exportDoneMsg:
                if msg.err != nil {
                        m.exportResult = "error: " + msg.err.Error()
                        m.exportIsErr = true
                } else {
                        m.exportResult = fmt.Sprintf("wrote %s — %d rows", msg.path, msg.rows)
                        m.exportIsErr = false
                }
                return m, nil
        }
        return m, nil
}

// ---------------------------------------------------------------------------
// Commands
// ---------------------------------------------------------------------------

func refreshCmd(dk *dockerops.Client) tea.Cmd {
        return func() tea.Msg {
                list, err := dk.ListLabContainers()
                if err != nil {
                        return refreshErrMsg{err: err}
                }
                return containersMsg{list: list}
        }
}

// deployCmd runs the whole deploy flow in one command: optional teardown of a
// conflicting lab profile (FR-16 switch), optional port remap (FR-11), then
// `docker compose --profile <p> up -d --build`.
func deployCmd(dk *dockerops.Client, cfg *config.Config, target deployTarget, remap map[int]int, teardown string) tea.Cmd {
        return func() tea.Msg {
                if teardown != "" {
                        if err := dockerops.ComposeDown(cfg.ComposeFile, teardown); err != nil {
                                return deployMsg{target: target, err: fmt.Errorf("teardown %s: %w", teardown, err)}
                        }
                }
                if len(remap) > 0 {
                        if err := config.RemapComposePorts(cfg.ComposeFile, remap); err != nil {
                                return deployMsg{target: target, err: fmt.Errorf("port override: %w", err)}
                        }
                }
                if err := dockerops.ComposeUp(cfg.ComposeFile, target.Profile); err != nil {
                        return deployMsg{target: target, err: err}
                }
                return deployMsg{target: target}
        }
}

func profileOpCmd(dk *dockerops.Client, op, profile string) tea.Cmd {
        return func() tea.Msg {
                var err error
                switch op {
                case "stop":
                        err = dk.StopProfile(profile)
                case "restart":
                        err = dk.RestartProfile(profile)
                }
                return profileOpMsg{op: op, profile: profile, err: err}
        }
}

func contOpCmd(dk *dockerops.Client, op, name string) tea.Cmd {
        return func() tea.Msg {
                var err error
                switch op {
                case "stop":
                        err = dk.StopContainer(name)
                case "restart":
                        err = dk.RestartContainer(name)
                case "start":
                        err = dk.StartContainer(name)
                }
                return contOpMsg{op: op, name: name, err: err}
        }
}

// confirmInfoCmd performs the FR-6 occupancy check: who (if anyone) holds the
// target port right now — a running lab container (and which profile) or
// another host process.
func confirmInfoCmd(dk *dockerops.Client, target deployTarget) tea.Cmd {
        return func() tea.Msg {
                st := confirmState{target: target, checked: true, portFree: dockerops.CheckPortFree(target.Port)}
                list, err := dk.ListLabContainers()
                if err == nil {
                        for _, ci := range list {
                                if ci.State != "running" {
                                        continue
                                }
                                for _, p := range ci.PublicPorts {
                                        if p == target.Port {
                                                st.occupied = true
                                                st.occupant = fmt.Sprintf("%s — %s", ci.Name, ci.Status)
                                                if len(ci.Profiles) > 0 {
                                                        st.heldByLab = strings.Join(ci.Profiles, ",")
                                                } else if ci.Service != "" {
                                                        st.heldByLab = ci.Service
                                                }
                                                st.sameProfile = dockerops.ProfileMatches(ci, target.Profile)
                                                break
                                        }
                                }
                                if st.occupied {
                                        break
                                }
                        }
                }
                if !st.occupied && !st.portFree {
                        // no lab container holds it, but something on the host does
                        st.occupied = true
                        st.occupant = "another host process (not a vlh-ctf container)"
                }
                return confirmInfoMsg{state: st}
        }
}

// ---------------------------------------------------------------------------
// Key handling
// ---------------------------------------------------------------------------

func (m Model) handleKey(msg tea.KeyMsg) (tea.Model, tea.Cmd) {
        if msg.String() == "ctrl+c" {
                m.closeLogs()
                return m, tea.Quit
        }
        if m.busy {
                return m, nil // pause keys during compose operations
        }
        switch m.screen {
        case scrMain:
                return m.keyMain(msg)
        case scrASLV, scrDSLTVSub:
                return m.keyDeployMenu(msg)
        case scrDSLTV:
                return m.keyCategoryMenu(msg)
        case scrStatus:
                return m.keyStatus(msg)
        case scrLogs:
                return m.keyLogs(msg)
        case scrActivity:
                return m.keyActivity(msg)
        case scrExport:
                return m.keyExport(msg)
        case scrHelp:
                return m.keyHelp(msg)
        case scrConfirm:
                return m.keyConfirm(msg)
        }
        return m, nil
}

func (m Model) keyMain(msg tea.KeyMsg) (tea.Model, tea.Cmd) {
        switch msg.String() {
        case "q", "esc":
                m.closeLogs()
                return m, tea.Quit
        case "up", "k":
                m.main.up()
                return m, nil
        case "down", "j":
                m.main.down()
                return m, nil
        case "enter", " ":
                return m.activateCurrent()
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

// keyDeployMenu handles the ASLV-modes and DSLTV-subclass menus.
func (m Model) keyDeployMenu(msg tea.KeyMsg) (tea.Model, tea.Cmd) {
        mu := m.curMenu()
        switch msg.String() {
        case "up", "k":
                if mu != nil {
                        mu.up()
                }
                return m, nil
        case "down", "j":
                if mu != nil {
                        mu.down()
                }
                return m, nil
        case "esc", "q":
                m.screen = m.backTo()
                return m, nil
        case "enter", " ", "d":
                return m.activateCurrent()
        case "s":
                if it := m.curSelectedItem(); it.action == "deploy" {
                        return m, profileOpCmd(m.dk, "stop", it.target.Profile)
                }
                return m, nil
        case "r":
                if it := m.curSelectedItem(); it.action == "deploy" {
                        return m, profileOpCmd(m.dk, "restart", it.target.Profile)
                }
                return m, nil
        case "l":
                cmd := m.enterLogsPicker()
                return m, cmd
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

func (m Model) keyCategoryMenu(msg tea.KeyMsg) (tea.Model, tea.Cmd) {
        switch msg.String() {
        case "up", "k":
                m.dsltvM.up()
                return m, nil
        case "down", "j":
                m.dsltvM.down()
                return m, nil
        case "esc", "q":
                m.screen = scrMain
                return m, nil
        case "enter", " ", "d":
                return m.activateCurrent()
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

// keyConfirm implements the FR-6 gated deploy: enter/d deploys when the port
// is free (or held by the same profile); D forces past the warning; p remaps
// the port via docker-compose.override.yml; x tears down the conflicting lab
// profile first (FR-16 subclass switching).
func (m Model) keyConfirm(msg tea.KeyMsg) (tea.Model, tea.Cmd) {
        switch msg.String() {
        case "esc", "q":
                m.screen = m.confirmFrom
                return m, nil
        case "p":
                m.cycleAltPort()
                return m, nil
        case "0":
                m.confirm.altPort = 0
                return m, nil
        case "R":
                return m, confirmInfoCmd(m.dk, m.confirm.target)
        case "x":
                cs := m.confirm
                if cs.occupied && !cs.sameProfile && cs.altPort == 0 && m.knownProfile(cs.heldByLab) {
                        m.busy = true
                        m.setMsg(fmt.Sprintf("stopping %s then deploying %s …", cs.heldByLab, cs.target.Profile), false)
                        return m, deployCmd(m.dk, m.cfg, cs.target, nil, cs.heldByLab)
                }
                m.setMsg("x: no conflicting lab profile identified (use its menu → s to stop, or p to remap)", true)
                return m, nil
        case "enter", "d", " ":
                cs := m.confirm
                if !cs.checked {
                        return m, confirmInfoCmd(m.dk, cs.target)
                }
                if cs.occupied && !cs.sameProfile && cs.altPort == 0 {
                        m.setMsg("port occupied — D force · p remap · x stop conflicting profile", true)
                        return m, nil
                }
                cmd := m.beginDeploy()
                return m, cmd
        case "D":
                cmd := m.beginDeploy()
                return m, cmd
        }
        return m, nil
}

func (m *Model) beginDeploy() tea.Cmd {
        cs := m.confirm
        remap := map[int]int{}
        note := ""
        if cs.altPort != 0 {
                remap[cs.target.Port] = cs.altPort
                note = fmt.Sprintf(" (port %d->%d via docker-compose.override.yml)", cs.target.Port, cs.altPort)
        }
        m.busy = true
        m.setMsg("deploying "+cs.target.Profile+note+" — docker compose up -d --build …", false)
        return deployCmd(m.dk, m.cfg, cs.target, remap, "")
}

// cycleAltPort advances the remap candidate to the next port that is free on
// the host and not bound by a lab container.
func (m *Model) cycleAltPort() {
        base := m.confirm.target.Port
        if m.confirm.altPort != 0 {
                base = m.confirm.altPort
        }
        for p := base + 1; p <= 65535; p++ {
                if p == m.confirm.target.Port {
                        continue
                }
                if !labPortTaken(m.statusRows, p) && dockerops.CheckPortFree(p) {
                        m.confirm.altPort = p
                        return
                }
        }
}

func labPortTaken(list []dockerops.ContainerInfo, port int) bool {
        for _, ci := range list {
                for _, p := range ci.PublicPorts {
                        if p == port {
                                return true
                        }
                }
        }
        return false
}

func (m Model) knownProfile(profile string) bool {
        if profile == "" {
                return false
        }
        for _, t := range m.allTargets() {
                if t.Profile == profile {
                        return true
                }
        }
        return false
}

// ---------------------------------------------------------------------------
// Mouse handling (FR-5: keyboard AND mouse)
// ---------------------------------------------------------------------------

func (m Model) handleClick(msg tea.MouseMsg) (tea.Model, tea.Cmd) {
        if msg.Action != tea.MouseActionPress {
                return m, nil
        }
        if m.busy {
                return m, nil
        }
        switch msg.Button {
        case tea.MouseButtonLeft:
                return m.handleLeftClick(msg)
        case tea.MouseButtonRight, tea.MouseButtonMiddle:
                return m.handleSecondaryClick(msg)
        }
        return m, nil
}

// handleLeftClick: select + primary action on menus; confirm deploy on the
// confirm screen; select rows in tables.
func (m Model) handleLeftClick(msg tea.MouseMsg) (tea.Model, tea.Cmd) {
        switch m.screen {
        case scrMain, scrASLV, scrDSLTV, scrDSLTVSub, scrLogs, scrExport:
                if m.screen == scrLogs && m.logStream != "" {
                        return m, nil // clicks are inert while streaming logs
                }
                idx, ok := m.menuIndexAt(msg.Y)
                if !ok {
                        return m, nil
                }
                mu := m.curMenu()
                mu.cursor = idx
                return m.activateCurrent()

        case scrConfirm:
                // clicking anywhere on the confirm screen == pressing enter
                return m.keyConfirm(tea.KeyMsg{Type: tea.KeyEnter})

        case scrStatus:
                rel := msg.Y - bodyTop()
                if rel < 1 || len(m.statusRows) == 0 {
                        return m, nil
                }
                idx := rel - 1
                if idx >= m.statusH || idx >= len(m.statusRows) {
                        return m, nil
                }
                m.status.SetCursor(idx)
                return m, nil

        case scrActivity:
                top := bodyTop() + 1 // header line
                if m.actErr != nil {
                        top++ // poll-error line
                }
                rel := msg.Y - top
                if rel < 1 || len(m.actRows) == 0 {
                        return m, nil
                }
                idx := rel - 1
                if idx >= m.activityH || idx >= len(m.actRows) {
                        return m, nil
                }
                m.activity.SetCursor(idx)
                return m, nil
        }
        return m, nil
}

// handleSecondaryClick: right click = stop, middle click = restart, acting on
// the clicked menu item (deploy menus) or the selected row (status).
func (m Model) handleSecondaryClick(msg tea.MouseMsg) (tea.Model, tea.Cmd) {
        switch m.screen {
        case scrASLV, scrDSLTVSub:
                idx, ok := m.menuIndexAt(msg.Y)
                if !ok {
                        return m, nil
                }
                mu := m.curMenu()
                mu.cursor = idx
                it := mu.selected()
                if it.action != "deploy" {
                        return m, nil
                }
                if msg.Button == tea.MouseButtonRight {
                        return m, profileOpCmd(m.dk, "stop", it.target.Profile)
                }
                return m, profileOpCmd(m.dk, "restart", it.target.Profile)

        case scrStatus:
                if len(m.statusRows) == 0 {
                        return m, nil
                }
                name := m.selectedContainer()
                if name == "" {
                        return m, nil
                }
                if msg.Button == tea.MouseButtonRight {
                        return m, contOpCmd(m.dk, "stop", name)
                }
                return m, contOpCmd(m.dk, "restart", name)
        }
        return m, nil
}

func (m Model) handleWheel(msg tea.MouseMsg) (tea.Model, tea.Cmd) {
        if m.screen == scrLogs && m.logStream != "" {
                switch msg.Button {
                case tea.MouseButtonWheelUp:
                        m.logVP.LineUp(3)
                case tea.MouseButtonWheelDown:
                        m.logVP.LineDown(3)
                }
                m.logFollow = m.logVP.AtBottom()
                return m, nil
        }
        if m.screen == scrStatus || m.screen == scrActivity {
                var cmd tea.Cmd
                if m.screen == scrStatus {
                        m.status, cmd = m.status.Update(msg)
                } else {
                        m.activity, cmd = m.activity.Update(msg)
                }
                return m, cmd
        }
        mu := m.curMenu()
        if mu == nil || len(mu.items) == 0 {
                return m, nil
        }
        switch msg.Button {
        case tea.MouseButtonWheelUp:
                for i := 0; i < 3; i++ {
                        mu.up()
                }
        case tea.MouseButtonWheelDown:
                for i := 0; i < 3; i++ {
                        mu.down()
                }
        }
        return m, nil
}

// menuIndexAt maps a screen row to a menu item index (visible window aware).
func (m Model) menuIndexAt(y int) (int, bool) {
        mu := m.curMenu()
        if mu == nil || len(mu.items) == 0 {
                return 0, false
        }
        vis := m.bodyHeight()
        off := mu.window(vis)
        rel := y - bodyTop()
        if rel < 0 || rel >= vis {
                return 0, false
        }
        idx := off + rel
        if idx < 0 || idx >= len(mu.items) {
                return 0, false
        }
        return idx, true
}

// ---------------------------------------------------------------------------
// Navigation helpers
// ---------------------------------------------------------------------------

func (m *Model) curMenu() *menu {
        switch m.screen {
        case scrMain:
                return &m.main
        case scrASLV:
                return &m.aslvM
        case scrDSLTV:
                return &m.dsltvM
        case scrDSLTVSub:
                return &m.subM
        case scrLogs:
                return &m.logs
        case scrExport:
                return &m.exportMenu
        }
        return nil
}

func (m Model) curSelectedItem() menuItem {
        mu := m.curMenu()
        if mu == nil {
                return menuItem{}
        }
        return mu.selected()
}

func (m Model) backTo() screen {
        if m.screen == scrDSLTVSub {
                return scrDSLTV
        }
        return scrMain
}

// startConfirm opens the deploy confirmation screen for a target and kicks off
// the FR-6 occupancy check.
func (m Model) startConfirm(t deployTarget) (tea.Model, tea.Cmd) {
        m.confirm = confirmState{target: t}
        m.confirmFrom = m.screen
        m.screen = scrConfirm
        return m, confirmInfoCmd(m.dk, t)
}

// activateCurrent performs the primary action of the selected item on the
// current menu screen (shared by enter key and left click).
func (m Model) activateCurrent() (tea.Model, tea.Cmd) {
        mu := m.curMenu()
        if mu == nil || len(mu.items) == 0 {
                return m, nil
        }
        it := mu.items[mu.cursor]
        switch m.screen {
        case scrMain:
                switch it.action {
                case "aslv":
                        m.screen = scrASLV
                        return m, nil
                case "dsltv":
                        m.screen = scrDSLTV
                        return m, nil
                case "status":
                        m.screen = scrStatus
                        return m, refreshCmd(m.dk)
                case "activity":
                        m.screen = scrActivity
                        cmd := m.startActivityPolling()
                        return m, cmd
                case "export":
                        m.screen = scrExport
                        return m, nil
                case "help":
                        m.screen = scrHelp
                        return m, nil
                case "quit":
                        m.closeLogs()
                        return m, tea.Quit
                }
        case scrASLV, scrDSLTVSub:
                if it.action == "deploy" {
                        return m.startConfirm(it.target)
                }
        case scrDSLTV:
                if strings.HasPrefix(it.action, "category:") {
                        m.openCategory(strings.TrimPrefix(it.action, "category:"))
                        m.refreshMenuMarks()
                        return m, nil
                }
        case scrLogs:
                if m.logStream == "" && it.action == "container" {
                        cmd := m.openLogs(it.text)
                        return m, cmd
                }
        case scrExport:
                if it.action == "ndjson" || it.action == "csv" {
                        return m.runExport(it.action)
                }
        }
        return m, nil
}

// openCategory builds the subclass menu for one DSLTV category.
func (m *Model) openCategory(catID string) {
        port := m.dsltv.Port
        if p, ok := m.cfg.DefaultPorts["dsltv"]; ok {
                port = p
        }
        var items []menuItem
        for _, cat := range m.dsltv.Categories {
                if cat.ID != catID {
                        continue
                }
                for _, sc := range cat.Subclasses {
                        desc := fmt.Sprintf("%s · %s · port %d", sc.Archetype, sc.Difficulty, port)
                        if sc.CutCandidate {
                                desc += " · cut-candidate"
                        }
                        items = append(items, menuItem{
                                text:   sc.Name,
                                desc:   desc,
                                alert:  sc.CutCandidate,
                                action: "deploy",
                                target: deployTarget{
                                        Profile: manifest.ProfileName(cat.ID, sc.Slug),
                                        Name:    fmt.Sprintf("%s / %s", cat.Name, sc.Name),
                                        Port:    port,
                                        Kind:    "dsltv",
                                        Note:    sc.Win,
                                },
                        })
                }
        }
        m.subM = menu{title: catID, items: items}
        m.screen = scrDSLTVSub
}

// ---------------------------------------------------------------------------
// Active-profile detection (FR-6)
// ---------------------------------------------------------------------------

// allTargets lists every deployable from the manifests (config port overrides
// applied where present).
func (m Model) allTargets() []deployTarget {
        out := make([]deployTarget, 0, len(m.aslv.Modes)+64)
        for _, mode := range m.aslv.Modes {
                port := mode.Port
                if p, ok := m.cfg.DefaultPorts[mode.Profile]; ok {
                        port = p
                }
                note := ""
                for _, mod := range m.aslv.Modules {
                        if mod.ID == mode.ID {
                                note = strings.Join(mod.Classes, "/") + " · " + strings.Join(mod.Stack, "+")
                                break
                        }
                }
                out = append(out, deployTarget{
                        Profile: mode.Profile,
                        Name:    mode.Name,
                        Port:    port,
                        Kind:    "aslv",
                        Note:    note,
                })
        }
        port := m.dsltv.Port
        if p, ok := m.cfg.DefaultPorts["dsltv"]; ok {
                port = p
        }
        for _, sc := range m.dsltv.SubclassList() {
                out = append(out, deployTarget{
                        Profile: manifest.ProfileName(sc.CategoryID, sc.Slug),
                        Name:    fmt.Sprintf("%s / %s", sc.CategoryName, sc.Name),
                        Port:    port,
                        Kind:    "dsltv",
                        Note:    sc.Win,
                })
        }
        return out
}

// isProfileActive reports whether any running lab container belongs to the
// target's profile. DSLTV relies on labels/slug service names (all subclasses
// share port 8119); ASLV also falls back to unique port matching.
func (m Model) isProfileActive(t deployTarget) bool {
        for _, ci := range m.statusRows {
                if ci.State != "running" {
                        continue
                }
                if dockerops.ProfileMatches(ci, t.Profile) {
                        return true
                }
                if t.Kind == "aslv" {
                        for _, p := range ci.PublicPorts {
                                if p == t.Port {
                                        return true
                                }
                        }
                }
        }
        return false
}

// activeProfiles returns the profiles with running lab containers (manifest
// order), used by Status/Activity and for menu "[running]" marks.
func (m Model) activeProfiles() []string {
        var out []string
        for _, t := range m.allTargets() {
                if m.isProfileActive(t) {
                        out = append(out, t.Profile)
                }
        }
        return out
}

func (m *Model) refreshMenuMarks() {
        active := map[string]bool{}
        for _, t := range m.allTargets() {
                if m.isProfileActive(t) {
                        active[t.Profile] = true
                }
        }
        for i := range m.aslvM.items {
                m.aslvM.items[i].ok = active[m.aslvM.items[i].target.Profile]
        }
        for i := range m.subM.items {
                m.subM.items[i].ok = active[m.subM.items[i].target.Profile]
        }
        for i := range m.dsltvM.items {
                act := m.dsltvM.items[i].action
                if !strings.HasPrefix(act, "category:") {
                        continue
                }
                catID := strings.TrimPrefix(act, "category:")
                any := false
                for _, sc := range m.dsltv.SubclassList() {
                        if sc.CategoryID == catID && active[manifest.ProfileName(sc.CategoryID, sc.Slug)] {
                                any = true
                                break
                        }
                }
                m.dsltvM.items[i].ok = any
        }
}

// ---------------------------------------------------------------------------
// View
// ---------------------------------------------------------------------------

func (m Model) View() string {
        if m.height == 0 {
                return Title.Render("VLH-CTF") + " starting…"
        }
        return m.header() + "\n\n" + m.body() + "\n\n" + m.footer()
}

func (m Model) body() string {
        switch m.screen {
        case scrMain:
                return m.main.view(m.width, m.bodyHeight())
        case scrASLV:
                return m.aslvM.view(m.width, m.bodyHeight())
        case scrDSLTV:
                return m.dsltvM.view(m.width, m.bodyHeight())
        case scrDSLTVSub:
                head := ""
                if m.subM.title != "" {
                        head = Dim.Render("category: " + m.subM.title) + "\n"
                }
                return head + m.subM.view(m.width, m.bodyHeight()-1)
        case scrStatus:
                return m.statusView()
        case scrLogs:
                return m.logsView()
        case scrActivity:
                return m.activityView()
        case scrExport:
                return m.exportView()
        case scrHelp:
                return m.helpView()
        case scrConfirm:
                return m.confirmView()
        }
        return ""
}

func (m Model) header() string {
        title := Title.Render("VLH-CTF") + Dim.Render(" lab controller")
        right := Dim.Render(screenName(m.screen) + " · " + m.cfg.ComposeFile)
        gap := m.width - lipgloss.Width(title) - lipgloss.Width(right)
        if gap < 1 {
                gap = 1
        }
        return title + strings.Repeat(" ", gap) + right + "\n" + repeatChar(m.width)
}

func (m Model) footer() string {
        msgLine := m.msg
        if msgLine != "" {
                if m.msgIsErr {
                        msgLine = Alert.Render(msgLine)
                } else {
                        msgLine = Normal.Render(msgLine)
                }
        }
        return repeatChar(m.width) + "\n" + msgLine + "\n" + HelpStyle.Render(m.helpHint())
}

// confirmView renders the FR-6 deploy confirmation: target info, port
// occupancy + holder, red warning when blocked, remap state.
func (m Model) confirmView() string {
        cs := m.confirm
        var b strings.Builder
        b.WriteString(Title.Render("Deploy: ") + cs.target.Name + "\n\n")
        b.WriteString("  profile:   " + cs.target.Profile + "\n")
        b.WriteString("  kind:      " + cs.target.Kind + "    port: " + strconv.Itoa(cs.target.Port) + "\n")
        if cs.target.Note != "" {
                b.WriteString("  info:      " + clipStr(cs.target.Note, maxInt(20, m.width-14)) + "\n")
        }
        b.WriteString("\n")
        if !cs.checked {
                b.WriteString(Dim.Render("  checking port occupancy…"))
        } else {
                portLabel := "  port " + strconv.Itoa(cs.target.Port) + ": "
                if cs.occupied {
                        if cs.sameProfile {
                                b.WriteString(portLabel + Normal.Render("held by this profile (up -d will recreate it)") + "\n")
                        } else {
                                b.WriteString(portLabel + Alert.Render("OCCUPIED — "+cs.occupant) + "\n")
                                if cs.heldByLab != "" {
                                        b.WriteString("             " + Alert.Render("lab occupant: "+cs.heldByLab) + "\n")
                                } else {
                                        b.WriteString("             " + Alert.Render("held by a non-lab host process") + "\n")
                                }
                                b.WriteString("\n  " + Alert.Render("deployment blocked — D = force · p = remap to a free port · x = stop lab occupant + deploy") + "\n")
                        }
                } else {
                        b.WriteString(portLabel + Normal.Render("FREE") + "\n")
                }
                if cs.altPort != 0 {
                        b.WriteString("\n  remap:     " + strconv.Itoa(cs.target.Port) + " -> " +
                                Normal.Render(strconv.Itoa(cs.altPort)) +
                                Dim.Render("  (writes docker-compose.override.yml)") + "\n")
                }
        }
        b.WriteString("\n" + HelpStyle.Render("  enter/d deploy · D force · p next free port · 0 clear remap · x stop occupant · R recheck · esc cancel"))
        return b.String()
}

func (m Model) helpHint() string {
        var s string
        switch m.screen {
        case scrMain:
                s = "↑/k ↓/j select · enter open · a activity · e export · ? help · q quit"
        case scrASLV:
                s = "enter/d deploy · s stop · r restart · l logs · a activity · esc back"
        case scrDSLTV, scrDSLTVSub:
                s = "enter open/deploy · s stop · r restart · l logs · esc back"
        case scrStatus:
                s = "s stop · S start · r restart · l/enter logs · R refresh · esc back"
        case scrLogs:
                if m.logStream == "" {
                        s = "enter open logs · R refresh · esc back"
                } else {
                        s = "f follow · ↑↓ scroll · g/G top/bottom · esc back to picker"
                }
        case scrActivity:
                s = "tab cycle profile · R refresh now · e export · esc back"
        case scrExport:
                s = "enter export · esc back"
        case scrHelp:
                s = "esc back"
        case scrConfirm:
                s = "enter deploy · D force · p remap · esc cancel"
        }
        return s
}

func screenName(s screen) string {
        switch s {
        case scrMain:
                return "main menu"
        case scrASLV:
                return "ASLV modes"
        case scrDSLTV:
                return "DSLTV categories"
        case scrDSLTVSub:
                return "DSLTV subclasses"
        case scrStatus:
                return "status"
        case scrLogs:
                return "logs"
        case scrActivity:
                return "activity"
        case scrExport:
                return "export"
        case scrHelp:
                return "help"
        case scrConfirm:
                return "deploy"
        }
        return ""
}

// ---------------------------------------------------------------------------
// Layout helpers
// ---------------------------------------------------------------------------

// bodyHeight is the number of body lines: total minus header (2), footer (3)
// and two blank separators.
func (m Model) bodyHeight() int {
        h := m.height - 7
        if h < 3 {
                h = 3
        }
        return h
}

// bodyTop is the 0-based screen row of the first body line.
func bodyTop() int { return 3 }

func repeatChar(n int) string {
        if n < 1 {
                return ""
        }
        return strings.Repeat("─", n)
}

func maxInt(a, b int) int {
        if a > b {
                return a
        }
        return b
}

// clipStr truncates s to at most n runes, appending an ellipsis. Call it on
// RAW strings only (before any ANSI styling).
func clipStr(s string, n int) string {
        if n < 1 {
                return ""
        }
        r := []rune(s)
        if len(r) <= n {
                return s
        }
        if n == 1 {
                return "…"
        }
        return string(r[:n-1]) + "…"
}

func (m *Model) setMsg(text string, isErr bool) {
        m.msg = text
        m.msgIsErr = isErr
}

// ---------------------------------------------------------------------------
// Simple menu widget
// ---------------------------------------------------------------------------

type menuItem struct {
        text   string
        desc   string
        action string // "aslv" | "dsltv" | "status" | ... | "deploy" | "category:<id>" | "container" | "ndjson"/"csv"
        alert  bool   // render label red (cut-candidates, stopped containers)
        ok     bool   // append a green [running] marker
        target deployTarget
}

type menu struct {
        title  string
        items  []menuItem
        cursor int
}

func (mu *menu) up() {
        if mu.cursor > 0 {
                mu.cursor--
        }
}

func (mu *menu) down() {
        if mu.cursor < len(mu.items)-1 {
                mu.cursor++
        }
}

func (mu menu) selected() menuItem {
        if mu.cursor >= 0 && mu.cursor < len(mu.items) {
                return mu.items[mu.cursor]
        }
        return menuItem{}
}

// window returns the index of the first visible item given the visible height.
func (mu menu) window(vis int) int {
        if vis < 1 {
                vis = 1
        }
        if mu.cursor >= vis {
                return mu.cursor - vis + 1
        }
        return 0
}

func (mu menu) view(width, height int) string {
        if len(mu.items) == 0 {
                return Dim.Render("(nothing to show)")
        }
        vis := height
        if vis < 1 {
                vis = 1
        }
        off := mu.window(vis)
        var b strings.Builder
        for i := off; i < len(mu.items) && i < off+vis; i++ {
                it := mu.items[i]
                cursor, label := "  ", it.text
                switch {
                case i == mu.cursor:
                        cursor = Normal.Render("> ")
                        label = lipgloss.NewStyle().Bold(true).Render(label)
                case it.alert:
                        label = Alert.Render(label)
                }
                line := cursor + label
                if it.desc != "" {
                        line += "  " + Dim.Render(clipStr(it.desc, maxInt(10, width-24)))
                }
                if it.ok {
                        line += " " + Normal.Render("[running]")
                }
                b.WriteString(line + "\n")
        }
        out := strings.TrimRight(b.String(), "\n")
        if len(mu.items) > vis {
                out += "\n" + Dim.Render(fmt.Sprintf("(%d/%d — wheel or j/k to scroll)", mu.cursor+1, len(mu.items)))
        }
        return out
}

func buildMainMenu() menu {
        return menu{
                title: "main",
                items: []menuItem{
                        {text: "Deploy ASLV", desc: "full-chain or standalone modules (ports 18021-18026)", action: "aslv"},
                        {text: "Deploy DSLTV", desc: "single-bug-class labs, one at a time (port 8119)", action: "dsltv"},
                        {text: "Status", desc: "lab containers, ports, active profiles", action: "status"},
                        {text: "Activity", desc: "live request log of the active profile", action: "activity"},
                        {text: "Export", desc: "cached activity rows to NDJSON / CSV", action: "export"},
                        {text: "Help", desc: "keys, ports, config, docker-socket warning", action: "help"},
                        {text: "Quit", desc: "", action: "quit"},
                },
        }
}

func buildASLVMenu(cfg *config.Config, a *manifest.ASLVManifest) menu {
        items := make([]menuItem, 0, len(a.Modes))
        for _, mode := range a.Modes {
                port := mode.Port
                if p, ok := cfg.DefaultPorts[mode.Profile]; ok {
                        port = p
                }
                note := ""
                for _, mod := range a.Modules {
                        if mod.ID == mode.ID {
                                note = strings.Join(mod.Classes, "/") + " · " + strings.Join(mod.Stack, "+")
                                break
                        }
                }
                desc := fmt.Sprintf("profile %s · port %d", mode.Profile, port)
                if note != "" {
                        desc += " · " + note
                }
                items = append(items, menuItem{
                        text:   fmt.Sprintf("%s — %s", strings.ToUpper(mode.ID), mode.Name),
                        desc:   desc,
                        action: "deploy",
                        target: deployTarget{Profile: mode.Profile, Name: mode.Name, Port: port, Kind: "aslv", Note: note},
                })
        }
        return menu{title: "ASLV", items: items}
}

func buildDSLTVMenu(d *manifest.DSLTVManifest) menu {
        items := make([]menuItem, 0, len(d.Categories))
        for _, cat := range d.Categories {
                items = append(items, menuItem{
                        text:   cat.Name,
                        desc:   fmt.Sprintf("%d subclasses · profile dsltv-%s-*", len(cat.Subclasses), cat.ID),
                        action: "category:" + cat.ID,
                })
        }
        return menu{title: "DSLTV", items: items}
}
