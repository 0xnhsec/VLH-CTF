// Package dockerops wraps the Docker SDK client for the VLH-CTF TUI.
//
// CONTRACT §9 (documented compromise): container lifecycle operations —
// list/start/stop/restart/logs — go through the Docker SDK for Go. ONLY the
// compose file-level orchestration (initial `up -d --build` of a profile and
// full profile teardown `down`) shells out to the `docker compose` CLI via
// exec.Command, because compose-in-SDK is not a supported library surface.
package dockerops

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"net"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	"github.com/docker/docker/api/types"
	"github.com/docker/docker/api/types/container"
	"github.com/docker/docker/api/types/filters"
	"github.com/docker/docker/client"
	"github.com/docker/docker/pkg/stdcopy"
)

const (
	composeProjectLabel = "com.docker.compose.project"
	composeServiceLabel = "com.docker.compose.service"
	vlhLabel            = "811911.vlh"  // CONTRACT §1
	profileLabel        = "811911.profile" // recommended per-service label (see tui/README)
	labProject          = "vlh-ctf"
)

// ContainerInfo is the TUI-facing view of one lab container.
type ContainerInfo struct {
	Name        string
	ID          string
	State       string // "running", "exited", ...
	Status      string // "Up 2 minutes", "Exited (0) ...", ...
	Ports       string // display form: "*:8119->8080/tcp 127.0.0.1:18119->8080/tcp"
	PublicPorts []int  // host-side published ports
	Service     string // compose service label
	Profiles    []string
}

// Client wraps the Docker SDK client.
type Client struct {
	api *client.Client
}

// NewClient connects to the Docker daemon (DOCKER_HOST / env), negotiating the
// API version.
func NewClient() (*Client, error) {
	api, err := client.NewClientWithOpts(client.FromEnv, client.WithAPIVersionNegotiation())
	if err != nil {
		return nil, fmt.Errorf("docker client: %w", err)
	}
	return &Client{api: api}, nil
}

// Close releases the underlying SDK client.
func (c *Client) Close() error { return c.api.Close() }

// listLab lists containers of the lab: compose project label `vlh-ctf` OR the
// namespace label `811911.vlh=1` (same-key label filters are OR'd by Docker).
func (c *Client) listLab(ctx context.Context, all bool) ([]types.Container, error) {
	f := filters.NewArgs()
	f.Add("label", composeProjectLabel+"="+labProject)
	f.Add("label", vlhLabel+"=1")
	return c.api.ContainerList(ctx, container.ListOptions{All: all, Filters: f})
}

func toInfo(cn *types.Container) ContainerInfo {
	info := ContainerInfo{
		ID:     cn.ID,
		State:  cn.State,
		Status: cn.Status,
		Ports:  formatPorts(cn.Ports),
	}
	if len(cn.Names) > 0 {
		info.Name = strings.TrimPrefix(cn.Names[0], "/")
	}
	for _, p := range cn.Ports {
		if p.PublicPort != 0 {
			info.PublicPorts = append(info.PublicPorts, int(p.PublicPort))
		}
	}
	if svc, ok := cn.Labels[composeServiceLabel]; ok {
		info.Service = svc
	}
	if prof, ok := cn.Labels[profileLabel]; ok {
		for _, p := range strings.Split(prof, ",") {
			if p = strings.TrimSpace(p); p != "" {
				info.Profiles = append(info.Profiles, p)
			}
		}
	}
	return info
}

func formatPorts(ports []types.Port) string {
	var parts []string
	for _, p := range ports {
		if p.PublicPort == 0 {
			continue // internal-only port
		}
		ip := p.IP
		if ip == "" || ip == "0.0.0.0" {
			ip = "*"
		}
		parts = append(parts, fmt.Sprintf("%s:%d->%d/%s", ip, p.PublicPort, p.PrivatePort, p.Type))
	}
	return strings.Join(parts, " ")
}

// ListLabContainers returns every lab container (running + stopped).
func (c *Client) ListLabContainers() ([]ContainerInfo, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	list, err := c.listLab(ctx, true)
	if err != nil {
		return nil, fmt.Errorf("docker: list containers: %w", err)
	}
	out := make([]ContainerInfo, 0, len(list))
	for i := range list {
		out = append(out, toInfo(&list[i]))
	}
	return out, nil
}

// ProfileMatches reports whether a container belongs to the given compose
// profile. Primary signal: the 811911.profile label. Fallbacks: DSLTV slug
// service naming (<slug>-app / <slug>-edge, CONTRACT §7) and ASLV
// profile-prefixed compose service names.
func ProfileMatches(ci ContainerInfo, profile string) bool {
	for _, p := range ci.Profiles {
		if p == profile {
			return true
		}
	}
	if strings.HasPrefix(profile, "dsltv-") {
		rest := strings.TrimPrefix(profile, "dsltv-") // "<category>-<slug>"
		idx := strings.Index(rest, "-")
		if idx < 0 {
			return false
		}
		slug := rest[idx+1:]
		for _, name := range []string{ci.Name, ci.Service} {
			if strings.Contains(name, slug+"-app") || strings.Contains(name, slug+"-edge") {
				return true
			}
		}
		return false
	}
	// ASLV fallback: compose service or container name prefixed by the profile id
	// (containers are named "vlh-ctf-<service>-<n>").
	return strings.HasPrefix(ci.Service, profile+"-") ||
		strings.HasPrefix(ci.Name, labProject+"-"+profile+"-")
}

func (c *Client) profileContainers(profile string) ([]types.Container, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	list, err := c.listLab(ctx, true)
	if err != nil {
		return nil, fmt.Errorf("docker: list containers: %w", err)
	}
	var out []types.Container
	for i := range list {
		if ProfileMatches(toInfo(&list[i]), profile) {
			out = append(out, list[i])
		}
	}
	return out, nil
}

// applyToProfile runs fn over the profile's containers: for "start" only
// stopped ones, for "stop"/"restart" only running ones. SDK lifecycle ops.
func (c *Client) applyToProfile(op, profile string, fn func(ctx context.Context, id string) error) error {
	list, err := c.profileContainers(profile)
	if err != nil {
		return err
	}
	if len(list) == 0 {
		return fmt.Errorf("profile %q has no lab containers (deploy it first)", profile)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 120*time.Second)
	defer cancel()
	var errs []string
	for i := range list {
		cn := &list[i]
		running := cn.State == "running"
		if op == "start" && running {
			continue
		}
		if op != "start" && !running {
			continue
		}
		if err := fn(ctx, cn.ID); err != nil {
			name := cn.ID
			if len(cn.Names) > 0 {
				name = strings.TrimPrefix(cn.Names[0], "/")
			}
			errs = append(errs, fmt.Sprintf("%s: %v", name, err))
		}
	}
	if len(errs) > 0 {
		return fmt.Errorf("%s profile %s: %s", op, profile, strings.Join(errs, "; "))
	}
	return nil
}

// StartProfile starts every stopped lab container of the profile (SDK).
func (c *Client) StartProfile(profile string) error {
	return c.applyToProfile("start", profile, func(ctx context.Context, id string) error {
		return c.api.ContainerStart(ctx, id, container.StartOptions{})
	})
}

// StopProfile stops every running lab container of the profile (SDK).
func (c *Client) StopProfile(profile string) error {
	return c.applyToProfile("stop", profile, func(ctx context.Context, id string) error {
		return c.api.ContainerStop(ctx, id, container.StopOptions{})
	})
}

// RestartProfile restarts every running lab container of the profile (SDK).
// Restart regenerates all flags (PRD FR-4).
func (c *Client) RestartProfile(profile string) error {
	return c.applyToProfile("restart", profile, func(ctx context.Context, id string) error {
		return c.api.ContainerRestart(ctx, id, container.StopOptions{})
	})
}

// resolve maps a container name (or ID) to its full container ID.
func (c *Client) resolve(name string) (string, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	list, err := c.listLab(ctx, true)
	if err != nil {
		return "", fmt.Errorf("docker: list containers: %w", err)
	}
	for i := range list {
		cn := &list[i]
		if cn.ID == name {
			return cn.ID, nil
		}
		for _, n := range cn.Names {
			if strings.TrimPrefix(n, "/") == name {
				return cn.ID, nil
			}
		}
	}
	return "", fmt.Errorf("container %q not found in project %s", name, labProject)
}

// StartContainer starts one lab container by name (SDK).
func (c *Client) StartContainer(name string) error {
	id, err := c.resolve(name)
	if err != nil {
		return err
	}
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	return c.api.ContainerStart(ctx, id, container.StartOptions{})
}

// StopContainer stops one lab container by name (SDK).
func (c *Client) StopContainer(name string) error {
	id, err := c.resolve(name)
	if err != nil {
		return err
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	return c.api.ContainerStop(ctx, id, container.StopOptions{})
}

// RestartContainer restarts one lab container by name (SDK).
func (c *Client) RestartContainer(name string) error {
	id, err := c.resolve(name)
	if err != nil {
		return err
	}
	ctx, cancel := context.WithTimeout(context.Background(), 120*time.Second)
	defer cancel()
	return c.api.ContainerRestart(ctx, id, container.StopOptions{})
}

// lineChanWriter splits a byte stream into lines delivered on ch. Sends never
// block: if the consumer is more than the channel buffer behind, lines are
// dropped (a human cannot keep up with 1024 lines anyway).
type lineChanWriter struct {
	ch  chan<- string
	buf []byte
}

func (w *lineChanWriter) Write(p []byte) (int, error) {
	w.buf = append(w.buf, p...)
	for {
		i := bytes.IndexByte(w.buf, '\n')
		if i < 0 {
			break
		}
		line := strings.TrimRight(string(w.buf[:i]), "\r")
		w.buf = w.buf[i+1:]
		select {
		case w.ch <- line:
		default:
		}
	}
	return len(p), nil
}

// StreamLogs tails one container's logs (FR-7): the last 200 lines first, then
// live follow. stdout and stderr are demuxed with stdcopy and merged in
// arrival order. The returned channel closes when ctx is cancelled or the feed
// ends. since == zero time means "no Since filter" (Tail covers the backlog).
//
// Note: the ctx parameter (rather than the bare name-only signature in the
// original task sketch) lets the TUI cancel the stream cleanly when leaving
// the logs view, avoiding a leaked goroutine + docker log pipe.
func (c *Client) StreamLogs(ctx context.Context, name string, since time.Time) (<-chan string, error) {
	rctx, cancel := context.WithCancel(ctx)
	id, err := c.resolve(name)
	if err != nil {
		if len(name) == 64 { // already a container ID
			id = name
		} else {
			cancel()
			return nil, err
		}
	}
	opts := container.LogsOptions{
		ShowStdout: true,
		ShowStderr: true,
		Follow:     true,
		Tail:       "200",
	}
	if !since.IsZero() {
		opts.Since = since.UTC().Format(time.RFC3339)
	}
	reader, err := c.api.ContainerLogs(rctx, id, opts)
	if err != nil {
		cancel()
		return nil, fmt.Errorf("docker: logs %s: %w", name, err)
	}
	ch := make(chan string, 1024)
	go func() {
		defer close(ch)
		defer cancel()
		defer reader.Close()
		w := &lineChanWriter{ch: ch}
		if _, err := stdcopy.StdCopy(w, w, reader); err != nil && ctx.Err() == nil {
			// surface non-cancellation stream errors as a final line
			select {
			case ch <- "vlh-tui: log stream error: " + err.Error():
			default:
			}
		}
	}()
	return ch, nil
}

// CheckPortFree reports whether a TCP listen on 127.0.0.1:port succeeds, i.e.
// no host process currently binds the port (FR-6 occupancy check).
func CheckPortFree(port int) bool {
	ln, err := net.Listen("tcp", fmt.Sprintf("127.0.0.1:%d", port))
	if err != nil {
		return false
	}
	return ln.Close() == nil
}

// ---------------------------------------------------------------------------
// Compose orchestration — the documented exec.Command compromise (§9)
// ---------------------------------------------------------------------------

// ComposeUp brings a compose profile up: `docker compose -f <file> --profile
// <p> up -d --build`, run with cwd at the compose file's directory.
func ComposeUp(composePath, profile string) error {
	return runCompose(composePath, profile, 15*time.Minute, "up", "-d", "--build")
}

// ComposeDown tears a compose profile down: `docker compose -f <file>
// --profile <p> down`.
func ComposeDown(composePath, profile string) error {
	return runCompose(composePath, profile, 5*time.Minute, "down")
}

func runCompose(composePath, profile string, timeout time.Duration, args ...string) error {
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()
	argv := []string{"compose", "-f", composePath, "--profile", profile}
	argv = append(argv, args...)
	cmd := exec.CommandContext(ctx, "docker", argv...)
	cmd.Dir = filepath.Dir(composePath)
	var buf bytes.Buffer
	cmd.Stdout = &buf
	cmd.Stderr = &buf
	if err := cmd.Run(); err != nil {
		if ctx.Err() == context.DeadlineExceeded {
			return fmt.Errorf("docker compose %s timed out after %s", strings.Join(args, " "), timeout)
		}
		out := strings.TrimSpace(buf.String())
		if out != "" {
			return fmt.Errorf("docker compose %s: %v\n%s", strings.Join(args, " "), err, clip(out))
		}
		return fmt.Errorf("docker compose %s: %v", strings.Join(args, " "), err)
	}
	return nil
}

// clip keeps error output to a sane size (tail end carries the actual error).
func clip(s string) string {
	const max = 2000
	if len(s) > max {
		return s[len(s)-max:]
	}
	return s
}

// ensure io is used (StdCopy signature requires io.Writer; the writer above
// implements it, and this anchor keeps the import honest if refactored).
var _ io.Writer = (*lineChanWriter)(nil)
