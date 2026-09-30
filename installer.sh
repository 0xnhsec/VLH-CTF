#!/usr/bin/env bash
# =============================================================================
# VLH-CTF installer — Arch Linux family (pacman) target, fish-shell friendly.
#
# Usage:
#   ./installer.sh            install deps, build base image + TUI
#   ./installer.sh --hosts    same, plus add lab hostnames to /etc/hosts
#                             (idempotent marked block; needs sudo)
#
# Notes:
#   - No interactive prompts (safe under fish); output is plain echo/printf.
#   - Containers resolve ALL lab hostnames via compose extra_hosts — the
#     /etc/hosts edit is OPTIONAL and only needed for host-browser play.
#   - /etc/hosts cannot express wildcards (*.aslv.lab tenant subdomains).
#     For wildcard host-side DNS run a local dnsmasq instead (optional):
#       address=/.aslv.lab/127.0.0.1
#       address=/.target.lab/127.0.0.1
# =============================================================================
set -euo pipefail

cd "$(dirname "$0")"

MARK_BEGIN="# BEGIN VLH-CTF hosts (added by installer.sh)"
MARK_END="# END VLH-CTF hosts (added by installer.sh)"
HOSTS_LINE="127.0.0.1 victim.target.lab attacker.target.lab collector.target.lab mail.target.lab victim.aslv.lab attacker.aslv.lab collector.aslv.lab mail.aslv.lab auth.aslv.lab edge.aslv.lab app.aslv.lab api.aslv.lab aslv.lab www.aslv.lab"

say()  { printf '[vlh-ctf] %s\n' "$*"; }
ok()   { printf '[vlh-ctf] \033[32mOK\033[0m %s\n' "$*"; }
warn() { printf '[vlh-ctf] \033[31m!!\033[0m %s\n' "$*"; }

# -----------------------------------------------------------------------------
# 0. distro check
# -----------------------------------------------------------------------------
if ! command -v pacman >/dev/null 2>&1; then
  warn "pacman not found — this installer targets the Arch Linux family (CachyOS etc.)."
  say  "On another distro install these yourself, then re-run the build steps below:"
  say  "  docker + compose v2 plugin, go (>=1.22), nodejs (>=20), jq, curl"
  say  "  make base && make tui"
  exit 1
fi

# -----------------------------------------------------------------------------
# 1. packages
# -----------------------------------------------------------------------------
PKGS=(docker docker-compose go nodejs jq curl)
missing=()
for p in "${PKGS[@]}"; do
  if pacman -Qi "$p" >/dev/null 2>&1; then
    ok "package present: $p"
  else
    missing+=("$p")
  fi
done
if [ "${#missing[@]}" -gt 0 ]; then
  say "installing missing packages via pacman: ${missing[*]}"
  sudo pacman -Sy --needed --noconfirm "${missing[@]}"
  ok "packages installed"
else
  ok "all required packages already installed"
fi

# -----------------------------------------------------------------------------
# 2. docker service
# -----------------------------------------------------------------------------
if ! command -v docker >/dev/null 2>&1; then
  warn "docker still not on PATH — install it manually and re-run"
  exit 1
fi
if ! systemctl is-active --quiet docker 2>/dev/null; then
  say "enabling + starting docker service"
  sudo systemctl enable --now docker
fi
ok "docker is running ($(docker --version))"

if ! docker compose version >/dev/null 2>&1; then
  warn "docker compose v2 plugin not available — install 'docker-compose' and re-run"
  exit 1
fi

say "NOTE: the TUI talks to the Docker socket — that access is host-root-equivalent"
say "      (NFR-4). Fine for a personal home lab; never expose this machine as-is."

# -----------------------------------------------------------------------------
# 3. base image + TUI
# -----------------------------------------------------------------------------
if docker image inspect vlh-dsltv-base:1.0.0 >/dev/null 2>&1; then
  ok "vlh-dsltv-base:1.0.0 already built (rebuild any time with: make base)"
else
  say "building shared DSLTV base image vlh-dsltv-base:1.0.0"
  docker build -t vlh-dsltv-base:1.0.0 ./dsltv/base
  ok "base image built"
fi

say "building the TUI (go mod tidy + go build)"
make tui
ok "TUI built at ./bin/vlh-tui"

# -----------------------------------------------------------------------------
# 4. optional: /etc/hosts entries (flag --hosts)
# -----------------------------------------------------------------------------
install_hosts_block() {
  say "adding lab hostnames to /etc/hosts (needs sudo; idempotent)"
  local tmp
  tmp="$(mktemp)"
  trap 'rm -f "$tmp"' RETURN
  if [ -f /etc/hosts ]; then
    awk -v begin="$MARK_BEGIN" -v end="$MARK_END" '
      $0 == begin { inblock = 1; next }
      $0 == end   { inblock = 0; next }
      !inblock    { print }
    ' /etc/hosts > "$tmp"
  else
    : > "$tmp"
  fi
  printf '%s\n%s\n%s\n' "$MARK_BEGIN" "$HOSTS_LINE" "$MARK_END" >> "$tmp"
  sudo install -m 644 "$tmp" /etc/hosts
  ok "/etc/hosts updated (block between '$MARK_BEGIN' and '$MARK_END')"
  say  "wildcards (*.aslv.lab tenant subdomains) are NOT expressible in /etc/hosts —"
  say  "containers resolve them via compose extra_hosts anyway; for host-side wildcard"
  say  "DNS run dnsmasq with: address=/.aslv.lab/127.0.0.1 and address=/.target.lab/127.0.0.1"
}

case "${1:-}" in
  --hosts) install_hosts_block ;;
  "") : ;;
  *) warn "unknown flag: $1 (supported: --hosts)"; exit 1 ;;
esac

# -----------------------------------------------------------------------------
# 5. next steps
# -----------------------------------------------------------------------------
printf '\n'
ok "install complete"
printf '\n'
printf 'Next steps:\n'
printf '  1. ./run-tui.sh                 launch the TUI (deploy / monitor / export)\n'
printf '  2. pick a profile:              ASLV full (:18024), ASLV m1..m5, or any\n'
printf '                                  DSLTV subclass (one at a time on :8119)\n'
printf '  3. docs/player-guide.md         how to actually play (incl. raw-socket labs)\n'
printf '  4. docs/deployment.md           modes, ports, DNS, lifecycle\n'
printf '\n'
printf 'Known tester accounts: 0xnhsec / vlh-tester-01   Noshiro / vlh-tester-02\n'
printf '\n'
