#!/usr/bin/env bash
# VLH-CTF — launch the TUI (single static Go binary, NFR-3).
set -euo pipefail
cd "$(dirname "$0")"
if [ ! -x ./bin/vlh-tui ]; then
  echo "[run-tui] bin/vlh-tui missing — build it first:  make tui   (or run ./installer.sh)" >&2
  exit 1
fi
exec ./bin/vlh-tui
