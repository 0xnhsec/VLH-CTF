#!/bin/sh
# aslv-core stub services entrypoint (STUB=auth|portal|mail).
set -e
mkdir -p "${DATA_DIR:-/data}" 2>/dev/null || true
exec node stub/server.js
