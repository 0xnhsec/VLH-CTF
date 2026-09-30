#!/bin/sh
# aslv-identity entrypoint: prepare volumes, then exec the identity server.
set -e
mkdir -p "${DATA_DIR:-/data}" || true
mkdir -p "${REGISTRY_DIR:-/registry}" 2>/dev/null || true
exec node src/server.js
