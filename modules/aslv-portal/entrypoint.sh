#!/bin/sh
# VLH-CTF M2 portal entrypoint: prepare volumes, then exec the app.
set -e
mkdir -p "${DATA_DIR:-/data}" 2>/dev/null || true
mkdir -p "${REGISTRY_DIR:-/registry}" 2>/dev/null || true
cd /app
exec node src/server.js
