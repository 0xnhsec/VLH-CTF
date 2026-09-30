#!/bin/sh
# aslv-api entrypoint: prepare volumes, then exec the API server.
set -e
mkdir -p "${DATA_DIR:-/data}" || true
mkdir -p "${REGISTRY_DIR:-/registry}" 2>/dev/null || true
exec /app/api
