#!/bin/sh
# DSLTV subclass entrypoint: prepare volumes, then exec the shared runtime.
set -e
mkdir -p "${DATA_DIR:-/data}" || true
mkdir -p "${REGISTRY_DIR:-/registry}" 2>/dev/null || true
exec node runtime.js
