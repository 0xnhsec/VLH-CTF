#!/bin/sh
# VLH-CTF M1 edge-back entrypoint.
# Generates the location-locked HTTP flag + the synthetic innocent secret at
# container start (CONTRACT §3: never hardcoded, never in env, regenerated on
# every restart), registers the flag in the registry (with fallback), then
# execs the binary (which serves /internal/flag from /data/flag.txt).
set -e

DATA_DIR="${DATA_DIR:-/data}"
REGISTRY_DIR="${REGISTRY_DIR:-/registry}"
mkdir -p "$DATA_DIR" 2>/dev/null || true
mkdir -p "$REGISTRY_DIR" 2>/dev/null || true

# 10 random decimal digits from /dev/urandom (busybox od is fine on alpine).
gen_digits() {
	od -An -N16 -tu8 /dev/urandom 2>/dev/null | tr -d ' \n' | cut -c1-10
}
# 32 hex chars (16 bytes).
gen_hex() {
	od -An -N16 -tx1 /dev/urandom 2>/dev/null | tr -d ' \n'
}

FLAG="ASLV{HTTP-$(gen_digits)}"
SECRET="$(gen_hex)"

printf '%s' "$FLAG" > "$DATA_DIR/flag.txt"
printf '%s' "$SECRET" > "$DATA_DIR/innocent-secret.txt"

now="$(date -u +%Y-%m-%dT%H:%M:%SZ)"
line="{\"flag\":\"$FLAG\",\"category\":\"HTTP\",\"unit\":\"m1\",\"archetype\":\"location-locked\",\"minted_at\":\"$now\",\"note\":\"held\"}"
if ! printf '%s\n' "$line" >> "$REGISTRY_DIR/flags.ndjson" 2>/dev/null; then
	printf '%s\n' "$line" >> "$DATA_DIR/registry-fallback.ndjson" 2>/dev/null || true
fi

echo "[entrypoint-edgeback] flag generated ($FLAG), secret generated, exec'ing edgeback"
exec /usr/local/bin/edgeback
