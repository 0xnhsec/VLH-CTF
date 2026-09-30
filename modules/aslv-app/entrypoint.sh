#!/bin/sh
# VLH-CTF ASLV M3 (aslv-app) entrypoint.
#
#   /data     module sqlite + lab state (flag-*.txt, seed.json, activity.jsonl)
#   /registry shared flag registry (flags.ndjson) — fallback: /data
#
# Boot sequence: volumes → .env/APP_KEY → fresh flag values →
# `php artisan migrate --seed --force` (wipes + reseeds; flags regenerate
# every restart, CONTRACT §3) → ownership fix-ups → exec CMD (Apache).
set -e

DATA_DIR="${DATA_DIR:-/data}"
REGISTRY_DIR="${REGISTRY_DIR:-/registry}"

mkdir -p "$DATA_DIR" 2>/dev/null || true
mkdir -p "$REGISTRY_DIR" 2>/dev/null || true

cd /var/www/html

# --- environment file ------------------------------------------------------
# The image ships .env.example only; the container filesystem gets its own
# .env (so APP_KEY is per-container, not baked into any layer).
if [ ! -f .env ]; then
    cp .env.example .env 2>/dev/null || true
fi

# Generate APP_KEY once per container filesystem (key:generate rewrites the
# empty APP_KEY= line). Kept across restarts of the same container.
if ! grep -q '^APP_KEY=base64:' .env 2>/dev/null; then
    php artisan key:generate --force || true
fi

# --- flags: fresh values every boot (CONTRACT §3) ---------------------------
# DatabaseSeeder reads these files and plants the values into the seeded
# documents; if a write failed it mints its own (and registers it).
rand_digits() {
    tr -dc '0-9' < /dev/urandom 2>/dev/null | head -c 9
}
printf 'ASLV{IDOR-%s}\n' "$(rand_digits)" > "$DATA_DIR/flag-idor.txt" 2>/dev/null || true
printf 'ASLV{BAC-%s}\n'  "$(rand_digits)" > "$DATA_DIR/flag-bac.txt"  2>/dev/null || true

# --- database ---------------------------------------------------------------
DB_FILE="${DB_DATABASE:-/data/app.db}"
[ -f "$DB_FILE" ] || touch "$DB_FILE"

# Build the package manifest deterministically (composer install ran with
# --no-scripts; Laravel can also build it lazily — this just avoids a
# first-request write).
php artisan package:discover --ansi > /dev/null 2>&1 || true

# Migrate + seed on EVERY boot: `--seed` re-runs DatabaseSeeder unconditionally
# (framework MigrateCommand), and the seeder wipes before reseeding, so the
# sqlite volume never carries stale users, tickets or flags.
php artisan migrate --seed --force

# artisan ran as root; Apache serves as www-data and must be able to write
# the sqlite file (+ journal files in the same directory), activity.jsonl and
# the Laravel storage dirs.
chown -R www-data:www-data "$DATA_DIR" storage bootstrap/cache 2>/dev/null || true

exec "$@"
