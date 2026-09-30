'use strict';
/*
 * VLH-CTF — ASLV M2 portal: event-verified flag system (CORS + CSRF).
 *
 * Neither flag exists at boot. The collector's /verify mints a flag only when
 * its dual check passes (CORS: cross-site context + payload bound to the
 * innocent session secret; CSRF: innocent-row state change). The minted
 * numeric derives deterministically from the innocent api_key hash — same
 * pattern as dsltv/base/runtime.js flagsApi.eventNumeric, so the value is
 * stable for a given boot-vintage of the innocent secret.
 *
 * Registry (CONTRACT §3): NDJSON lines appended to $REGISTRY_DIR/flags.ndjson,
 * falling back to /data/registry-fallback.ndjson when the registry volume is
 * not writable.
 */
const crypto = require('crypto');
const fs = require('fs');
const path = require('path');

const nowIso = () => new Date().toISOString();

function initFlags({ db, SEED, registryDir, dataDir }) {
  const registryFile = (() => {
    const p = path.join(registryDir, 'flags.ndjson');
    try { fs.appendFileSync(p, ''); return p; } catch (_) { return path.join(dataDir, 'registry-fallback.ndjson'); }
  })();

  const registryAppend = (obj) => {
    try { fs.appendFileSync(registryFile, JSON.stringify(obj) + '\n'); } catch (_) { /* best effort */ }
  };

  const ensureRow = (category) => {
    db.prepare(`INSERT INTO flags (category, flag, archetype, state, minted_at)
                VALUES (?, NULL, 'event-verified', 'unminted', NULL)
                ON CONFLICT(category) DO NOTHING`)
      .run(category);
  };

  const eventNumeric = (category) => {
    const h = crypto.createHash('sha256').update(`${SEED.innocent.api_key}:${category}`).digest('hex');
    return String(parseInt(h.slice(0, 12), 16) % 1000000000).padStart(9, '0');
  };

  const eventFlag = (category) => `ASLV{${category}-${eventNumeric(category)}}`;

  return {
    eventFlag,
    minted: (category) =>
      db.prepare("SELECT flag FROM flags WHERE category = ? AND state = 'minted'").get(category)?.flag || null,
    mint: (category) => {
      ensureRow(category);
      const flag = eventFlag(category);
      db.prepare("UPDATE flags SET state = 'minted', flag = ?, minted_at = ? WHERE category = ?")
        .run(flag, nowIso(), category);
      registryAppend({ flag, category, unit: 'm2', archetype: 'event-verified', minted_at: nowIso(), note: 'minted' });
      return flag;
    },
    bootUnminted: (categories) => {
      for (const category of categories) {
        ensureRow(category);
        registryAppend({
          flag: null, category, unit: 'm2', archetype: 'event-verified',
          minted_at: nowIso(), note: 'event-verified, unminted at boot',
        });
      }
    },
  };
}

module.exports = { initFlags };
