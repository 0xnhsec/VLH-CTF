'use strict';
/*
 * VLH-CTF — ASLV M5 aslv-identity: identity-gated flags (arch §7.5).
 *
 * Three flags, three DISTINCT win states — never mere authentication success:
 *   AUTH  — session user == innocent AND session provenance auth_method == 'reset'
 *   JWT   — verified token carrying the claim combo the issuer never mints
 *           (sub == innocent uuid AND role == 'admin')
 *   OAUTH — linked_identities row linking the innocent client identity to a
 *           FOREIGN (attacker) OAuth identity
 */
const { db, registryAppend, randDigits, nowIso } = require('./db');

const CATEGORIES = ['AUTH', 'JWT', 'OAUTH'];

function bootstrap() {
  // Flags regenerate every boot (CONTRACT §3).
  db.prepare('DELETE FROM flags').run();
  for (const category of CATEGORIES) {
    const flag = `ASLV{${category}-${randDigits(9)}}`;
    db.prepare('INSERT INTO flags (category, flag, state, minted_at) VALUES (?,?,?,?)')
      .run(category, flag, 'held', nowIso());
    registryAppend({
      flag, category, unit: 'm5', archetype: 'identity-gated',
      minted_at: nowIso(), note: 'held',
    });
  }
}

function get(category) {
  return db.prepare('SELECT flag FROM flags WHERE category = ?').get(category)?.flag || null;
}

function markMinted(category) {
  const res = db.prepare("UPDATE flags SET state='minted', minted_at=? WHERE category=? AND state!='minted'")
    .run(nowIso(), category);
  if (res.changes > 0) {
    registryAppend({
      flag: get(category), category, unit: 'm5', archetype: 'identity-gated',
      minted_at: nowIso(), note: 'minted',
    });
  }
}

module.exports = { bootstrap, get, markMinted, CATEGORIES };
