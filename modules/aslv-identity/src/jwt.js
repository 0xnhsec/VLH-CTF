'use strict';
/*
 * VLH-CTF — ASLV M5 aslv-identity: JWT surface.
 *
 * POST /jwt/issue — the REAL issuer: RS256 tokens signed with the boot keypair,
 * claims {sub: user.uuid, role: user.role, tenant, iat}. It never mints the
 * combo sub=innocent-uuid + role=admin.
 *
 * GET /jwks.json   — public keys (consumed by M3/M4 for signature-only checks).
 *
 * vulnerableVerify(token) — the DELIBERATELY VULNERABLE verifier used by
 * GET /flag/jwt and GET /whoami (arch §7.5: flag only for the impossible claim
 * combo). Signature sources, in order:
 *   alg=none      → signature accepted as-is (classic none-alg)
 *   header.jwk    → verify RS256 with the EMBEDDED key (jwk header injection)
 *   header.jku    → fetch the URL, verify with its first RSA key (jku)
 *   header.kid    → SQL string concat lookup in the keys table (SQLi — a
 *                   UNION SELECT can return an attacker-chosen key row)
 *   default       → verify with the issuer's own boot key
 */
const crypto = require('crypto');
const jwt = require('jsonwebtoken');
const { db, keys, tenantFor } = require('./db');

function issueToken(user) {
  return jwt.sign(
    { sub: user.uuid, role: user.role, tenant: user.tenant || tenantFor(user.username) },
    keys.privatePem,
    { algorithm: 'RS256', keyid: keys.kid, expiresIn: '1h', issuer: 'aslv-identity' },
  );
}

function jwksJSON() {
  return { keys: [{ kty: 'RSA', kid: keys.kid, n: keys.publicJwk.n, e: keys.publicJwk.e, alg: 'RS256', use: 'sig' }] };
}

function verifyRS256WithJwk(signingInput, sigB64url, jwk) {
  try {
    const pub = crypto.createPublicKey({ key: { kty: 'RSA', n: jwk.n, e: jwk.e }, format: 'jwk' });
    return crypto.verify('RSA-SHA256', Buffer.from(signingInput), pub, Buffer.from(sigB64url, 'base64url'));
  } catch (_) {
    return false;
  }
}

async function vulnerableVerify(token) {
  const parts = String(token || '').split('.');
  if (parts.length !== 3) throw new Error('malformed token');
  let header;
  let claims;
  try {
    header = JSON.parse(Buffer.from(parts[0], 'base64url').toString('utf8'));
    claims = JSON.parse(Buffer.from(parts[1], 'base64url').toString('utf8'));
  } catch (_) {
    throw new Error('bad header/claims JSON');
  }
  const signingInput = `${parts[0]}.${parts[1]}`;
  const alg = String(header.alg || 'none');

  if (alg === 'none') {
    // DELIBERATELY VULNERABLE: alg=none accepted without any signature.
    return { ok: true, via: 'alg-none', claims };
  }
  if (alg !== 'RS256') {
    throw new Error(`unsupported alg ${alg}`);
  }

  if (header.jwk && header.jwk.n && header.jwk.e) {
    // DELIBERATELY VULNERABLE: embedded jwk header wins over the trusted keys.
    if (verifyRS256WithJwk(signingInput, parts[2], header.jwk)) {
      return { ok: true, via: 'jwk-injection', claims };
    }
    throw new Error('jwk signature mismatch');
  }

  if (header.jku) {
    // DELIBERATELY VULNERABLE: attacker-controlled jku URL is fetched and used.
    const ctrl = new AbortController();
    const timer = setTimeout(() => ctrl.abort(), 3000);
    try {
      const resp = await fetch(String(header.jku), { signal: ctrl.signal });
      const jwks = await resp.json();
      const k = (jwks.keys || []).find((x) => x.kty === 'RSA' && x.n && x.e);
      if (k && verifyRS256WithJwk(signingInput, parts[2], k)) {
        return { ok: true, via: 'jku', claims };
      }
      throw new Error('jku verification failed');
    } finally {
      clearTimeout(timer);
    }
  }

  if (header.kid) {
    // DELIBERATELY VULNERABLE: kid is concatenated into SQL (injection surface).
    const kid = String(header.kid);
    const row = db.prepare(`SELECT * FROM keys WHERE kid = '${kid}'`).get();
    if (row && verifyRS256WithJwk(signingInput, parts[2], row)) {
      return { ok: true, via: 'kid', claims };
    }
    throw new Error('kid lookup/verification failed');
  }

  if (verifyRS256WithJwk(signingInput, parts[2], keys.publicJwk)) {
    return { ok: true, via: 'issuer-key', claims };
  }
  throw new Error('signature mismatch');
}

module.exports = { issueToken, jwksJSON, vulnerableVerify };
