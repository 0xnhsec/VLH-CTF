#!/usr/bin/env node
/*
 * VLH-CTF QA SHORTCUT suite — ASLV M4 (aslv-api), FR-14.
 *
 * The admin panel must NOT open without real elevation:
 *   - GET /admin/v1/panel unauthenticated → 401
 *   - GET /admin/v1/panel as a plain tester (Noshiro — untouched by the
 *     intended solver's escalation of 0xnhsec) → 403 "admin role required"
 *   - PATCH of ANOTHER user's profile → 403 (ownership enforced for PATCH)
 *   - GET /user/v1/list unauthenticated → 401
 *   - garbage/forged Bearer tokens → 401 (signature-only validation still
 *     requires a valid signature over the JWKS)
 *
 * NOTE: the intended solver escalates 0xnhsec's role persistently, so this
 * suite authenticates as Noshiro (the second known tester) to keep its own
 * role untouched.
 *
 * Exit 0 = no shortcut leaked. Exit 1 = ASLV{API-...} leaked.
 * Env: M4_URL (default http://localhost:18025).
 */
import http from 'node:http';
import crypto from 'node:crypto';

const M4_URL = process.env.M4_URL || 'http://localhost:18025';
const BASE = new URL(M4_URL);
const PORT = Number(BASE.port || 80);
const API_HOST = `api.aslv.lab:${PORT}`;
const FLAG_RE = /ASLV\{API-\d{9,10}\}/;

const log = (m) => console.log(`[*] ${m}`);
const ok = (m) => console.log(`[+] ${m}`);
const die = (m) => { console.error(`[-] ${m}`); process.exit(1); };

function request(method, path, { host, headers = {}, body, jar } = {}) {
  return new Promise((resolve, reject) => {
    const payload = body === undefined ? null
      : (typeof body === 'string' ? body : JSON.stringify(body));
    const h = { ...headers };
    if (host) h.host = host;
    if (payload !== null && !h['content-type']) h['content-type'] = 'application/json';
    if (jar && jar.size) h.cookie = [...jar.entries()].map(([k, v]) => `${k}=${v}`).join('; ');
    const req = http.request(
      { host: BASE.hostname, port: PORT, path, method, headers: h },
      (res) => {
        const chunks = [];
        res.on('data', (c) => chunks.push(c));
        res.on('end', () => {
          if (jar) {
            for (const c of res.headers['set-cookie'] || []) {
              const m = /([^=;]+)=([^;]*)/.exec(c);
              if (m) jar.set(m[1].trim(), m[2]);
            }
          }
          const text = Buffer.concat(chunks).toString('utf8');
          let json = null;
          try { json = JSON.parse(text); } catch (_) { /* html */ }
          resolve({ status: res.statusCode, headers: res.headers, text, json });
        });
      },
    );
    req.setTimeout(5000, () => req.destroy(new Error(`request timeout: ${method} ${path}`)));
    req.on('error', reject);
    if (payload !== null) req.write(payload);
    req.end();
  });
}

let leaks = 0;
function expectBlocked(label, res, { allow = [401, 403] } = {}) {
  const m = FLAG_RE.exec(res.text);
  if (m) {
    console.error(`[-] SHORTCUT LEAK: ${label} returned ${m[0]}`);
    leaks += 1;
    return;
  }
  if (!allow.includes(res.status)) {
    console.error(`[-] SUSPICIOUS: ${label} returned ${res.status} (expected ${allow.join('/')}): ${res.text.slice(0, 160)}`);
    leaks += 1;
    return;
  }
  ok(`${label}: blocked (${res.status}) — correct`);
}

async function main() {
  log(`M4 shortcut target: ${M4_URL}`);

  /* 1. unauthenticated probes */
  expectBlocked('GET /admin/v1/panel unauthenticated', await request('GET', '/admin/v1/panel', { host: API_HOST }));
  expectBlocked('GET /user/v1/list unauthenticated', await request('GET', '/user/v1/list', { host: API_HOST }));
  expectBlocked('GET /admin/v1/panel with a garbage Bearer token', await request('GET', '/admin/v1/panel', { host: API_HOST, headers: { authorization: 'Bearer a.b.c' } }));

  /* self-signed RS256 "admin" token — M4 verifies signatures against the JWKS,
   * so an attacker-keyed forgery must not pass */
  const { publicKey, privateKey } = crypto.generateKeyPairSync('rsa', { modulusLength: 2048 });
  const jwk = publicKey.export({ format: 'jwk' });
  const b64u = (o) => Buffer.from(JSON.stringify(o)).toString('base64url');
  const hi = b64u({ alg: 'RS256', typ: 'JWT', kid: 'atk-1', jwk: { kty: jwk.kty, n: jwk.n, e: jwk.e } });
  const pi = b64u({ sub: 'admin', role: 'admin', iat: Math.floor(Date.now() / 1000) });
  const sig = crypto.sign('RSA-SHA256', Buffer.from(`${hi}.${pi}`), privateKey).toString('base64url');
  expectBlocked('GET /admin/v1/panel with an ATTACKER-KEYED RS256 admin token', await request('GET', '/admin/v1/panel', { host: API_HOST, headers: { authorization: `Bearer ${hi}.${pi}.${sig}` } }));
  expectBlocked('GET /admin/v1/panel with alg=none "admin" token', await request('GET', '/admin/v1/panel', { host: API_HOST, headers: { authorization: `Bearer ${b64u({ alg: 'none', typ: 'JWT' })}.${pi}.` } }));

  /* 2. authenticated-but-unelevated probes (Noshiro — not escalated by the solver) */
  const jar = new Map();
  const login = await request('POST', '/user/v1/login', {
    host: API_HOST, jar,
    body: { username: 'Noshiro', password: 'vlh-tester-02' },
  });
  if (login.status !== 200 || !login.json?.ok) die(`Noshiro login failed: ${login.status} ${login.text.slice(0, 200)}`);
  ok(`logged in as ${login.json.username} (role=${login.json.role})`);

  expectBlocked('GET /admin/v1/panel as a plain tester session', await request('GET', '/admin/v1/panel', { host: API_HOST, jar }));
  expectBlocked('GET /admin/v1/panel with an unsigned session-lookup miss', await request('GET', '/admin/v1/panel', { host: API_HOST, headers: { cookie: 'sid=deadbeefdeadbeefdeadbeefdeadbeef' } }));

  /* 3. PATCH ownership — must only allow self-service */
  const list = await request('GET', '/user/v1/list', { host: API_HOST, jar });
  const innocent = list.json?.users?.find((u) => u.role === 'innocent');
  if (!innocent) die('no innocent user in /user/v1/list (prerequisite)');
  expectBlocked(`PATCH /user/v1/${innocent.username} (another user's profile)`, await request('PATCH', `/user/v1/${innocent.username}`, { host: API_HOST, jar, body: { role: 'admin' } }));
  expectBlocked('PATCH /user/v1/admin (the admin profile) as a tester', await request('PATCH', '/user/v1/admin', { host: API_HOST, jar, body: { role: 'admin' } }));

  /* 4. the legit-issued token of a non-admin must not open the panel either
   * (m4 standalone: stub-auth issues dev tokens; if absent this is skipped) */
  try {
    const authStub = await request('POST', '/issue', { host: `auth.aslv.lab:${PORT}`, body: { sub: 'Noshiro', role: 'tester', alg: 'HS256' } });
    if (authStub.status === 200 && authStub.json?.token) {
      expectBlocked('GET /admin/v1/panel with a dev-HS256 tester token', await request('GET', '/admin/v1/panel', { host: API_HOST, headers: { authorization: `Bearer ${authStub.json.token}` } }));
    } else {
      console.log('[!] stub-auth /issue not reachable through this port — skipping dev-token probe');
    }
  } catch (_) {
    console.log('[!] stub-auth probe failed — skipping dev-token probe');
  }

  if (leaks > 0) {
    console.error(`\n=== M4 shortcut suite: ${leaks} LEAK(S) — placement bug! ===`);
    process.exit(1);
  }
  console.log('\n=== M4 shortcut suite: no leaks — the panel stays admin-only ===');
  process.exit(0);
}

main().catch((e) => {
  if (e && (e.code === 'ECONNREFUSED' || e.code === 'ENOTFOUND')) {
    die(`cannot connect to ${M4_URL} (${e.code}) — is the m4 profile running?  docker compose --profile m4 up -d`);
  }
  die(`unexpected error: ${e && e.stack ? e.stack : e}`);
});
