#!/usr/bin/env node
/*
 * VLH-CTF QA SHORTCUT suite — ASLV M5 (aslv-identity), FR-14.
 *
 * Verifies the identity-gated flags CANNOT be earned without the intended
 * win state (§7.5): unauthenticated calls, mere logins, legit tokens, and
 * self-linking must all fail. Exit 0 = no shortcut leaked (good);
 * exit 1 = a flag leaked through a shortcut (BAD — placement bug).
 *
 * Env: M5_URL (default http://localhost:18026).
 */
import http from 'node:http';
import crypto from 'node:crypto';

const M5_URL = process.env.M5_URL || 'http://localhost:18026';
const BASE = new URL(M5_URL);
const FLAG_RE = /ASLV\{(AUTH|JWT|OAUTH)-\d{9,10}\}/;

function request(method, path, { headers = {}, body, jar, host } = {}) {
  return new Promise((resolve, reject) => {
    const payload = body === undefined ? null
      : (typeof body === 'string' ? body : JSON.stringify(body));
    const h = { ...headers };
    if (host) h.host = host; // vhost override (destination stays BASE)
    if (payload !== null && !h['content-type']) h['content-type'] = 'application/json';
    if (jar && jar.size) h.cookie = [...jar.entries()].map(([k, v]) => `${k}=${v}`).join('; ');
    const req = http.request({ host: BASE.hostname, port: BASE.port || 80, path, method, headers: h }, (res) => {
      const chunks = [];
      res.on('data', (c) => chunks.push(c));
      res.on('end', () => {
        if (jar) for (const c of res.headers['set-cookie'] || []) {
          const m = /([^=]+)=([^;]*)/.exec(c);
          if (m) jar.set(m[1], m[2]);
        }
        const text = Buffer.concat(chunks).toString('utf8');
        let json = null;
        try { json = JSON.parse(text); } catch (_) { /* html */ }
        resolve({ status: res.statusCode, headers: res.headers, text, json });
      });
    });
    req.on('error', reject);
    if (payload !== null) req.write(payload);
    req.end();
  });
}

const step = (msg) => console.log(`[*] ${msg}`);
let leaked = 0;
function expectNoFlag(label, res) {
  const m = FLAG_RE.exec(res.text);
  if (m) {
    console.error(`[-] SHORTCUT LEAK: ${label} returned ${m[0]}`);
    leaked += 1;
  } else {
    console.log(`[+] ${label}: no flag (status ${res.status}) — correct`);
  }
}

async function main() {
  step(`M5 target: ${M5_URL}`);

  /* 1. unauthenticated flag calls */
  for (const p of ['/flag/auth', '/flag/jwt', '/flag/oauth']) {
    expectNoFlag(`unauthenticated GET ${p}`, await request('GET', p));
  }
  expectNoFlag('garbage bearer GET /flag/jwt', await request('GET', '/flag/jwt', { headers: { authorization: 'Bearer a.b.c' } }));

  /* 2. mere login (password provenance, own account) must not earn AUTH */
  const atk = `sc_${crypto.randomBytes(3).toString('hex')}`;
  const reg = await request('POST', '/register', { body: { username: atk, password: 'shortcut-pass-1' } });
  if (reg.status !== 200) { console.error(`[-] register failed: ${reg.text}`); process.exit(1); }
  const jar = new Map();
  const login1 = await request('POST', '/login', { body: { username: atk, password: 'shortcut-pass-1' }, jar });
  await request('POST', '/mfa/verify', { body: { code: reg.json.mfa_code, user: atk }, jar });
  expectNoFlag('password login GET /flag/auth', await request('GET', '/flag/auth', { jar }));

  /* 3. reset provenance on OWN account must not earn AUTH (identity gate) */
  await request('POST', '/forgot', { body: { username: atk } });
  const day = new Date().toISOString().slice(0, 10).replace(/-/g, '');
  const prefix = crypto.createHash('md5').update(`${atk}:${day}`).digest('hex').slice(0, 12);
  const resetJar = new Map();
  let resetOk = false;
  for (let c = 1; c <= 8; c++) {
    const r = await request('POST', '/reset', { body: { token: `${prefix}-${String(c).padStart(2, '0')}`, new_password: 'shortcut-pass-2' }, jar: resetJar });
    if (r.status === 200 && r.json?.ok) { resetOk = true; break; }
  }
  if (!resetOk) { console.error('[-] could not reset own account (prerequisite failed)'); process.exit(1); }
  expectNoFlag('own-account reset session GET /flag/auth', await request('GET', '/flag/auth', { jar: resetJar }));

  /* 4. legitimately issued token (own identity, own role) must not earn JWT */
  const iss = await request('POST', '/jwt/issue', { body: { username: atk, password: 'shortcut-pass-2' } });
  if (iss.status !== 200 || !iss.json?.token) { console.error(`[-] jwt/issue failed: ${iss.text}`); process.exit(1); }
  expectNoFlag('legit token GET /flag/jwt', await request('GET', '/flag/jwt', { headers: { authorization: `Bearer ${iss.json.token}` } }));

  /* 5. self-linking (own client session + own code) must not earn OAUTH */
  const authz = await request('GET', '/oauth/authorize?' + new URLSearchParams({
    client_id: 'web', redirect_uri: 'http://client.aslv.lab/client/callback',
    response_type: 'code', state: 'x', scope: 'openid',
  }).toString(), { jar });
  const code = new URL(authz.headers.location || '', 'http://x').searchParams.get('code');
  if (!code) { console.error('[-] authorize failed (prerequisite)'); process.exit(1); }
  // Callback on the client vhost: creates a client session for OURSELVES (no
  // linking row — identity matches), which must NOT satisfy the OAUTH gate.
  const clientJar = new Map();
  const cb = await request('GET', `/client/callback?code=${encodeURIComponent(code)}&state=x`, {
    host: 'client.aslv.lab',
    jar: clientJar,
  });
  if (cb.status !== 302) { console.error(`[-] client callback failed: ${cb.status} ${cb.text.slice(0, 200)}`); process.exit(1); }
  // A second own-code pass with the existing client session: still self — no foreign link.
  const authz2 = await request('GET', '/oauth/authorize?' + new URLSearchParams({
    client_id: 'web', redirect_uri: 'http://client.aslv.lab/client/callback',
    response_type: 'code', state: 'x', scope: 'openid',
  }).toString(), { jar });
  const code2 = new URL(authz2.headers.location || '', 'http://x').searchParams.get('code');
  if (code2) {
    await request('GET', `/client/callback?code=${encodeURIComponent(code2)}&state=x`, {
      host: 'client.aslv.lab', jar: clientJar,
    });
  }
  expectNoFlag('after self-callback GET /flag/oauth', await request('GET', '/flag/oauth', { jar }));

  if (leaked > 0) {
    console.error(`\n=== M5 SHORTCUT suite: ${leaked} LEAK(S) — placement bug! ===`);
    process.exit(1);
  }
  console.log('\n=== M5 shortcut suite: no leaks — placement holds ===');
  process.exit(0);
}

main().catch((e) => { console.error(`[-] unexpected error: ${e.stack || e}`); process.exit(1); });
