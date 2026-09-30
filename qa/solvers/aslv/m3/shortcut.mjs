#!/usr/bin/env node
/*
 * VLH-CTF QA SHORTCUT suite — ASLV M3 (aslv-app / Laravel), FR-14.
 *
 * The misplaced-authorization surfaces must still BLOCK the naive paths:
 *   - /api/documents/{uuid} from a WRONG (or tenant-less) Host → 403
 *   - /api/documents/{uuid} unauthenticated → 401/redirect
 *   - /api/documents/{random-uuid} → 404
 *   - /admin/users (proper can:admin gate) as a tester → 403
 *   - /admin/users/impersonate?user_id=<non-admin> → 403
 *   - /support/tickets (the legitimate leak point) itself carries no flag
 *
 * Exit 0 = no shortcut leaked. Exit 1 = ASLV{IDOR|BAC-...} leaked (bad).
 * Env: M3_URL (default http://localhost:18023).
 */
import http from 'node:http';

const M3_URL = process.env.M3_URL || 'http://localhost:18023';
const BASE = new URL(M3_URL);
const PORT = Number(BASE.port || 80);
const NEUTRAL_HOST = `portal.aslv.lab:${PORT}`;
const FLAG_RE = /ASLV\{(?:IDOR|BAC)-\d{9,10}\}/;
const UUID_RE = /[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}/gi;

const log = (m) => console.log(`[*] ${m}`);
const ok = (m) => console.log(`[+] ${m}`);
const die = (m) => { console.error(`[-] ${m}`); process.exit(1); };

function request(method, path, { host, headers = {}, body, jar } = {}) {
  return new Promise((resolve, reject) => {
    const payload = body === undefined ? null
      : (typeof body === 'string' ? body : JSON.stringify(body));
    const h = { ...headers };
    if (host) h.host = host;
    if (payload !== null && !h['content-type']) {
      h['content-type'] = typeof body === 'string'
        ? 'application/x-www-form-urlencoded'
        : 'application/json';
    }
    if (jar && jar.size) h.cookie = [...jar.entries()].map(([k, v]) => `${k}=${v}`).join('; ');
    if (jar && jar.has('XSRF-TOKEN') && !h['x-xsrf-token']) {
      h['x-xsrf-token'] = decodeURIComponent(jar.get('XSRF-TOKEN'));
    }
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
function expectBlocked(label, res, { allow = [401, 403, 404, 302] } = {}) {
  const m = FLAG_RE.exec(res.text);
  if (m) {
    console.error(`[-] SHORTCUT LEAK: ${label} returned ${m[0]}`);
    leaks += 1;
    return;
  }
  if (!allow.includes(res.status)) {
    console.error(`[-] SUSPICIOUS: ${label} returned ${res.status} (expected one of ${allow.join('/')}) — excerpt: ${res.text.slice(0, 160)}`);
    leaks += 1;
    return;
  }
  ok(`${label}: blocked (${res.status}) — correct`);
}

async function main() {
  log(`M3 shortcut target: ${M3_URL}`);

  /* 1. login as the known tester (needed to show the blocked paths are
   * authenticated-but-unauthorized, not merely unauthenticated). */
  const jar = new Map();
  const loginPage = await request('GET', '/login', { host: NEUTRAL_HOST, jar });
  if (loginPage.status !== 200) die(`GET /login failed: ${loginPage.status} — is the m3 profile running?`);
  const form = new URLSearchParams({ username: '0xnhsec', password: 'vlh-tester-01' }).toString();
  let login = await request('POST', '/login', { host: NEUTRAL_HOST, jar, body: form });
  if (login.status === 419) {
    const token = /name="_token"\s+value="([^"]+)"/.exec(loginPage.text)?.[1];
    if (token) {
      const form2 = new URLSearchParams({ _token: token, username: '0xnhsec', password: 'vlh-tester-01' }).toString();
      login = await request('POST', '/login', { host: NEUTRAL_HOST, jar, body: form2 });
    }
  }
  if (login.status !== 302) die(`tester login failed: ${login.status} ${login.text.slice(0, 200)}`);
  ok('logged in as 0xnhsec');

  /* 2. learn the innocent document uuid from the legitimate leak point */
  const tickets = await request('GET', '/support/tickets', { host: NEUTRAL_HOST, jar });
  if (tickets.status !== 200) die(`GET /support/tickets failed: ${tickets.status}`);
  const uuid = (tickets.text.match(UUID_RE) || [])[0];
  if (!uuid) die('no document uuid found in /support/tickets (prerequisite for the shortcut probes)');
  ok(`innocent document uuid from tickets: ${uuid}`);
  expectBlocked('GET /support/tickets must not itself carry a flag', tickets, { allow: [200] });

  /* 3. IDOR shortcut probes */
  expectBlocked('GET /api/documents/{uuid} from the WRONG tenant (tenant-less Host)', await request('GET', `/api/documents/${uuid}`, { host: NEUTRAL_HOST, jar }));
  expectBlocked('GET /api/documents/{uuid} from tester-browsing Host www.aslv.lab', await request('GET', `/api/documents/${uuid}`, { host: `www.aslv.lab:${PORT}`, jar }));
  expectBlocked('GET /api/documents/{uuid} UNAUTHENTICATED (any host)', await request('GET', `/api/documents/${uuid}`, { host: NEUTRAL_HOST }));
  expectBlocked('GET /api/documents/{random-uuid} (nonexistent)', await request('GET', '/api/documents/00000000-0000-4000-8000-000000000000', { host: NEUTRAL_HOST, jar }));

  /* 4. BAC shortcut probes */
  expectBlocked('GET /admin/users (can:admin gate) as a tester', await request('GET', '/admin/users', { host: NEUTRAL_HOST, jar }));
  expectBlocked('GET /admin/users UNAUTHENTICATED', await request('GET', '/admin/users', { host: NEUTRAL_HOST }));
  expectBlocked('GET /admin/users/impersonate?user_id=0xnhsec (target is NOT an admin)', await request('GET', '/admin/users/impersonate?user_id=0xnhsec', { host: NEUTRAL_HOST, jar }));
  expectBlocked('GET /admin/users/impersonate?user_id=Noshiro (target is NOT an admin)', await request('GET', '/admin/users/impersonate?user_id=Noshiro', { host: NEUTRAL_HOST, jar }));
  expectBlocked('GET /admin/users/impersonate UNAUTHENTICATED', await request('GET', '/admin/users/impersonate?user_id=admin', { host: NEUTRAL_HOST }));

  if (leaks > 0) {
    console.error(`\n=== M3 shortcut suite: ${leaks} LEAK(S)/ANOMALY(IES) — placement bug! ===`);
    process.exit(1);
  }
  console.log('\n=== M3 shortcut suite: no leaks — misplaced checks still block the naive paths ===');
  process.exit(0);
}

main().catch((e) => {
  if (e && (e.code === 'ECONNREFUSED' || e.code === 'ENOTFOUND')) {
    die(`cannot connect to ${M3_URL} (${e.code}) — is the m3 profile running?  docker compose --profile m3 up -d`);
  }
  die(`unexpected error: ${e && e.stack ? e.stack : e}`);
});
