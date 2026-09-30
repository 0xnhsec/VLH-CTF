#!/usr/bin/env node
/*
 * VLH-CTF QA SHORTCUT suite — ASLV M1 (aslv-edge), FR-14.
 *
 * The location-locked /internal/flag must be unreachable by every NON-smuggling
 * request through the gateway: plain GET/POST with any Host (edge, internal,
 * collector, unknown), naive pipelining on one socket, and duplicate Host
 * headers (nginx rejects those with 400 by design).
 *
 * Exit 0 = no shortcut leaked (good). Exit 1 = ASLV{HTTP-...} appeared in a
 * plain (non-desync) response — placement bug.
 *
 * Env: M1_URL (default http://localhost:18021).
 */
import net from 'node:net';

const M1_URL = process.env.M1_URL || 'http://localhost:18021';
const BASE = new URL(M1_URL);
const GW_HOST = BASE.hostname;
const GW_PORT = Number(BASE.port || 80);
const PORT = GW_PORT;
const FLAG_RE = /ASLV\{HTTP-\d{9,10}\}/;

const log = (m) => console.log(`[*] ${m}`);
const ok = (m) => console.log(`[+] ${m}`);
const die = (m) => { console.error(`[-] ${m}`); process.exit(1); };

function rawExchange(payload, { timeoutMs = 6000, quietMs = 600 } = {}) {
  return new Promise((resolve, reject) => {
    const chunks = [];
    let settled = false;
    let quiet = null;
    const sock = net.connect({ host: GW_HOST, port: GW_PORT });
    const finish = (err) => {
      if (settled) return;
      settled = true;
      clearTimeout(quiet);
      sock.destroy();
      if (err) reject(err);
      else resolve({ text: Buffer.concat(chunks).toString('latin1'), bytes: Buffer.concat(chunks).length });
    };
    const arm = () => { clearTimeout(quiet); quiet = setTimeout(() => finish(), quietMs); };
    sock.setTimeout(timeoutMs);
    sock.on('connect', () => { sock.write(payload); arm(); });
    sock.on('data', () => arm());
    sock.on('data', (c) => chunks.push(c));
    sock.on('timeout', () => finish());
    sock.on('close', () => finish());
    sock.on('error', (e) => finish(e));
  });
}

let leaks = 0;
function expectBlocked(label, text) {
  const m = FLAG_RE.exec(text);
  if (m) {
    console.error(`[-] SHORTCUT LEAK: ${label} returned ${m[0]}`);
    leaks += 1;
  } else {
    const st = (text.match(/HTTP\/1\.[01] \d{3}/g) || []).join(', ') || 'no status line';
    ok(`${label}: blocked (${st}) — correct`);
  }
}

async function main() {
  log(`M1 shortcut target: ${M1_URL}`);

  /* plain requests through the gateway with every interesting Host */
  const cases = [
    ['GET /internal/flag  Host: edge.aslv.lab', 'GET /internal/flag HTTP/1.1\r\nHost: edge.aslv.lab\r\nConnection: close\r\n\r\n'],
    ['GET /internal/flag  Host: internal.aslv.lab', 'GET /internal/flag HTTP/1.1\r\nHost: internal.aslv.lab\r\nConnection: close\r\n\r\n'],
    ['GET /internal/flag  Host: collector.aslv.lab', 'GET /internal/flag HTTP/1.1\r\nHost: collector.aslv.lab\r\nConnection: close\r\n\r\n'],
    ['GET /internal/flag  Host: localhost (unknown)', 'GET /internal/flag HTTP/1.1\r\nHost: solver-unknown.local\r\nConnection: close\r\n\r\n'],
    ['POST /internal/flag Host: edge.aslv.lab', 'POST /internal/flag HTTP/1.1\r\nHost: edge.aslv.lab\r\nContent-Length: 0\r\nConnection: close\r\n\r\n'],
    ['GET /flag           Host: internal.aslv.lab', 'GET /flag HTTP/1.1\r\nHost: internal.aslv.lab\r\nConnection: close\r\n\r\n'],
    ['GET /app/vault      Host: edge.aslv.lab (public page, must not carry a flag)', 'GET /app/vault HTTP/1.1\r\nHost: edge.aslv.lab\r\nConnection: close\r\n\r\n'],
  ];
  for (const [label, payload] of cases) {
    let r;
    try {
      r = await rawExchange(payload);
    } catch (e) {
      die(`request failed during "${label}": ${e.message} — is the m1 profile running?`);
    }
    expectBlocked(label, r.text);
  }

  /* naive pipelining: a "smuggle" written as a second, plainly-framed request
   * on the same connection — nginx delimits it correctly and routes it by ITS
   * Host header (internal vhost → 404). This is the shortcut the location
   * lock must survive. */
  const pipelined =
    'POST /app/search HTTP/1.1\r\nHost: edge.aslv.lab\r\nContent-Type: application/x-www-form-urlencoded\r\nContent-Length: 9\r\n\r\nq=desync'
    + 'GET /internal/flag HTTP/1.1\r\nHost: internal.aslv.lab\r\nConnection: close\r\n\r\n';
  try {
    const r = await rawExchange(pipelined, { timeoutMs: 7000, quietMs: 700 });
    expectBlocked('naive pipelined GET /internal/flag (plain framing)', r.text);
  } catch (e) {
    die(`pipelined request failed: ${e.message}`);
  }

  /* duplicate Host through the gateway — nginx itself rejects (400), which is
   * exactly the documented defense of the location-locked zone. */
  try {
    const r = await rawExchange('GET /flag HTTP/1.1\r\nHost: edge.aslv.lab\r\nHost: internal.aslv.lab\r\nConnection: close\r\n\r\n');
    expectBlocked('duplicate Host headers (edge + internal)', r.text);
  } catch (e) {
    die(`duplicate-Host request failed: ${e.message}`);
  }

  if (leaks > 0) {
    console.error(`\n=== M1 shortcut suite: ${leaks} LEAK(S) — placement bug! ===`);
    process.exit(1);
  }
  console.log('\n=== M1 shortcut suite: no leaks — location lock holds ===');
  process.exit(0);
}

main().catch((e) => {
  if (e && (e.code === 'ECONNREFUSED' || e.code === 'ENOTFOUND')) {
    die(`cannot connect to ${M1_URL} (${e.code}) — is the m1 profile running?  docker compose --profile m1 up -d`);
  }
  die(`unexpected error: ${e && e.stack ? e.stack : e}`);
});
