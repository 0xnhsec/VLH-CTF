'use strict';
/*
 * VLH-CTF — ASLV M0 stub services (aslv-core).
 *
 * ONE image, THREE personalities selected via env STUB:
 *   STUB=auth   — dev JWT signer for M3/M4 standalone JWT-validation trust-edge testing
 *   STUB=portal — minimal static "organization portal" upstream for M1/M5 standalone
 *   STUB=mail   — in-memory mailbox: HTTP API + dark-theme mail UI + mini SMTP server on :1025
 *
 * Zero npm dependencies (node:http + node:crypto + node:net only).
 * Stubs have NO vulnerabilities of their own beyond what standalone testing needs.
 */
const http = require('http');
const net = require('net');
const crypto = require('crypto');

const STUB = process.env.STUB || 'portal';
const HTTP_PORT = parseInt(process.env.PORT || '3000', 10);
const SMTP_PORT = parseInt(process.env.SMTP_PORT || '1025', 10);
const DATA_DIR = process.env.DATA_DIR || '/data';

const nowIso = () => new Date().toISOString();
const randHex = (n) => crypto.randomBytes(Math.ceil(n / 2)).toString('hex').slice(0, n);
const esc = (s) => String(s == null ? '' : s)
  .replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;')
  .replace(/"/g, '&quot;').replace(/'/g, '&#39;');

/* -------------------------------------------------------------- tiny JWT lib */
const b64u = (buf) => Buffer.from(buf).toString('base64url');

function hs256Sign(payloadObj, secret) {
  const h = b64u(JSON.stringify({ alg: 'HS256', typ: 'JWT' }));
  const p = b64u(JSON.stringify(payloadObj));
  const sig = crypto.createHmac('sha256', secret).update(`${h}.${p}`).digest('base64url');
  return `${h}.${p}.${sig}`;
}

function hs256Verify(token, secret) {
  const parts = String(token || '').split('.');
  if (parts.length !== 3) return null;
  const expect = crypto.createHmac('sha256', secret).update(`${parts[0]}.${parts[1]}`).digest('base64url');
  if (!crypto.timingSafeEqual(Buffer.from(parts[2]), Buffer.from(expect))) return null;
  try { return JSON.parse(Buffer.from(parts[1], 'base64url').toString('utf8')); } catch (_) { return null; }
}

/* ------------------------------------------------------------ STUB=auth state */
const DEV_SECRET = 'aslv-stub-dev-key'; // well-known dev secret — that is the point of a stub
let stubKey = null; // boot-generated RSA keypair (deviation note in README)
try {
  stubKey = crypto.generateKeyPairSync('rsa', { modulusLength: 2048 });
} catch (e) {
  console.error('[stub-auth] RSA keypair generation failed:', e.message);
}

function rs256Sign(payloadObj, privateKey) {
  const h = b64u(JSON.stringify({ alg: 'RS256', typ: 'JWT', kid: 'stub-1' }));
  const p = b64u(JSON.stringify(payloadObj));
  const sig = crypto.sign('RSA-SHA256', Buffer.from(`${h}.${p}`), privateKey).toString('base64url');
  return `${h}.${p}.${sig}`;
}

function rs256Verify(token, publicKey) {
  const parts = String(token || '').split('.');
  if (parts.length !== 3) return null;
  let ok = false;
  try {
    ok = crypto.verify('RSA-SHA256', Buffer.from(`${parts[0]}.${parts[1]}`), publicKey, Buffer.from(parts[2], 'base64url'));
  } catch (_) { ok = false; }
  if (!ok) return null;
  try { return JSON.parse(Buffer.from(parts[1], 'base64url').toString('utf8')); } catch (_) { return null; }
}

function stubPublicJwk() {
  if (!stubKey) return { keys: [] };
  const j = stubKey.publicKey.export({ format: 'jwk' });
  return { keys: [{ kty: j.kty, kid: 'stub-1', n: j.n, e: j.e, alg: 'RS256', use: 'sig' }] };
}

/* ---------------------------------------------------------- STUB=portal state */
const portalSessions = new Map(); // sid -> { username }
const STUB_INNOCENT = { username: 'usr_' + randHex(4), api_key: randHex(32) };

/* ------------------------------------------------------------- STUB=mail state */
const mailbox = []; // {id, ts, from, to, subject, body}
let mailSeq = 0;

function storeMail({ from, to, subject, body }) {
  mailSeq += 1;
  const m = { id: mailSeq, ts: nowIso(), from: from || '', to: to || '', subject: subject || '(no subject)', body: body || '' };
  mailbox.push(m);
  return m;
}

/* mini SMTP server — minimal verb parsing: HELO/EHLO, MAIL FROM, RCPT TO, DATA, RSET, NOOP, QUIT */
function startSmtp() {
  const server = net.createServer((sock) => {
    let state = 'cmd';
    let buf = '';
    let from = '';
    let rcpts = [];

    function finishData(raw) {
      const lines = raw.split(/\r?\n/);
      let subject = '';
      let i = 0;
      for (; i < lines.length; i++) {
        if (lines[i] === '') break;
        const m = /^subject:\s*(.*)$/i.exec(lines[i]);
        if (m) subject = m[1];
      }
      const body = lines.slice(i + 1).join('\n');
      for (const to of rcpts) storeMail({ from, to, subject, body });
      from = '';
      rcpts = [];
      sock.write('250 OK queued\r\n');
    }

    function handleCmdLine(line) {
      const l = line.trim();
      if (!l) return;
      const verb = l.split(/\s+/)[0].toUpperCase();
      if (verb === 'HELO' || verb === 'EHLO') {
        sock.write('250 stub-mail\r\n');
      } else if (verb === 'MAIL') {
        const m = /FROM:\s*<([^>]*)>/i.exec(l) || /FROM:\s*(\S+)/i.exec(l);
        from = m ? m[1] : '';
        sock.write('250 OK\r\n');
      } else if (verb === 'RCPT') {
        const m = /TO:\s*<([^>]*)>/i.exec(l) || /TO:\s*(\S+)/i.exec(l);
        if (m) rcpts.push(m[1]);
        sock.write('250 OK\r\n');
      } else if (verb === 'DATA') {
        if (!rcpts.length) { sock.write('503 no recipients\r\n'); return; }
        state = 'data';
        sock.write('354 end with <CRLF>.<CRLF>\r\n');
      } else if (verb === 'RSET') {
        from = '';
        rcpts = [];
        sock.write('250 OK\r\n');
      } else if (verb === 'NOOP') {
        sock.write('250 OK\r\n');
      } else if (verb === 'QUIT') {
        sock.write('221 bye\r\n');
        sock.end();
      } else {
        sock.write('502 not implemented\r\n');
      }
    }

    function pump() {
      for (;;) {
        if (state === 'cmd') {
          const m = /\r?\n/.exec(buf);
          if (!m) return;
          const line = buf.slice(0, m.index);
          buf = buf.slice(m.index + m[0].length);
          handleCmdLine(line);
        } else {
          let idx = buf.indexOf('\r\n.\r\n');
          let sepLen = 5;
          if (idx === -1) { idx = buf.indexOf('\n.\n'); sepLen = 3; }
          if (idx === -1) return;
          const raw = buf.slice(0, idx);
          buf = buf.slice(idx + sepLen);
          state = 'cmd';
          finishData(raw);
        }
      }
    }

    sock.setEncoding('utf8');
    sock.write('220 stub-mail ESMTP ready\r\n');
    sock.on('data', (chunk) => {
      buf += chunk;
      pump();
    });
    sock.on('error', () => { /* client dropped */ });
  });
  server.listen(SMTP_PORT, () => {
    console.log(`[stub-mail] mini SMTP listening on :${SMTP_PORT}`);
  });
}

/* ------------------------------------------------------------------- HTML */
const CSS = `
  :root { color-scheme: dark; }
  body { font-family: ui-monospace, Menlo, Consolas, monospace; background:#0a0f0a; color:#c7f0c7; margin:0; padding:2rem; }
  a { color:#4ade80; } h1 { color:#4ade80; font-size:1.2rem; }
  .card { border:1px solid #1c3a1c; background:#0d140d; border-radius:6px; padding:1rem; margin:.75rem 0; max-width:760px; }
  table { border-collapse:collapse; font-size:.85rem; } th,td { border:1px solid #1c3a1c; padding:.35rem .5rem; text-align:left; }
  th { color:#4ade80; } code { color:#facc15; } .muted { color:#5c8a5c; font-size:.8rem; }
  input,button { font:inherit; background:#0f1a0f; color:#c7f0c7; border:1px solid #2a5a2a; border-radius:4px; padding:.4rem .6rem; }
  button { cursor:pointer; border-color:#4ade80; color:#4ade80; }
`;

const page = (title, body) => `<!doctype html><html><head><meta charset="utf-8"><title>${esc(title)}</title><style>${CSS}</style></head><body>${body}</body></html>`;

/* ---------------------------------------------------------------- servers */
function readBody(req) {
  return new Promise((resolve) => {
    const chunks = [];
    req.on('data', (c) => { if (chunks.length < 64) chunks.push(c); });
    req.on('end', () => resolve(Buffer.concat(chunks).toString('utf8')));
  });
}

async function parseBody(req) {
  const raw = await readBody(req);
  const ct = String(req.headers['content-type'] || '');
  if (ct.includes('application/json')) {
    try { return JSON.parse(raw); } catch (_) { return {}; }
  }
  if (ct.includes('application/x-www-form-urlencoded')) {
    return Object.fromEntries(new URLSearchParams(raw));
  }
  if (raw.trim().startsWith('{')) {
    try { return JSON.parse(raw); } catch (_) { return {}; }
  }
  return { raw };
}

function json(res, status, obj) {
  res.writeHead(status, { 'Content-Type': 'application/json' });
  res.end(JSON.stringify(obj) + '\n');
}

const server = http.createServer(async (req, res) => {
  const u = new URL(req.url, 'http://stub');
  const p = u.pathname;
  try {
    if (p === '/healthz') return json(res, 200, { ok: true, stub: STUB });

    if (STUB === 'auth') {
      if (req.method === 'POST' && p === '/issue') {
        const b = await parseBody(req);
        const claims = {
          sub: String(b.sub || 'stub-subject'),
          role: String(b.role || 'user'),
          tenant: String(b.tenant || 'default'),
          iat: Math.floor(Date.now() / 1000),
        };
        const alg = String(b.alg || 'HS256').toUpperCase();
        const token = alg === 'RS256' && stubKey
          ? rs256Sign(claims, stubKey.privateKey)
          : hs256Sign(claims, DEV_SECRET);
        return json(res, 200, { token, alg: alg === 'RS256' && stubKey ? 'RS256' : 'HS256', claims });
      }
      if (req.method === 'GET' && p === '/jwks.json') {
        // Exposes the stub's boot RSA public key so M4's RS256/HS256-confusion
        // validation paths are exercisable in standalone mode (README deviation note).
        return json(res, 200, stubPublicJwk());
      }
      if (req.method === 'GET' && p === '/whoami') {
        const m = /^Bearer\s+(.+)$/.exec(String(req.headers.authorization || ''));
        const qToken = u.searchParams.get('token');
        const token = m ? m[1] : qToken;
        if (!token) return json(res, 400, { error: 'Bearer token or ?token= required' });
        let claims = null; let verifiedBy = null;
        if ((claims = hs256Verify(token, DEV_SECRET))) verifiedBy = 'hs256-dev-secret';
        else if (stubKey && (claims = rs256Verify(token, stubKey.publicKey))) verifiedBy = 'rs256-stub-key';
        else {
          try { claims = JSON.parse(Buffer.from(String(token).split('.')[1] || '', 'base64url').toString('utf8')); } catch (_) { claims = null; }
        }
        return json(res, 200, { verified: !!verifiedBy, by: verifiedBy, claims });
      }
      return json(res, 404, { error: 'not found', stub: 'auth', see: ['POST /issue', 'GET /jwks.json', 'GET /whoami', 'GET /healthz'] });
    }

    if (STUB === 'portal') {
      if (req.method === 'GET' && (p === '/' || p === '/login')) {
        return res.end(page('Stub portal', `
          <h1>ASLV organization portal (stub)</h1>
          <div class="card"><p class="muted">Minimal static upstream for standalone modes. Any username/password logs in.</p>
          <form method="POST" action="/login">
            <p><input name="username" placeholder="username" value="0xnhsec" required>
               <input name="password" type="password" placeholder="password" value="vlh-tester-01" required>
               <button>sign in</button></p>
          </form></div>`));
      }
      if (req.method === 'POST' && p === '/login') {
        const b = await parseBody(req);
        const sid = randHex(32);
        portalSessions.set(sid, { username: String(b.username || 'stub-user'), at: nowIso() });
        res.writeHead(302, { 'Set-Cookie': `sid=${sid}; Path=/; HttpOnly; SameSite=Lax`, Location: '/me' });
        return res.end();
      }
      if (req.method === 'GET' && p === '/me') {
        const cookies = Object.fromEntries(String(req.headers.cookie || '').split(';').map((c) => c.trim().split('=')));
        const s = portalSessions.get(cookies.sid);
        if (!s) { res.writeHead(302, { Location: '/login' }); return res.end(); }
        return res.end(page('Account', `
          <h1>Stub account</h1>
          <div class="card"><table>
            <tr><th>username</th><td>${esc(s.username)}</td></tr>
            <tr><th>email</th><td>${esc(s.username)}@aslv.lab</td></tr>
            <tr><th>portal</th><td>stub-portal (static)</td></tr>
          </table></div>
          <p class="muted">This stub exists so standalone modules have a portal-shaped upstream. No bugs of interest live here.</p>`));
      }
      if (req.method === 'GET' && p === '/_internal/innocent-secret') {
        return json(res, 200, { username: STUB_INNOCENT.username, api_key: STUB_INNOCENT.api_key });
      }
      if (req.method === 'GET' && p === '/_internal/csrf-state') {
        return json(res, 200, { changed: false });
      }
      const mUser = /^\/_internal\/user\/([^/]+)$/.exec(p);
      if (req.method === 'GET' && mUser) {
        const username = decodeURIComponent(mUser[1]);
        return json(res, 200, {
          username,
          email: `${username}@aslv.lab`,
          recovery_email: null,
          source: 'stub-portal',
        });
      }
      return json(res, 404, { error: 'not found', stub: 'portal', see: ['GET /', 'POST /login', 'GET /me', 'GET /_internal/*'] });
    }

    if (STUB === 'mail') {
      if (req.method === 'POST' && p === '/internal/mail') {
        const b = await parseBody(req);
        if (!b.to || !b.subject) return json(res, 400, { error: 'to, subject, body required' });
        const m = storeMail({ from: b.from || 'internal@aslv.lab', to: String(b.to), subject: String(b.subject), body: String(b.body || '') });
        return json(res, 200, { id: m.id });
      }
      if (req.method === 'GET' && p === '/') {
        const items = mailbox.slice().reverse();
        return res.end(page('Stub mail', `
          <h1>Stub mailbox</h1>
          <p class="muted">All lab mail for this deployment lands here (stub-mail; MailHog in full mode). Mail is a token carrier, never a flag carrier.</p>
          <table><tr><th>id</th><th>time</th><th>from</th><th>to</th><th>subject</th><th>view</th></tr>
          ${items.map((m) => `<tr><td>${m.id}</td><td>${esc(m.ts)}</td><td>${esc(m.from)}</td><td>${esc(m.to)}</td><td>${esc(m.subject)}</td><td><a href="/mail/${m.id}">open</a></td></tr>`).join('') || '<tr><td colspan="6" class="muted">empty</td></tr>'}
          </table>`));
      }
      const mMail = /^\/mail\/(\d+)$/.exec(p);
      if (req.method === 'GET' && mMail) {
        const m = mailbox.find((x) => String(x.id) === mMail[1]);
        if (!m) return json(res, 404, { error: 'no such mail' });
        const links = String(m.body).match(/https?:\/\/[^\s"'<>)]+/g) || [];
        return json(res, 200, { id: m.id, ts: m.ts, from: m.from, to: m.to, subject: m.subject, body: m.body, links });
      }
      return json(res, 404, { error: 'not found', stub: 'mail', see: ['POST /internal/mail', 'GET /', 'GET /mail/{id}'] });
    }

    return json(res, 400, { error: `unknown STUB=${STUB}` });
  } catch (e) {
    return json(res, 500, { error: String(e && e.message ? e.message : e) });
  }
});

server.listen(HTTP_PORT, () => {
  console.log(`[stub] aslv-core stub=${STUB} HTTP listening on :${HTTP_PORT}`);
  if (STUB === 'mail') startSmtp();
});
