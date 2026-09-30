'use strict';
/*
 * VLH-CTF — ASLV M5 aslv-identity: OAuth 2.0 surface.
 *
 * ONE express app, TWO vhosts (Host-dispatched in server.js):
 *   auth.aslv.lab   → the Authorization Server (this file's asRouter)
 *   client.aslv.lab → a demo CLIENT app "web" (this file's clientRouter)
 *
 * Deliberate flaws (the OAUTH flag surface, arch §7.5):
 *   - redirect_uri validation is a substring check includes('client.aslv.lab')
 *     → path-confusion bypass: https://attacker.aslv.lab/client.aslv.lab/callback
 *   - the client's /client/login generates a state value but /client/callback
 *     NEVER validates it → login-CSRF: deliver your own authorization code to
 *     the victim's callback and their client session gets linked to (or
 *     replaced by) YOUR AS identity → linked_identities row
 *   - the token endpoint does not re-validate redirect_uri and there is no PKCE
 *   - response_type=token (implicit grant) → token in URL fragment; the buggy
 *     client page posts it to /client/implicit/finish
 *   - any scope string is accepted and carried into the token (scope creep)
 */
const express = require('express');
const { db, randHex, nowIso, esc, render, usersApi } = require('./db');

const CLIENT_ID = 'web';
const REDIRECT_URI = process.env.CLIENT_REDIRECT_URI || 'http://client.aslv.lab/client/callback';
const AUTH_ORIGIN = (process.env.AUTH_ORIGIN || 'http://auth.aslv.lab:18026').replace(/\/+$/, '');

/* --------------------------------------------------------------- helpers */

function exchangeCode(code) {
  const row = db.prepare('SELECT * FROM oauth_codes WHERE code = ? AND used = 0').get(String(code || ''));
  if (!row) return null;
  if (Date.now() - new Date(row.created_at).getTime() > 10 * 60 * 1000) return null;
  db.prepare('UPDATE oauth_codes SET used = 1 WHERE code = ?').run(row.code);
  const token = randHex(32);
  db.prepare('INSERT INTO oauth_tokens (token, user_id, scope, created_at) VALUES (?,?,?,?)')
    .run(token, row.user_id, row.scope, nowIso());
  const user = usersApi.byId(row.user_id);
  if (!user) return null;
  return { access_token: token, sub: user.uuid, username: user.username, scope: row.scope };
}

function buildRedirect(uri, params, mode) {
  const u = new URL(uri);
  if (mode === 'fragment') {
    u.hash = new URLSearchParams(params).toString();
  } else {
    for (const [k, v] of Object.entries(params)) u.searchParams.set(k, String(v));
  }
  return u.toString();
}

/* -------------------------------------------------- AS router (auth vhost) */

const asRouter = express.Router();

asRouter.get('/oauth/authorize', (req, res) => {
  const sid = /(?:^|;\s*)sid=([^;]*)/.exec(String(req.headers.cookie || ''))?.[1];
  const session = sid ? db.prepare('SELECT s.*, u.id uid FROM sessions s JOIN users u ON u.id = s.user_id WHERE s.sid = ? AND s.mfa_pending = 0').get(sid) : null;
  if (!session) return res.status(401).type('html').send(render('Login required', '<h1>AS login required</h1><p class="muted">Sign in at <a href="/login">/login</a> first — the authorize endpoint needs an AS session.</p>'));

  const client_id = String(req.query.client_id || '');
  const redirect_uri = String(req.query.redirect_uri || '');
  const response_type = String(req.query.response_type || 'code');
  const state = String(req.query.state || '');
  const scope = String(req.query.scope || '');

  if (client_id !== CLIENT_ID) return res.status(400).json({ error: 'unknown client_id' });
  // DELIBERATELY VULNERABLE: substring check, not exact-match against the
  // registered redirect_uri. https://attacker.aslv.lab/client.aslv.lab/callback
  // passes because the string simply CONTAINS client.aslv.lab (path confusion).
  if (!redirect_uri.includes('client.aslv.lab')) return res.status(400).json({ error: 'invalid redirect_uri' });

  if (response_type === 'token') {
    // Implicit grant: access token in the URL fragment.
    const token = randHex(32);
    db.prepare('INSERT INTO oauth_tokens (token, user_id, scope, created_at) VALUES (?,?,?,?)')
      .run(token, session.uid, scope, nowIso());
    return res.redirect(302, buildRedirect(redirect_uri, {
      access_token: token, token_type: 'Bearer', state, scope,
    }, 'fragment'));
  }

  // Authorization code (default).
  const code = randHex(24);
  db.prepare('INSERT INTO oauth_codes (code, client_id, user_id, redirect_uri, scope, used, created_at) VALUES (?,?,?,?,?,0,?)')
    .run(code, client_id, session.uid, redirect_uri, scope, nowIso());
  res.redirect(302, buildRedirect(redirect_uri, { code, state }, 'query'));
});

asRouter.post('/oauth/token', (req, res) => {
  const b = req.body || {};
  if (String(b.grant_type || '') !== 'authorization_code') {
    return res.status(400).json({ error: 'unsupported_grant_type' });
  }
  // DELIBERATELY VULNERABLE: redirect_uri is NOT re-validated against the
  // authorize-time value and there is no PKCE (no code_verifier accepted).
  const ident = exchangeCode(b.code);
  if (!ident) return res.status(400).json({ error: 'invalid_grant' });
  res.json({ access_token: ident.access_token, token_type: 'Bearer', scope: ident.scope || '' });
});

asRouter.get('/oauth/userinfo', (req, res) => {
  const m = /^Bearer\s+(.+)$/.exec(String(req.headers.authorization || ''));
  if (!m) return res.status(401).json({ error: 'bearer token required' });
  const t = db.prepare('SELECT * FROM oauth_tokens WHERE token = ?').get(m[1]);
  if (!t) return res.status(401).json({ error: 'invalid token' });
  const u = usersApi.byId(t.user_id);
  if (!u) return res.status(401).json({ error: 'invalid token' });
  res.json({ sub: u.uuid, username: u.username, email: u.email, role: u.role, scope: t.scope || '' });
});

/* --------------------------------------------- client app (client.aslv.lab) */

const clientRouter = express.Router();

clientRouter.get('/', (req, res) => {
  res.type('html').send(render('Client app', `
    <h1>client.aslv.lab — demo SSO client "web"</h1>
    <div class="card">
      <p>This internal app authenticates against the organization AS (<code>auth.aslv.lab</code>) via OAuth 2.0.</p>
      <p><a href="/client/login">Login with SSO →</a></p>
      <p class="muted">Also present: <a href="/client/implicit">implicit-grant page</a> (response_type=token).</p>
    </div>`));
});
clientRouter.get('/client', (req, res) => res.redirect('/'));

clientRouter.get('/client/login', (req, res) => {
  // state is generated… but see /client/callback — it is never validated.
  const state = randHex(8);
  const url = `${AUTH_ORIGIN}/oauth/authorize?` + new URLSearchParams({
    client_id: CLIENT_ID,
    redirect_uri: REDIRECT_URI,
    response_type: 'code',
    scope: 'openid profile',
    state,
  }).toString();
  res.redirect(302, url);
});

clientRouter.get('/client/callback', (req, res) => {
  const code = String(req.query.code || '');
  // DELIBERATELY VULNERABLE: req.query.state is ignored (MissingState).
  const ident = exchangeCode(code);
  if (!ident) return res.status(400).type('html').send(render('Callback', '<h1>Invalid code</h1>'));

  const csid = /(?:^|;\s*)csid=([^;]*)/.exec(String(req.headers.cookie || ''))?.[1];
  const cs = csid ? db.prepare('SELECT * FROM client_sessions WHERE csid = ?').get(csid) : null;

  if (cs && cs.user_uuid && cs.user_uuid !== ident.sub) {
    // Login-CSRF linking: a DIFFERENT AS identity arrives while the victim is
    // already signed in at the client → the app silently links + switches.
    db.prepare('INSERT INTO linked_identities (client_user_uuid, oauth_sub, created_at) VALUES (?,?,?)')
      .run(cs.user_uuid, ident.sub, nowIso());
    db.prepare('UPDATE client_sessions SET user_uuid = ? WHERE csid = ?').run(ident.sub, cs.csid);
  }
  if (!cs) {
    const fresh = randHex(32);
    db.prepare('INSERT INTO client_sessions (csid, user_uuid, created_at) VALUES (?,?,?)').run(fresh, ident.sub, nowIso());
    res.setHeader('Set-Cookie', `csid=${fresh}; Path=/; HttpOnly; SameSite=Lax`);
  }
  res.redirect('/client/me');
});

clientRouter.get('/client/me', (req, res) => {
  const csid = /(?:^|;\s*)csid=([^;]*)/.exec(String(req.headers.cookie || ''))?.[1];
  const cs = csid ? db.prepare('SELECT * FROM client_sessions WHERE csid = ?').get(csid) : null;
  if (!cs) return res.status(401).type('html').send(render('Client app', '<h1>Not signed in</h1><p><a href="/client/login">Login with SSO →</a></p>'));
  const u = usersApi.byUuid(cs.user_uuid);
  const links = db.prepare('SELECT * FROM linked_identities WHERE client_user_uuid = ? ORDER BY id DESC').all(cs.user_uuid);
  res.type('html').send(render('Client app', `
    <h1>Signed in at the client app</h1>
    <div class="card"><table>
      <tr><th>client identity</th><td>${esc(u ? u.username : cs.user_uuid)} <span class="muted">(${esc(cs.user_uuid)})</span></td></tr>
      <tr><th>linked oauth identities</th><td>${links.length ? links.map((l) => esc(l.oauth_sub)).join('<br>') : '<span class="muted">none</span>'}</td></tr>
    </table></div>
    <p class="muted">linked_identities rows are exactly what the OAUTH flag gate reads (§7.5).</p>`));
});

clientRouter.get('/client/implicit', (req, res) => {
  // The buggy client page: reads the implicit-grant token from location.hash
  // and POSTs it to /client/implicit/finish (a real browser flow; in solo play
  // the victim bot's finalUrl keeps the fragment, or you POST manually).
  res.type('html').send(render('Client app', `
    <h1>Implicit grant landing</h1>
    <div class="card"><p class="muted">If this page is opened with <code>#access_token=…</code>, the client JS exchanges it for a session.</p></div>
    <p><a href="${esc(AUTH_ORIGIN)}/oauth/authorize?${new URLSearchParams({ client_id: CLIENT_ID, redirect_uri: REDIRECT_URI, response_type: 'token', scope: 'openid', state: randHex(6) }).toString()}">Start implicit flow →</a></p>
    <script>
      var m = /access_token=([^&]+)/.exec(location.hash);
      if (m) {
        fetch('/client/implicit/finish', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ access_token: decodeURIComponent(m[1]) })
        }).then(function () { location.href = '/client/me'; });
      }
    </script>`));
});

clientRouter.post('/client/implicit/finish', (req, res) => {
  const token = String((req.body || {}).access_token || '');
  const t = db.prepare('SELECT * FROM oauth_tokens WHERE token = ?').get(token);
  if (!t) return res.status(400).json({ error: 'invalid token' });
  const u = usersApi.byId(t.user_id);
  if (!u) return res.status(400).json({ error: 'invalid token' });
  const csid = randHex(32);
  db.prepare('INSERT INTO client_sessions (csid, user_uuid, created_at) VALUES (?,?,?)').run(csid, u.uuid, nowIso());
  res.setHeader('Set-Cookie', `csid=${csid}; Path=/; HttpOnly; SameSite=Lax`);
  res.json({ ok: true, signed_in_as: u.username });
});

module.exports = { asRouter, clientRouter, exchangeCode, CLIENT_ID, REDIRECT_URI, AUTH_ORIGIN };
