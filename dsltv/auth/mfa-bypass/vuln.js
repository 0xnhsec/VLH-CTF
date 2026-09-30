'use strict';
/*
 * DSLTV AUTH/MfaBypass — "Vaultis".
 * Two-factor flow: step 1 (password) returns an mfa_token for a PENDING
 * login; step 2 (POST /mfa/verify {mfa_token, code}) checks a 4-digit code.
 * THE BUG: step 2 has no rate limit and the code space is only 10^4 —
 * brute-force it to complete the innocent user's pending MFA login and get
 * a fully verified session for their account.
 *
 * Solo-play plumbing: the victim bot (collector /victim) can start the
 * innocent user's SSO login at GET/POST /__sso (loopback-only), which
 * reveals the pending mfa_token in its response page.
 */
module.exports = {
  meta: {
    category: 'AUTH',
    subName: 'MfaBypass',
    archetype: 'identity-gated',
    difficulty: 'high',
    description: 'Vaultis MFA: the code verification endpoint is unlimited and the code is only 4 digits — brute-force the innocent user\'s pending login.',
    flags: [{ category: 'AUTH', subName: 'MfaBypass', archetype: 'identity-gated' }],
  },
  async setup(ctx) {
    const { app, render, esc, users, flags, session, db } = ctx;

    db.exec(`CREATE TABLE IF NOT EXISTS mfa_pending (
      token TEXT PRIMARY KEY, user_id INTEGER NOT NULL, created_at TEXT NOT NULL
    )`);
    try { db.exec('ALTER TABLE sessions ADD COLUMN mfa_verified INTEGER NOT NULL DEFAULT 0'); } catch (_) { /* already added this boot */ }

    /* static per-user 4-digit codes (dev build — authenticator apps not wired) */
    const upd = db.prepare('UPDATE users SET mfa_secret = ? WHERE id = ?');
    for (const u of users.all()) upd.run(ctx.randDigits(4), u.id);

    const isJson = (req) => /json/i.test(String(req.headers['content-type'] || '')) || /json/i.test(String(req.headers.accept || ''));
    const sleep = (ms) => new Promise((r) => { setTimeout(r, ms); });
    const isLoopback = (req) => ['127.0.0.1', '::1', '::ffff:127.0.0.1'].includes(req.socket.remoteAddress || '');

    const loginPage = (msg) => render('Vaultis — sign in', `
      <h1>🔐 Vaultis</h1>
      <p class="muted">two-step verified accounts</p>
      <div class="card">
        <form method="POST" action="/login" onsubmit="return postAsJson(this,'/login')">
          <p><input name="username" placeholder="username" size="14"> <input name="password" type="password" placeholder="password" size="14"> <button>sign in</button></p>
        </form>
        ${msg ? `<p class="muted">${esc(msg)}</p>` : ''}
        <p class="muted">testers: 0xnhsec / vlh-tester-01 · Noshiro / vlh-tester-02 (codes mailed on step 1)</p>
      </div>
      <script>
        function postAsJson(form, path){const f=new FormData(form);const o={};f.forEach((v,k)=>o[k]=v);
          fetch(path,{method:'POST',headers:{'content-type':'application/json'},body:JSON.stringify(o)})
            .then(r=>r.json()).then(j=>{out.textContent=JSON.stringify(j,null,2);}).catch(e=>{out.textContent=String(e);});
          return false;}
      </script>
      <pre id="out">—</pre>`);

    /* step 1: password → pending login (no session yet) */
    app.post('/login', (req, res) => {
      const { username, password } = req.body || {};
      const user = users.verify(username, password);
      if (!user) {
        if (isJson(req)) return res.status(401).json({ error: 'invalid credentials' });
        return res.status(401).type('html').send(loginPage('invalid credentials'));
      }
      const token = ctx.randHex(16);
      db.prepare('INSERT INTO mfa_pending (token, user_id, created_at) VALUES (?,?,?)').run(token, user.id, ctx.nowIso());
      if (user.role === 'tester') {
        /* tester mailboxes are local; customer codes route to their authenticator */
        ctx.mail.send({
          to: user.email,
          subject: 'Vaultis verification code',
          body: `Hello ${user.username},\n\nYour verification code is: ${user.mfa_secret}\n\n(dev build: codes are static per account.)`,
        });
      }
      const out = { mfa_required: true, mfa_token: token, next: 'POST /mfa/verify {mfa_token, code}' };
      if (isJson(req)) return res.json(out);
      res.type('html').send(render('Vaultis — step 2', `
        <h1>🔐 Vaultis — verification required</h1>
        <div class="card">
          <p>account <b>${esc(user.username)}</b> requires a verification code.</p>
          <p>pending mfa_token: <code>${esc(token)}</code></p>
          <form method="POST" action="/mfa/verify" onsubmit="return postAsJson(this,'/mfa/verify')">
            <p><input name="mfa_token" value="${esc(token)}" size="36"> <input name="code" placeholder="4-digit code" size="12"> <button>verify</button></p>
          </form>
          <p class="muted">testers receive the code by mail (mail.target.lab)</p>
        </div>
        <script>
          function postAsJson(form, path){const f=new FormData(form);const o={};f.forEach((v,k)=>o[k]=v);
            fetch(path,{method:'POST',headers:{'content-type':'application/json'},body:JSON.stringify(o)})
              .then(r=>r.json()).then(j=>{out.textContent=JSON.stringify(j,null,2);}).catch(e=>{out.textContent=String(e);});
            return false;}
        </script>
        <pre id="out">—</pre>`));
    });

    /* step 2 — THE BUG: no rate limit, 4-digit code space (10^4). */
    app.post('/mfa/verify', async (req, res) => {
      const { mfa_token, code } = req.body || {};
      await sleep(5); // simulated verify latency — that is ALL the protection
      const row = db.prepare('SELECT * FROM mfa_pending WHERE token = ?').get(String(mfa_token || ''));
      if (!row) return res.status(404).json({ error: 'unknown mfa_token' });
      const user = users.byId(row.user_id);
      if (!user) return res.status(404).json({ error: 'account vanished' });
      if (String(code) !== String(user.mfa_secret)) {
        return res.status(401).json({ error: 'invalid code' });
      }
      db.prepare('DELETE FROM mfa_pending WHERE token = ?').run(row.token);
      const sid = session.create(user, 'password');
      db.prepare('UPDATE sessions SET mfa_verified = 1 WHERE sid = ?').run(sid);
      res.setHeader('Set-Cookie', `sid=${sid}; Path=/; HttpOnly; SameSite=Lax`);
      return res.json({ ok: true, mfa_verified: true, signed_in: user.username });
    });

    /* identity gate: innocent account + MFA-verified session */
    app.get('/flag', (req, res) => {
      const auth = session.get(req);
      if (!auth) return res.status(401).json({ error: 'login required' });
      const innocent = users.innocent();
      if (auth.user.username === innocent.username && auth.session.mfa_verified === 1) {
        return res.json({ ok: true, flag: flags.held('AUTH', 'MfaBypass') });
      }
      return res.status(403).json({
        error: 'the flag needs a fully MFA-verified session for the innocent account',
        you: { sub: auth.user.username, mfa_verified: !!auth.session.mfa_verified },
      });
    });

    /* victim-bot SSO: starts the innocent user's step-1 login server-side and
       shows the pending mfa_token. Loopback-only (the bot runs in-container):
       the PLAYER reaches this via POST /victim on the collector vhost. */
    const sso = (req, res) => {
      if (!isLoopback(req)) {
        return res.status(403).type('html').send(render('Vaultis SSO', '<p>SSO bridge is internal (identity-provider host only).</p>'));
      }
      const innocent = users.innocent();
      const token = ctx.randHex(16);
      db.prepare('INSERT INTO mfa_pending (token, user_id, created_at) VALUES (?,?,?)').run(token, innocent.id, ctx.nowIso());
      /* compact page on purpose: the victim bot relays only the first 1200
         bytes — the pending token must appear early for the player to read it */
      res.type('html').send(`<!doctype html><html><head><meta charset="utf-8"><title>Vaultis SSO</title></head><body>
<h1>Vaultis SSO</h1>
<p>signed in as <b>${esc(innocent.username)}</b></p>
<p>Multi-factor required. Pending verification token: <code>${esc(token)}</code></p>
<p>complete step 2 at POST /mfa/verify with the 4-digit code</p>
</body></html>`);
    };
    app.get('/__sso', sso);
    app.post('/__sso', sso);

    app.get('/logout', (req, res) => { ctx.logout(req, res); res.redirect('/'); });

    app.get('/', (req, res) => {
      const auth = session.get(req);
      if (!auth) return res.type('html').send(loginPage());
      res.type('html').send(render('Vaultis', `
        <h1>🔐 Vaultis</h1>
        <p>signed in as <b>${esc(auth.user.username)}</b>${auth.session.mfa_verified ? ' · MFA verified' : ''} · <a href="/logout">sign out</a></p>
        <div class="card"><p class="muted">member vault: <code>GET /flag</code> — requires a fully verified session for the innocent account.</p></div>`));
    });

    const stack = app.stack;
    const layer = stack[stack.length - 1];
    if (layer && layer.route && layer.route.path === '/') { stack.pop(); stack.unshift(layer); }
  },
};
