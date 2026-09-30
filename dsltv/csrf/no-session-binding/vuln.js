'use strict';
/*
 * DSLTV CSRF — NoSessionBinding · theme "Corpx Hub — team workspace settings".
 * Flaw: POST /account/recovery-email requires a CSRF token and validates it —
 * but against a single GLOBAL static token shown on every user's /account
 * page (generated once at boot). Tokens that are not bound to the session
 * protect nothing: the attacker logs in with their own account, reads the
 * very same token from their own settings page, and submits it cross-site
 * riding the victim's cookie.
 * Event-verified (eventKind csrf): /verify mints once the innocent's
 * recovery_email row changes from its seed value.
 */
module.exports = {
  meta: {
    category: 'CSRF', subName: 'NoSessionBinding', archetype: 'event-verified', eventKind: 'csrf', difficulty: 'medium',
    description: 'Corpx Hub\'s CSRF token is one global static secret visible on every account page — not session-bound, so the attacker\'s own token works cross-site.',
    flags: [{ category: 'CSRF', subName: 'NoSessionBinding', archetype: 'event-verified', eventKind: 'csrf' }],
  },
  async setup(ctx) {
    const esc = ctx.esc;
    const validEmail = (s) => /^[^@\s]+@[^@\s]+\.[^@\s]+$/.test(s);

    /* one token for the whole deployment — regenerated per container restart */
    const GLOBAL_TOKEN = 'gst_' + ctx.randHex(16);
    ctx.state.set('global_csrf_token', GLOBAL_TOKEN);

    /* --- the protected-looking state change -------------------------------- */
    ctx.app.post('/account/recovery-email', (req, res) => {
      const auth = ctx.session.get(req);
      if (!auth) return res.status(401).json({ error: 'login required' });
      const email = String((req.body && req.body.recovery_email) || '');
      if (!validEmail(email)) return res.status(400).json({ error: 'a valid recovery_email is required' });
      if (String((req.body && req.body.csrf_token) || '') !== GLOBAL_TOKEN) { /* ← validates… */
        return res.status(403).json({ error: 'invalid or missing csrf token' });
      } /* …but against a GLOBAL token, not the victim session's ← flaw */
      ctx.db.prepare('UPDATE users SET recovery_email = ? WHERE id = ?').run(email, auth.user.id);
      res.json({ ok: true, recovery_email: email });
    });

    /* --- themed UI --------------------------------------------------------- */
    ctx.app.get('/', (req, res) => {
      const auth = ctx.session.get(req);
      if (!auth) {
        return res.type('html').send(ctx.render('Corpx Hub', `
          <h1>Corpx Hub — team workspace</h1>
          <div class="card">
            <p>One hub for your team\'s threads, docs and account settings.</p>
            <form method="post" action="/login">
              <p><input name="username" placeholder="username" autocomplete="off" required>
                 <input name="password" type="password" placeholder="password" required>
                 <button>sign in</button></p>
            </form>
            <p class="muted">Player accounts are documented in the player guide (0xnhsec / Noshiro).</p>
          </div>`, { tagline: 'team hub — Corpx' }));
      }
      res.type('html').send(ctx.render('Corpx Hub', `
        <h1>Corpx Hub — ${esc(auth.user.username)}</h1>
        <div class="card">
          <p>Team threads: 3 unread. Shared docs: contracts/, roadmap/.</p>
          <p>Recovery email: <code>${esc(auth.user.recovery_email || '(not set)')}</code> — manage it in <a href="/account">account settings</a>.</p>
        </div>
        <form method="post" action="/logout"><button>sign out</button></form>`, { tagline: 'team hub — Corpx' }));
    });

    ctx.app.get('/account', (req, res) => {
      const auth = ctx.session.get(req);
      if (!auth) return res.redirect('/');
      res.type('html').send(ctx.render('Account settings', `
        <h1>Account settings — ${esc(auth.user.username)}</h1>
        <div class="card">
          <h2>Recovery email</h2>
          <p>Current: <code>${esc(auth.user.recovery_email || '(not set)')}</code></p>
          <form method="post" action="/account/recovery-email">
            <input type="hidden" name="csrf_token" value="${esc(GLOBAL_TOKEN)}">
            <p><input name="recovery_email" type="email" placeholder="new recovery email" required>
               <button>save recovery email</button></p>
          </form>
          <p class="muted">Site-wide CSRF protection (SEC-08): every change must carry the site token <code>${esc(GLOBAL_TOKEN.slice(0, 8))}…</code></p>
        </div>`, { tagline: 'team hub — Corpx' }));
    });

    ctx.app.post('/login', (req, res) => {
      const u = ctx.users.verify(req.body && req.body.username, req.body && req.body.password);
      if (!u) return res.status(401).type('html').send(ctx.render('Corpx Hub', '<h1>Corpx Hub</h1><div class="card">Wrong credentials. <a href="/">back</a></div>'));
      ctx.login(res, u);
      res.redirect('/');
    });
    ctx.app.post('/logout', (req, res) => { ctx.logout(req, res); res.redirect('/'); });
  },
};
