'use strict';
/*
 * DSLTV CSRF — SameSiteNone · theme "Snackco — cookie shop".
 * Flaw: POST /account/recovery-email carries no CSRF token — the product
 * relies on the session cookie's SameSite attribute for cross-site
 * protection. But the login route sets the session cookie with
 * SameSite=None (ctx.login opts.cookie=['SameSite=None']), so the browser
 * attaches it to cross-site POSTs and the classic form-post CSRF works.
 * Browser reality: SameSite=Lax (the base default) already blocks cookies
 * on cross-site POSTs; None explicitly re-enables them (and in modern
 * browsers additionally demands the Secure attribute — not required on
 * this lab's plain-HTTP origin). The victim bot attaches the session
 * cookie regardless, so it models the None-vs-Lax difference conceptually;
 * the /verify checker still requires the real innocent-row state change.
 * Event-verified (eventKind csrf): /verify mints once the innocent's
 * recovery_email row changes from its seed value.
 */
module.exports = {
  meta: {
    category: 'CSRF', subName: 'SameSiteNone', archetype: 'event-verified', eventKind: 'csrf', difficulty: 'low',
    description: 'Snackco relies on SameSite for CSRF defence but logs users in with SameSite=None cookies — cross-site form posts ride the session.',
    flags: [{ category: 'CSRF', subName: 'SameSiteNone', archetype: 'event-verified', eventKind: 'csrf' }],
  },
  async setup(ctx) {
    const esc = ctx.esc;
    const validEmail = (s) => /^[^@\s]+@[^@\s]+\.[^@\s]+$/.test(s);

    /* --- the (token-less) state change ------------------------------------- */
    ctx.app.post('/account/recovery-email', (req, res) => {
      const auth = ctx.session.get(req);
      if (!auth) return res.status(401).json({ error: 'login required' });
      const email = String((req.body && req.body.recovery_email) || '');
      if (!validEmail(email)) return res.status(400).json({ error: 'a valid recovery_email is required' });
      /* no CSRF token: "the SameSite cookie policy covers us" (SEC-02) */
      ctx.db.prepare('UPDATE users SET recovery_email = ? WHERE id = ?').run(email, auth.user.id);
      const viaForm = String(req.headers['content-type'] || '').includes('application/x-www-form-urlencoded');
      if (viaForm) return res.redirect('/account');
      res.json({ ok: true, recovery_email: email });
    });

    /* --- themed UI --------------------------------------------------------- */
    ctx.app.get('/', (req, res) => {
      const auth = ctx.session.get(req);
      if (!auth) {
        return res.type('html').send(ctx.render('Snackco', `
          <h1>Snackco — the cookie shop</h1>
          <div class="card">
            <p>Order snack boxes, manage your delivery and recovery settings.</p>
            <form method="post" action="/login">
              <p><input name="username" placeholder="username" autocomplete="off" required>
                 <input name="password" type="password" placeholder="password" required>
                 <button>sign in</button></p>
            </form>
            <p class="muted">Player accounts are documented in the player guide (0xnhsec / Noshiro).</p>
          </div>`, { tagline: 'snacks — Snackco' }));
      }
      res.type('html').send(ctx.render('Snackco', `
        <h1>Snackco — ${esc(auth.user.username)}</h1>
        <div class="card">
          <p>Today's box: <span class="muted">oat bars, cocoa almonds, sea-salt chips</span>.</p>
          <p>Next delivery: <span class="muted">Thursday</span>. Recovery email: <code>${esc(auth.user.recovery_email || '(not set)')}</code> — manage it in <a href="/account">account settings</a>.</p>
        </div>
        <form method="post" action="/logout"><button>sign out</button></form>`, { tagline: 'snacks — Snackco' }));
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
            <p><input name="recovery_email" type="email" placeholder="new recovery email" required>
               <button>save recovery email</button></p>
          </form>
          <p class="muted">Changes are protected by our session cookie's SameSite policy (SEC-02) — no tokens needed.</p>
        </div>`, { tagline: 'snacks — Snackco' }));
    });

    /* --- login: the flaw lives HERE (SameSite=None on the session cookie) --- */
    ctx.app.post('/login', (req, res) => {
      const u = ctx.users.verify(req.body && req.body.username, req.body && req.body.password);
      if (!u) return res.status(401).type('html').send(ctx.render('Snackco', '<h1>Snackco</h1><div class="card">Wrong credentials. <a href="/">back</a></div>'));
      ctx.login(res, u, { cookie: ['SameSite=None'] }); /* ← flaw: cross-site POSTs keep the cookie */
      res.redirect('/');
    });
    ctx.app.post('/logout', (req, res) => { ctx.logout(req, res); res.redirect('/'); });
  },
};
