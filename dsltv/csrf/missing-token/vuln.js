'use strict';
/*
 * DSLTV CSRF — MissingToken · theme "Mailgard — mailbox settings".
 * Flaw: POST /account/recovery-email changes the logged-in user's recovery
 * email and has ZERO CSRF protection — no token, no origin/referer check,
 * no custom header. Any cross-site page the victim visits can silently
 * submit this form with the victim's session cookie.
 * Event-verified (eventKind csrf): the base /verify mints the flag once the
 * innocent user's recovery_email row changes from its seed value.
 */
module.exports = {
  meta: {
    category: 'CSRF', subName: 'MissingToken', archetype: 'event-verified', eventKind: 'csrf', difficulty: 'low',
    description: 'Mailgard\'s recovery-email change has no CSRF token at all — a cross-site form silently rewrites the victim\'s recovery email.',
    flags: [{ category: 'CSRF', subName: 'MissingToken', archetype: 'event-verified', eventKind: 'csrf' }],
  },
  async setup(ctx) {
    const esc = ctx.esc;

    const applyChange = (auth, email) => {
      ctx.db.prepare('UPDATE users SET recovery_email = ? WHERE id = ?').run(email, auth.user.id);
    };
    const validEmail = (s) => /^[^@\s]+@[^@\s]+\.[^@\s]+$/.test(s);

    /* --- the vulnerable state change (no protection of any kind) ----------- */
    ctx.app.post('/account/recovery-email', (req, res) => {
      const auth = ctx.session.get(req);
      if (!auth) return res.status(401).json({ error: 'login required' });
      const email = String((req.body && req.body.recovery_email) || '');
      if (!validEmail(email)) return res.status(400).json({ error: 'a valid recovery_email is required' });
      applyChange(auth, email); /* ← flaw: no CSRF token, no origin check */
      const viaForm = String(req.headers['content-type'] || '').includes('application/x-www-form-urlencoded');
      if (viaForm) return res.redirect('/account');
      res.json({ ok: true, recovery_email: email });
    });

    /* --- themed UI --------------------------------------------------------- */
    ctx.app.get('/', (req, res) => {
      const auth = ctx.session.get(req);
      if (!auth) {
        return res.type('html').send(ctx.render('Mailgard', `
          <h1>Mailgard — your mailbox, guarded</h1>
          <div class="card">
            <p>Mailgard hosts your inbox and your account recovery settings.</p>
            <form method="post" action="/login">
              <p><input name="username" placeholder="username" autocomplete="off" required>
                 <input name="password" type="password" placeholder="password" required>
                 <button>sign in</button></p>
            </form>
            <p class="muted">Player accounts are documented in the player guide (0xnhsec / Noshiro).</p>
          </div>`, { tagline: 'mailbox — Mailgard' }));
      }
      res.type('html').send(ctx.render('Mailgard', `
        <h1>Mailgard — ${esc(auth.user.username)}</h1>
        <div class="card">
          <p>Inbox: no unread mail. Folders: inbox, archive, receipts.</p>
          <p>Recovery email: <code>${esc(auth.user.recovery_email || '(not set)')}</code> — manage it in <a href="/account">account settings</a>.</p>
        </div>
        <form method="post" action="/logout"><button>sign out</button></form>`, { tagline: 'mailbox — Mailgard' }));
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
          <p class="muted">Used to recover your mailbox if you lose your password.</p>
        </div>`, { tagline: 'mailbox — Mailgard' }));
    });

    ctx.app.post('/login', (req, res) => {
      const u = ctx.users.verify(req.body && req.body.username, req.body && req.body.password);
      if (!u) return res.status(401).type('html').send(ctx.render('Mailgard', '<h1>Mailgard</h1><div class="card">Wrong credentials. <a href="/">back</a></div>'));
      ctx.login(res, u);
      res.redirect('/');
    });
    ctx.app.post('/logout', (req, res) => { ctx.logout(req, res); res.redirect('/'); });
  },
};
