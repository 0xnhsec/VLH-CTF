'use strict';
/*
 * DSLTV CSRF — MethodSwitch · theme "Shipl — shipment settings".
 * Flaw: POST /account/recovery-email validates a per-session CSRF token
 * (the protection is real on the POST route), but the same handler was also
 * mounted at PUT /account/recovery-email for the "Shipl API clients" — a
 * route added later without the token check. Cross-site requests can simply
 * use PUT (still a simple request for HTML forms? no — but the victim bot
 * models an API-capable cross-site client; in-browser, fetch PUT without
 * custom headers is a simple request too, no preflight).
 * Event-verified (eventKind csrf): /verify mints once the innocent's
 * recovery_email row changes from its seed value.
 */
module.exports = {
  meta: {
    category: 'CSRF', subName: 'MethodSwitch', archetype: 'event-verified', eventKind: 'csrf', difficulty: 'medium',
    description: 'Shipl\'s POST change validates a CSRF token, but the parallel PUT route (added for API clients) skips the check entirely.',
    flags: [{ category: 'CSRF', subName: 'MethodSwitch', archetype: 'event-verified', eventKind: 'csrf' }],
  },
  async setup(ctx) {
    const esc = ctx.esc;
    const validEmail = (s) => /^[^@\s]+@[^@\s]+\.[^@\s]+$/.test(s);

    const sessionToken = (sid) => {
      let t = ctx.state.get('csrf:' + sid);
      if (!t) { t = 'tok_' + ctx.randHex(16); ctx.state.set('csrf:' + sid, t); }
      return t;
    };

    const applyChange = (req, res, auth, requireToken) => {
      const email = String((req.body && req.body.recovery_email) || '');
      if (!validEmail(email)) return res.status(400).json({ error: 'a valid recovery_email is required' });
      if (requireToken) {
        const expect = sessionToken(auth.session.sid);
        if (String((req.body && req.body.csrf_token) || '') !== expect) {
          return res.status(403).json({ error: 'invalid or missing csrf token' });
        }
      }
      ctx.db.prepare('UPDATE users SET recovery_email = ? WHERE id = ?').run(email, auth.user.id);
      res.json({ ok: true, recovery_email: email });
    };

    /* --- the protected route... -------------------------------------------- */
    ctx.app.post('/account/recovery-email', (req, res) => {
      const auth = ctx.session.get(req);
      if (!auth) return res.status(401).json({ error: 'login required' });
      applyChange(req, res, auth, true); /* POST: token enforced */
    });

    /* --- ...and the same handler mounted without the check (the flaw) ------ */
    ctx.app.put('/account/recovery-email', (req, res) => {
      const auth = ctx.session.get(req);
      if (!auth) return res.status(401).json({ error: 'login required' });
      applyChange(req, res, auth, false); /* PUT: "API clients" route — no token check ← flaw */
    });

    /* --- themed UI --------------------------------------------------------- */
    ctx.app.get('/', (req, res) => {
      const auth = ctx.session.get(req);
      if (!auth) {
        return res.type('html').send(ctx.render('Shipl', `
          <h1>Shipl — shipment settings</h1>
          <div class="card">
            <p>Shipl manages your delivery addresses and notification settings.</p>
            <form method="post" action="/login">
              <p><input name="username" placeholder="username" autocomplete="off" required>
                 <input name="password" type="password" placeholder="password" required>
                 <button>sign in</button></p>
            </form>
            <p class="muted">Player accounts are documented in the player guide (0xnhsec / Noshiro).</p>
          </div>`, { tagline: 'shipments — Shipl' }));
      }
      res.type('html').send(ctx.render('Shipl', `
        <h1>Shipl — ${esc(auth.user.username)}</h1>
        <div class="card">
          <p>Active delivery: <span class="muted">none</span>. Address book: home, office.</p>
          <p>Recovery email: <code>${esc(auth.user.recovery_email || '(not set)')}</code> — manage it in <a href="/account">account settings</a>.</p>
        </div>
        <form method="post" action="/logout"><button>sign out</button></form>`, { tagline: 'shipments — Shipl' }));
    });

    ctx.app.get('/account', (req, res) => {
      const auth = ctx.session.get(req);
      if (!auth) return res.redirect('/');
      const token = sessionToken(auth.session.sid);
      res.type('html').send(ctx.render('Account settings', `
        <h1>Account settings — ${esc(auth.user.username)}</h1>
        <div class="card">
          <h2>Recovery email</h2>
          <p>Current: <code>${esc(auth.user.recovery_email || '(not set)')}</code></p>
          <form method="post" action="/account/recovery-email">
            <input type="hidden" name="csrf_token" value="${esc(token)}">
            <p><input name="recovery_email" type="email" placeholder="new recovery email" required>
               <button>save recovery email</button></p>
          </form>
          <p class="muted">All state changes require your session's CSRF token (SEC-31). API clients may use the PUT variant of the same endpoint.</p>
        </div>`, { tagline: 'shipments — Shipl' }));
    });

    ctx.app.post('/login', (req, res) => {
      const u = ctx.users.verify(req.body && req.body.username, req.body && req.body.password);
      if (!u) return res.status(401).type('html').send(ctx.render('Shipl', '<h1>Shipl</h1><div class="card">Wrong credentials. <a href="/">back</a></div>'));
      ctx.login(res, u);
      res.redirect('/');
    });
    ctx.app.post('/logout', (req, res) => { ctx.logout(req, res); res.redirect('/'); });
  },
};
