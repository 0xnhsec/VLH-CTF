'use strict';
/*
 * DSLTV CSRF — ExistenceCheck · theme "Billfold — billing settings".
 * Flaw: POST /account/recovery-email validates the per-session CSRF token
 * only inside `if (req.body.csrf_token) { ... }`. Submitting the form
 * WITHOUT the csrf_token field skips validation entirely — an existence
 * check guarding a validation step is not a validation step.
 * Event-verified (eventKind csrf): /verify mints once the innocent's
 * recovery_email row changes from its seed value.
 */
module.exports = {
  meta: {
    category: 'CSRF', subName: 'ExistenceCheck', archetype: 'event-verified', eventKind: 'csrf', difficulty: 'low',
    description: 'Billfold validates the CSRF token only when the field is present — omitting csrf_token skips validation entirely.',
    flags: [{ category: 'CSRF', subName: 'ExistenceCheck', archetype: 'event-verified', eventKind: 'csrf' }],
  },
  async setup(ctx) {
    const esc = ctx.esc;
    const validEmail = (s) => /^[^@\s]+@[^@\s]+\.[^@\s]+$/.test(s);

    const sessionToken = (sid) => {
      let t = ctx.state.get('csrf:' + sid);
      if (!t) { t = 'tok_' + ctx.randHex(16); ctx.state.set('csrf:' + sid, t); }
      return t;
    };

    /* --- the vulnerable state change --------------------------------------- */
    ctx.app.post('/account/recovery-email', (req, res) => {
      const auth = ctx.session.get(req);
      if (!auth) return res.status(401).json({ error: 'login required' });
      const email = String((req.body && req.body.recovery_email) || '');
      if (!validEmail(email)) return res.status(400).json({ error: 'a valid recovery_email is required' });
      if (req.body && req.body.csrf_token) { /* ← flaw: validation only runs when the field EXISTS */
        const expect = sessionToken(auth.session.sid);
        if (String(req.body.csrf_token) !== expect) {
          return res.status(403).json({ error: 'invalid csrf token' });
        }
      } /* no field → no validation → straight through */
      ctx.db.prepare('UPDATE users SET recovery_email = ? WHERE id = ?').run(email, auth.user.id);
      res.json({ ok: true, recovery_email: email });
    });

    /* --- themed UI --------------------------------------------------------- */
    ctx.app.get('/', (req, res) => {
      const auth = ctx.session.get(req);
      if (!auth) {
        return res.type('html').send(ctx.render('Billfold', `
          <h1>Billfold — billing settings</h1>
          <div class="card">
            <p>Billfold keeps your invoices and recovery contact in order.</p>
            <form method="post" action="/login">
              <p><input name="username" placeholder="username" autocomplete="off" required>
                 <input name="password" type="password" placeholder="password" required>
                 <button>sign in</button></p>
            </form>
            <p class="muted">Player accounts are documented in the player guide (0xnhsec / Noshiro).</p>
          </div>`, { tagline: 'billing — Billfold' }));
      }
      res.type('html').send(ctx.render('Billfold', `
        <h1>Billfold — ${esc(auth.user.username)}</h1>
        <div class="card">
          <p>Open invoices: 0. Last payment: <span class="muted">none this cycle</span>.</p>
          <p>Recovery email: <code>${esc(auth.user.recovery_email || '(not set)')}</code> — manage it in <a href="/account">account settings</a>.</p>
        </div>
        <form method="post" action="/logout"><button>sign out</button></form>`, { tagline: 'billing — Billfold' }));
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
          <p class="muted">Changes are CSRF-protected (SEC-14): the token is validated whenever the form includes one.</p>
        </div>`, { tagline: 'billing — Billfold' }));
    });

    ctx.app.post('/login', (req, res) => {
      const u = ctx.users.verify(req.body && req.body.username, req.body && req.body.password);
      if (!u) return res.status(401).type('html').send(ctx.render('Billfold', '<h1>Billfold</h1><div class="card">Wrong credentials. <a href="/">back</a></div>'));
      ctx.login(res, u);
      res.redirect('/');
    });
    ctx.app.post('/logout', (req, res) => { ctx.logout(req, res); res.redirect('/'); });
  },
};
