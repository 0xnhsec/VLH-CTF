'use strict';
/*
 * DSLTV AUTH/SessionFixation — "Anchor ID".
 * Bug: the login flow ADOPTS a client-supplied session id. POST /login
 * accepts an optional {sid}; when no session exists under that sid yet, the
 * new session is created WITH that id (pre-authentication fixation). The
 * SSO bridge POST /__sso (victim-bot only) logs the innocent user in through
 * the same flawed code path — fixate your chosen sid, let the victim's SSO
 * login adopt it, then ride their session.
 */
module.exports = {
  meta: {
    category: 'AUTH',
    subName: 'SessionFixation',
    archetype: 'identity-gated',
    difficulty: 'high',
    description: 'Anchor ID portal: logins adopt client-supplied session ids — fixate one, let the victim\'s SSO login bind it, hijack the session.',
    flags: [{ category: 'AUTH', subName: 'SessionFixation', archetype: 'identity-gated' }],
  },
  async setup(ctx) {
    const { app, render, esc, users, flags, session, db } = ctx;

    const isJson = (req) => /json/i.test(String(req.headers['content-type'] || '')) || /json/i.test(String(req.headers.accept || ''));
    const isLoopback = (req) => ['127.0.0.1', '::1', '::ffff:127.0.0.1'].includes(req.socket.remoteAddress || '');
    const sidExists = (sid) => !!db.prepare('SELECT sid FROM sessions WHERE sid = ?').get(sid);

    const loginPage = (msg) => render('Anchor ID — sign in', `
      <h1>⚓ Anchor ID</h1>
      <p class="muted">single sign-on for the harbor district</p>
      <div class="card">
        <form method="POST" action="/login" onsubmit="return postAsJson(this,'/login')">
          <p><input name="username" placeholder="username" size="14"> <input name="password" type="password" placeholder="password" size="14"> <button>sign in</button></p>
        </form>
        ${msg ? `<p class="muted">${esc(msg)}</p>` : ''}
        <p class="muted">testers: 0xnhsec / vlh-tester-01 · Noshiro / vlh-tester-02 · session ids are server-generated and rotated on login</p>
      </div>
      <script>
        function postAsJson(form, path){const f=new FormData(form);const o={};f.forEach((v,k)=>o[k]=v);
          fetch(path,{method:'POST',headers:{'content-type':'application/json'},body:JSON.stringify(o)})
            .then(r=>r.json()).then(j=>{out.textContent=JSON.stringify(j,null,2);}).catch(e=>{out.textContent=String(e);});
          return false;}
      </script>
      <pre id="out">—</pre>`);

    /* THE BUG: the login flow adopts a client-supplied sid (pre-auth
       fixation — models accepting session ids from links/cookie tosses). */
    const adoptOrCreate = (user, clientSid) => {
      const sid = String(clientSid || '');
      if (sid && !sidExists(sid)) {
        db.prepare('INSERT INTO sessions (sid, user_id, auth_method, created_at) VALUES (?,?,?,?)')
          .run(sid, user.id, 'password', ctx.nowIso());
        return sid;
      }
      return session.create(user, 'password');
    };

    app.post('/login', (req, res) => {
      const { username, password, sid } = req.body || {};
      const user = users.verify(username, password);
      if (!user) {
        if (isJson(req)) return res.status(401).json({ error: 'invalid credentials' });
        return res.status(401).type('html').send(loginPage('invalid credentials'));
      }
      const newSid = adoptOrCreate(user, sid);
      res.setHeader('Set-Cookie', `sid=${newSid}; Path=/; HttpOnly; SameSite=Lax`);
      if (isJson(req)) return res.json({ ok: true, signed_in: user.username, sid_adopted: sid || undefined });
      res.redirect('/');
    });

    /* identity gate: a session for the innocent account */
    app.get('/flag', (req, res) => {
      const auth = session.get(req);
      if (!auth) return res.status(401).json({ error: 'login required' });
      const innocent = users.innocent();
      if (auth.user.username === innocent.username) {
        return res.json({ ok: true, flag: flags.held('AUTH', 'SessionFixation') });
      }
      return res.status(403).json({ error: 'the flag needs a session for the innocent account', you: auth.user.username });
    });

    app.get('/logout', (req, res) => { ctx.logout(req, res); res.redirect('/'); });

    /* victim-bot SSO: logs the INNOCENT user in through the same flawed
       adoption path. Loopback-only (the bot runs in-container) — the PLAYER
       reaches this via POST /victim on the collector vhost with a sid payload. */
    const sso = (req, res) => {
      if (!isLoopback(req)) {
        return res.status(403).type('html').send(render('Anchor SSO', '<p>SSO bridge is internal (identity-provider host only).</p>'));
      }
      const innocent = users.innocent();
      const sid = String((req.body || {}).sid || '');
      const boundSid = adoptOrCreate(innocent, sid);
      res.type('html').send(render('Anchor SSO', `
        <h1>⚓ Anchor SSO</h1>
        <p>signed in as <b>${esc(innocent.username)}</b> via the identity provider</p>
        <div class="card"><p class="muted">${sid ? 'session id adopted from request context' : 'fresh session issued'}</p></div>`));
      void boundSid;
    };
    app.get('/__sso', sso);
    app.post('/__sso', sso);

    app.get('/', (req, res) => {
      const auth = session.get(req);
      if (!auth) return res.type('html').send(loginPage());
      res.type('html').send(render('Anchor ID', `
        <h1>⚓ Anchor ID</h1>
        <p>signed in as <b>${esc(auth.user.username)}</b> · <a href="/logout">sign out</a></p>
        <div class="card"><p class="muted">member vault: <code>GET /flag</code> — requires a session for the innocent account.</p></div>`));
    });

    const stack = app.stack;
    const layer = stack[stack.length - 1];
    if (layer && layer.route && layer.route.path === '/') { stack.pop(); stack.unshift(layer); }
  },
};
