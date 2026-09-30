'use strict';
/*
 * DSLTV JWT/WeakHMAC — "HashHouse".
 * Bug: tokens are HS256-signed with a weak human-chosen secret. Verification
 * itself is correct — the secret is crackable offline (the changelog admits
 * the intern picked it), after which the gated claim pair can be minted.
 */
module.exports = {
  meta: {
    category: 'JWT',
    subName: 'WeakHMAC',
    archetype: 'identity-gated',
    difficulty: 'medium',
    description: 'HashHouse API: HS256 tokens signed with a weak intern-chosen secret — crack it offline and forge the gated claims.',
    flags: [{ category: 'JWT', subName: 'WeakHMAC', archetype: 'identity-gated' }],
  },
  async setup(ctx) {
    const { app, render, esc, users, flags, jwt } = ctx;

    const WEAK_SECRET = 'flag-hunter'; // the flaw — weak human-chosen HMAC secret

    const dec = (s) => { try { return JSON.parse(Buffer.from(String(s), 'base64url').toString('utf8')); } catch (_) { return null; } };
    const bearer = (req) => { const m = /^Bearer\s+(.+)$/i.exec(String(req.headers.authorization || '')); return m ? m[1] : null; };

    app.post('/login', (req, res) => {
      const { username, password } = req.body || {};
      const user = users.verify(username, password);
      if (!user) return res.status(401).json({ error: 'invalid credentials' });
      const token = jwt.sign({ sub: user.username, role: user.role }, WEAK_SECRET, { algorithm: 'HS256', expiresIn: '1h' });
      res.json({ ok: true, token, sub: user.username, role: user.role, hint: 'gated endpoint: GET /flag/jwt — it opens for one specific sub+role pair' });
    });

    /* legit leak: account directory (the gated identity is in here) */
    app.get('/api/directory', (req, res) => {
      res.json({ users: users.all().map((u) => ({ username: u.username, role: u.role })) });
    });

    app.get('/api/whoami', (req, res) => {
      const token = bearer(req);
      if (!token) return res.status(400).json({ error: 'Authorization: Bearer <token> required' });
      const parts = String(token).split('.');
      res.json({ header: dec(parts[0]), payload: dec(parts[1]), note: 'debug decoder — no verification performed' });
    });

    app.get('/changelog', (req, res) => {
      res.type('html').send(render('HashHouse — changelog', `
        <h1>🎫 HashHouse changelog</h1>
        <div class="card"><pre>v1.3  token revocation backlog (again)
v1.2  HS256 signing introduced — the intern picked the
      secret on a Friday; rotation ticket filed
v1.1  account directory API (/api/directory)
v1.0  launch</pre></div>
        <p class="muted">weak HMAC secrets fall to offline dictionary attacks (hashcat -m 16500).</p>`));
    });

    /* verification is correct — the SECRET is the flaw */
    const verifyToken = (token) => {
      try {
        return { ok: true, payload: jwt.verify(token, WEAK_SECRET, { algorithms: ['HS256'] }) };
      } catch (e) { return { ok: false, error: e.message }; }
    };

    app.get('/flag/jwt', (req, res) => {
      const token = bearer(req);
      if (!token) return res.status(401).json({ error: 'Authorization: Bearer <token> required' });
      const v = verifyToken(token);
      if (!v.ok) return res.status(401).json({ error: `verification failed: ${v.error}` });
      const p = v.payload || {};
      const innocent = users.innocent();
      if (p.sub === innocent.username && p.role === 'admin') {
        return res.json({ ok: true, flag: flags.held('JWT', 'WeakHMAC') });
      }
      return res.status(403).json({ error: 'claims rejected — the gate needs one specific sub+role pair', got: { sub: p.sub, role: p.role } });
    });

    const landing = () => render('HashHouse', `
      <h1>🎫 HashHouse</h1>
      <p class="muted">bearer-token API portal · JWTs (HS256) issued at POST /login</p>
      <div class="card">
        <form onsubmit="return doLogin()">
          <p><input id="u" value="0xnhsec" size="16" autocomplete="off"> <input id="p" type="password" size="16" placeholder="password"> <button>log in</button></p>
        </form>
        <p class="muted">testers: 0xnhsec / vlh-tester-01 · Noshiro / vlh-tester-02</p>
      </div>
      <div class="card">
        <p><textarea id="tok" rows="3" cols="88" placeholder="paste a JWT here…"></textarea></p>
        <p><button onclick="who()">decode (whoami)</button> <button onclick="flag()">GET /flag/jwt</button></p>
        <pre id="out">—</pre>
      </div>
      <p class="muted">directory: <a href="/api/directory">/api/directory</a> · <a href="/changelog">changelog</a></p>
      <script>
        async function doLogin(){const r=await fetch('/login',{method:'POST',headers:{'content-type':'application/json'},body:JSON.stringify({username:document.getElementById('u').value,password:document.getElementById('p').value})});const j=await r.json();document.getElementById('out').textContent=JSON.stringify(j,null,2);if(j.token)document.getElementById('tok').value=j.token;return false;}
        async function who(){const r=await fetch('/api/whoami',{headers:{authorization:'Bearer '+document.getElementById('tok').value}});document.getElementById('out').textContent=JSON.stringify(await r.json(),null,2);}
        async function flag(){const r=await fetch('/flag/jwt',{headers:{authorization:'Bearer '+document.getElementById('tok').value}});document.getElementById('out').textContent=JSON.stringify(await r.json(),null,2);}
      </script>`);

    app.get('/', (req, res) => { res.type('html').send(landing()); });

    const stack = app.stack;
    const layer = stack[stack.length - 1];
    if (layer && layer.route && layer.route.path === '/') { stack.pop(); stack.unshift(layer); }
  },
};
