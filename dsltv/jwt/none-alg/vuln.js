'use strict';
/*
 * DSLTV JWT/NoneAlg — "TokenWorks".
 * Bug: the /flag/jwt verifier trusts the token header's alg claim. When
 * alg=none it accepts the payload without any signature check, so anyone can
 * mint the gated identity combo (sub=innocent, role=admin) in an unsigned
 * token.
 */
module.exports = {
  meta: {
    category: 'JWT',
    subName: 'NoneAlg',
    archetype: 'identity-gated',
    difficulty: 'low',
    description: 'TokenWorks API: the verifier accepts alg=none tokens without a signature check — forge the gated identity/role claim pair.',
    flags: [{ category: 'JWT', subName: 'NoneAlg', archetype: 'identity-gated' }],
  },
  async setup(ctx) {
    const { app, render, esc, users, flags, jwt } = ctx;
    const crypto = ctx.crypto;
    const SECRET = ctx.randHex(32); // real signing secret — never leaves the server

    const dec = (s) => { try { return JSON.parse(Buffer.from(String(s), 'base64url').toString('utf8')); } catch (_) { return null; } };
    const bearer = (req) => { const m = /^Bearer\s+(.+)$/i.exec(String(req.headers.authorization || '')); return m ? m[1] : null; };

    app.post('/login', (req, res) => {
      const { username, password } = req.body || {};
      const user = users.verify(username, password);
      if (!user) return res.status(401).json({ error: 'invalid credentials' });
      const token = jwt.sign({ sub: user.username, role: user.role }, SECRET, { algorithm: 'HS256', expiresIn: '1h' });
      res.json({ ok: true, token, sub: user.username, role: user.role, hint: 'gated endpoint: GET /flag/jwt — it opens for one specific sub+role pair' });
    });

    /* legit leak: account directory (the gated identity is in here) */
    app.get('/api/directory', (req, res) => {
      res.json({ users: users.all().map((u) => ({ username: u.username, role: u.role })) });
    });

    /* debug decoder (no verification) — helps inspect header/payload claims */
    app.get('/api/whoami', (req, res) => {
      const token = bearer(req);
      if (!token) return res.status(400).json({ error: 'Authorization: Bearer <token> required' });
      const parts = String(token).split('.');
      res.json({ header: dec(parts[0]), payload: dec(parts[1]), note: 'debug decoder — no verification performed' });
    });

    /* THE BUG: header alg is trusted; alg=none skips the signature entirely. */
    const verifyToken = (token) => {
      const parts = String(token).split('.');
      if (parts.length !== 3) return { ok: false, error: 'malformed token' };
      const header = dec(parts[0]);
      if (!header || !header.alg) return { ok: false, error: 'missing alg' };
      if (String(header.alg).toLowerCase() === 'none') {
        const payload = dec(parts[1]);
        if (!payload) return { ok: false, error: 'unreadable payload' };
        return { ok: true, payload }; // accepted — no signature check at all
      }
      try {
        return { ok: true, payload: jwt.verify(token, SECRET, { algorithms: ['HS256'] }) };
      } catch (e) { return { ok: false, error: e.message }; }
    };

    /* identity gate: the impossible-issued combo sub=innocent + role=admin */
    app.get('/flag/jwt', (req, res) => {
      const token = bearer(req);
      if (!token) return res.status(401).json({ error: 'Authorization: Bearer <token> required' });
      const v = verifyToken(token);
      if (!v.ok) return res.status(401).json({ error: `verification failed: ${v.error}` });
      const p = v.payload || {};
      const innocent = users.innocent();
      if (p.sub === innocent.username && p.role === 'admin') {
        return res.json({ ok: true, flag: flags.held('JWT', 'NoneAlg') });
      }
      return res.status(403).json({ error: 'claims rejected — the gate needs one specific sub+role pair', got: { sub: p.sub, role: p.role } });
    });

    const landing = () => render('TokenWorks', `
      <h1>🎫 TokenWorks</h1>
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
      <p class="muted">directory: <a href="/api/directory">/api/directory</a> · the verifier believes whatever the token header tells it</p>
      <script>
        async function doLogin(){const r=await fetch('/login',{method:'POST',headers:{'content-type':'application/json'},body:JSON.stringify({username:document.getElementById('u').value,password:document.getElementById('p').value})});const j=await r.json();document.getElementById('out').textContent=JSON.stringify(j,null,2);if(j.token)document.getElementById('tok').value=j.token;return false;}
        async function who(){const r=await fetch('/api/whoami',{headers:{authorization:'Bearer '+document.getElementById('tok').value}});document.getElementById('out').textContent=JSON.stringify(await r.json(),null,2);}
        async function flag(){const r=await fetch('/flag/jwt',{headers:{authorization:'Bearer '+document.getElementById('tok').value}});document.getElementById('out').textContent=JSON.stringify(await r.json(),null,2);}
      </script>`);

    app.get('/', (req, res) => { res.type('html').send(landing()); });

    /* base registers a fallback GET / before setup() runs and express dispatches
       in registration order — move this lab's themed landing to the front. */
    const stack = app.stack;
    const layer = stack[stack.length - 1];
    if (layer && layer.route && layer.route.path === '/') { stack.pop(); stack.unshift(layer); }
  },
};
