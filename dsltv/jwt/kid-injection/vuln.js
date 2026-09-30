'use strict';
/*
 * DSLTV JWT/KidInjection — "KeyVault".
 * Bug: the verifier resolves the HMAC secret by interpolating the token
 * header's `kid` into a raw SQL string:
 *     SELECT key FROM signing_keys WHERE kid = '<header.kid>'
 * String concatenation → SQL injection. Return a secret you choose and the
 * HS256 verification runs with YOUR key.
 */
module.exports = {
  meta: {
    category: 'JWT',
    subName: 'KidInjection',
    archetype: 'identity-gated',
    difficulty: 'high',
    description: 'KeyVault JWTs: the kid lookup concatenates the header claim into SQL — inject your own signing secret.',
    flags: [{ category: 'JWT', subName: 'KidInjection', archetype: 'identity-gated' }],
  },
  async setup(ctx) {
    const { app, render, esc, users, flags, jwt, db } = ctx;
    const crypto = ctx.crypto;

    db.exec(`CREATE TABLE IF NOT EXISTS signing_keys (
      kid TEXT PRIMARY KEY, key TEXT NOT NULL
    )`);
    const SERVER_KID = 'legacy-2023';
    const SERVER_KEY = ctx.randHex(32); // per-boot HMAC secret for legit tokens
    const ins = db.prepare('INSERT OR REPLACE INTO signing_keys (kid, key) VALUES (?,?)');
    ins.run(SERVER_KID, SERVER_KEY);
    ins.run('migration-2024', ctx.randHex(32));

    const b64u = (o) => Buffer.from(JSON.stringify(o)).toString('base64url');
    const dec = (s) => { try { return JSON.parse(Buffer.from(String(s), 'base64url').toString('utf8')); } catch (_) { return null; } };
    const bearer = (req) => { const m = /^Bearer\s+(.+)$/i.exec(String(req.headers.authorization || '')); return m ? m[1] : null; };
    const hsSign = (header, payload, secret) => {
      const h = b64u(header), p = b64u(payload);
      const s = crypto.createHmac('sha256', secret).update(`${h}.${p}`).digest('base64url');
      return `${h}.${p}.${s}`;
    };

    app.post('/login', (req, res) => {
      const { username, password } = req.body || {};
      const user = users.verify(username, password);
      if (!user) return res.status(401).json({ error: 'invalid credentials' });
      const token = hsSign({ alg: 'HS256', typ: 'JWT', kid: SERVER_KID },
        { sub: user.username, role: user.role, iat: Math.floor(Date.now() / 1000) }, SERVER_KEY);
      res.json({ ok: true, token, sub: user.username, role: user.role, alg: 'HS256', kid: SERVER_KID,
        hint: 'gated endpoint: GET /flag/jwt — it opens for one specific sub+role pair' });
    });

    /* flavor/debug: which key ids exist (never the keys themselves) */
    app.get('/api/keys', (req, res) => {
      res.json({ kids: db.prepare('SELECT kid FROM signing_keys ORDER BY kid').all().map((r) => r.kid) });
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

    /* THE BUG: kid concatenated into SQL — inject a known key of your choice. */
    const verifyToken = (token) => {
      const parts = String(token).split('.');
      if (parts.length !== 3) return { ok: false, error: 'malformed token' };
      const header = dec(parts[0]);
      if (!header || !header.alg) return { ok: false, error: 'missing alg' };
      if (String(header.alg).toUpperCase() !== 'HS256') return { ok: false, error: `unsupported alg ${header.alg}` };
      let row;
      try {
        row = db.prepare(`SELECT key FROM signing_keys WHERE kid = '${String(header.kid == null ? '' : header.kid)}'`).get();
      } catch (e) { return { ok: false, error: `key lookup failed: ${e.message}` }; }
      if (!row) return { ok: false, error: 'unknown kid' };
      try {
        return { ok: true, payload: jwt.verify(token, row.key, { algorithms: ['HS256'] }) };
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
        return res.json({ ok: true, flag: flags.held('JWT', 'KidInjection') });
      }
      return res.status(403).json({ error: 'claims rejected — the gate needs one specific sub+role pair', got: { sub: p.sub, role: p.role } });
    });

    const landing = () => render('KeyVault', `
      <h1>🗄 KeyVault</h1>
      <p class="muted">JWT portal · HS256 · rotating signing keys resolved by kid</p>
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
      <p class="muted">active key ids: <a href="/api/keys">/api/keys</a> · directory: <a href="/api/directory">/api/directory</a></p>
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
