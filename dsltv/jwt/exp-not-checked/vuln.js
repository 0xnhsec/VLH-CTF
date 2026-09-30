'use strict';
/*
 * DSLTV JWT/ExpNotChecked — "ChronoAuth" (identity-gated, state variant).
 * Bug: the verifier ignores token expiration (ignoreExpiration). Logout only
 * clears the client cookie — JWTs are stateless and are never revoked, so an
 * expired token minted 30 days ago by the legacy "migration script" (which
 * issued role=admin) still authenticates. The security audit log at
 * /leaked-tokens retained the innocent user's pre-migration token after their
 * logout. Replay it at GET /flag/jwt.
 */
module.exports = {
  meta: {
    category: 'JWT',
    subName: 'ExpNotChecked',
    archetype: 'identity-gated',
    difficulty: 'medium',
    description: 'ChronoAuth: expired tokens never die — the verifier ignores exp and logout revokes nothing; replay the leaked pre-migration token.',
    flags: [{ category: 'JWT', subName: 'ExpNotChecked', archetype: 'identity-gated' }],
  },
  async setup(ctx) {
    const { app, render, esc, users, flags, jwt, state } = ctx;
    const crypto = ctx.crypto;

    const SECRET = ctx.randHex(32);
    const MIGRATION_TS = Math.floor(Date.now() / 1000) - 30 * 86400; // migration finished 30 days ago

    const b64u = (o) => Buffer.from(JSON.stringify(o)).toString('base64url');
    const dec = (s) => { try { return JSON.parse(Buffer.from(String(s), 'base64url').toString('utf8')); } catch (_) { return null; } };
    const bearer = (req) => { const m = /^Bearer\s+(.+)$/i.exec(String(req.headers.authorization || '')); return m ? m[1] : null; };
    const hsSign = (header, payload, secret) => {
      const h = b64u(header), p = b64u(payload);
      const s = crypto.createHmac('sha256', secret).update(`${h}.${p}`).digest('base64url');
      return `${h}.${p}.${s}`;
    };

    /* the token the audit log retained: minted by the legacy migration script
       (pre-migration tokens carried role=admin), expired 30 days ago, "logged
       out" since — but logout only cleared the victim's cookie. */
    const innocent = users.innocent();
    const legacyToken = hsSign(
      { alg: 'HS256', typ: 'JWT', kid: 'pre-migration' },
      { sub: innocent.username, role: 'admin', iat: MIGRATION_TS - 86400, exp: MIGRATION_TS - 3600, iss: 'migration-script' },
      SECRET);
    state.set('audit_legacy_token', { user: innocent.username, token: legacyToken, event: 'logout', ts: ctx.nowIso() });

    app.post('/login', (req, res) => {
      const { username, password } = req.body || {};
      const user = users.verify(username, password);
      if (!user) return res.status(401).json({ error: 'invalid credentials' });
      const token = jwt.sign({ sub: user.username, role: user.role }, SECRET, { algorithm: 'HS256', expiresIn: '1h' });
      res.json({ ok: true, token, sub: user.username, role: user.role,
        hint: 'gated endpoint: GET /flag/jwt — it opens for one specific sub+role pair' });
    });

    /* logout flaw: cookie-only. Stateless JWTs are never revoked server-side. */
    app.post('/logout', (req, res) => {
      res.setHeader('Set-Cookie', 'sid=; Path=/; Max-Age=0');
      res.json({ ok: true, note: 'client cookie cleared — JWTs are stateless; issued tokens are not revoked' });
    });

    /* the legit leak: the security audit log retained the logged-out token */
    app.get('/leaked-tokens', (req, res) => {
      res.type('html').send(render('ChronoAuth — security audit log', `
        <h1>⏱ Security audit log</h1>
        <p class="muted">retention: 90 days · token events are kept for incident review</p>
        <div class="card"><table>
          <tr><th>time</th><th>user</th><th>event</th><th>token</th></tr>
          <tr>
            <td>${esc(new Date((MIGRATION_TS - 3600) * 1000).toISOString())}</td>
            <td>${esc(innocent.username)}</td>
            <td>logout — cookie cleared client-side; token NOT revoked (stateless JWT)</td>
            <td><code style="word-break:break-all">${esc(legacyToken)}</code></td>
          </tr>
        </table></div>
        <div class="card"><p class="muted">note: tokens minted by the pre-migration script carried
        <code>role=admin</code> (legacy claim mapping). The migration completed
        ${esc(new Date(MIGRATION_TS * 1000).toISOString().slice(0, 10))}.</p></div>`));
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

    /* THE BUG: ignoreExpiration — expired tokens still verify. */
    const verifyToken = (token) => {
      try {
        return { ok: true, payload: jwt.verify(token, SECRET, { algorithms: ['HS256'], ignoreExpiration: true }) };
      } catch (e) { return { ok: false, error: e.message }; }
    };

    /* identity gate (+ state variant): the replayed token must pre-date the
       migration — fresh forges (if you ever had the secret) would not. */
    app.get('/flag/jwt', (req, res) => {
      const token = bearer(req);
      if (!token) return res.status(401).json({ error: 'Authorization: Bearer <token> required' });
      const v = verifyToken(token);
      if (!v.ok) return res.status(401).json({ error: `verification failed: ${v.error}` });
      const p = v.payload || {};
      const innocentUser = users.innocent();
      if (p.sub === innocentUser.username && p.role === 'admin'
          && typeof p.iat === 'number' && p.iat < MIGRATION_TS) {
        return res.json({ ok: true, flag: flags.held('JWT', 'ExpNotChecked'), replay: true });
      }
      return res.status(403).json({ error: 'claims rejected — the gate needs the pre-migration sub+role pair (replayed)', got: { sub: p.sub, role: p.role, iat: p.iat } });
    });

    const landing = () => render('ChronoAuth', `
      <h1>⏱ ChronoAuth</h1>
      <p class="muted">JWT portal · "tokens are stateless — logout is a client concern"</p>
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
      <p class="muted">audit log: <a href="/leaked-tokens">/leaked-tokens</a> · directory: <a href="/api/directory">/api/directory</a></p>
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
