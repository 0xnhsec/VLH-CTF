'use strict';
const http = require('http');

/*
 * DSLTV JWT/JkuBypass — "Federate".
 * Bug: the verifier reads the token header's `jku` claim and fetches THAT
 * URL's JWKS to find the signing key — with no allowlist. Point jku at a
 * key set you control (the exploit server's page store works fine), embed
 * your own public JWK there, and RS256-sign tokens with your private key.
 */
module.exports = {
  meta: {
    category: 'JWT',
    subName: 'JkuBypass',
    archetype: 'identity-gated',
    difficulty: 'high',
    description: 'Federate gateway: the verifier fetches the header-supplied jku URL with no allowlist — host your own JWKS and sign your own tokens.',
    flags: [{ category: 'JWT', subName: 'JkuBypass', archetype: 'identity-gated' }],
  },
  async setup(ctx) {
    const { app, render, esc, users, flags } = ctx;
    const crypto = ctx.crypto;

    const { publicKey, privateKey } = crypto.generateKeyPairSync('rsa', { modulusLength: 2048 });
    const jwk = publicKey.export({ format: 'jwk' });
    const KID = 'fed-' + ctx.randHex(4);
    const JWKS_URL = `${ctx.urls.victim}/jwks.json`;

    const b64u = (o) => Buffer.from(JSON.stringify(o)).toString('base64url');
    const dec = (s) => { try { return JSON.parse(Buffer.from(String(s), 'base64url').toString('utf8')); } catch (_) { return null; } };
    const bearer = (req) => { const m = /^Bearer\s+(.+)$/i.exec(String(req.headers.authorization || '')); return m ? m[1] : null; };
    const rsSign = (header, payload, key) => {
      const h = b64u(header), p = b64u(payload);
      const s = crypto.createSign('RSA-SHA256').update(`${h}.${p}`).sign(key, 'base64url');
      return `${h}.${p}.${s}`;
    };

    /* internal fetch (the flaw is the missing allowlist, not the transport):
       *.target.lab hosts resolve to this container via the sidecar — rewrite
       them to loopback, keeping the Host header so vhost routing still works. */
    const fetchText = (urlStr, timeoutMs) => new Promise((resolve, reject) => {
      let u;
      try { u = new URL(String(urlStr)); } catch (_) { return reject(new Error('bad jku url')); }
      const opts = { method: 'GET', headers: {} };
      if (u.hostname.endsWith('.' + ctx.labDomain)) {
        opts.host = '127.0.0.1'; opts.port = ctx.listenPort;
        opts.path = u.pathname + u.search;
        opts.headers.host = `${u.hostname}:${u.port || 8119}`;
      } else {
        opts.host = u.hostname; opts.port = u.port || 80;
        opts.path = u.pathname + u.search;
      }
      const req = http.request(opts, (res) => {
        let data = ''; let n = 0;
        res.on('data', (c) => { n += c.length; if (n <= 16384) data += c; });
        res.on('end', () => resolve(data));
      });
      req.setTimeout(timeoutMs || 3000, () => req.destroy(new Error('jku fetch timeout')));
      req.on('error', reject);
      req.end();
    });

    app.post('/login', (req, res) => {
      const { username, password } = req.body || {};
      const user = users.verify(username, password);
      if (!user) return res.status(401).json({ error: 'invalid credentials' });
      const token = rsSign(
        { alg: 'RS256', typ: 'JWT', kid: KID, jku: JWKS_URL },
        { sub: user.username, role: user.role, iat: Math.floor(Date.now() / 1000) },
        privateKey);
      res.json({ ok: true, token, sub: user.username, role: user.role, alg: 'RS256', kid: KID,
        hint: 'gated endpoint: GET /flag/jwt — it opens for one specific sub+role pair' });
    });

    /* the platform's own key set (legit endpoint) */
    app.get('/jwks.json', (req, res) => res.json({
      keys: [{ kty: jwk.kty, n: jwk.n, e: jwk.e, kid: KID, use: 'sig', alg: 'RS256' }],
    }));

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

    /* THE BUG: header.jku is fetched verbatim — no allowlist, no pinning. */
    const verifyToken = async (token) => {
      const parts = String(token).split('.');
      if (parts.length !== 3) return { ok: false, error: 'malformed token' };
      const header = dec(parts[0]);
      if (!header || !header.alg) return { ok: false, error: 'missing alg' };
      if (String(header.alg).toUpperCase() !== 'RS256') return { ok: false, error: `unsupported alg ${header.alg}` };
      const jku = header.jku || JWKS_URL;
      let jwks;
      try { jwks = JSON.parse(await fetchText(jku)); } catch (e) { return { ok: false, error: `jku fetch failed: ${e.message}` }; }
      const key = (jwks.keys || []).find((k) => !header.kid || k.kid === header.kid);
      if (!key) return { ok: false, error: 'no matching key in key set' };
      let pub;
      try { pub = crypto.createPublicKey({ key, format: 'jwk' }); } catch (e) { return { ok: false, error: `bad jwk: ${e.message}` }; }
      const ok = crypto.createVerify('RSA-SHA256').update(`${parts[0]}.${parts[1]}`)
        .verify(pub, Buffer.from(parts[2], 'base64url'));
      return ok ? { ok: true, payload: dec(parts[1]) } : { ok: false, error: 'signature mismatch' };
    };

    app.get('/flag/jwt', async (req, res) => {
      try {
        const token = bearer(req);
        if (!token) return res.status(401).json({ error: 'Authorization: Bearer <token> required' });
        const v = await verifyToken(token);
        if (!v.ok) return res.status(401).json({ error: `verification failed: ${v.error}` });
        const p = v.payload || {};
        const innocent = users.innocent();
        if (p.sub === innocent.username && p.role === 'admin') {
          return res.json({ ok: true, flag: flags.held('JWT', 'JkuBypass') });
        }
        return res.status(403).json({ error: 'claims rejected — the gate needs one specific sub+role pair', got: { sub: p.sub, role: p.role } });
      } catch (e) {
        return res.status(500).json({ error: String(e && e.message ? e.message : e) });
      }
    });

    const landing = () => render('Federate', `
      <h1>🌐 Federate</h1>
      <p class="muted">federated JWT gateway · tokens carry a jku (key-set URL) header claim</p>
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
      <p class="muted">platform key set: <a href="/jwks.json">/jwks.json</a> · directory: <a href="/api/directory">/api/directory</a> · exploit server: <a href="${ctx.urls.attacker}/">attacker.target.lab</a></p>
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
