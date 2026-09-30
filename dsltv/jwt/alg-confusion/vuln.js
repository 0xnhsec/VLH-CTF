'use strict';
/*
 * DSLTV JWT/AlgConfusion — "KeySmith".
 * Bug: the server issues RS256 tokens (keypair generated at boot, public key
 * published at /pubkey and /jwks.json), but the verifier accepts the token
 * header's alg — for HS256 it verifies the HMAC using the PUBLIC KEY PEM
 * STRING as the shared secret (classic RS256→HS256 algorithm confusion).
 */
module.exports = {
  meta: {
    category: 'JWT',
    subName: 'AlgConfusion',
    archetype: 'identity-gated',
    difficulty: 'high',
    description: 'KeySmith identity: the verifier does HS256 with the RSA public key as the HMAC secret — sign your own token with the public key.',
    flags: [{ category: 'JWT', subName: 'AlgConfusion', archetype: 'identity-gated' }],
  },
  async setup(ctx) {
    const { app, render, esc, users, flags } = ctx;
    const crypto = ctx.crypto;

    const { publicKey, privateKey } = crypto.generateKeyPairSync('rsa', { modulusLength: 2048 });
    const PUBLIC_PEM = publicKey.export({ type: 'spki', format: 'pem' });
    const jwk = publicKey.export({ format: 'jwk' });
    const KID = 'ks-' + ctx.randHex(4);

    const b64u = (o) => Buffer.from(JSON.stringify(o)).toString('base64url');
    const dec = (s) => { try { return JSON.parse(Buffer.from(String(s), 'base64url').toString('utf8')); } catch (_) { return null; } };
    const bearer = (req) => { const m = /^Bearer\s+(.+)$/i.exec(String(req.headers.authorization || '')); return m ? m[1] : null; };
    const rsSign = (header, payload, key) => {
      const h = b64u(header), p = b64u(payload);
      const s = crypto.createSign('RSA-SHA256').update(`${h}.${p}`).sign(key, 'base64url');
      return `${h}.${p}.${s}`;
    };

    app.post('/login', (req, res) => {
      const { username, password } = req.body || {};
      const user = users.verify(username, password);
      if (!user) return res.status(401).json({ error: 'invalid credentials' });
      const token = rsSign({ alg: 'RS256', typ: 'JWT', kid: KID },
        { sub: user.username, role: user.role, iat: Math.floor(Date.now() / 1000) }, privateKey);
      res.json({ ok: true, token, sub: user.username, role: user.role, alg: 'RS256', kid: KID,
        hint: 'gated endpoint: GET /flag/jwt — it opens for one specific sub+role pair' });
    });

    /* public key directory (a legit JWKS endpoint) */
    app.get('/pubkey', (req, res) => res.type('text/plain').send(PUBLIC_PEM));
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

    /* THE BUG: alg taken from the token header. On HS256 the verifier uses the
       PUBLIC KEY PEM string as the HMAC shared secret. */
    const verifyToken = (token) => {
      const parts = String(token).split('.');
      if (parts.length !== 3) return { ok: false, error: 'malformed token' };
      const header = dec(parts[0]);
      if (!header || !header.alg) return { ok: false, error: 'missing alg' };
      if (String(header.alg).toUpperCase() === 'HS256') {
        const expect = crypto.createHmac('sha256', PUBLIC_PEM).update(`${parts[0]}.${parts[1]}`).digest('base64url');
        if (expect === parts[2]) return { ok: true, payload: dec(parts[1]) };
        return { ok: false, error: 'HMAC mismatch (HS256 path)' };
      }
      if (String(header.alg).toUpperCase() === 'RS256') {
        const ok = crypto.createVerify('RSA-SHA256').update(`${parts[0]}.${parts[1]}`)
          .verify(publicKey, Buffer.from(parts[2], 'base64url'));
        return ok ? { ok: true, payload: dec(parts[1]) } : { ok: false, error: 'signature mismatch (RS256 path)' };
      }
      return { ok: false, error: `unsupported alg ${header.alg}` };
    };

    app.get('/flag/jwt', (req, res) => {
      const token = bearer(req);
      if (!token) return res.status(401).json({ error: 'Authorization: Bearer <token> required' });
      const v = verifyToken(token);
      if (!v.ok) return res.status(401).json({ error: `verification failed: ${v.error}` });
      const p = v.payload || {};
      const innocent = users.innocent();
      if (p.sub === innocent.username && p.role === 'admin') {
        return res.json({ ok: true, flag: flags.held('JWT', 'AlgConfusion') });
      }
      return res.status(403).json({ error: 'claims rejected — the gate needs one specific sub+role pair', got: { sub: p.sub, role: p.role } });
    });

    const landing = () => render('KeySmith', `
      <h1>🗝 KeySmith</h1>
      <p class="muted">identity provider · RS256 JWTs issued at POST /login</p>
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
      <p class="muted">public key: <a href="/pubkey">/pubkey (PEM)</a> · <a href="/jwks.json">/jwks.json</a> · directory: <a href="/api/directory">/api/directory</a></p>
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
