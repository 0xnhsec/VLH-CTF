'use strict';
/*
 * DSLTV IDOR — FilePath · theme "Docvault — document locker". Resource-resident.
 * Flaw: documents are fetched by FILE PATH — GET /files?path=notes/<name>.txt
 * — and the handler never maps the requested file to the requesting user's
 * ownership (the workspace catalog openly lists every document's path).
 * Path traversal is blocked (resolved paths must stay inside the vault) —
 * this is an ownership-bypass IDOR, not a traversal bug. The innocent's
 * seeded file contains the flag.
 */
module.exports = {
  meta: {
    category: 'IDOR', subName: 'FilePath', archetype: 'resource-resident', difficulty: 'medium',
    description: 'Docvault serves documents by file path with no ownership mapping — the innocent\'s private file holds the flag.',
    flags: [{ category: 'IDOR', subName: 'FilePath', archetype: 'resource-resident' }],
  },
  async setup(ctx) {
    const esc = ctx.esc;
    const fs = require('fs');
    const path = require('path');
    const DATA_DIR = process.env.DATA_DIR || '/data';
    const VAULT = path.join(DATA_DIR, 'vault');

    ctx.db.exec(`
      CREATE TABLE IF NOT EXISTS documents (
        path TEXT PRIMARY KEY,
        owner_id INTEGER,
        title TEXT NOT NULL
      )`);

    const t1 = ctx.users.byUsername('0xnhsec');
    const t2 = ctx.users.byUsername('Noshiro');
    const innocent = ctx.users.innocent();
    const flag = ctx.flags.held('IDOR', 'FilePath');

    /* --- seed the vault (files on disk + catalog rows) ---------------------- */
    const docs = [
      { rel: 'notes/welcome.txt', owner: null, title: 'Welcome to Docvault', body: 'Docvault: one locker for every team document.\nFiles are addressed by path, e.g. /files?path=notes/welcome.txt' },
      { rel: 'notes/0xnhsec-scratchpad.txt', owner: t1.id, title: 'Scratchpad', body: 'todo: renew domain; call plumber; buy stamps' },
      { rel: 'notes/0xnhsec-expenses.txt', owner: t1.id, title: 'Expenses draft', body: 'coffee 4.20; train 12.00; book 19.99' },
      { rel: 'notes/noshiro-scratchpad.txt', owner: t2.id, title: 'Scratchpad', body: 'ideas: kettlebell timer app; paper photo scanner' },
      { rel: `notes/${innocent.username}-private.txt`, owner: innocent.id, title: 'Private — do not share', body: `Docvault private note.\n${flag}\nKeep this file to yourself.` }, /* ← the flag file */
    ];
    fs.mkdirSync(path.join(VAULT, 'notes'), { recursive: true });
    const insDoc = ctx.db.prepare('INSERT OR REPLACE INTO documents (path, owner_id, title) VALUES (?,?,?)');
    for (const d of docs) {
      fs.writeFileSync(path.join(VAULT, d.rel), d.body);
      insDoc.run(d.rel, d.owner, d.title);
    }
    const catalog = () => ctx.db.prepare('SELECT d.path, d.title, u.username AS owner FROM documents d LEFT JOIN users u ON u.id = d.owner_id ORDER BY d.path').all();
    const ownerFiles = (uid) => ctx.db.prepare('SELECT path, title FROM documents WHERE owner_id = ? ORDER BY path').all(uid);

    /* --- the vulnerable fetch (path is the only reference; no ownership) ---- */
    ctx.app.get('/files', (req, res) => {
      const auth = ctx.session.get(req);
      if (!auth) return res.status(401).json({ error: 'login required' });
      const rel = String(req.query.path || '');
      const full = path.resolve(VAULT, rel);
      if (full !== VAULT && !full.startsWith(VAULT + path.sep)) {
        return res.status(400).json({ error: 'path escapes the vault' }); /* traversal blocked — this lab is about ownership */
      }
      let content;
      try { content = fs.readFileSync(full, 'utf8'); } catch (_) { return res.status(404).json({ error: 'no such document' }); }
      res.type('text/plain').send(content); /* ← no check that the file belongs to the session user */
    });

    /* --- themed UI --------------------------------------------------------- */
    ctx.app.get('/', (req, res) => {
      const auth = ctx.session.get(req);
      if (!auth) {
        return res.type('html').send(ctx.render('Docvault', `
          <h1>Docvault — document locker</h1>
          <div class="card">
            <p>Every team document, one locker. Files are addressed by path.</p>
            <form method="post" action="/login">
              <p><input name="username" placeholder="username" autocomplete="off" required>
                 <input name="password" type="password" placeholder="password" required>
                 <button>sign in</button></p>
            </form>
            <p class="muted">Player accounts are documented in the player guide (0xnhsec / Noshiro).</p>
          </div>`, { tagline: 'documents — Docvault' }));
      }
      res.type('html').send(ctx.render('Docvault', `
        <h1>Docvault — ${esc(auth.user.username)}</h1>
        <div class="card">
          <h2>your documents</h2>
          <table><tr><th>title</th><th>path</th><th>open</th></tr>
          ${ownerFiles(auth.user.id).map((d) => `<tr><td>${esc(d.title)}</td><td><code>${esc(d.path)}</code></td><td><a href="/files?path=${encodeURIComponent(d.path)}">view</a></td></tr>`).join('') || '<tr><td colspan="3" class="muted">no documents</td></tr>'}
          </table>
        </div>
        <div class="card">
          <h2>fetch a document</h2>
          <form method="get" action="/files">
            <p><input name="path" placeholder="notes/…" size="40" required> <button>open</button></p>
          </form>
          <p class="muted">The workspace <a href="/catalog">catalog</a> lists every document's path. Paths resolve inside the vault only.</p>
        </div>
        <form method="post" action="/logout"><button>sign out</button></form>`, { tagline: 'documents — Docvault' }));
    });

    ctx.app.get('/catalog', (req, res) => {
      const auth = ctx.session.get(req);
      if (!auth) return res.redirect('/');
      res.type('html').send(ctx.render('Catalog', `
        <h1>Workspace catalog</h1>
        <div class="card">
          <table><tr><th>title</th><th>owner</th><th>path</th></tr>
          ${catalog().map((d) => `<tr><td>${esc(d.title)}</td><td>${esc(d.owner || '(shared)')}</td><td><code>${esc(d.path)}</code></td></tr>`).join('')}
          </table>
          <p class="muted">Catalog entries are visible workspace-wide; document access is resolved by path.</p>
        </div>
        <p><a href="/">← back</a></p>`, { tagline: 'documents — Docvault' }));
    });

    ctx.app.post('/login', (req, res) => {
      const u = ctx.users.verify(req.body && req.body.username, req.body && req.body.password);
      if (!u) return res.status(401).type('html').send(ctx.render('Docvault', '<h1>Docvault</h1><div class="card">Wrong credentials. <a href="/">back</a></div>'));
      ctx.login(res, u);
      res.redirect('/');
    });
    ctx.app.post('/logout', (req, res) => { ctx.logout(req, res); res.redirect('/'); });
  },
};
