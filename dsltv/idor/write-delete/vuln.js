'use strict';
/*
 * DSLTV IDOR — WriteDelete · theme "Scrappad — collaborative scratchpad". Resource-resident.
 * Flaw: the READ path learned its lesson — GET /api/notes/{id} enforces
 * ownership — but the WRITE paths did not: PATCH and DELETE on
 * /api/notes/{id} were mounted without the ownership middleware. PATCH
 * returns the updated object INCLUDING the untouched body, so patching the
 * innocent's note (e.g. title only) leaks its body — the flag.
 */
module.exports = {
  meta: {
    category: 'IDOR', subName: 'WriteDelete', archetype: 'resource-resident', difficulty: 'medium',
    description: 'Scrappad checks ownership on GET but not on PATCH/DELETE — patching the innocent\'s note echoes its body, which holds the flag.',
    flags: [{ category: 'IDOR', subName: 'WriteDelete', archetype: 'resource-resident' }],
  },
  async setup(ctx) {
    const esc = ctx.esc;
    ctx.db.exec(`
      CREATE TABLE IF NOT EXISTS notes (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        owner_id INTEGER NOT NULL,
        title TEXT NOT NULL,
        body TEXT NOT NULL,
        created_at TEXT NOT NULL
      )`);

    ctx.db.exec('DELETE FROM notes'); /* notes are seed-owned — wipe + reseed so restarts never duplicate or keep stale flags */
    const ins = ctx.db.prepare('INSERT INTO notes (owner_id, title, body, created_at) VALUES (?,?,?,?)');
    const t1 = ctx.users.byUsername('0xnhsec');
    const t2 = ctx.users.byUsername('Noshiro');
    const innocent = ctx.users.innocent();
    const flag = ctx.flags.held('IDOR', 'WriteDelete');
    const now = ctx.nowIso();
    ins.run(t1.id, 'standup notes', 'monday: ship the cache purge; wednesday: retro', now);
    ins.run(t1.id, 'book quotes', '"The fastest route is often the one nobody guards."', now);
    ins.run(t2.id, 'recipe draft', 'sourdough: 500g flour, 350g water, 100g starter', now);
    ins.run(t2.id, 'parking spot', 'level 3, bay 41', now);
    ins.run(innocent.id, 'my secret stash', flag, now); /* ← the flag note (id 5) */

    const noteById = (id) => ctx.db.prepare('SELECT * FROM notes WHERE id = ?').get(Number(id));
    const ownNotes = (uid) => ctx.db.prepare('SELECT id, title, created_at FROM notes WHERE owner_id = ? ORDER BY id').all(uid);

    /* --- READ path: ownership enforced (the "fixed" part) ------------------- */
    ctx.app.get('/api/notes/:id', (req, res) => {
      const auth = ctx.session.get(req);
      if (!auth) return res.status(401).json({ error: 'login required' });
      const n = noteById(req.params.id);
      if (!n) return res.status(404).json({ error: 'no such note' });
      if (n.owner_id !== auth.user.id) return res.status(403).json({ error: 'not your note' }); /* the check exists… */
      res.json({ id: n.id, owner_id: n.owner_id, title: n.title, body: n.body, created_at: n.created_at });
    });

    /* --- WRITE paths: no ownership check (the flaw) ------------------------- */
    ctx.app.patch('/api/notes/:id', (req, res) => {
      const auth = ctx.session.get(req);
      if (!auth) return res.status(401).json({ error: 'login required' });
      const n = noteById(req.params.id);
      if (!n) return res.status(404).json({ error: 'no such note' });
      const title = (req.body && req.body.title !== undefined) ? String(req.body.title) : n.title;
      const body = (req.body && req.body.body !== undefined) ? String(req.body.body) : n.body;
      ctx.db.prepare('UPDATE notes SET title = ?, body = ? WHERE id = ?').run(title, body, n.id);
      const upd = noteById(n.id);
      res.json({ id: upd.id, owner_id: upd.owner_id, title: upd.title, body: upd.body, created_at: upd.created_at }); /* ← echoes the body */
    });

    ctx.app.delete('/api/notes/:id', (req, res) => {
      const auth = ctx.session.get(req);
      if (!auth) return res.status(401).json({ error: 'login required' });
      const n = noteById(req.params.id);
      if (!n) return res.status(404).json({ error: 'no such note' });
      ctx.db.prepare('DELETE FROM notes WHERE id = ?').run(n.id);
      res.json({ deleted: true, id: n.id }); /* destructive write also unguarded — but the PATCH leak is the win */
    });

    /* --- themed UI --------------------------------------------------------- */
    ctx.app.get('/', (req, res) => {
      const auth = ctx.session.get(req);
      if (!auth) {
        return res.type('html').send(ctx.render('Scrappad', `
          <h1>Scrappad — collaborative scratchpad</h1>
          <div class="card">
            <p>Draft, edit, toss. Reading other people\'s pads is blocked — editing is where the magic happens.</p>
            <form method="post" action="/login">
              <p><input name="username" placeholder="username" autocomplete="off" required>
                 <input name="password" type="password" placeholder="password" required>
                 <button>sign in</button></p>
            </form>
            <p class="muted">Player accounts are documented in the player guide (0xnhsec / Noshiro).</p>
          </div>`, { tagline: 'scratchpad — Scrappad' }));
      }
      res.type('html').send(ctx.render('Scrappad', `
        <h1>Scrappad — ${esc(auth.user.username)}</h1>
        <div class="card">
          <h2>your pads</h2>
          <table><tr><th>id</th><th>title</th><th>created</th></tr>
          ${ownNotes(auth.user.id).map((n) => `<tr><td>${n.id}</td><td>${esc(n.title)}</td><td>${esc(n.created_at)}</td></tr>`).join('') || '<tr><td colspan="3" class="muted">no pads yet</td></tr>'}
          </table>
          <p class="muted">Reads are strictly owner-only (SEC-40). Edits go through <code>PATCH /api/notes/{id}</code>; deletes through <code>DELETE /api/notes/{id}</code>.</p>
        </div>
        <div class="card">
          <h2>edit a pad (yours)</h2>
          <form onsubmit="return false">
            <p><input id="nid" placeholder="note id" size="6">
               <input id="ntitle" placeholder="new title">
               <button id="patchbtn">PATCH</button>
               <button id="delbtn" type="button">DELETE</button></p>
          </form>
          <pre id="out" class="muted"></pre>
        </div>
        <script>
          var out = document.getElementById('out');
          document.getElementById('patchbtn').addEventListener('click', function () {
            fetch('/api/notes/' + document.getElementById('nid').value, { method: 'PATCH', credentials: 'same-origin', headers: {'Content-Type': 'application/json'}, body: JSON.stringify({ title: document.getElementById('ntitle').value }) })
              .then(function (r) { return r.json(); }).then(function (j) { out.textContent = JSON.stringify(j, null, 2); });
          });
          document.getElementById('delbtn').addEventListener('click', function () {
            fetch('/api/notes/' + document.getElementById('nid').value, { method: 'DELETE', credentials: 'same-origin' })
              .then(function (r) { return r.json(); }).then(function (j) { out.textContent = JSON.stringify(j, null, 2); });
          });
        </script>
        <form method="post" action="/logout"><button>sign out</button></form>`, { tagline: 'scratchpad — Scrappad' }));
    });

    ctx.app.post('/login', (req, res) => {
      const u = ctx.users.verify(req.body && req.body.username, req.body && req.body.password);
      if (!u) return res.status(401).type('html').send(ctx.render('Scrappad', '<h1>Scrappad</h1><div class="card">Wrong credentials. <a href="/">back</a></div>'));
      ctx.login(res, u);
      res.redirect('/');
    });
    ctx.app.post('/logout', (req, res) => { ctx.logout(req, res); res.redirect('/'); });
  },
};
