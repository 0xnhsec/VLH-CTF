'use strict';
/*
 * DSLTV IDOR — NumericId · theme "Notekeep — quick notes". Resource-resident.
 * Flaw: GET /api/notes/{id} (and the /notes/{id} view page) require a login
 * but never compare the note's owner with the session user — sequential
 * integer ids let any authenticated user walk the whole table. The innocent
 * user's seeded note contains the flag.
 */
module.exports = {
  meta: {
    category: 'IDOR', subName: 'NumericId', archetype: 'resource-resident', difficulty: 'low',
    description: 'Notekeep serves notes by sequential integer id with no ownership check — the innocent\'s private note holds the flag.',
    flags: [{ category: 'IDOR', subName: 'NumericId', archetype: 'resource-resident' }],
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

    /* --- seed: testers' notes, the innocent's flag note, an admin decoy ------ */
    ctx.db.exec('DELETE FROM notes'); /* notes are seed-owned — wipe + reseed so restarts never duplicate or keep stale flags */
    const ins = ctx.db.prepare('INSERT INTO notes (owner_id, title, body, created_at) VALUES (?,?,?,?)');
    const t1 = ctx.users.byUsername('0xnhsec');
    const t2 = ctx.users.byUsername('Noshiro');
    const innocent = ctx.users.innocent();
    const admin = ctx.users.admin();
    const flag = ctx.flags.held('IDOR', 'NumericId');
    const now = ctx.nowIso();
    ins.run(t1.id, 'grocery list', 'oat milk, rye bread, coffee beans', now);
    ins.run(t1.id, 'gym plan', 'mon: legs · wed: pull · fri: run 5k', now);
    ins.run(t2.id, 'trip ideas', 'kyoto in autumn; lisbon in spring', now);
    ins.run(t2.id, 'wifi password', 'hunter2 — rotate monthly', now);
    ins.run(innocent.id, 'private — do not share', flag, now); /* ← the flag note (id 5) */
    ins.run(admin.id, 'ops runbook', 'restart order: cache → queue → sidecar', now);

    const noteById = (id) => ctx.db.prepare('SELECT * FROM notes WHERE id = ?').get(Number(id));
    const ownNotes = (uid) => ctx.db.prepare('SELECT id, title, created_at FROM notes WHERE owner_id = ? ORDER BY id').all(uid);

    /* --- the vulnerable endpoint (auth yes, ownership no) ------------------- */
    ctx.app.get('/api/notes/:id', (req, res) => {
      const auth = ctx.session.get(req);
      if (!auth) return res.status(401).json({ error: 'login required' });
      const n = noteById(req.params.id);
      if (!n) return res.status(404).json({ error: 'no such note' });
      res.json({ id: n.id, owner_id: n.owner_id, title: n.title, body: n.body, created_at: n.created_at }); /* ← no ownership check */
    });

    ctx.app.get('/notes/:id', (req, res) => {
      const auth = ctx.session.get(req);
      if (!auth) return res.redirect('/');
      const n = noteById(req.params.id);
      if (!n) return res.status(404).type('html').send(ctx.render('Notekeep', '<h1>Notekeep</h1><div class="card">No such note. <a href="/">back</a></div>'));
      res.type('html').send(ctx.render('Note ' + n.id, `
        <h1>${esc(n.title)}</h1>
        <div class="card"><pre>${esc(n.body)}</pre>
        <p class="muted">note #${n.id} · owner_id ${n.owner_id}</p></div>
        <p><a href="/">← all notes</a></p>`, { tagline: 'notes — Notekeep' }));
    });

    /* --- themed UI --------------------------------------------------------- */
    ctx.app.get('/', (req, res) => {
      const auth = ctx.session.get(req);
      if (!auth) {
        return res.type('html').send(ctx.render('Notekeep', `
          <h1>Notekeep — quick notes</h1>
          <div class="card">
            <p>Keep lists, plans and private snippets. Notes get short numeric ids.</p>
            <form method="post" action="/login">
              <p><input name="username" placeholder="username" autocomplete="off" required>
                 <input name="password" type="password" placeholder="password" required>
                 <button>sign in</button></p>
            </form>
            <p class="muted">Player accounts are documented in the player guide (0xnhsec / Noshiro).</p>
          </div>`, { tagline: 'notes — Notekeep' }));
      }
      res.type('html').send(ctx.render('Notekeep', `
        <h1>Notekeep — ${esc(auth.user.username)}</h1>
        <div class="card">
          <h2>your notes</h2>
          <table><tr><th>id</th><th>title</th><th>created</th><th>open</th></tr>
          ${ownNotes(auth.user.id).map((n) => `<tr><td>${n.id}</td><td>${esc(n.title)}</td><td>${esc(n.created_at)}</td><td><a href="/notes/${n.id}">view</a> · <a href="/api/notes/${n.id}">json</a></td></tr>`).join('') || '<tr><td colspan="4" class="muted">no notes yet</td></tr>'}
          </table>
        </div>
        <div class="card">
          <h2>open a note by id</h2>
          <form method="get" action="/notes/1" onsubmit="this.action='/notes/'+this.elements['id'].value;return true;">
            <p><input name="id" placeholder="note id" size="6" required> <button>open</button></p>
          </form>
          <p class="muted">Every note has a short numeric id — handy for sharing… or not.</p>
        </div>
        <form method="post" action="/logout"><button>sign out</button></form>`, { tagline: 'notes — Notekeep' }));
    });

    ctx.app.post('/login', (req, res) => {
      const u = ctx.users.verify(req.body && req.body.username, req.body && req.body.password);
      if (!u) return res.status(401).type('html').send(ctx.render('Notekeep', '<h1>Notekeep</h1><div class="card">Wrong credentials. <a href="/">back</a></div>'));
      ctx.login(res, u);
      res.redirect('/');
    });
    ctx.app.post('/logout', (req, res) => { ctx.logout(req, res); res.redirect('/'); });
  },
};
