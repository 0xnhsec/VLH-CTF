'use strict';
/*
 * DSLTV http/host-routing-bypass — HostRoutingBypass (location-locked, medium).
 * "Edge Node Console" — the victim app also serves an internal admin console
 * that is only meant to exist on the internal vhost admin-internal.target.lab.
 * That host is NOT routed to the app by the lab's edge (it falls into the
 * catch-all *.target.lab → attacker space), so the console is unroutable.
 * Flaw: the app decides "am I serving the internal vhost" from the effective
 * host — trusting X-Forwarded-Host when present. Sending a request to the
 * victim vhost with X-Forwarded-Host: admin-internal.target.lab activates the
 * admin routes. /admin/panel returns the flag (the location is the lock).
 */
module.exports = {
  meta: {
    category: 'HTTP', subName: 'HostRoutingBypass', archetype: 'location-locked', difficulty: 'medium',
    description: 'Edge Node Console — the internal admin vhost is unroutable, but the app trusts X-Forwarded-Host to decide which vhost it is serving. Entry: http://victim.target.lab:8119/home',
    flags: [{ category: 'HTTP', subName: 'HostRoutingBypass', archetype: 'location-locked' }],
  },
  async setup(ctx) {
    const esc = ctx.esc;
    const render = ctx.render;
    const ADMIN_PREFIX = 'admin-internal.';

    /* THE FLAW: effective host honors X-Forwarded-Host first ("we sit behind our edge proxy"). */
    const effectiveHost = (req) => {
      const xfh = req.headers['x-forwarded-host'];
      const raw = (Array.isArray(xfh) ? xfh[0] : xfh) || req.headers.host || '';
      return String(raw).split(':')[0].toLowerCase();
    };
    const isAdminVhost = (req) => effectiveHost(req).startsWith(ADMIN_PREFIX);

    ctx.app.get('/home', (req, res) => {
      res.type('html').send(render('Edge node', `
        <h1>Edge Node Console — public status</h1>
        <div class="card">
          <table>
            <tr><th>node</th><td>edge-07</td></tr>
            <tr><th>region</th><td>eu-central</td></tr>
            <tr><th>effective host</th><td><code>${esc(effectiveHost(req))}</code></td></tr>
            <tr><th>internal admin</th><td><code>admin-internal.${esc(ctx.labDomain)}</code> <span class="muted">(internal-only vhost — not routed through the public edge)</span></td></tr>
          </table>
        </div>
        <p class="muted">Operators: the admin console is served by this same app but only on the internal vhost.
        The app runs behind the edge proxy, which forwards the original host in
        <code>X-Forwarded-Host</code>.</p>`));
    });

    /* admin console — only mounted when the effective host says internal vhost */
    ctx.app.use('/admin', (req, res, next) => {
      if (!isAdminVhost(req)) {
        return res.status(404).type('html').send(render('404', `
          <p>No admin console on the public vhost. (Hint: the app believes <code>X-Forwarded-Host</code>.)</p>`));
      }
      next();
    });
    ctx.app.get('/admin', (req, res) => {
      res.type('html').send(render('Admin console', `
        <h1>Edge Node Console — admin</h1>
        <p>Internal admin console active (effective host <code>${esc(effectiveHost(req))}</code>).</p>
        <p><a href="/admin/panel">/admin/panel</a></p>`));
    });
    ctx.app.get('/admin/panel', (req, res) => {
      if (!isAdminVhost(req)) return res.status(404).json({ error: 'admin vhost required' });
      res.json({ flag: ctx.flags.held('HTTP', 'HostRoutingBypass'), panel: 'edge-07 control', effective_host: effectiveHost(req) });
    });
  },
};
