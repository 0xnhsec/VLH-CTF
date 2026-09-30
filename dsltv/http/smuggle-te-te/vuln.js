'use strict';
/*
 * DSLTV http/smuggle-te-te — SmuggleTeTe (location-locked, critical).
 * "EdgeMesh CDN" — raw-TCP edge (FRONT :8080) in front of the app origin
 * (BACKEND :8081, the base express runtime).
 *
 * Both sides are TE (chunked) parsers — the desync is a parser differential on
 * the SERIALIZED request. When re-serializing a chunked request for the origin,
 * the front's header writer has two bugs:
 *   1. it mangles the Transfer-Encoding header name with a trailing dash
 *      ("Transfer-Encoding-: chunked") — the origin's strict parser does not
 *      recognize it as Transfer-Encoding (it silently treats it as an unknown
 *      header instead of rejecting, unlike the space/xchunked obfuscations);
 *   2. it writes Content-Length from its framing record — the size of the
 *      FIRST chunk — while emitting the FULL de-chunked body.
 * The origin, seeing no recognizable TE, frames by that (too short) CL:
 * everything after the first chunk's bytes becomes the origin's next request.
 *
 * Location lock: GET /internal/flag exists on the origin, but the FRONT answers
 * 403 for every request it parses whose path starts with /internal.
 */
const net = require('net');

module.exports = {
  meta: {
    category: 'HTTP', subName: 'SmuggleTeTe', archetype: 'location-locked', difficulty: 'critical',
    description: 'EdgeMesh CDN edge — TE.TE: the edge serializer mangles Transfer-Encoding and miscomputes Content-Length, desyncing the chunked origin. /internal/flag is blocked at the edge. Entry: http://victim.target.lab:8119/home',
    flags: [{ category: 'HTTP', subName: 'SmuggleTeTe', archetype: 'location-locked' }],
  },
  async setup(ctx) {
    const render = ctx.render;

    /* ---------------- origin (backend, served on :8081 by the base runtime) ---------------- */
    ctx.app.get('/home', (req, res) => {
      res.type('html').send(render('EdgeMesh origin', `
        <h1>EdgeMesh CDN — origin status</h1>
        <div class="card"><p>origin healthy · edge proxy :8119 → edge-front → this origin</p>
        <p class="muted">Edge policy: requests to <code>/internal/*</code> are rejected at the edge with 403.</p></div>
        <p class="muted">The edge re-serializes chunked uploads before forwarding them to the origin.</p>`));
    });
    ctx.app.post('/home', (req, res) => {
      res.json({ origin: 'healthy', note: 'POST accepted at /home' });
    });
    ctx.app.get('/internal/flag', (req, res) => {
      res.json({ flag: ctx.flags.held('HTTP', 'SmuggleTeTe'), note: 'reached the origin /internal route — the edge never parsed this request' });
    });

    /* ------------------------- raw-TCP edge front (:8080) ------------------------- */
    const FRONT_PORT = 8080;
    const BACK_HOST = '127.0.0.1';
    const BACK_PORT = 8081;
    const MAX_BUF = 1024 * 1024;

    const parseHeaders = (buf) => {
      const headEnd = buf.indexOf('\r\n\r\n');
      if (headEnd < 0) return { need: true };
      const lines = buf.slice(0, headEnd).toString('latin1').split('\r\n');
      const m = /^(\S+) (\S+) (\S+)$/.exec(lines[0]);
      if (!m) return { bad: true };
      let cl, te, teValue;
      for (let i = 1; i < lines.length; i++) {
        const idx = lines[i].indexOf(':');
        if (idx < 0) return { bad: true };
        const name = lines[i].slice(0, idx).trim().toLowerCase();
        const value = lines[i].slice(idx + 1).trim();
        if (name === 'content-length' && cl === undefined) cl = parseInt(value, 10);
        if (name === 'transfer-encoding' && te === undefined) { te = value; teValue = value; }
      }
      if (cl !== undefined && (!Number.isFinite(cl) || cl < 0)) return { bad: true };
      return { need: false, bad: false, method: m[1], target: m[2], version: m[3],
        headerLines: lines.slice(1), headEnd: headEnd + 4, cl, te, teValue };
    };

    const parseChunked = (buf, off) => {
      /* returns {end, dechunked, firstChunk} — firstChunk = size of the first
       * chunk (0 when the body is empty), used by the buggy serializer below. */
      let pos = off;
      const parts = [];
      let firstChunk = 0;
      for (;;) {
        const lineEnd = buf.indexOf('\r\n', pos);
        if (lineEnd < 0) return { need: true };
        const sizeTok = buf.slice(pos, lineEnd).toString('latin1').split(';')[0].trim();
        if (!/^[0-9a-fA-F]+$/.test(sizeTok)) return { bad: true };
        const size = parseInt(sizeTok, 16);
        pos = lineEnd + 2;
        if (parts.length === 0) firstChunk = size;
        if (size === 0) {
          if (buf.indexOf('\r\n', pos) !== pos) {
            let p = pos;
            for (;;) {
              const e = buf.indexOf('\r\n', p);
              if (e < 0) return { need: true };
              if (e === p) { pos = e + 2; break; }
              p = e + 2;
            }
          } else pos += 2;
          return { end: pos, dechunked: Buffer.concat(parts), firstChunk };
        }
        if (buf.length < pos + size + 2) return { need: true };
        parts.push(buf.slice(pos, pos + size));
        pos += size;
        if (buf.slice(pos, pos + 2).toString('latin1') !== '\r\n') return { bad: true };
        pos += 2;
      }
    };

    const rebuildHeaders = (lines, drop, add) => {
      const dropSet = new Set(drop || []);
      const out = [];
      for (const l of lines) {
        const idx = l.indexOf(':');
        if (idx < 0) continue;
        if (dropSet.has(l.slice(0, idx).trim().toLowerCase())) continue;
        out.push(l);
      }
      for (const a of (add || [])) out.push(a);
      return out.join('\r\n');
    };

    const server = net.createServer((client) => {
      const back = net.connect(BACK_PORT, BACK_HOST);
      let dead = false;
      const fail = (status, reason) => {
        if (dead) return;
        dead = true;
        const body = reason + '\n';
        const text = status === 403 ? 'Forbidden' : 'Bad Request';
        client.write('HTTP/1.1 ' + status + ' ' + text + '\r\nContent-Type: text/plain\r\nContent-Length: '
          + Buffer.byteLength(body) + '\r\nConnection: close\r\n\r\n' + body);
        client.end();
        setTimeout(() => { client.destroy(); back.destroy(); }, 150);
      };
      back.on('error', () => { if (!dead) { dead = true; client.destroy(); } });
      client.on('error', () => { if (!dead) { dead = true; back.destroy(); } });
      back.on('data', (d) => { if (!client.destroyed) client.write(d); });
      back.on('close', () => { if (!dead) { dead = true; client.end(); } });
      client.on('close', () => { dead = true; back.destroy(); });
      let buf = Buffer.alloc(0);
      client.on('data', (d) => {
        if (dead) return;
        if (buf.length + d.length > MAX_BUF) return fail(400, 'request too large');
        buf = Buffer.concat([buf, d]);
        pump();
      });
      function pump() {
        while (!dead) {
          const h = parseHeaders(buf);
          if (h.need) return;
          if (h.bad) return fail(400, 'malformed request');
          const path = h.target.split('?')[0];
          if (path === '/internal' || path.startsWith('/internal/')) {
            return fail(403, 'edge policy: /internal is not routed through this edge');
          }
          let totalLen;
          if (h.te !== undefined) {
            /* FRONT is a TE parser: it consumes the full chunked message. */
            const c = parseChunked(buf, h.headEnd);
            if (c.need) return;
            if (c.bad) return fail(400, 'malformed chunked body');
            /* THE FLAW (serializer bugs):
             *  - mangled TE name ("Transfer-Encoding-") — origin cannot recognize TE;
             *  - Content-Length taken from the framing record = FIRST CHUNK SIZE,
             *    while the FULL de-chunked body is emitted. */
            const out = h.method + ' ' + h.target + ' ' + h.version + '\r\n'
              + rebuildHeaders(h.headerLines, ['transfer-encoding', 'content-length'],
                ['Transfer-Encoding-: ' + (h.teValue || 'chunked'), 'Content-Length: ' + c.firstChunk])
              + '\r\n\r\n';
            back.write(Buffer.from(out, 'latin1'));
            back.write(c.dechunked);
            totalLen = c.end;
          } else if (h.cl !== undefined) {
            if (buf.length < h.headEnd + h.cl) return;
            back.write(buf.slice(0, h.headEnd + h.cl));
            totalLen = h.headEnd + h.cl;
          } else {
            back.write(buf.slice(0, h.headEnd));
            totalLen = h.headEnd;
          }
          buf = buf.slice(totalLen);
        }
      }
    });
    await new Promise((resolve, reject) => {
      server.once('error', reject);
      server.listen(FRONT_PORT, '0.0.0.0', resolve);
    });
  },
};
