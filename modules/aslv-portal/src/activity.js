'use strict';
/*
 * VLH-CTF — ASLV M2 portal: activity telemetry.
 *
 * Every request is logged as {ts, identifier, is_authenticated, data,
 * latency_ms} into the local SQLite activity table AND a JSONL mirror at
 * /data/activity.jsonl. When ACTIVITY_SINK is set (full mode: the M0
 * collector's /ingest), each row is also POSTed there fire-and-forget with a
 * 1s timeout. GET /internal/activity (main listener, all vhosts) serves the
 * latest 5000 rows as NDJSON, newest first.
 *
 * Shared convention: `req.auth` (set by the session-peek middleware installed
 * before this one) identifies the acting user.
 */
const fs = require('fs');
const path = require('path');

const nowIso = () => new Date().toISOString();

function makeActivity({ db, dataDir, sinkUrl, unit }) {
  const jsonlFile = path.join(dataDir, 'activity.jsonl');

  const postSink = (row) => {
    if (!sinkUrl) return;
    const body = JSON.stringify(row);
    const controller = new AbortController();
    const timer = setTimeout(() => controller.abort(), 1000);
    fetch(sinkUrl, {
      method: 'POST',
      headers: { 'content-type': 'application/x-ndjson' },
      body,
      signal: controller.signal,
    }).catch(() => {}).finally(() => clearTimeout(timer));
  };

  const record = (row) => {
    try {
      db.prepare('INSERT INTO activity (ts, identifier, is_authenticated, data, latency_ms) VALUES (?,?,?,?,?)')
        .run(row.ts, row.identifier, row.is_authenticated ? 1 : 0, row.data, row.latency_ms);
    } catch (_) { /* never break the request */ }
    try { fs.appendFileSync(jsonlFile, JSON.stringify(row) + '\n'); } catch (_) { /* best effort */ }
    postSink(row);
  };

  const middleware = (req, res, next) => {
    const start = process.hrtime.bigint();
    res.on('finish', () => {
      try {
        const auth = req.auth || null;
        const ip = (req.socket && req.socket.remoteAddress) || '-';
        const identifier = auth
          ? auth.user.username
          : `${ip}/${(req.cookies ? req.cookies.sid || 'anon' : 'anon').toString().slice(0, 8)}`;
        const latency = Number(process.hrtime.bigint() - start) / 1e6;
        record({
          ts: nowIso(),
          identifier,
          is_authenticated: !!auth,
          data: `${req.method} ${req.originalUrl}`,
          latency_ms: Math.round(latency * 100) / 100,
          unit,
        });
      } catch (_) { /* never break the request */ }
    });
    next();
  };

  const handler = (req, res) => {
    const rows = db.prepare('SELECT ts, identifier, is_authenticated, data, latency_ms FROM activity ORDER BY id DESC LIMIT 5000').all();
    res.type('application/x-ndjson').send(rows.map((r) => JSON.stringify({
      ts: r.ts,
      identifier: r.identifier,
      is_authenticated: !!r.is_authenticated,
      data: r.data,
      latency_ms: r.latency_ms,
      unit,
    })).join('\n') + '\n');
  };

  /* Accept forwarded activity rows (NDJSON string, single object, or array). */
  const ingest = (req, res) => {
    let rows = [];
    const b = req.body;
    if (typeof b === 'string') {
      rows = b.split('\n').filter((l) => l.trim());
    } else if (Array.isArray(b)) {
      rows = b.map((x) => (typeof x === 'string' ? x : JSON.stringify(x)));
    } else if (b && typeof b === 'object') {
      rows = [JSON.stringify(b)];
    } else if (typeof req.rawBody === 'string' && req.rawBody.trim()) {
      rows = req.rawBody.split('\n').filter((l) => l.trim());
    }
    let count = 0;
    for (const line of rows) {
      try { JSON.parse(line); count += 1; } catch (_) { /* skip invalid lines */ }
      try { fs.appendFileSync(jsonlFile, line.trim() + '\n'); } catch (_) { /* best effort */ }
    }
    res.json({ ingested: count });
  };

  return { middleware, handler, ingest };
}

module.exports = { makeActivity };
