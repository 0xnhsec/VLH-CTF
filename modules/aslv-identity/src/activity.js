'use strict';
/*
 * VLH-CTF — ASLV M5 aslv-identity: activity logging.
 *
 * Every request → {ts, identifier, is_authenticated, data, latency_ms} into the
 * local SQLite store + async POST to ACTIVITY_SINK (the M0 collector /ingest)
 * when the env is set. GET /internal/activity exports NDJSON (latest first).
 */
const express = require('express');
const { db, nowIso } = require('./db');

const ACTIVITY_SINK = process.env.ACTIVITY_SINK || '';

function postSink(row) {
  if (!ACTIVITY_SINK) return;
  fetch(ACTIVITY_SINK, {
    method: 'POST',
    headers: { 'content-type': 'application/json' },
    body: JSON.stringify(row),
  }).catch(() => { /* best effort — never break the request */ });
}

function middleware(req, res, next) {
  const start = process.hrtime.bigint();
  res.on('finish', () => {
    try {
      const sid = /(?:^|;\s*)sid=([^;]*)/.exec(String(req.headers.cookie || ''))?.[1];
      const session = sid ? db.prepare('SELECT s.*, u.username FROM sessions s JOIN users u ON u.id = s.user_id WHERE s.sid = ? AND s.mfa_pending = 0').get(sid) : null;
      const identifier = session ? session.username : `${req.socket.remoteAddress || '-'}/${(sid || 'anon').slice(0, 8)}`;
      const latency = Number(process.hrtime.bigint() - start) / 1e6;
      const row = {
        ts: nowIso(),
        identifier,
        is_authenticated: !!session,
        data: `${req.method} ${req.originalUrl}`,
        latency_ms: Math.round(latency * 100) / 100,
      };
      db.prepare('INSERT INTO activity (ts, identifier, is_authenticated, data, latency_ms) VALUES (?,?,?,?,?)')
        .run(row.ts, row.identifier, row.is_authenticated ? 1 : 0, row.data, row.latency_ms);
      postSink(row);
    } catch (_) { /* never break the request */ }
  });
  next();
}

const router = express.Router();
router.get('/internal/activity', (req, res) => {
  const rows = db.prepare('SELECT ts, identifier, is_authenticated, data, latency_ms FROM activity ORDER BY id DESC LIMIT 5000').all();
  res.type('application/x-ndjson');
  res.send(rows.map((r) => JSON.stringify({
    ts: r.ts, identifier: r.identifier, is_authenticated: !!r.is_authenticated,
    data: r.data, latency_ms: r.latency_ms, unit: 'm5',
  })).join('\n') + '\n');
});

module.exports = { middleware, router };
