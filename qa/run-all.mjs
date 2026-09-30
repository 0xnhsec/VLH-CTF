#!/usr/bin/env node
/*
 * VLH-CTF QA runner (FR-14) — executes every solver.mjs AND shortcut.mjs under
 * qa/solvers/** (recursive) and prints a results table.
 *
 * Semantics (CONTRACT §11 / architecture-decisions §7.4 QA rule):
 *   solver.mjs   exit 0 → PASS           intended path earned the flag(s)
 *                exit ≠ 0 → FAIL         broken lab or broken solver
 *   shortcut.mjs exit 0 → PASS           every naive path stayed BLOCKED (no flag)
 *                exit ≠ 0 → SKIP-LEAKED  a naive path leaked a flag — critical
 *                                       placement bug (FR-14 violation)
 *
 * Exit code: 0 only when nothing FAILs and no shortcut leaks; 1 otherwise.
 *
 * Labs must be RUNNING before run-all starts (per profile — see qa/README.md);
 * a refused connection is reported as FAIL with the solver's compose hint.
 *
 * Env / argv (KEY=VALUE):
 *   SKIP=chain   skip the full-mode chain solvers (qa/solvers/aslv/chain/*)
 *   SKIP=jwt     skip the DSLTV JWT solvers (only one dsltv sidecar can bind
 *                :8119 at a time — FR-3/FR-16)
 *   ONLY=<substr> run only suites whose path contains <substr>
 *   TIMEOUT_MS  per-suite timeout in ms (default 180000)
 * Usage: node qa/run-all.mjs          (or: make qa)
 */
import { spawnSync } from 'node:child_process';
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const QA_DIR = path.dirname(fileURLToPath(import.meta.url));
const SOLVERS_DIR = path.join(QA_DIR, 'solvers');
const PER_SUITE_TIMEOUT = Number(process.env.TIMEOUT_MS || 180000);

/* env vars, plus KEY=VALUE argv forms (node qa/run-all.mjs SKIP=chain) */
const args = {};
for (const a of process.argv.slice(2)) {
  const m = /^([A-Za-z_][A-Za-z0-9_]*)=(.*)$/.exec(a);
  if (m) args[m[1]] = m[2];
}
const skip = String(args.SKIP ?? process.env.SKIP ?? '').toLowerCase();
const only = String(args.ONLY ?? process.env.ONLY ?? '');

/* --------------------------------------------------------- discovery */
function discover(dir, acc = []) {
  for (const ent of fs.readdirSync(dir, { withFileTypes: true })) {
    const p = path.join(dir, ent.name);
    if (ent.isDirectory()) discover(p, acc);
    else if (ent.isFile() && (ent.name === 'solver.mjs' || ent.name === 'shortcut.mjs')) acc.push(p);
  }
  return acc;
}

let files = discover(SOLVERS_DIR).sort();
const discovered = files.length;
if (skip.includes('chain')) files = files.filter((f) => !f.includes(`${path.sep}chain${path.sep}`));
if (skip.includes('jwt')) files = files.filter((f) => !f.includes(`${path.sep}jwt${path.sep}`));
if (only) files = files.filter((f) => f.includes(only));
const skipped = discovered - files.length;

if (discovered === 0) {
  console.error('no solver/shortcut files found — run from the repo root: node qa/run-all.mjs');
  process.exit(1);
}
if (files.length === 0) {
  console.error(`all ${discovered} discovered suites were skipped (SKIP=${skip} ONLY=${only}) — nothing to run`);
  process.exit(1);
}

/* --------------------------------------------------------------- run */
const results = [];
for (const file of files) {
  const kind = path.basename(file) === 'solver.mjs' ? 'solver' : 'shortcut';
  const suite = path.relative(SOLVERS_DIR, path.dirname(file)).split(path.sep).join('/');
  const t0 = Date.now();
  const r = spawnSync('node', [file], { cwd: QA_DIR, encoding: 'utf8', timeout: PER_SUITE_TIMEOUT, env: process.env });
  const ms = Date.now() - t0;
  const out = `${r.stdout || ''}${r.stderr || ''}`.trimEnd();
  const lastLine = out ? (out.split('\n').filter((l) => l.trim()).pop() || '') : '';
  const labDown = /ECONNREFUSED|ENOTFOUND|EHOSTUNREACH|lab not running|cannot connect to|is the .* running/.test(out);
  const result = r.status === 0 ? 'PASS' : (kind === 'shortcut' ? 'SKIP-LEAKED' : 'FAIL');
  results.push({ suite, kind, result, ms, lastLine, labDown, signal: r.signal, error: r.error ? String(r.error) : null });
  const mark = result === 'PASS' ? '✔' : '✘';
  console.error(`[${mark}] ${result.padEnd(11)} ${suite}/${kind}  (${(ms / 1000).toFixed(1)}s)` +
    (result === 'PASS' ? '' : `\n     ↳ ${lastLine.slice(0, 160)}`));
}

/* ------------------------------------------------------------- report */
const pad = (s, n) => String(s).padEnd(n);
console.log('\n==== VLH-CTF QA RESULTS ====================================================');
console.log(`${pad('suite', 24)}${pad('name', 9)}${pad('result', 12)}${pad('ms', 8)}note`);
console.log('-'.repeat(100));
for (const r of results) {
  const note = r.labDown ? 'lab not running?' : (r.result === 'PASS' ? '' : r.lastLine);
  console.log(`${pad(r.suite, 24)}${pad(r.kind, 9)}${pad(r.result, 12)}${pad(String(r.ms), 8)}${note.slice(0, 42)}`);
}
const pass = results.filter((r) => r.result === 'PASS').length;
const fail = results.filter((r) => r.result === 'FAIL').length;
const leaked = results.filter((r) => r.result === 'SKIP-LEAKED').length;
console.log('-'.repeat(100));
console.log(`TOTAL ${results.length}   PASS ${pass}   FAIL ${fail}   SKIP-LEAKED ${leaked}   skipped(by env) ${skipped}`);
if (leaked > 0) {
  console.log('\n*** SHORTCUT LEAKS ARE CRITICAL (FR-14): a naive path minted a flag in:');
  for (const r of results.filter((x) => x.result === 'SKIP-LEAKED')) console.log(`    ${r.suite}/${r.kind} — ${r.lastLine.slice(0, 90)}`);
}
if (fail + leaked > 0) process.exit(1);
console.log('\nAll suites passed: intended paths win, shortcuts stay blocked. (FR-14 ✔)');
process.exit(0);
