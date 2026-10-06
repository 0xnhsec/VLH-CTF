#!/usr/bin/env node
/**
 * VLH-CTF — docker-compose.yml generator.
 *
 * Reads `manifests/dsltv-manifest.yaml` (single source of truth for the 54
 * DSLTV subclasses) plus a hardcoded ASLV service map (kept in lockstep with
 * `manifests/aslv-manifest.yaml`) and writes `docker-compose.yml` at the repo
 * root, per CONTRACT §7:
 *
 *   profile                 services
 *   ----------------------  -------------------------------------------------
 *   full                    10  (gateway, edge-front, edge-back, portal, app,
 *                              api, identity, collector, postgres, mailhog)
 *   m1                      6   (edge trio + stub-auth/stub-portal/stub-mail)
 *   m2                      4   (portal-std + sidecar + stub-auth + stub-mail)
 *   m3                      4   (app-std + sidecar + stub-auth + stub-mail)
 *   m4                      3   (api-std + sidecar + stub-auth)
 *   m5                      4   (identity-std + sidecar + stub-portal + stub-mail)
 *   dsltv-<cat>-<slug>      2 × 54 (<slug>-app + <slug>-edge on :8119)
 *
 * Every service carries label 811911.vlh=1 and joins network `vlh`
 * (name 811911_vlh). DSLTV sidecars all bind host 8119 + loopback 18119 →
 * only ONE dsltv profile can be active at a time (Docker-enforced exclusivity,
 * PRD FR-3 / FR-16).
 *
 * Usage:   cd tools && npm install && node gen-compose.mjs      (or: make compose)
 */

import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

import yaml from 'js-yaml';

const HERE = path.dirname(fileURLToPath(import.meta.url));
const ROOT = path.resolve(HERE, '..');
const DSLTV_MANIFEST_PATH = path.join(ROOT, 'manifests', 'dsltv-manifest.yaml');
const ASLV_MANIFEST_PATH = path.join(ROOT, 'manifests', 'aslv-manifest.yaml');
const OUT_PATH = path.join(ROOT, 'docker-compose.yml');

const EXPECTED_DSLTV_SUBCLASSES = 54;

/** Host port of the full-mode gateway (CONTRACT §2). The services behind it
 *  bake absolute URLs with this port (identity OAuth origin/redirect, portal
 *  nav fallback), so it lives in exactly one place. */
const FULL_PORT = 18024;

/* ------------------------------------------------------------------------- */
/* Tiny deterministic YAML emitter (js-yaml cannot emit comments).           */
/* Only the shapes used below are supported: ordered maps, string arrays,    */
/* string/number scalars. JSON string escaping is a valid YAML double-quoted */
/* scalar, so scalar() quotes anything that is not a boring bare word.       */
/* ------------------------------------------------------------------------- */

const BARE_RE = /^[A-Za-z_][A-Za-z0-9_./-]*$/;
const KEY_RE = /^[A-Za-z0-9_][A-Za-z0-9_.-]*$/;
const RESERVED = new Set(['true', 'false', 'null', 'yes', 'no', 'on', 'off', '~']);

function scalar(v) {
  if (v === null || v === undefined) return 'null';
  if (typeof v === 'number' || typeof v === 'boolean') return String(v);
  const s = String(v);
  if (BARE_RE.test(s) && !RESERVED.has(s.toLowerCase())) return s;
  return JSON.stringify(s);
}

function yamlKey(k) {
  const s = String(k);
  if (KEY_RE.test(s) && !RESERVED.has(s.toLowerCase())) return s;
  return JSON.stringify(s);
}

function emitMapping(obj, indent, out) {
  const pad = ' '.repeat(indent);
  for (const [k, v] of Object.entries(obj)) {
    if (v === null || v === undefined) {
      out.push(`${pad}${yamlKey(k)}:`);
    } else if (Array.isArray(v)) {
      if (v.length === 0) {
        out.push(`${pad}${yamlKey(k)}: []`);
      } else {
        out.push(`${pad}${yamlKey(k)}:`);
        for (const item of v) out.push(`${pad}  - ${scalar(item)}`);
      }
    } else if (typeof v === 'object') {
      out.push(`${pad}${yamlKey(k)}:`);
      emitMapping(v, indent + 2, out);
    } else {
      out.push(`${pad}${yamlKey(k)}: ${scalar(v)}`);
    }
  }
}

/* ------------------------------------------------------------------------- */
/* Shared building blocks                                                    */
/* ------------------------------------------------------------------------- */

const LABEL = { '811911.vlh': '1' };
const NETS = ['vlh'];

/** nginx sidecar bootstrap: envsubst the template, then run nginx in foreground.
 *  `$$` is compose-escaped `$` — envsubst expands the listed vars from the
 *  container environment at start. */
const SIDECAR_CMD =
  '/bin/sh -c "envsubst \'$$LAB_PORT $$APP_HOST $$AUTH_HOST $$MAIL_HOST $$PORTAL_HOST\' < /tpl/nginx.conf.template > /etc/nginx/nginx.conf && nginx -g \'daemon off;\'"';
const SIDECAR_IMAGE = 'nginx:1.27-alpine';

/** Lab vhosts the ASLV gateway may need to resolve for in-container absolute-URL
 *  use (routing itself is Host-header based; contract §4). */
const ASLV_LAB_HOSTS = [
  'aslv.lab',
  'www.aslv.lab',
  'auth.aslv.lab',
  'mail.aslv.lab',
  'collector.aslv.lab',
  'attacker.aslv.lab',
  'edge.aslv.lab',
];

const edgeBuild = (target) => ({ context: './modules/aslv-edge', target });
const coreBuild = (target) => ({ context: './modules/aslv-core', target });

/** aslv-core `stubs` image — one image, many services (STUB selects the role). */
const stubService = (kind, profile) => ({
  build: coreBuild('stubs'),
  environment: { STUB: kind },
  networks: NETS,
  labels: LABEL,
  profiles: [profile],
});

const stubMailService = (profile) => ({
  build: coreBuild('stub-mail'),
  networks: NETS,
  labels: LABEL,
  profiles: [profile],
});

/** nginx sidecar bound to the module port (template owned by the module). */
const moduleSidecar = ({ template, appHost, ports, profile, extraEnv = {} }) => ({
  image: SIDECAR_IMAGE,
  command: SIDECAR_CMD,
  environment: { LAB_PORT: '80', APP_HOST: appHost, ...extraEnv },
  volumes: [`${template}:/tpl/nginx.conf.template:ro`],
  ports,
  depends_on: [appHost],
  networks: NETS,
  labels: LABEL,
  profiles: [profile],
});

/* ------------------------------------------------------------------------- */
/* Service collection (order = output order)                                 */
/* ------------------------------------------------------------------------- */

/** @type {Array<{name?: string, note?: string[], def?: object}>} */
const services = [];
const svc = (name, def, note = []) => services.push({ name, note, def });
const block = (note) => services.push({ note });

/* ========================================================================= */
/* ASLV — full-chain mode (profile: full)                                    */
/* ========================================================================= */

block([
  '  # ===========================================================================',
  '  # ASLV — FULL-CHAIN MODE (profile: full)',
  '  #',
  '  # One nginx gateway on :18024 routes by Host header (CONTRACT §4):',
  '  #   aslv.lab / www.aslv.lab -> portal   (+ /user/v1/ path prefix -> api)',
  '  #   *.aslv.lab (tenants)    -> app      auth.aslv.lab  -> identity',
  '  #   mail.aslv.lab           -> mailhog  collector.aslv.lab -> collector',
  '  #   attacker.aslv.lab       -> portal exploit-server vhost',
  '  #   edge.aslv.lab           -> edge backend (smuggling surface)',
  '  #   internal.aslv.lab       -> 404 (location-locked zone, deliberately unrouted)',
  '  #',
  '  # Every trust edge (M5->M3/M4, M2<->M3/M4, M2 forms, M1->M3/M4, M0<->M5/M3,',
  '  # M4->M3) is LIVE in this mode — no edge stubbed (FR-13).',
  '  # TUI collector mgmt binding: http://127.0.0.1:18090 (loopback only).',
  '  # ===========================================================================',
]);

svc('gateway', {
  build: edgeBuild('gateway-full'),
  ports: [`${FULL_PORT}:80`],
  depends_on: ['edge-front', 'portal', 'app', 'api', 'identity', 'mailhog'],
  volumes: ['./modules/aslv-edge/conf/gateway-full.conf:/etc/nginx/conf.d/default.conf:ro'],
  extra_hosts: Object.fromEntries(ASLV_LAB_HOSTS.map((h) => [h, '127.0.0.1'])),
  networks: NETS,
  labels: LABEL,
  profiles: ['full'],
}, [
  '  # gateway — the only host-exposed lab port in full mode. The vhost routing',
  '  # conf is owned by the aslv-edge module (modules/aslv-edge/conf/gateway-full.conf).',
  '  # extra_hosts exists so any in-container absolute URL to a lab vhost resolves',
  '  # to 127.0.0.1 (routing itself is Host-header based).',
]);

svc('edge-front', {
  build: edgeBuild('edgefront'),
  environment: { EDGE_MODE: '${EDGE_MODE:-cl-te}' },
  networks: NETS,
  labels: LABEL,
  profiles: ['full'],
}, [
  '  # edge-front — M1 raw-TCP front proxy. EDGE_MODE selects the desync flavor',
  '  # (cl-te | te-cl | te-te) via .env. Internal :8080 only, never host-exposed.',
]);

svc('edge-back', {
  build: edgeBuild('edgeback'),
  environment: { REGISTRY_DIR: '/registry' },
  volumes: ['m1-data:/data', 'vlh-registry:/registry'],
  networks: NETS,
  labels: LABEL,
  profiles: ['full'],
}, [
  '  # edge-back — M1 raw-TCP backend. /internal/flag (location-locked,',
  '  # ASLV{HTTP-...}) lives here, unrouted at the gateway — reachable only via',
  '  # request smuggling (raw sockets, arch §8).',
]);

svc('portal', {
  build: './modules/aslv-portal',
  environment: {
    // The image defaults are the M2 STANDALONE shape (STANDALONE=1,
    // PORTAL_PORT=18022). Full mode runs the same app behind the gateway on
    // FULL_PORT — without these overrides every absolute URL the portal
    // renders (header nav, bot Host fallback) points at 18022, a port this
    // profile never publishes.
    STANDALONE: '0',
    PORTAL_PORT: String(FULL_PORT),
    LAB_DOMAIN: 'aslv.lab',
    ACTIVITY_SINK: 'http://collector:8090/ingest',
  },
  volumes: ['m2-data:/data', 'vlh-registry:/registry'],
  networks: NETS,
  labels: LABEL,
  profiles: ['full'],
}, [
  '  # portal — M2 Express (minimal, no CSRF middleware): login, profile,',
  '  # recovery-email change (CSRF surface), CORS-reflecting endpoints, exploit-',
  '  # server vhost (attacker.aslv.lab), victim vhost (victim.aslv.lab).',
]);

svc('app', {
  build: './modules/aslv-app',
  environment: { LAB_DOMAIN: 'aslv.lab', ACTIVITY_SINK: 'http://collector:8090/ingest' },
  volumes: ['m3-data:/data', 'vlh-registry:/registry'],
  networks: NETS,
  labels: LABEL,
  profiles: ['full'],
}, [
  '  # app — M3 Laravel, subdomain-per-tenant. Innocent private doc holds',
  '  # ASLV{IDOR-...} (resource-resident, carries pivot material); BAC horizontal',
  '  # + vertical -> ASLV{BAC-...}.',
]);

svc('api', {
  build: './modules/aslv-api',
  environment: { LAB_DOMAIN: 'aslv.lab', ACTIVITY_SINK: 'http://collector:8090/ingest' },
  volumes: ['m4-data:/data', 'vlh-registry:/registry'],
  networks: NETS,
  labels: LABEL,
  profiles: ['full'],
}, [
  '  # api — M4 Go REST, path-based /user/v1/{user}/... BOLA/BFLA/BOPLA composite.',
  '  # Stage-gated ASLV{API-...}: flag1 after mass-assignment escalation, flag2 at',
  '  # the claim-checked admin endpoint.',
]);

svc('identity', {
  build: './modules/aslv-identity',
  environment: {
    LAB_DOMAIN: 'aslv.lab',
    ACTIVITY_SINK: 'http://collector:8090/ingest',
    SMTP_HOST: 'mailhog',
    SMTP_PORT: '1025',
    // Image defaults are the m5 STANDALONE shape (AUTH_ORIGIN on :18026 and
    // a mail fallback pointing at stub-mail — neither exists in this profile).
    // Full mode is a single origin: everything on the gateway port.
    AUTH_ORIGIN: `http://auth.aslv.lab:${FULL_PORT}`,
    CLIENT_REDIRECT_URI: `http://client.aslv.lab:${FULL_PORT}/client/callback`,
    MAIL_HTTP_URL: '',
  },
  volumes: ['m5-data:/data', 'vlh-registry:/registry'],
  networks: NETS,
  labels: LABEL,
  profiles: ['full'],
}, [
  '  # identity — M5 AS: sessions record auth_method provenance, password reset',
  '  # (predictable token), MFA surfaces, OAuth 2.0 AS + client, JWT issuing.',
  '  # Outbound mail goes over SMTP to mailhog:1025 (MailHog has no mail-creating',
  '  # HTTP API — identity POSTs via SMTP instead).',
]);

svc('collector', {
  build: coreBuild('collector'),
  environment: {
    DATABASE_URL: 'postgres://${POSTGRES_USER:-vlh}:${POSTGRES_PASSWORD:-vlh}@postgres:5432/${POSTGRES_DB:-vlh}',
    PORTAL_INTERNAL_URL: 'http://portal:3000',
  },
  ports: ['127.0.0.1:18090:8090'],
  volumes: ['collector-data:/data'],
  networks: NETS,
  labels: LABEL,
  profiles: ['full'],
}, [
  '  # collector — M0 Go collector: POST /ingest (activity), GET /internal/activity',
  '  # (NDJSON), POST /exfil + GET /verify (event-verified dual-check mint for',
  '  # ASLV CORS/CSRF, CONTRACT §3). 127.0.0.1:18090 = TUI mgmt binding.',
  '  # DATABASE_URL = optional Postgres activity archive (full mode only).',
]);

svc('postgres', {
  image: 'postgres:16-alpine',
  environment: {
    POSTGRES_USER: '${POSTGRES_USER:-vlh}',
    POSTGRES_PASSWORD: '${POSTGRES_PASSWORD:-vlh}',
    POSTGRES_DB: '${POSTGRES_DB:-vlh}',
  },
  volumes: ['pg-data:/var/lib/postgresql/data'],
  networks: NETS,
  labels: LABEL,
  profiles: ['full'],
}, [
  '  # postgres — M0 central store, FULL MODE ONLY (activity archive). Per-module',
  '  # app persistence stays SQLite on named volumes in BOTH modes (arch §6, v1',
  '  # interpretation — see docs/deployment.md). Internal :5432, never host-exposed.',
]);

svc('mailhog', {
  image: 'mailhog/mailhog:v1.0.1',
  networks: NETS,
  labels: LABEL,
  profiles: ['full'],
}, [
  '  # mailhog — SMTP :1025 (identity posts here), UI :8025 reachable only via the',
  '  # mail.aslv.lab vhost through the gateway. Mail is a TOKEN carrier, never a',
  '  # flag carrier (CONTRACT §3).',
]);

/* ========================================================================= */
/* ASLV — standalone modes (profiles m1..m5)                                 */
/* ========================================================================= */

block([
  '  # ===========================================================================',
  '  # ASLV STANDALONE MODES (profiles m1..m5)',
  '  #',
  '  # One module + aslv-core stubs (stub-auth signs dev tokens, stub-portal',
  '  # serves static pages, stub-mail replaces MailHog — CONTRACT §6). Each mode',
  '  # binds its own 1802x port and its loopback collector-mgmt port (18091..18095)',
  '  # which the TUI polls for the activity table:',
  '  #   m1 -> http://127.0.0.1:18091/internal/activity (Host: edge.aslv.lab)',
  '  #   m2 -> http://127.0.0.1:18092/internal/activity (Host: collector.aslv.lab)',
  '  #   m3 -> http://127.0.0.1:18093/internal/activity (Host: collector.aslv.lab)',
  '  #   m4 -> http://127.0.0.1:18094/internal/activity (Host: collector.aslv.lab)',
  '  #   m5 -> http://127.0.0.1:18095/internal/activity (Host: collector.aslv.lab)',
  '  #',
  '  # Standalone profiles may co-exist with each other (distinct ports) but must',
  '  # NOT run alongside `full` — the module shares its data/registry volumes',
  '  # with its full-mode twin.',
  '  # ===========================================================================',
]);

/* ---- m1: edge ------------------------------------------------------------ */

svc('edge-gateway-std', {
  build: edgeBuild('gateway-standalone'),
  ports: ['18021:80', '127.0.0.1:18091:80'],
  networks: NETS,
  labels: LABEL,
  profiles: ['m1'],
}, [
  '  # ---- profile m1: ASLV EDGE ----------------------------------------------',
  '  # M1 standalone IS the edge: its own gateway (target gateway-standalone)',
  '  # binds :18021 and routes the vhosts itself — no extra sidecar (CONTRACT §4).',
  '  # 127.0.0.1:18091 = TUI activity mgmt (Host: edge.aslv.lab).',
]);

svc('edge-front-std', {
  build: edgeBuild('edgefront'),
  environment: { EDGE_MODE: '${EDGE_MODE:-cl-te}' },
  networks: NETS,
  labels: LABEL,
  profiles: ['m1'],
}, [
  '  # edge-front-std — raw-TCP front proxy; EDGE_MODE (cl-te|te-cl|te-te) via .env.',
]);

svc('edge-back-std', {
  build: edgeBuild('edgeback'),
  environment: { REGISTRY_DIR: '/registry' },
  volumes: ['m1-data:/data', 'm1-registry:/registry'],
  networks: NETS,
  labels: LABEL,
  profiles: ['m1'],
}, [
  '  # edge-back-std — location-locked /internal/flag lives here. Standalone uses',
  '  # its own m1-registry volume (no shared vlh-registry outside full mode).',
]);

svc('stub-auth-1', stubService('auth', 'm1'), [
  '  # stub-auth-1 — aslv-core "stubs" image (one image, two services), STUB=auth.',
]);
svc('stub-portal-1', stubService('portal', 'm1'), [
  '  # stub-portal-1 — same "stubs" image, STUB=portal (static pages).',
]);
svc('stub-mail-1', stubMailService('m1'), [
  '  # stub-mail-1 — aslv-core "stub-mail" target: standalone mailbox UI + sink.',
]);

/* ---- m2: portal ----------------------------------------------------------- */

svc('portal-std', {
  build: './modules/aslv-portal',
  environment: { STANDALONE: '1', LAB_DOMAIN: 'aslv.lab' },
  volumes: ['m2-data:/data', 'm2-registry:/registry'],
  networks: NETS,
  labels: LABEL,
  profiles: ['m2'],
}, [
  '  # ---- profile m2: ASLV PORTAL --------------------------------------------',
  '  # nginx sidecar binds :18022 and does vhost routing (victim.aslv.lab /',
  '  # attacker.aslv.lab / collector.aslv.lab / mail.aslv.lab — CONTRACT §4), so',
  '  # origins are genuine for CORS/CSRF with M1 fully offline.',
  '  # portal-std — M2 standalone shape (STANDALONE=1: embedded mini-API +',
  '  # mini-collector, no M3/M4 dependency).',
]);

svc('portal-edge-std', moduleSidecar({
  template: './modules/aslv-portal/sidecar/nginx.conf.template',
  appHost: 'portal-std',
  ports: ['18022:80', '127.0.0.1:18092:80'],
  profile: 'm2',
  extraEnv: { MAIL_HOST: 'stub-mail-2' },
}), [
  '  # portal-edge-std — nginx sidecar; template owned by aslv-portal.',
  '  # 127.0.0.1:18092 = TUI activity mgmt (Host: collector.aslv.lab).',
]);

svc('stub-auth-2', stubService('auth', 'm2'), [
  '  # stub-auth-2 — aslv-core "stubs" image, STUB=auth.',
]);
svc('stub-mail-2', stubMailService('m2'), [
  '  # stub-mail-2 — aslv-core "stub-mail" target.',
]);

/* ---- m3: app --------------------------------------------------------------- */

svc('app-std', {
  build: './modules/aslv-app',
  environment: { STANDALONE: '1', LAB_DOMAIN: 'aslv.lab' },
  volumes: ['m3-data:/data', 'm3-registry:/registry'],
  networks: NETS,
  labels: LABEL,
  profiles: ['m3'],
}, [
  '  # ---- profile m3: ASLV APP -----------------------------------------------',
  '  # Laravel app behind its own nginx sidecar on :18023.',
  '  # app-std — standalone shape (stub-auth replaces M5, stub-mail replaces M0).',
]);

svc('app-edge-std', moduleSidecar({
  template: './modules/aslv-app/sidecar/nginx.conf.template',
  appHost: 'app-std',
  ports: ['18023:80', '127.0.0.1:18093:80'],
  profile: 'm3',
}), [
  '  # app-edge-std — nginx sidecar; template owned by aslv-app.',
  '  # 127.0.0.1:18093 = TUI activity mgmt (Host: collector.aslv.lab).',
]);

svc('stub-auth-3', stubService('auth', 'm3'), [
  '  # stub-auth-3 — aslv-core "stubs" image, STUB=auth.',
]);
svc('stub-mail-3', stubMailService('m3'), [
  '  # stub-mail-3 — aslv-core "stub-mail" target.',
]);

/* ---- m4: api ---------------------------------------------------------------- */

svc('api-std', {
  build: './modules/aslv-api',
  environment: { STANDALONE: '1', LAB_DOMAIN: 'aslv.lab' },
  volumes: ['m4-data:/data', 'm4-registry:/registry'],
  networks: NETS,
  labels: LABEL,
  profiles: ['m4'],
}, [
  '  # ---- profile m4: ASLV API ------------------------------------------------',
  '  # Go REST API behind its own nginx sidecar on :18025 (stub-auth signs dev',
  '  # tokens; no mail needed in m4).',
]);

svc('api-edge-std', moduleSidecar({
  template: './modules/aslv-api/sidecar/nginx.conf.template',
  appHost: 'api-std',
  ports: ['18025:80', '127.0.0.1:18094:80'],
  profile: 'm4',
  extraEnv: { AUTH_HOST: 'stub-auth-4' },
}), [
  '  # api-edge-std — nginx sidecar; template owned by aslv-api.',
  '  # 127.0.0.1:18094 = TUI activity mgmt (Host: collector.aslv.lab).',
]);

svc('stub-auth-4', stubService('auth', 'm4'), [
  '  # stub-auth-4 — aslv-core "stubs" image, STUB=auth.',
]);

/* ---- m5: identity -------------------------------------------------------------- */

svc('identity-std', {
  build: './modules/aslv-identity',
  environment: {
    STANDALONE: '1',
    LAB_DOMAIN: 'aslv.lab',
    SMTP_HOST: 'stub-mail-5',
    SMTP_PORT: '1025',
  },
  volumes: ['m5-data:/data', 'm5-registry:/registry'],
  networks: NETS,
  labels: LABEL,
  profiles: ['m5'],
}, [
  '  # ---- profile m5: ASLV IDENTITY --------------------------------------------',
  '  # Node/Express AS behind its own nginx sidecar on :18026.',
  '  # identity-std — standalone shape; outbound mail goes over SMTP to',
  '  # stub-mail-5:1025 (stub-portal-5 replaces the M2 portal surface).',
]);

svc('identity-edge-std', moduleSidecar({
  template: './modules/aslv-identity/sidecar/nginx.conf.template',
  appHost: 'identity-std',
  ports: ['18026:80', '127.0.0.1:18095:80'],
  profile: 'm5',
  extraEnv: { MAIL_HOST: 'stub-mail-5', PORTAL_HOST: 'stub-portal-5' },
}), [
  '  # identity-edge-std — nginx sidecar; template owned by aslv-identity.',
  '  # 127.0.0.1:18095 = TUI activity mgmt (Host: collector.aslv.lab).',
]);

svc('stub-portal-5', stubService('portal', 'm5'), [
  '  # stub-portal-5 — aslv-core "stubs" image, STUB=portal.',
]);
svc('stub-mail-5', stubMailService('m5'), [
  '  # stub-mail-5 — aslv-core "stub-mail" target (identity SMTP sink).',
]);

/* ========================================================================= */
/* DSLTV — one app + sidecar pair per manifest subclass                       */
/* ========================================================================= */

const manifest = yaml.load(fs.readFileSync(DSLTV_MANIFEST_PATH, 'utf8'));
if (!manifest || !Array.isArray(manifest.categories)) {
  throw new Error(`${DSLTV_MANIFEST_PATH}: expected top-level categories array`);
}

const ARCHETYPES = new Set([
  'resource-resident', 'identity-gated', 'event-verified', 'location-locked', 'stage-gated',
]);
const DIFFICULTIES = new Set(['low', 'medium', 'high', 'critical']);
const seenSlugs = new Set();
const seenProfiles = new Set();
let subclassCount = 0;

block([
  '  # ===========================================================================',
  '  # DSLTV — STANDALONE SUBCLASSES (profiles dsltv-<category>-<slug>, 54 total)',
  '  #',
  '  # Every subclass = <slug>-app + <slug>-edge pair, fully self-contained',
  '  # (own SQLite, own seed, zero dependency on other subclasses or ASLV — FR-15).',
  '  #',
  '  # The sidecar is a RAW L4 pass-through (dsltv/base/sidecar/nginx.conf.template):',
  '  # 8119 -> <slug>-app:8080. Vhost routing (victim/attacker/collector/mail',
  '  # .target.lab) happens INSIDE the app by Host header, so origins are genuinely',
  '  # distinct and HTTP framing is never normalized (NFR-5). The app container is',
  '  # never directly exposed.',
  '  #',
  '  # EXCLUSIVITY (PRD FR-3 / FR-16): ALL <slug>-edge sidecars bind the SAME host',
  '  # ports — 8119 (lab) + 127.0.0.1:18119 (collector mgmt). Only ONE dsltv-*',
  '  # profile can be active at a time: Docker rejects the second port binding with',
  '  # a clean error, which the TUI surfaces; the TUI tears the previous pair down',
  '  # before starting a new one. This is by design.',
  '  #',
  '  # TUI polls the ACTIVE subclass at http://127.0.0.1:18119/internal/activity',
  '  # and /verify with Host: collector.target.lab.',
  '  # ===========================================================================',
]);

for (const cat of manifest.categories) {
  if (!cat.id || !Array.isArray(cat.subclasses)) {
    throw new Error(`dsltv-manifest: category missing id or subclasses: ${JSON.stringify(cat)}`);
  }
  block([
    `  # ---- ${cat.id} (${cat.name}) ${'-'.repeat(Math.max(1, 64 - cat.id.length - cat.name.length))}`,
  ]);
  for (const sub of cat.subclasses) {
    const { slug, name, archetype } = sub;
    if (!slug || !name || !archetype) {
      throw new Error(`dsltv-manifest/${cat.id}: entry missing slug/name/archetype: ${JSON.stringify(sub)}`);
    }
    if (!/^[a-z0-9]+(-[a-z0-9]+)*$/.test(slug)) {
      throw new Error(`dsltv-manifest/${cat.id}: slug not kebab-case: ${slug}`);
    }
    if (seenSlugs.has(slug)) throw new Error(`duplicate slug across categories: ${slug}`);
    seenSlugs.add(slug);
    if (!ARCHETYPES.has(archetype)) {
      throw new Error(`dsltv-manifest/${slug}: unknown archetype: ${archetype}`);
    }
    if (!DIFFICULTIES.has(sub.difficulty)) {
      throw new Error(`dsltv-manifest/${slug}: unknown difficulty: ${sub.difficulty}`);
    }
    const profile = `dsltv-${cat.id}-${slug}`;
    if (seenProfiles.has(profile)) throw new Error(`duplicate profile: ${profile}`);
    seenProfiles.add(profile);
    subclassCount += 1;

    const kind = sub.eventKind ? `${archetype}/${sub.eventKind}` : archetype;
    const cut = sub.cut_candidate ? ' — CUT CANDIDATE' : '';
    const note = `  # ${cat.name} / ${name} — ${kind}, difficulty ${sub.difficulty}${cut}`;

    svc(`${slug}-app`, {
      build: `./dsltv/${cat.id}/${slug}`,
      environment: { SUBCLASS: slug, LAB_DOMAIN: 'target.lab', REGISTRY_DIR: '/registry' },
      volumes: [`${slug}-data:/data`, `${slug}-registry:/registry`],
      networks: NETS,
      labels: LABEL,
      profiles: [profile],
    }, [note]);

    svc(`${slug}-edge`, {
      image: SIDECAR_IMAGE,
      command: SIDECAR_CMD,
      environment: { LAB_PORT: '8119', APP_HOST: `${slug}-app` },
      volumes: ['./dsltv/base/sidecar/nginx.conf.template:/tpl/nginx.conf.template:ro'],
      ports: ['8119:8119', '127.0.0.1:18119:8119'],
      depends_on: [`${slug}-app`],
      networks: NETS,
      labels: LABEL,
      profiles: [profile],
    });
  }
}

if (subclassCount !== EXPECTED_DSLTV_SUBCLASSES) {
  console.warn(
    `[gen-compose] WARNING: expected ${EXPECTED_DSLTV_SUBCLASSES} DSLTV subclasses, manifest has ${subclassCount}`,
  );
}

/* ------------------------------------------------------------------------- */
/* Volumes                                                                   */
/* ------------------------------------------------------------------------- */

/** @type {Array<{name: string, note: string}>} */
const volumes = [];
const pushVol = (name, note) => volumes.push({ name, note });

pushVol('vlh-registry', 'shared ASLV flag registry — full mode only');
for (const m of ['m1', 'm2', 'm3', 'm4', 'm5']) {
  pushVol(`${m}-data`, `ASLV ${m} app data (SQLite — both modes, arch §6)`);
}
for (const m of ['m1', 'm2', 'm3', 'm4', 'm5']) {
  pushVol(`${m}-registry`, `ASLV ${m} flag registry — standalone mode`);
}
pushVol('collector-data', 'M0 collector activity store');
pushVol('pg-data', 'Postgres data — full mode activity archive');
for (const cat of manifest.categories) {
  for (const sub of cat.subclasses) {
    pushVol(`${sub.slug}-data`, `dsltv ${sub.slug} app data (isolated, FR-15)`);
    pushVol(`${sub.slug}-registry`, `dsltv ${sub.slug} flag registry`);
  }
}

/* ------------------------------------------------------------------------- */
/* Render                                                                    */
/* ------------------------------------------------------------------------- */

const out = [];
const W = (line = '') => out.push(line);

W('# =============================================================================');
W('# VLH-CTF — docker-compose.yml  (GENERATED FILE — DO NOT EDIT)');
W('#');
W('# Regenerate:  cd tools && npm install && node gen-compose.mjs     (or: make compose)');
W('# Sources:     manifests/dsltv-manifest.yaml   (54 DSLTV subclasses)');
W('#              + hardcoded ASLV service map in tools/gen-compose.mjs');
W('#              (kept in lockstep with manifests/aslv-manifest.yaml)');
W('#');
W('# Profile map (CONTRACT §7):');
W('#   full                 ASLV full-chain mode .......... gateway :18024');
W('#   m1 m2 m3 m4 m5       ASLV standalone modules ....... :18021 :18022 :18023 :18025 :18026');
W('#   dsltv-<cat>-<slug>   one per DSLTV subclass (54) ... sidecar :8119');
W('#');
W('# EXCLUSIVITY (PRD FR-3 / FR-16): every DSLTV <slug>-edge sidecar binds host');
W('# port 8119 (and loopback collector port 18119), so only ONE dsltv-* profile');
W('# can be active at a time — a second `up` fails cleanly on the port binding');
W('# (Docker-native behavior, surfaced by the TUI, which tears the previous pair');
W('# down first). ASLV standalone profiles bind distinct 1802x ports and may');
W('# co-exist with each other, but do NOT run a module standalone profile together');
W('# with `full` — they share that module\'s data/registry volumes.');
W('#');
W('# Env interpolation (.env / .env.example):');
W('#   EDGE_MODE                   cl-te | te-cl | te-te  (edge-front desync flavor)');
W('#   POSTGRES_USER/PASSWORD/DB   M0 Postgres credentials (full mode)');
W('# =============================================================================');
W();
W('name: vlh-ctf');
W();
W('networks:');
W('  vlh:');
W('    name: "811911_vlh"');
W();
W('volumes:');
W('  # ---- ASLV shared (full mode) ----');
for (let i = 0; i < volumes.length; i += 1) {
  const v = volumes[i];
  if (v.name === 'm1-data') W('  # ---- ASLV per-module data + standalone registries ----');
  if (v.name === 'collector-data') W('  # ---- M0 collector / postgres ----');
  if (v.name === `${manifest.categories[0].subclasses[0].slug}-data`) {
    W('  # ---- DSLTV: one data + one registry volume per subclass (isolated, FR-15) ----');
  }
  W(`  ${v.name}:   # ${v.note}`);
}
W();
W('services:');
for (const entry of services) {
  for (const line of entry.note || []) W(line);
  if (!entry.name) {
    W();
    continue;
  }
  W(`  ${yamlKey(entry.name)}:`);
  // Exact profile label (the tui/README "recommended" one): it makes the
  // TUI's active-profile detection independent of the published ports, so a
  // FR-11 port remap (docker-compose.override.yml) can never hide which
  // profile is running — nor which host port it now answers on.
  if (entry.def.labels && Array.isArray(entry.def.profiles) && entry.def.profiles.length === 1) {
    entry.def.labels = { ...entry.def.labels, '811911.profile': entry.def.profiles[0] };
  }
  emitMapping(entry.def, 4, out);
  W();
}
W('# ==== end of generated file ====');

const text = `${out.join('\n')}\n`;

/* ------------------------------------------------------------------------- */
/* Validate what we just rendered (parse it back with js-yaml)                */
/* ------------------------------------------------------------------------- */

function validate(text) {
  const doc = yaml.load(text);
  if (doc.name !== 'vlh-ctf') throw new Error('validate: top-level name must be vlh-ctf');
  if (!doc.networks || doc.networks.vlh?.name !== '811911_vlh') {
    throw new Error('validate: networks.vlh.name must be 811911_vlh');
  }
  const names = Object.keys(doc.services);
  if (new Set(names).size !== names.length) throw new Error('validate: duplicate service names');

  const byProfile = new Map();
  for (const [name, s] of Object.entries(doc.services)) {
    if (s.labels?.['811911.vlh'] !== '1') throw new Error(`validate: ${name} missing label 811911.vlh=1`);
    if (!Array.isArray(s.networks) || !s.networks.includes('vlh')) {
      throw new Error(`validate: ${name} missing network vlh`);
    }
    if (!Array.isArray(s.profiles) || s.profiles.length === 0) {
      throw new Error(`validate: ${name} missing profiles`);
    }
    if (s.labels?.['811911.profile'] !== s.profiles[0]) {
      throw new Error(`validate: ${name} missing label 811911.profile=${s.profiles[0]}`);
    }
    for (const p of s.profiles) {
      if (!byProfile.has(p)) byProfile.set(p, []);
      byProfile.get(p).push(name);
    }
    // every named volume reference must be declared top-level
    for (const v of s.volumes || []) {
      if (typeof v === 'string' && !v.startsWith('.') && !v.startsWith('/') && v.includes(':')) {
        const vol = v.split(':')[0];
        if (!doc.volumes || !(vol in doc.volumes)) {
          throw new Error(`validate: ${name} references undeclared volume ${vol}`);
        }
      }
    }
  }
  const expect = {
    full: 10, m1: 6, m2: 4, m3: 4, m4: 3, m5: 4,
  };
  for (const [p, n] of Object.entries(expect)) {
    const got = byProfile.get(p)?.length ?? 0;
    if (got !== n) throw new Error(`validate: profile ${p} should have ${n} services, has ${got}`);
  }
  let dsltvPairs = 0;
  for (const [p, names2] of byProfile) {
    if (p.startsWith('dsltv-')) {
      if (names2.length !== 2) throw new Error(`validate: profile ${p} should have exactly 2 services`);
      dsltvPairs += 1;
      const edge = names2.find((n) => n.endsWith('-edge'));
      const edgeSvc = doc.services[edge];
      const want = ['8119:8119', '127.0.0.1:18119:8119'];
      if (JSON.stringify(edgeSvc.ports) !== JSON.stringify(want)) {
        throw new Error(`validate: ${edge} ports must be ${want.join(', ')}`);
      }
    }
  }
  if (dsltvPairs !== subclassCount) {
    throw new Error(`validate: dsltv profile count ${dsltvPairs} != manifest subclasses ${subclassCount}`);
  }
  const total = names.length;
  const expectedTotal = 10 + 6 + 4 + 4 + 3 + 4 + 2 * subclassCount;
  if (total !== expectedTotal) {
    throw new Error(`validate: expected ${expectedTotal} services, got ${total}`);
  }
  return { total, byProfile, volumes: Object.keys(doc.volumes).length, dsltvPairs };
}

const stats = validate(text);
fs.writeFileSync(OUT_PATH, text);

console.log(`[gen-compose] wrote ${path.relative(ROOT, OUT_PATH)}`);
console.log(
  `[gen-compose] services: ${stats.total} (full=10, standalone=21, dsltv=${2 * stats.dsltvPairs})`,
);
console.log(
  `[gen-compose] profiles: ${stats.byProfile.size} (full, m1..m5, ${stats.dsltvPairs} dsltv-*) | volumes: ${stats.volumes}`,
);
console.log('[gen-compose] YAML re-parsed and structurally validated OK');
