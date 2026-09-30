# VLH-CTF — Manifest Schemas

Both manifests are the **single source of truth** for what exists in the lab
("adding a module/subclass is a data change" — arch §6). Schemas per CONTRACT §8.

| File | Describes |
|---|---|
| `manifests/aslv-manifest.yaml` | ASLV deployment modes + modules (M0–M5) |
| `manifests/dsltv-manifest.yaml` | All 54 DSLTV subclasses, grouped by category |

---

## 1. `aslv-manifest.yaml`

```yaml
version: 1            # schema version (integer)
project: vlh-ctf      # fixed
product_line: aslv    # fixed

modes:                # deployment modes = compose profiles
  - id: full          # unique mode id
    name: Full-chain (all modules)
    port: 18024       # the only host-facing lab port for the mode
    profile: full     # docker compose --profile selector
    collector_port: 18090   # loopback collector mgmt port (TUI activity view)
  # ... m1..m5 ...

modules:              # the six ASLV modules
  - id: m1                      # m0..m5
    codename: aslv-edge         # folder under modules/
    name: Edge / Infrastructure # human-readable
    stack: [nginx, go]          # tech stack
    classes: [HTTP]             # bug classes (empty for m0)
    port: 18021                 # standalone port (null for m0)
    profile: m1                 # standalone profile (null for m0)
    flags:                      # flag placement per category (arch §7.0)
      - {category: HTTP, archetype: location-locked}
```

Notes:

- `collector_port` is a documented **extension** beyond the CONTRACT §8 example
  so the TUI can seed its config defaults; `~/.config/aslv-dsltv/config.toml`
  remains the runtime source of truth (it can override).
- `m0` has `port: null`, `profile: null`, `flags: []` — shared foundation, never
  host-exposed, no bugs of its own.

### Consumers

- **TUI**: modes → ASLV menu (name, port, profile); modules → module list with
  classes/flags; `collector_port` → activity polling target for the active mode.
- **Humans/docs**: port map, stack map, flag placement map.
- The **compose generator** does *not* read this file — its ASLV service map is
  hardcoded in `tools/gen-compose.mjs` (build contexts/targets/stubs are not
  expressible in the manifest schema) and must be kept in lockstep with it.

## 2. `dsltv-manifest.yaml`

```yaml
version: 1
project: vlh-ctf
product_line: dsltv
port: 8119             # sidecar port every subclass binds (exclusively)
collector_port: 18119  # loopback collector mgmt port (TUI)

categories:
  - id: jwt                      # folder dsltv/jwt/, lowercase, no dashes
    name: JWT                    # display name; also the flag CATEGORY
    subclasses:
      - slug: none-alg           # kebab-case; folder dsltv/jwt/none-alg/
        name: NoneAlg            # PascalCase — appears in the flag SubName
        archetype: identity-gated  # resource-resident | identity-gated |
                                  # event-verified | location-locked | stage-gated
                                  # (event-verified entries additionally carry
                                  #  eventKind: cors|csrf — cors/csrf categories)
        cut_candidate: false      # v1 cut-candidate review flag
        difficulty: low           # low | medium | high | critical
        win: "Forge an alg:none token ..."   # 1-line win condition (arch §7.3)
```

Derived identifiers (do not hand-maintain — everything derives from
`<category id>` + `slug`):

| Thing | Value |
|---|---|
| Folder | `dsltv/<category id>/<slug>/` |
| Compose profile | `dsltv-<category id>-<slug>` |
| Services | `<slug>-app`, `<slug>-edge` |
| Volumes | `<slug>-data`, `<slug>-registry` |
| Flag | `DSLTV{<CATEGORY>-<name>-<9-10 digits>}` |

Constraints (enforced by the generator):

- slugs are kebab-case and **globally unique across categories** (they prefix
  service/volume names);
- archetype and difficulty values come from the fixed enums above;
- `eventKind` only on `event-verified` entries (`cors` or `csrf`);
- the flag `SubName` must equal `name` exactly (PascalCase).

## 3. How the compose generator consumes the DSLTV manifest

`tools/gen-compose.mjs` (run via `make compose`):

1. Loads `manifests/dsltv-manifest.yaml` with js-yaml and validates the
   constraints above (fails hard on violations, warns if the subclass count
   drifts from 54).
2. Emits, per subclass, the `<slug>-app` service (build context, `SUBCLASS`,
   `LAB_DOMAIN=target.lab`, `REGISTRY_DIR=/registry`, data+registry volumes) and
   the `<slug>-edge` nginx sidecar (raw L4 pass-through `8119 → <slug>-app:8080`
   from the shared `dsltv/base/sidecar/nginx.conf.template`, loopback `18119`
   mgmt binding, profile `dsltv-<category>-<slug>`).
3. Emits the hardcoded ASLV service map (full + m1..m5) and all volumes.
4. Re-parses its own output and asserts the structure (service counts per
   profile, labels, networks, port bindings, volume declarations) before
   writing `docker-compose.yml`.

## 4. How the TUI consumes the manifests

- **Main menu**: ASLV → `modes` (deploy target = `profile`); DSLTV →
  `categories` → `subclasses` (deploy target = derived profile).
- **Status/Activity**: after deploying mode X, poll `collector_port` for the
  activity table (`GET /internal/activity`) and the verifier (`GET /verify`).
- **Anything else** (descriptions, difficulty) is display-only.

## 5. Adding a subclass = data change

1. Add the entry to `manifests/dsltv-manifest.yaml` (category → subclasses).
2. Create `dsltv/<category>/<slug>/Dockerfile` + `vuln.js` per
   `dsltv/base/README.md` (the shared base provides boot/flags/verifier/mail).
3. Regenerate: `make compose`.
4. Deploy: `make up-dsltv-<category>-<slug>` (or via TUI, which re-reads the
   manifest).

No other file needs touching — compose services, volumes, profiles, and TUI menu
entries all derive from the manifest.
