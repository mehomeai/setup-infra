# Development setup + lifecycle

Rerunnable development setup/check/configuration for the Me home service, plus
a small managed lifecycle (start/status/stop, bootstrap, backup/restore,
optional named-tunnel adapter, service-unit generation). No root, no global
machine changes, no downloaded installers, no real tunnel, no public endpoint.

Toolchain discovery: compatible Node (`>=24.18.0 <25`) is discovered from
`--node`, `ME_HOME_NODE`, `PATH`, then well-known nvm layouts — never a
hardcoded username-specific path. Same for the home checkout
(`--infra-checkout`, `ME_HOME_INFRA_CHECKOUT`, or `../infra-server`) and the
agent-runtime python (`--runtime-python`, `ME_HOME_RUNTIME_PYTHON`, or the
framework checkout's `.venv`).

## Quick start (development Mac + Node 24)

```sh
# 1. Prerequisites are checked by the setup itself; Node 24.18 is discovered,
#    not hardcoded. Point at alternates explicitly when needed:
#    --node /path/to/node --infra-checkout /path/to/infra-server

# 2. Run setup (default destination ~/.local/share/me-home):
python3 scripts/me_setup.py setup

#    Or pick an explicit destination (paths with spaces are safe), with
#    optional coordination/notification opt-ins (both default disabled):
python3 scripts/me_setup.py setup --data-dir ~/.local/share/me-home --port 7070
#    [--public-home-url https://home.example.com] [--coordinator-enabled]
#    [--notifications-enabled --expo-project-id <public-id>]

# 3. Validate at any time:
python3 scripts/me_setup.py check
python3 scripts/me_setup.py config-show

# 4. Managed lifecycle (operates ONLY on the process it started):
python3 scripts/me_lifecycle.py start --data-dir ~/.local/share/me-home
python3 scripts/me_lifecycle.py status --data-dir ~/.local/share/me-home
python3 scripts/me_lifecycle.py bootstrap --data-dir ~/.local/share/me-home --user alice
python3 scripts/me_lifecycle.py backup --data-dir ~/.local/share/me-home
python3 scripts/me_lifecycle.py stop --data-dir ~/.local/share/me-home
```

Environment overrides: `ME_HOME_DATA_DIR`, `ME_HOME_PORT`, `ME_HOME_NODE`,
`ME_HOME_INFRA_CHECKOUT`, `ME_HOME_FRAMEWORK_CHECKOUT`, `ME_HOME_RUNTIME_PYTHON`.
Exit codes: `0` ok, `1` operation/state failure, `2` usage/validation, `3`
missing prerequisite, `4` parked external dependency (tunnel only).

Disk guard: 1 GiB free is required (production guard, honest on a full disk).
An explicit `--min-disk-mib N` below 1024 is a labelled dev-only override for
synthetic local checks; runs with it log `DEV OVERRIDE` and must never be
presented as a provisioned installation. Tests mock disk pressure instead of
pretending a whole application is provisioned.

## What setup creates

`<data-dir>/` (default `~/.local/share/me-home`):

| Path | Contents | Preservation |
| --- | --- | --- |
| `config/config.json` | Service/data directory config, schema v1. No secrets, ever | Backed up to `backups/` before any change; incompatible versions fail instead of overwriting |
| `config/service.env` | Non-secret environment for the service (`HOME_DB/HOST/PORT`, runtime opt-ins). Secret values never appear here | Regenerated on every setup; secrets stay in the operator shell |
| `data/home.sqlite` (+WAL) | The H1 home database (H1 `--db` target) | **Owned by the home service; setup never deletes it.** `backup`/`restore` are the only writers, with verification + guards |
| `data/household/` | Household user/conversation/task data root (owned by the home service) | **Never deleted or modified by setup.** Repeat runs preserve every file |
| `data/household/pairing/` | Phone enrollment material (per-device, revocable; issued by the home service, not by setup) | Preserved; setup only ensures the directory exists |
| `secrets/` (mode `0700`) | Tunnel connector + admin credentials, provisioned separately as mode `0600` files | Setup writes no credential values here, only a `README.md` policy note |
| `logs/`, `tmp/` | Service logs and scratch space | Created if missing |
| `backups/` | Timestamped `config-<ts>.json` copies, `home-<ts>.sqlite` db snapshots, `home-full-<ts>.tar.gz` full archives, `pre-restore-*` preservation copies | Appended, never pruned by setup |

`config.json` records `installation_id` plus `installation_source` (`reserved-`
placeholder, `home-database`, `live-service`, `restored-database`). The home
database is the authority: on rerun, setup adopts the db's id when present, so
no invented identity survives first contact with the real service. Also
recorded: dev `service` binding (loopback-only, default `127.0.0.1:7070`
matching H1's local default), the reserved database path
(`<data-dir>/data/home.sqlite`), the `home_api` contract pointer
(`infra-server/contracts/home-api-v1.md`, status `home-api-v1`), the
`runtime_bridge` probe (H2 `runtime-bridge-v1`: python, import cwd, status),
local-first `models` + capability ceiling (remote explicitly opted in, fixture
tests-only; local endpoint is the ChatOllama base URL **without** `/v1` —
H3's own `.../v1` default would misconfigure ChatOllama and is H3's bug to
fix), discovered tool paths, the disabled tunnel state, and the deployment
boundary (macOS dev now, Linux declared future, no service-manager installer).

## Runtime/model/capability env

`start` builds the home child environment from config using exactly the keys
the home reads (`runtime-config.mjs`, verified read-only): `ME_RUNTIME_ARGV`
(JSON array, space-safe) + `ME_RUNTIME_CWD`, `HOME_MODEL_PROVIDER/NAME/ENDPOINT`,
`HOME_ALLOW_FIXTURE_MODEL`, `ME_RUNTIME_ALLOW_REMOTE`, `HOME_CAP_*`,
`ME_RUNTIME_ALLOW_CODE_EXEC`, plus `ME_RUNTIME_SANDBOX=docker` when code
execution is explicitly enabled (emitted from both the start gate and the
generated service units). Config wins over the operator shell for this
managed key set; secrets (`ME_RUNTIME_MODEL_API_KEY` and tunnel credentials)
are inherited from the operator shell only, never persisted anywhere by
setup. `service.env` carries the same non-secret set with shell-safe quoting
(`set -a; . config/service.env`), and generated launchd (plistlib) / systemd
units embed the identical env and checkout working directory while execing
the shared guard (config/me-home.exec.py), which re-derives the Node argv
(incl. transform flags) and execs Node only when the journal is clean. Unit
and guard files never contain secrets: generation warns when a remote key is
present instead of baking it in. Local endpoint is the ChatOllama-correct
`http://127.0.0.1:11434` (no `/v1`); household data and execution stay on
the home host, and an explicitly enabled remote provider receives
prompts/tool context. Live-model checks use synthetic data only.

## Cloud coordination + notifications (S7/H7, default disabled)

`config.json` carries non-secret `coordinator` (enabled/backend_url/
public_home_url/credentials_file/allow_http_loopback) and `notifications`
(enabled/expo_project_id) sections. `service.env`, `start`, and generated
units wire `HOME_COORDINATOR_CREDENTIALS_FILE` (+ loopback opt-in) and
`HOME_NOTIFICATIONS_ENABLED`/`HOME_EXPO_PROJECT_ID` only when enabled;
`HOME_EXPO_ACCESS_TOKEN` is inherited from the operator shell only and is
never persisted, logged, or baked into units. The private credentials file
defaults to `<data-dir>/secrets/backend-home-token.json` (parent 0700, file
0600, atomic write, no symlink). Changing coordination/notification settings
requires a service reload (`stop`/`start` or unit reload); setup never
auto-restarts active jobs. See `docs/home-coordination-activation.md` for
the exact operator sequence, manual tunnel gates, and recovery.

## Safety rules enforced

- **Unsafe destinations rejected:** filesystem root, system locations
  (`/bin`, `/sbin`, `/usr`, `/etc`, `/System`, `/Library`, …), your home
  directory itself, shared temp dirs, existing non-directory paths, and any
  path inside the `setup-infra` source checkout.
- **Loopback only:** `--host` must be `127.0.0.1`, `::1`, or `localhost`.
  Anything else fails with a pointer to the production tunnel boundary doc.
- **Non-root:** running as root (euid 0) fails. Unprivileged ports only (≥1024).
- **No network side effects:** setup only binds the chosen port transiently to
  test availability; it starts no listener, downloads nothing, and contacts no
  provider.
- **Secret hygiene:** `config.json` is asserted secret-free on read; log lines
  pass through redaction for `token/secret/password/key/credential` patterns.

## Repeat setup / upgrade behavior

1. Re-running `setup` with the same options refreshes `updated_at` and directory
   modes, keeps `installation_id` and `created_at`, and leaves `data/household/`
   untouched (covered by `scripts/test_me_setup.py`).
2. Changing `--port`/`--host` backs up the previous config to `backups/` first.
3. A config with an unknown `schema_version` or missing keys aborts with an
   explicit migration error — setup never migrates or wipes data silently.
4. To relocate: run `setup --data-dir <new>`, then move `data/household/`
   explicitly and back it up first. There is no implicit copy/delete.

## Linux boundary (declared, not installed)

The same script runs on Linux (same Python stdlib-only dependency, same Node
`>=24.18.0 <25` requirement) and records it as the declared future deployment
target in `config.json`. It installs **no** systemd unit, creates **no**
system user, and claims **no** production service-manager installer. That
remains future work.

## Home integration: managed lifecycle against this config

`infra-server/contracts/home-api-v1.md` (authoritative) plus
`infra-server/contracts/home-api-v1.openapi.json` define the home API.
Setup records the contract version in `home_api.contract_status`; the
authoritative routes, versions, and launch flags always come from the home
service, never from this repository. The agent bridge is published at
`agentic-framework/docs/runtime-bridge-v1.md`; setup probes
`me_runtime.bridge` importability (src-layout aware) and records the result
without executing runs.

```sh
python3 scripts/me_lifecycle.py start --data-dir ~/.local/share/me-home
# start detects the home's transitive TypeScript import and retries once with
# --experimental-transform-types, recording the effective node_args in config.

python3 scripts/me_lifecycle.py bootstrap --data-dir ~/.local/share/me-home --user alice
# Prints the one-time invitation JSON on stdout ONLY (pipeable); warnings go to
# stderr; nothing is logged. Deliver it to the intended phone, then pair.
# --format pairing-v1 wraps the actual local bootstrap output with the locally
# configured public URL into trusted home-pairing-v1 JSON
# { protocol, home_url, installation_id, invitation_id, invitation_secret,
# user_id } (raw stays default for backward compatibility; never a backend hint).

# 5. Optional cloud coordination (S7, default disabled, zero network):
python3 scripts/me_lifecycle.py coordinator prepare --data-dir ~/.local/share/me-home \
  [--public-url https://home.example.com]   # no network; records install + local URL
# owner phone mints the one-time ticket, then (STDIN only, never argv/JWT):
python3 scripts/me_lifecycle.py coordinator activate --data-dir ~/.local/share/me-home < ticket.json
# service reload required (never auto-restarts active jobs), then verify:
python3 scripts/me_lifecycle.py stop --data-dir ~/.local/share/me-home
python3 scripts/me_lifecycle.py start --data-dir ~/.local/share/me-home
python3 scripts/me_lifecycle.py coordinator status --data-dir ~/.local/share/me-home
python3 scripts/me_lifecycle.py coordinator check --data-dir ~/.local/share/me-home
# Full sequence, tunnel gates, and recovery: docs/home-coordination-activation.md.

python3 scripts/me_lifecycle.py backup --data-dir ~/.local/share/me-home
# --scope db (default): online-safe SQLite snapshot API + checkpoint +
# header/integrity/id verification. Covers the SQLite database only — task
# workspaces, runtime checkpoints, and household files are NOT included.
python3 scripts/me_lifecycle.py backup --scope full --data-dir ~/.local/share/me-home
# --scope full: stopped-service .tar.gz archive (SQLite via backup API +
# per-task workspaces incl. .me_runtime/graph.db checkpoints + household
# files + manifest.json). Requires the managed service STOPPED (refuses
# while running/stale/port-held). Symlinks/hardlinks/device files are
# refused, never followed. Setup-owned config, logs, secrets/, run/,
# backups/, tmp/, service.env, operator env vars, and tunnel credential
# files are never read into the archive (not a bare-metal image). Workspace
# files ARE private household data and may hold user/agent-written secrets
# or browser sessions: no secret scanning, redaction, or encryption is
# performed or claimed — archive mode 0600, local-only, never uploaded.

python3 scripts/me_lifecycle.py stop --data-dir ~/.local/share/me-home [--force]
# Signals ONLY the verified managed process (pid + argv fingerprint + start
# time). Liveness uses `pid_exited()` (`ps` zombie check): zombies count as
# exited, so a reaped child is never reported as still running. Stale/foreign
# pidfiles are refused, never acted on. `--force` (SIGKILL) remains available
# but normal `stop` exits 0.

python3 scripts/me_lifecycle.py restore --data-dir ~/.local/share/me-home \
  --from backups/home-<ts>.sqlite --confirm-destructive
# --scope db (default, legacy): refuses while the service/port is up;
# verifies the source (magic + integrity + installation_id), preserves the
# current db as pre-restore-*, removes stale WAL sidecars, restores,
# re-verifies (readiness guard), adopts the restored authoritative id.
# Sessions/devices are preserved as archived (same semantics as before).
python3 scripts/me_lifecycle.py restore --scope full --data-dir ~/.local/share/me-home \
  --from backups/home-full-<ts>.tar.gz --confirm-destructive
# --scope full: two-pass streaming validation BEFORE any mutation (pass A is
# a header-only preflight with an honest unpacked-bytes free-space estimate,
# so a small archive hiding a large expansion is refused without filling the
# disk; pass B streams payloads in 64 KiB chunks with per-file/total caps on
# ACTUAL bytes). Rejects absolute / traversal / over-long-name / oversize
# PAX / symlink / hardlink / device / duplicate / oversize entries,
# over-cap manifests, manifest hash mismatches, SQLite integrity +
# installation_id mismatches, corrupt runtime-checkpoint SQLite (known
# checkpoint .db files must be valid SQLite; garbage magic denies), and
# checkpoint/thread or inbox binding mismatches. Bounds default to
# 20000 files / 1 GiB unpacked / 100 MiB per file / 1 GiB archive; the
# trusted operator may raise them via ME_HOME_FULL_MAX_{FILES,TOTAL_BYTES,
# FILE_BYTES,ARCHIVE_BYTES,MANIFEST_BYTES,PENDING_BYTES} (own shell only).
# Then: builds a scrubbed+verified ready tree, writes a durable write-ahead
# 0600 restore journal (intent fsync before each rename, done fsync after;
# journal file+dir fsync; full archive output flush/fsync before reporting),
# and swaps by same-filesystem rename (never recursive-wipe of live data;
# trees absent from the archive are left untouched, never deleted).
# Cross-filesystem layouts are refused (EXDEV) before any mutation with a
# clear error. The multi-object swap is NOT one atomic transaction: an
# interrupted restore leaves the journal `started`, and both `start` and the
# generated service guard refuse until recovery. Recovery reconciles
# in-progress intents against src/dst existence (idempotent, never deletes
# original data) then replays the rollback, reporting its own failures
# instead of claiming a recovery it did not perform.
# Restored sessions/devices/invitations are revoked/consumed while
# installation_id, users, conversations, tasks, artifacts, and checkpoints
# are preserved. Old phones stay revoked: pair fresh devices afterwards
# (`bootstrap --user <same-user>` + `/v1/pair`), then resume waiting tasks
# via `/v1/tasks/<id>/inputs`. Cross-path restores (different data dir)
# rebase ONLY the pending.json `workspace` binding to the canonical live
# path after validating run/task/binding match; the adopted
# installation_id is explicit under --confirm-destructive. If a backend
# endpoint registration maps installation_id to a host, update it to the
# restored home's host/port; endpoint rediscovery otherwise follows the
# normal `status`/`healthz` flow. Never accepts input account/user IDs as
# identity — installation_id always comes from the restored database.
python3 scripts/me_lifecycle.py restore-recover --data-dir ~/.local/share/me-home
# Replays an interrupted full restore's journal: rolls back journaled
# renames and the recorded config identity, verifies the prestate, clears
# the journal. Refuses while the service/port is up. With no journal there
# is nothing to do (exit 0).

python3 scripts/me_lifecycle.py tunnel configure --data-dir ~/.local/share/me-home \
  --hostname home.example.com --credential-file secrets/tunnel-cred.json
# Default protection=home-pairing (phone-compatible): HTTPS via the named
# tunnel, NO Access barrier; the home enforces one-time invitation enrollment,
# per-device revocable credentials, and session auth on every private route.
# Public surface is only minimal health plus the rate-limited pair/session
# endpoints (429 + Retry-After). Pair phones with the one-time invitation:
# https://home.example.com/v1/pair, then call the API with session auth.
# Optional provider edge path (NOT phone-app-ready):
#   --protection cloudflare-access --access-team myteam --access-aud <AUD-tag>
# emits the official originRequest.access block so the connector validates
# Access JWTs before proxying. It requires separate edge auth; native phone
# clients cannot complete it — use home-pairing for phones.
python3 scripts/me_lifecycle.py tunnel run  # needs cloudflared; else exit 4 (parked)
# run refuses unknown contracts, non-loopback bindings, unknown/mixed
# protection modes, and configs missing their mode's enforcement markers.
python3 scripts/me_lifecycle.py service --format launchd|systemd
# Files under config/ only (unit + shared pre-exec guard config/me-home.exec.py);
# never installs. Units exec the guard (python, no shell, no secrets), which
# re-checks the restore journal + loopback binding and only then execs Node
# via os.execv (same PID, signals preserved). Autostart therefore cannot bypass
# the interrupted-restore guard that `start` also enforces. Enable manually,
# see printed hints.
```

Role split (do not blur it): setup owns prerequisite validation, directory
layout, and non-secret config. The home service owns invitation issuance,
device enrollment, session tokens, and all household data. Setup never handles
raw pairing invitation secrets, device secrets, or session tokens — those are
returned once by the home service CLI/API and live in `secrets/` (connector +
admin, mode `0600`, never in tracked files) or on the enrolled phone.

`home_api.launch` in `config.json` repeats the exact start command for the
configured binding so operators copy it instead of reconstructing flags.

## Current behavior notes

- **Home service needs the TS transform flag:** `src/server.mjs`
  transitively imports `vendor/openmuse/.../worker.ts`, which uses
  non-erasable TypeScript syntax, so plain `node src/cli.mjs` crashes with
  `ERR_UNSUPPORTED_TYPESCRIPT_SYNTAX`. Lifecycle retries once with
  `--experimental-transform-types` and records the effective flags.
- **Shutdown works:** `stop` signals only the fingerprinted managed process
  and checks liveness with `pid_exited()` (zombies count as exited). A prior
  60s-hang report was a diagnostic error: it looped `os.kill(pid, 0)`,
  which reports zombies alive; it never called `pid_exited()`/`waitpid`.
  Normal `stop` exits 0.
- **Bridge is src-layout, not installed:** `me_runtime` imports only with
  cwd `<checkout>/src`; setup probes the checkout root first, then `src`,
  and records `unavailable-transient` (never fatal) when the bridge is
  unreachable. Bridge model config stays local-first; remote is explicit
  opt-in with the key in the operator shell only.

Verified here: `87 tests` pass
(`python3 -m unittest discover -s scripts -p 'test_*.py' -v`), including a
cross-path waiting-input backup/restore/resume round-trip against the real
home plus the real fixture bridge (home A -> home B with rebased checkpoint
binding, re-pair + answer -> completion after restore), plus streaming,
strict-checkpoint, binding, journaled-rollback, real-kill crash-window
(os._exit/SIGKILL after first move, fresh recover) and autostart-guard
(blocked guard binds nothing, recovered guard becomes ready) regressions —
and 18 S7 tests: prepare/activate/status/check, exact-schema 0600 persist,
wrong-install short-circuit, symlink/mode gates, no-JWT auth, redacted logs,
bad-reply/redirect/timeout/unknown-outcome, recovery rotation, notifications
wiring, pairing-v1, plus a real backend redeem + real home H8 heartbeat +
backend discovery round-trip (synthetic loopback only).
