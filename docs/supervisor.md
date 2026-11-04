# OpenCode setup supervisor (`scripts/me_supervisor.py`)

Autonomous installer/supervisor for the Me home. The home computer installs
OpenCode; this supervisor drives it with a persisted, machine-verifiable
checklist, continues OpenCode when it replies/stops early, and parks for the
operator instead of faking completion.

Parent authority (load-bearing): the supervisor process re-runs STATIC
trusted checks after every agent turn. Conversational "done", CLI exit 0, or
a config flag written by the agent NEVER counts unless ALL required checks
PASS with actual filesystem/service evidence.

## Commands

```sh
# fresh supervised run (workspace = explicit agent working dir)
python3 scripts/me_supervisor.py start --data-dir DIR --workspace DIR [--require-service] [--allow-install] [--max-attempts 8] [--max-stagnant 3] [--attempt-timeout 300] [--wall-timeout 1800] [--upstream-doctor PATH] [--upstream-contract PATH] [--require-backup]

# live verifier state (redacted)
python3 scripts/me_supervisor.py status --data-dir DIR

# resume a persisted RUNNING/STALLED/FAILED run (keeps attempts/session)
python3 scripts/me_supervisor.py resume --data-dir DIR

# run the trusted verifiers once, no agent (operator preflight)
python3 scripts/me_supervisor.py recheck --data-dir DIR [--require-service] [--upstream-doctor PATH] [--upstream-contract PATH] [--require-backup]

# OpenCode binary path: show official installer plan / install if missing
python3 scripts/me_supervisor.py install-check [--allow-install]
```

State: `<data-dir>/supervisor/run.json` (0600, dir 0700, atomic, versioned).
Lock: `<data-dir>/supervisor/lock` (second concurrent run refuses; fcntl
exclusive, stale content is message-only and overwritten by the next holder).
Doctor anchor: `<data-dir>/supervisor/doctor.sha256` (0600; JSON closure
digest + file map of the trusted module closure).

Exit codes: `0` READY (`production`), `0` CONFIGURED (`configure` profile,
explicitly not complete), `0` TEST_READY (`test` profile, synthetic only),
`1` FAILED/STALLED, `2` usage/lock, `3` prerequisite (install refusal),
`4` NEEDS_INPUT (genuine external gate parked, redacted).

## Check states

| State        | Meaning |
|--------------|---------|
| `RUNNING`    | required checks failing; agent turns continue (bounded) |
| `READY`      | ALL required checks PASS with evidence (parent-verified, production only) |
| `CONFIGURED` | configure profile verified (explicitly not complete, never production READY) |
| `TEST_READY` | TEST profile verified (fixture/synthetic only, never production READY) |
| `NEEDS_INPUT`| genuine external gate: missing OpenCode binary approval, operator credential/license/hardware, explicit user approval. Structured redacted reason; loop stops, no burn |
| `STALLED`    | N turns with no verifier progress (chat-only replies don't count; digests strip timestamps/random text). Bounded stop; fix manually, `resume` |
| `FAILED`     | attempt or wall-clock budget exhausted |

Required checks (always): `opencode_cli`, `prereqs`, `config`, `storage`,
`db_identity` (authoritative home-DB installation id), `model_profile`
(exact configured API, really probed). Production adds the live platform bar:
`upstream_platform` (TRUSTED upstream-doctor subprocess, see below),
`backup_coverage` (FULL storage bar per A datastorage-contract), plus
`home_health` (`/healthz` contract + id) and `service_runtime` when service
is required. `owner_token` joins when coordination is enabled. `upstream_stack`
and unconfigured capabilities stay explicit `OPTIONAL` — never skip-as-pass,
and a legacy `fixture` provider NEVER reports production READY (only the
named TEST profile completes as TEST_READY).

Failed checks print concrete `next:` commands that are repeated into the
next OpenCode turn. Optional checks list separately as informational.

## Upstream platform: trusted doctor only

`upstream_platform` PASSes ONLY from a LIVE trusted upstream-doctor
subprocess (`upstream-platform-v1`, A-owned infra-server
`src/upstream-doctor.mjs` via `node --experimental-transform-types
src/cli.mjs upstream-doctor`, probing ENABLED), run with cwd = the doctor's
own module root (the doctor resolves its vendor manifest from there, never
from the caller's data dir):

- Discovery: `--upstream-doctor` / `ME_UPSTREAM_DOCTOR` / config
  `upstream.doctor_bin` / `<data-dir>/upstream/bin/upstream-doctor` /
  sibling `../infra-server/src/cli.mjs`. Symlinks refused anywhere.
- Contract gate (fail-closed): the live report must carry
  `doctor_contract == "upstream-platform-v1/full.1"` (top-level or
  `checks.doctor_contract`; C's required marker, published in
  `results/setup-wire-contract.json` for A to implement in
  `results/setup-doctor-contract.json`) AND every name in the required
  evidence set with verified values. Minimal/forged READY, arbitrary JSON
  keys, generic `/healthz` 200s, `probe:false` anywhere, `unknown`
  sentinels, or missing required evidence can NEVER authorize READY.
- Required evidence (published names): `checks.mode` (full),
  `checks.upstream` + `checks.sourcePin` (pinned repo+ref, files>0),
  `checks.config` (gate pass, no missing), `checks.supervisor` (health ok,
  docker true, authenticated list), `checks.perUserBoundary`,
  `checks.versions` (pinned), `checks.license` (required+key, self-hosted),
  `checks.upstreamServer` (health ok), `checks.postgres` (configured),
  `checks.intelligence` (key, self-hosted), `checks.model` (non-fixture),
  `checks.telemetry` (product telemetry off), `checks.datastore`,
  `checks.probe` (true).
- Integrity over the module CLOSURE (entrypoint hash alone is NOT trust:
  imported `upstream-doctor/config/computer` modules are mutable): every
  `*.mjs` under the doctor module root + the vendor manifest (+ approved
  patches via `ME_UPSTREAM_APPROVED_PATCHES` when declared) is hashed; the
  operator pins the closure via `ME_UPSTREAM_DOCTOR_SHA256` or provides the
  release manifest via `ME_UPSTREAM_DOCTOR_MANIFEST`. Checked on every
  invocation/resume AND re-verified after each run (swap-during-run race).
  No pin/manifest on first sight = unverified source: NEEDS_INPUT (never
  silent TOFU); tamper/mismatch = FAIL. Legacy entrypoint-only anchors are
  NOT carried over. A source checkout stays separate from this immutable
  verifier.
- Invocation is bounded like agent turns (streaming caps, 64 KiB doctor cap
  with flood kill, process-group TERM→KILL→reap, residual pipe-holder kill
  via spawn-time pgid, bounded joins, shared ACTIVE deadline, signals
  persist RUNNING).
- Doctor NEEDS_INPUT (missing license/model/hardware) parks as NEEDS_INPUT
  (independent fixable checks continue meanwhile); FAILED (drift, unsafe
  SINGLE_USER, tamper, unhardened report) is FAIL. Missing/unpinned doctor
  parks as NEEDS_INPUT. Cached/operator-written reports never authorize
  READY (only live subprocess stdout is parsed).

## Backup scope: explicit unsupported capability, opt-in requirement

Operational agent readiness does NOT claim backup-complete. Complete
upstream backup (Postgres + Intelligence threads + computer volumes) is an
explicit SEPARATE unsupported capability (`backup.supported=false`) until a
real verifiable upstream backup path lands. The SQLite-only archive covers
sqlite+tasks+household ONLY and must never be labelled complete
full-platform; `backup full` / `restore full` refuse incomplete archives
explicitly, and actual legacy backup behavior is preserved.

- Default (no `--require-backup`): `backup_coverage` is OPTIONAL stating
  `backup.supported=false`, so operational READY stays reachable without
  disguising the gap as an operator gate.
- Explicit `--require-backup` (or `ME_REQUIRE_BACKUP=1`) product policy:
  truthfully UNSUPPORTED/NOT READY (FAIL with the concrete integration
  path per `results/datastorage-contract.json`), never a checkbox PASS --
  with or without declared volumes (omission hides nothing).
- The `READY` evidence notes the exclusion explicitly
  (`backup.supported=false ... backups excluded/unsupported`).

## Operator gates (honest parking)

- OpenCode missing -> `NEEDS_INPUT opencode-not-installed`; user-invoked
  `start` installs by default (official installer
  `https://opencode.ai/install`, checksums at
  `https://github.com/anomalyco/opencode/releases`, pinned digest via
  `OPENCODE_INSTALLER_SHA256`, version via `OPENCODE_VERSION`, platform/arch
  validated, no silent unsupported OS; opt out with `--no-install`) or
  install manually and `resume`. `install-check --allow-install` is explicit.
- The DEV CLI is never installed/downgraded/modified (`--allow-install`
  only acts when the binary is missing; existing binaries are left alone;
  no XDG overrides are set).
- Remote model credentials, tunnel credentials, licenses, hardware, and
  explicit user approvals park as `NEEDS_INPUT` with a redacted reason;
  other independent fixes continue where possible.
- Setup CLI model/auth is DISTINCT from the product native harness model: a
  fresh home can have the binary with no CLI auth. Structured CLI
  authentication errors park as `NEEDS_INPUT opencode-cli-auth-required`
  (secure `opencode auth login` + resume; default model preserved; never a
  STALLED burn; developer auth files never read). Only CLI-level signals
  count (stderr + JSON error parts), never agent prose.
- Explicit backup requirement (`--require-backup` / `ME_REQUIRE_BACKUP=1`)
  is an honest UNSUPPORTED FAIL (concrete integration path), never an
  operator gate and never a checkbox PASS.
- Unmigrated configs (no `upstream` section) park as NEEDS_INPUT until the
  operator selects `full|core` explicitly (fresh installs default full;
  reruns preserve the explicit choice; core = computer-plane dev/partial,
  not the original Me runtime).
- Scoped OpenCode permissions: each turn inherits the operator env plus a
  scoped `OPENCODE_PERMISSION` allowing ONLY the installation-owned
  `<workspace>/**` and `<data-dir>/**` trees (never global config, never
  personal paths; operator denies win; `OPENCODE_CONFIG_CONTENT` passes
  through untouched). Permission-denied/question signals
  are captured as bounded structured events classified `taskpath` (our scope)
  vs `external` (agent left scope).

## Safety notes

- Secrets never persisted in state/logs/prompts (all output via redact()).
  State shows digests + truncated redacted evidence. Symlinked state/lock/
  anchor/doctor paths refused.
- Bounded: attempts (8), stagnant turns (3), attempt wall time (300s),
  whole-run wall time as ACTIVE seconds (1800s; parked NEEDS_INPUT/STOPPED
  time excluded, monotonic window, resume keeps attempts/session and may
  raise bounded budgets explicitly), stdout/stderr caps (256 KiB each,
  4x flood kill), 200 events, 4096B/line, 200 kept lines. Session IDs latch
  DURING streaming (survive tail eviction), strict JSON envelope parse only.
  Timeout/flood kills the whole agent process group (SIGTERM -> SIGKILL ->
  reap); exited leaders with pipe-holding grandchildren get residual-group
  kill before close (no close/read deadlock); joins bounded; no orphans.
  Whole-lifecycle SIGINT/SIGTERM (including during checks) persist RUNNING
  for `resume` and return 130/143 without launching new turns.
- The agent works in the explicit `--workspace` only (default: cwd) and may
  touch setup-infra files only; completion criteria are never its choice.
- Checker integrity is the parent process re-reading the filesystem/DB/HTTP
  service plus the anchored trusted doctor. Same-user-root tamper-proofing
  is NOT claimed beyond the anchored digest gate.
