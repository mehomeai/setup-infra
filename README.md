# setup-infra

Local installation and infrastructure bootstrap for Me Home AI.

Part of [Me Home AI](https://github.com/mehomeai), a privacy-first home agentic system.
Learn about the vision at [Me — Your intelligence. Yours.](https://mehomeai.replit.app/me/).
## Status

This repository provides the rerunnable development setup and managed lifecycle
for the Me home service (implemented on review branch
`feat/home-agent-foundation`; committed/pushed; draft PR #1 pending
review/checks; no merge to protected `main`, no deployed release):
`scripts/me_setup.py` (prerequisites, config, non-secret environment) and
`scripts/me_lifecycle.py` (managed start/status/stop, home-CLI bootstrap,
cloud-coordination activation (`coordinator prepare/activate/status/check`,
S7), scoped backup/restore (`--scope db` SQLite snapshot, `--scope full`
stopped-service household archive), fail-closed named-tunnel adapter,
service-unit generation with a shared pre-exec guard). Verified (final):
**99 pass / 0 fail** (`python3 -m unittest discover -s scripts -p
'test_*.py' -v`, 229.8s),
including live end-to-ends against the real home API: pairing/conversation
plus a fixture agent task through the real runtime bridge, a cross-path
waiting-input backup/restore/resume round-trip (home A -> home B, rebased
checkpoint binding, re-pair + answer -> completion), and a real backend
redeem + real home heartbeat + backend discovery round-trip (S7, synthetic
loopback only). Overall evidence:
`backend-server/docs/final-validation.md`. Start injects the exact trusted env
the home reads (`ME_RUNTIME_ARGV` JSON array + `ME_RUNTIME_CWD`,
`HOME_MODEL_PROVIDER/NAME/ENDPOINT`, `HOME_ALLOW_FIXTURE_MODEL`,
`ME_RUNTIME_ALLOW_REMOTE`, `HOME_CAP_*`, `ME_RUNTIME_ALLOW_CODE_EXEC`,
`ME_RUNTIME_SANDBOX=docker` when code execution is explicitly enabled;
coordination/notification references when explicitly enabled;
secrets inherited from the operator shell only, never persisted). Local
endpoint is the ChatOllama-correct `http://127.0.0.1:11434` (no `/v1`).
Household data and execution stay on the home host; an explicitly enabled
remote provider receives the scoped prompt/history/tool context. Start the
loopback home once (or bootstrap the initial DB) so SQLite mints the REAL
authoritative `installation_id` before `coordinator prepare`/`activate` —
the fresh-setup reserved config UUID is NOT usable as identity. `backup`/`restore --scope db`
(default) cover the SQLite database only (online-safe API + verification);
`--scope full` archives the database (backup API) plus per-task workspaces
including `.me_runtime` checkpoints, household files, and a manifest —
config/logs/secrets excluded, local-only, never uploaded. Full restore
validates before mutating, swaps by same-filesystem rename under a durable
write-ahead journal (NOT one atomic transaction) with rollback, and revokes
restored sessions/devices/invitations (pair fresh devices afterwards), so a
rolled-back backup cannot revive a revoked phone. Generated launchd/systemd
units exec the shared guard (config/me-home.exec.py), which refuses to boot
on an interrupted restore and only then execs Node. Default tunnel mode
is `home-pairing` (HTTPS via the named tunnel, phone-app compatible); the
optional `cloudflare-access` mode enforces Access JWTs at the edge and needs
separate edge auth (native phone clients cannot complete it). No root, no
global install, no public endpoint; service units and tunnel launches are
explicit operator actions.

Planned next (not implemented yet): the home computer installs OpenCode;
setup-infra acts as the independent supervisor with a persisted
machine-verifiable checklist, continues OpenCode when it replies/stops
early, and provides bounded retries/stall detection plus a
needs-user-input state. THIS LAYER IS NOT IMPLEMENTED YET; the current
deterministic setup/lifecycle tools form the executor/check foundation.

```sh
python3 scripts/me_setup.py setup [--data-dir DIR] [--port N]
python3 scripts/me_setup.py check [--data-dir DIR]
python3 scripts/me_lifecycle.py start|status|stop|bootstrap|coordinator|backup|restore|tunnel|service ...
python3 scripts/me_lifecycle.py backup --scope full [--output OUT.tar.gz]      # service stopped only
python3 scripts/me_lifecycle.py restore --scope full --from OUT.tar.gz --confirm-destructive
python3 scripts/me_lifecycle.py coordinator prepare|activate|status|check      # S7, STDIN ticket-only
python3 -m unittest discover -s scripts -p 'test_*.py' -v
```

See [`docs/home-coordination-activation.md`](docs/home-coordination-activation.md)
for the exact S7 operator sequence, manual hardware/tunnel gates, and
recovery (fresh recovery tickets, lost-credential reactivation).

See [`docs/development-setup.md`](docs/development-setup.md) for the full flow
and [`docs/production-tunnel-boundary.md`](docs/production-tunnel-boundary.md)
for the tunnel adapter and parked provider checks. The home entrypoint needs
`--experimental-transform-types`; lifecycle retries once with it automatically.

## Scope

Installation, local prerequisites, configuration, upgrades, and recovery.

The setup flow provisions a protected home endpoint through a named tunnel
and starts one-time phone pairing. Provider connector credentials stay with
the home/provisioning service; each enrolled phone gets separate, revocable
application access. The cross-repository design is recorded in
`infra-server/docs/connection-and-pairing.md`.

## Contributing

Start with the [contribution guide](https://github.com/mehomeai/.github/blob/main/CONTRIBUTING.md),
[code of conduct](https://github.com/mehomeai/.github/blob/main/CODE_OF_CONDUCT.md), and
[governance](https://github.com/mehomeai/.github/blob/main/GOVERNANCE.md).
Discuss substantial changes in an issue before implementing them. Pull requests
should include relevant tests and documentation once application code exists.

For questions and cross-project planning, use [community discussions](https://github.com/mehomeai/.github/discussions).
Report vulnerabilities privately through this repository's **Security → Report a vulnerability**;
see the [security policy](https://github.com/mehomeai/.github/blob/main/SECURITY.md).

## License

[Apache License 2.0](LICENSE). Third-party code, model weights, and datasets may
have their own terms and must be reviewed before inclusion.
