# Session Handoff — setup-infra (2026-11-03)

> WIP draft on `feat/upstream-agent-infrastructure`. NOT main / production-ready. Original migration paused; only publication handoff complete. Parent owns all Git. Do not fix code now.

- Central handoff: https://github.com/mehomeai/.github/blob/feat/upstream-agent-infrastructure/docs/agent-infrastructure-handoff-2026-11-03.md (note: `../.github` is wrong from `docs/`; restore clones `.github` as `me-github`)
- Machine-readable: https://github.com/mehomeai/.github/blob/feat/upstream-agent-infrastructure/docs/agent-infrastructure-checkpoint/agent-infrastructure-checkpoint-2026-11-03.json
- Immutable snapshot (preserve): https://github.com/mehomeai/.github/blob/feat/upstream-agent-infrastructure/docs/agent-infrastructure-checkpoint/git-snapshot.json
- This repo branch: `feat/upstream-agent-infrastructure` (WIP draft)
- PR: https://github.com/mehomeai/setup-infra/pull/2
- Reported: supervisor 52/52, setup 24/24, lifecycle 27/27, coordinator 30/30, crashwindow 4/4, fullbackup 21/21; module-closure anchoring + bounded runner; `--require-backup` strict optional (operational READY excludes backup claims).
- CRITICAL ACTUAL RESULT `python3 -m unittest discover -s scripts -p "test_me*.py"`: ran 166 tests, 268.950s, FAILED 3 — `test_imported_dependency_tamper_fails_closure` (DoctorIntegrityCases), `test_generic_key_satisfies_native_check` (NativeKeyCases), `test_operational_ready_reachable_without_backup_claims` (OperationalReadinessCases). Highest-priority resume blockers; source deliberately preserved unfinished; suite NOT passing.
- Needs review: installer interrupted mid effective-key tests — partial code checkpointed, NOT finished; doctor closure + strict READY schema vs final contract; cache handshake with infra-server.
- Parent all-8 repository-health checks pass. Final post-push CI pending / not awaited.
- Resume: central restore snippet → inspect partial key-mapping/tests + manifest mismatch → narrow OpenCode fixes → Linux acceptance. Mandate: `opencode run` default model only.
