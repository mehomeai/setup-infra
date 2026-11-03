#!/usr/bin/env python3
"""Pre-exec guard for generated launchd/systemd units (setup-infra task).

Generated service units never exec Node directly: their ProgramArguments /
ExecStart run this wrapper as `[python, me-home.exec.py, --data-dir DIR,
--node NODE, --entrypoint ENTRY]`. The wrapper verifies its own config and
restore journal and only then replaces itself with the real home service via
os.execv (same PID, so SIGTERM/signals go straight to Node; no orphan shim,
no shell, no persisted secrets).

Checks (mirroring me_lifecycle.do_start's fail-closed guard):
- config must load and bind loopback only;
- an interrupted full restore (journal status `started`) refuses with the
  same `restore-recover` message instead of booting mixed data.

On success the wrapper execs:
  [node, *node_args_for(node, entrypoint), entrypoint, start,
   --db=.. --host=.. --port=..]
with the inherited unit environment (HOME_* from the unit, secrets only from
the service context, never baked in) and cwd set to the checkout root.
"""

from __future__ import annotations

import argparse
import os
import sys
from pathlib import Path

_SETUP_SCRIPTS_DIR = "@SETUP_SCRIPTS_DIR@"  # replaced at generation time

sys.path.insert(0, str(Path(__file__).resolve().parent))
if _SETUP_SCRIPTS_DIR and not _SETUP_SCRIPTS_DIR.startswith("@"):
    sys.path.insert(0, _SETUP_SCRIPTS_DIR)

import me_lifecycle
import me_setup


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(description="Guarded home service exec (no install)")
    p.add_argument("--data-dir", required=True)
    p.add_argument("--node", required=True)
    p.add_argument("--entrypoint", required=True)
    return p


def main(argv: list | None = None) -> int:
    args = build_parser().parse_args(argv)
    try:
        data_dir = me_setup.resolve_data_dir(args.data_dir)
    except me_setup.SetupError as exc:
        print(f"me-home.exec: error: {exc}", file=sys.stderr, flush=True)
        return 2
    try:
        _, cfg = me_lifecycle.load_cfg(data_dir)
    except me_setup.SetupError as exc:
        print(f"me-home.exec: error: {exc}", file=sys.stderr, flush=True)
        return 2
    try:
        host = cfg["service"]["host"]
        port = int(cfg["service"]["port"])
        db_path = str(cfg["service"]["db_path"])
    except (KeyError, ValueError, TypeError) as exc:
        print(f"me-home.exec: error: bad service config ({exc})",
              file=sys.stderr, flush=True)
        return 2
    if host not in me_setup.LOOPBACK_HOSTS:
        print(f"me-home.exec: error: refusing non-loopback host {host}",
              file=sys.stderr, flush=True)
        return 2
    blocked = me_lifecycle.incomplete_journal(data_dir)
    if blocked is not None:
        print(f"me-home.exec: error: refusing to start: interrupted full restore "
              f"(journal {blocked.name}); live data may be mixed. Run "
              f"`restore-recover --data-dir {data_dir}` first, then retry.",
              file=sys.stderr, flush=True)
        return 1
    node_bin = args.node
    entrypoint = Path(args.entrypoint)
    if not Path(node_bin).is_file() and not node_bin.startswith("/"):
        # Allow bare `node` resolved via PATH for hand-written units; prefer
        # absolute paths in generated units.
        pass
    try:
        flags = me_setup.node_args_for(node_bin, entrypoint)[1:]
    except me_setup.SetupError as exc:
        print(f"me-home.exec: error: {exc}", file=sys.stderr, flush=True)
        return 2
    if not entrypoint.is_file():
        print(f"me-home.exec: error: home entrypoint missing: {entrypoint}",
              file=sys.stderr, flush=True)
        return 3
    argv_exec = [node_bin, *flags, str(entrypoint), "start",
                 f"--db={db_path}", f"--host={host}", f"--port={port}"]
    workdir = str(entrypoint.parent.parent)
    try:
        os.chdir(workdir)
    except OSError as exc:
        print(f"me-home.exec: error: cannot chdir to {workdir}: {exc}",
              file=sys.stderr, flush=True)
        return 1
    try:
        os.execv(node_bin, argv_exec)
    except OSError as exc:
        print(f"me-home.exec: error: exec node failed: {exc}",
              file=sys.stderr, flush=True)
        return 1
    return 1  # unreachable


if __name__ == "__main__":
    sys.exit(main())
