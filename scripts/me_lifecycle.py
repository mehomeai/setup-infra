#!/usr/bin/env python3
"""Usable development lifecycle for the Me home service (setup-infra task S2).

Small, explicit operator commands around the H1 home service and the optional
named-Cloudflare-tunnel adapter. Complements scripts/me_setup.py (which owns
prerequisites, config, and non-secret environment):

- start/status/stop manage ONLY the home process this tool started, tracked by
  run/home-service.pid plus an argv fingerprint. A stale or foreign pidfile is
  never acted on: stop/status refuse instead of killing unrelated processes.
- bootstrap calls the home's actual local CLI (src/cli.mjs bootstrap) and
  displays the one-time invitation material only to the local operator
  (stdout). It is never written to log files or tracked files.
- backup/restore have two explicit scopes: --scope db (default, SQLite backup
  API snapshot, WAL-safe online, plus header + integrity + installation_id
  guards) and --scope full (stopped-service .tar.gz of SQLite + per-task
  workspaces incl. .me_runtime checkpoints + household files + manifest;
  setup-owned config/logs/secrets excluded, local-only; workspace files ARE
  private household data and may hold user-written secrets -- no scanning or
  redaction claimed). Full restore streams validation in two passes
  (header-only preflight with an honest unpacked free-space estimate, then
  bounded 64 KiB-chunk extraction with caps on actual bytes), rebases
  pending.json workspace bindings cross-path after run/task/binding checks,
  requires strict checkpoint SQLite integrity, and swaps by same-filesystem
  rename under a durable write-ahead 0600 journal (intent fsync before each
  rename, done fsync after; journal file+dir fsync; pre-restore preservation
  + rollback that reports its own failures; multi-object swap is NOT one
  atomic transaction). restore-recover reconciles in-progress intents against
  src/dst existence and replays the rollback idempotently; start refuses
  while a journal is open. Cross-filesystem layouts are refused (EXDEV)
  before any mutation. Full restore
  scrubs restored sessions/devices/invitations (fresh pairing required).
  Restore refuses while the managed service (or anything on its port) is up
  and requires explicit --confirm-destructive.
- tunnel configure/run/status is an optional named-tunnel adapter over an
  existing cloudflared binary and an externally supplied least-privileged
  credential file (mode 0600, never logged, never in argv, never in a phone
  QR). It fails closed without hostname + credential + Access-team protection
  config. Quick Tunnels are refused. No account provisioning or public
  endpoint is created here; credential-dependent live checks are parked for
  the user (exit 4).
- service generate writes launchd/systemd unit files into config/ only plus a
  shared pre-exec guard (config/me-home.exec.py). Units exec the guard
  (python, no shell, no secrets), which re-checks the restore journal and
  loopback binding and only then execs Node (same PID, signals preserved);
  autostart therefore cannot bypass the interrupted-restore guard that
  `start` also enforces. It never installs anything globally; it prints the
  manual enable commands.

Loopback only: start refuses non-loopback hosts, and the home CLI itself warns
on non-loopback binds. No sudo, no system/root mutation, no downloads.

Exit codes: 0 ok, 1 operation/state failure, 2 usage/validation, 3 missing
prerequisite, 4 parked external dependency (tunnel run without cloudflared,
bridge unavailable where a live bridge is required).
"""

from __future__ import annotations

import argparse
import contextlib
import datetime
import errno
import json
import os
import re
import shlex
import shutil
import signal
import sqlite3
import stat
import subprocess
import sys
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

import me_setup
import me_coordinator

EXIT_PARKED = 4
STOP_GRACE_SECONDS = 10
START_READY_SECONDS = 15

PIDFILE_RELPATH = Path("run") / "home-service.pid"
TUNNEL_PIDFILE_RELPATH = Path("run") / "cloudflared.pid"


# Secrets inherited from the operator environment only, never persisted.
# The home reads exactly this key for remote providers (see H3
# runtime-config.mjs); setup never writes it anywhere. HOME_EXPO_ACCESS_TOKEN
# (H7 optional push provider token) follows the same rule: memory-only.
RUNTIME_SECRET_ALLOWLIST = ("ME_RUNTIME_MODEL_API_KEY",)
PUSH_SECRET_ALLOWLIST = ("HOME_EXPO_ACCESS_TOKEN",)


def build_home_env(cfg: dict) -> dict:
    """Build the trusted home-service environment from generated config.

    Emits exactly the keys H3's runtime-config.mjs / R5 exec.py read
    (verified read-only): ME_RUNTIME_ARGV (JSON array, space-safe) +
    ME_RUNTIME_CWD, HOME_MODEL_*, HOME_ALLOW_FIXTURE_MODEL,
    ME_RUNTIME_ALLOW_REMOTE, HOME_CAP_*, ME_RUNTIME_ALLOW_CODE_EXEC, and
    ME_RUNTIME_SANDBOX=docker when code execution is explicitly enabled
    (Docker-only; no host fallback; missing docker/image is an honest
    prerequisite denial). Absent/false host flags are omitted (H3 treats
    absent as false). Secret values are inherited from the operator's own
    environment only when present there, and are never persisted by setup.
    """
    env: dict[str, str] = {}
    bridge = cfg.get("runtime_bridge", {}) or {}
    if bridge.get("status") == "importable" and bridge.get("python"):
        env["ME_RUNTIME_ARGV"] = json.dumps([bridge["python"], "-m", "me_runtime.bridge"])
        if bridge.get("import_cwd"):
            env["ME_RUNTIME_CWD"] = bridge["import_cwd"]
    models = cfg.get("models", {}) or {}
    provider = str(models.get("provider", "local") or "local")
    env["HOME_MODEL_PROVIDER"] = provider
    if models.get("name"):
        env["HOME_MODEL_NAME"] = str(models["name"])
    if provider == "fixture":
        if models.get("allow_fixture"):
            env["HOME_ALLOW_FIXTURE_MODEL"] = "1"
    else:
        if models.get("endpoint"):
            env["HOME_MODEL_ENDPOINT"] = str(models["endpoint"])
    if provider in ("openai", "anthropic") and models.get("allow_remote"):
        env["ME_RUNTIME_ALLOW_REMOTE"] = "1"
    if provider == "openai" and models.get("use_responses_api"):
        env["HOME_MODEL_USE_RESPONSES_API"] = "true"
    caps = models.get("capabilities", {}) or {}
    if caps.get("web_fetch"):
        env["HOME_CAP_WEB_FETCH"] = "1"
    if caps.get("browser"):
        env["HOME_CAP_BROWSER"] = "1"
    if caps.get("animation"):
        env["HOME_CAP_ANIMATION"] = "1"
    if caps.get("code_exec"):
        env["HOME_CAP_CODE_EXEC"] = "1"
    if models.get("allow_code_exec"):
        env["ME_RUNTIME_ALLOW_CODE_EXEC"] = "1"
    if models.get("code_sandbox") == "docker":
        env["ME_RUNTIME_SANDBOX"] = "docker"
    egress = [h for h in (caps.get("egress") or []) if h]
    if egress:
        env["HOME_CAP_EGRESS"] = ",".join(egress)
    # S7 coordinator (default disabled): wire the PRIVATE file reference only
    # when the operator enabled coordination. Only the absolute PATH crosses
    # here; the home_token itself lives in the 0600 file (H8 reads it).
    coord = cfg.get("coordinator", {}) or {}
    if coord.get("enabled") and (coord.get("credentials_file") or "").strip():
        env["HOME_COORDINATOR_CREDENTIALS_FILE"] = str(coord["credentials_file"]).strip()
        if coord.get("allow_http_loopback"):
            env["HOME_COORDINATOR_ALLOW_HTTP_LOOPBACK"] = "1"
    elif os.environ.get("HOME_COORDINATOR_CREDENTIALS_FILE", "").strip() and coord.get("enabled"):
        # Explicit shell override honored only when config enables wiring.
        env["HOME_COORDINATOR_CREDENTIALS_FILE"] = os.environ["HOME_COORDINATOR_CREDENTIALS_FILE"].strip()
    # H7 notifications (default disabled): public project id is config; the
    # optional access token is inherited from the operator shell only, never
    # persisted anywhere by setup.
    notif = cfg.get("notifications", {}) or {}
    if notif.get("enabled"):
        env["HOME_NOTIFICATIONS_ENABLED"] = "1"
        if (notif.get("expo_project_id") or "").strip():
            env["HOME_EXPO_PROJECT_ID"] = str(notif["expo_project_id"]).strip()[:128]
    # Inherit authorized secrets from the operator shell only. Never written
    # to files by setup; the home reads them from its own process env.
    for name in (*RUNTIME_SECRET_ALLOWLIST, "HOME_EXPO_ACCESS_TOKEN"):
        if os.environ.get(name):
            env[name] = os.environ[name]
    return env


# --- shared helpers ----------------------------------------------------------

def err(msg: str) -> None:
    print(me_setup.redact(msg), file=sys.stderr, flush=True)


def out(msg: str) -> None:
    print(msg, flush=True)


def utc_stamp() -> str:
    return datetime.datetime.now(datetime.timezone.utc).strftime("%Y%m%dT%H%M%SZ")


def load_cfg(data_dir: Path) -> tuple[Path, dict]:
    data_dir = me_setup.resolve_data_dir(data_dir)
    return data_dir, me_setup.load_config(data_dir)


def resolve_node(explicit: str | None) -> str:
    node_bin, detail = me_setup.find_node(explicit or None)
    if not node_bin:
        raise me_setup.SetupError(f"no compatible node found: {detail}")
    return node_bin


def resolve_home_cli(infra_checkout: str | None) -> tuple[Path, Path]:
    """Return (checkout dir, cli entrypoint). Raises SetupError (transient H1 dep)."""
    checkout = me_setup.resolve_checkout(
        infra_checkout or None, "ME_HOME_INFRA_CHECKOUT", "infra-server",
        ("src/cli.mjs", "src/server.mjs"), "home service")
    if checkout is None:
        raise me_setup.SetupError(
            "infra-server checkout not found (pass --infra-checkout, set "
            "ME_HOME_INFRA_CHECKOUT, or place it at ../infra-server). "
            "H1 may still be modifying home; rerun when stable.")
    mjs, ts = checkout / "src" / "cli.mjs", checkout / "src" / "cli.ts"
    if mjs.is_file():
        return checkout, mjs
    if ts.is_file():
        return checkout, ts
    raise me_setup.SetupError(
        f"home CLI entrypoint missing under {checkout}/src (expected cli.mjs); "
        "H1 may still be modifying home; rerun when stable.")


def run_home_cli(node_bin: str, entrypoint: Path, cli_args: list, *,
                env: dict | None = None, cwd: str | None = None,
                timeout: int = 60) -> subprocess.CompletedProcess:
    """Run the home CLI once, retrying with TypeScript transform flags.

    Same policy as start: H1's entrypoint is plain ESM but may transitively
    import .ts with non-erasable syntax while H1 is mid-migration. One retry
    with H1's own spike-script flags, then the caller reports honestly.
    """
    argv = [*me_setup.node_args_for(node_bin, entrypoint), str(entrypoint), *cli_args]
    try:
        proc = subprocess.run(argv, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                              timeout=timeout, text=True, env=env, cwd=cwd)
    except (OSError, subprocess.SubprocessError) as exc:
        raise me_setup.SetupError(f"home CLI failed to run: {exc}")
    if (proc.returncode != 0
            and "ERR_UNSUPPORTED_TYPESCRIPT_SYNTAX" in (proc.stderr or "")
            and "--experimental-transform-types" not in argv):
        # Invitation material must stay stdout-only: this policy note goes to
        # stderr so a piped/parsed stdout stays pure JSON.
        err("home CLI needs TypeScript transform flags; retrying once "
            "with --experimental-transform-types")
        argv = [node_bin, *me_setup.NODE_TS_FLAGS, str(entrypoint), *cli_args]
        try:
            proc = subprocess.run(argv, stdout=subprocess.PIPE,
                                  stderr=subprocess.PIPE, timeout=timeout,
                                  text=True, env=env, cwd=cwd)
        except (OSError, subprocess.SubprocessError) as exc:
            raise me_setup.SetupError(f"home CLI failed to run: {exc}")
    return proc


def spawn_home(node_bin: str, entrypoint: Path, extra_node_flags: list,
               cli_args: list, env: dict, cwd: str, log_path: Path):
    """Spawn the home service detached, logging to log_path. Returns Popen.

    extra_node_flags covers the TypeScript case: H1's service entrypoint is
    plain ESM, but it may transitively import .ts with non-erasable syntax
    (H1 work in progress); then Node needs --experimental-transform-types,
    the same flags H1's own spike scripts use. The caller decides the policy.
    """
    argv = [node_bin, *extra_node_flags, str(entrypoint), *cli_args]
    fh = open(log_path, "a", encoding="utf-8")
    try:
        proc = subprocess.Popen(argv, stdout=fh, stderr=subprocess.STDOUT,
                                start_new_session=True, env=env, cwd=cwd)
    finally:
        fh.close()  # child keeps its own fd; do not leak ours (ResourceWarning)
    return proc, argv


def tail_of(path: Path, limit: int = 2000) -> str:
    try:
        text = path.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return ""
    return text[-limit:]


def pidfile_path(data_dir: Path) -> Path:
    return data_dir / PIDFILE_RELPATH


def read_pidfile(data_dir: Path) -> dict | None:
    pf = pidfile_path(data_dir)
    if not pf.is_file():
        return None
    try:
        record = json.loads(pf.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return {"pid": None, "corrupt": True, "path": str(pf)}
    return record if isinstance(record, dict) else {"pid": None, "corrupt": True}


def pid_stat(pid: int) -> str | None:
    """Short process state (e.g. 'R', 'S', 'Z+') or None when unreadable."""
    try:
        out = subprocess.check_output(["ps", "-p", str(pid), "-o", "stat="],
                                      stderr=subprocess.STDOUT, timeout=10,
                                      text=True).strip()
    except (OSError, subprocess.SubprocessError):
        return None
    return out.split()[0] if out else None


def pid_exited(pid: int) -> bool:
    """True when the pid is gone, or a zombie awaiting reap.

    A child stopped by our SIGTERM/SIGKILL stays a zombie while its spawner
    lives (same-process start/stop, tests, library use). kill(pid, 0)
    succeeds on zombies, so a naive alive-check would report a successful
    stop as "still running" forever. Zombies hold no resources and never
    come back: treat them as exited.
    """
    try:
        os.kill(pid, 0)
    except ProcessLookupError:
        return True
    except PermissionError:
        return False
    st = pid_stat(pid)
    return st is not None and st.startswith("Z")


def pid_alive(pid: int) -> bool:
    """True when the pid exists and is not a zombie (see pid_exited)."""
    return not pid_exited(pid)


def pid_cmdline(pid: int) -> str | None:
    """Return the full command line of pid, or None when it cannot be read."""
    try:
        out_ = subprocess.check_output(["ps", "-p", str(pid), "-o", "args="],
                                       stderr=subprocess.STDOUT, timeout=10,
                                       text=True).strip()
    except (OSError, subprocess.SubprocessError):
        return None
    return out_ or None


def fingerprint_matches(record: dict, cmdline: str | None) -> bool:
    """True only when the live cmdline is recognisably OUR managed process.

    Signals: normalized executable token (case/version-insensitive, so the
    macOS app-bundle "Python" matches a "python3" binary), the home entrypoint
    marker, the exact db path and port, plus a start-time check against pid
    reuse (ps lstart vs the recorded started_at, 120s tolerance). A stale or
    foreign pid fails closed: callers must refuse, never signal.
    """
    if not cmdline:
        return False  # cannot verify: refuse destructive action
    try:
        db = str(record.get("db", ""))
        port = str(record.get("port", ""))
        exe = str(record.get("exe", ""))
    except AttributeError:
        return False
    if not db or not port or not exe:
        return False
    exe_token = re.sub(r"[\d.]+$", "", os.path.basename(exe).lower())
    if not exe_token or exe_token not in cmdline.lower():
        return False
    if "cli.mjs" not in cmdline:
        return False
    if db not in cmdline or f"--port={port}" not in cmdline:
        return False
    return lstart_matches(record.get("started_at"), record.get("pid"))


def lstart_matches(started_at: str | None, pid) -> bool:
    """True when the process start time agrees with the pidfile record.

    Missing record timestamp (old pidfiles) skips this signal rather than
    failing: the cmdline signals above still apply.
    """
    if not started_at:
        return True
    try:
        recorded = datetime.datetime.fromisoformat(str(started_at)).timestamp()
    except (ValueError, TypeError):
        return True
    actual = pid_lstart_epoch(pid)
    if actual is None:
        return False
    return abs(actual - recorded) <= 120


def pid_lstart_epoch(pid) -> float | None:
    """Process start time as an epoch, via ps etime. None when unreadable."""
    try:
        out = subprocess.check_output(["ps", "-p", str(pid), "-o", "etime="],
                                      stderr=subprocess.STDOUT, timeout=10,
                                      text=True).strip()
    except (OSError, subprocess.SubprocessError):
        return None
    if not out:
        return None
    try:
        days = 0
        if "-" in out:
            d, out = out.split("-", 1)
            days = int(d)
        parts = [int(x) for x in out.split(":")]
        while len(parts) < 3:
            parts.insert(0, 0)
        elapsed = days * 86400 + parts[-3] * 3600 + parts[-2] * 60 + parts[-1]
    except ValueError:
        return None
    return time.time() - elapsed


def managed_state(data_dir: Path, cfg: dict) -> tuple[str, dict | None]:
    """Classify the managed home process.

    Returns ("running"|"stopped"|"stale", pidfile record or None).
    "stale" covers: missing/unparseable pidfile with a live port, dead pid,
    or a pid whose cmdline is not our managed process. Never kills anything.
    """
    record = read_pidfile(data_dir)
    host = cfg["service"]["host"]
    port = int(cfg["service"]["port"])
    port_held, _ = me_setup.port_free(host, port)
    port_held = not port_held
    if record is None:
        return ("stale" if port_held else "stopped"), None
    if record.get("corrupt") or not isinstance(record.get("pid"), int):
        return "stale", record
    pid = record["pid"]
    if not pid_alive(pid):
        return "stale", record
    if fingerprint_matches(record, pid_cmdline(pid)):
        return "running", record
    return "stale", record


def wait_for_exit(pid: int, timeout: float) -> bool:
    deadline = time.time() + timeout
    while time.time() < deadline:
        if not pid_alive(pid):
            return True
        time.sleep(0.25)
    return not pid_alive(pid)


def wait_for_healthz(host: str, port: int, timeout: float) -> dict | None:
    deadline = time.time() + timeout
    while time.time() < deadline:
        body, _ = me_setup.fetch_healthz(host, port)
        if body is not None and body.get("status") == "ok":
            return body
        time.sleep(0.5)
    return None


def backup_config(data_dir: Path, note: str) -> Path:
    stamp = utc_stamp()
    dest = data_dir / "backups" / f"config-{stamp}.json"
    shutil.copy2(me_setup.config_path(data_dir), dest)
    me_setup.log(f"config backed up to {dest} ({note})")
    return dest


# --- start / status / stop -----------------------------------------------------

def _record_start_flags(data_dir: Path, cfg: dict, node_bin: str,
                        used_flags: list) -> None:
    """Persist the node argv actually used to boot (transform fallback or not)."""
    try:
        launch = cfg.get("home_api", {}).get("launch", {})
        if launch.get("node_args", []) != used_flags or launch.get("node") != node_bin:
            backup_config(data_dir, "record effective start flags")
            cfg["home_api"]["launch"]["node"] = node_bin
            cfg["home_api"]["launch"]["node_args"] = used_flags
            cfg["updated_at"] = datetime.datetime.now(datetime.timezone.utc).isoformat()
            me_setup.write_atomic(me_setup.config_path(data_dir),
                                  json.dumps(cfg, indent=2, sort_keys=True) + "\n")
    except (OSError, me_setup.SetupError, KeyError) as exc:
        err(f"warning: service is up but start-flags record failed: {exc}")


def do_start(data_dir: Path, *, node_explicit=None, infra_explicit=None,
             detach_note: bool = True) -> int:
    try:
        data_dir, cfg = load_cfg(data_dir)
    except me_setup.SetupError as exc:
        err(f"error: {exc}")
        return 2
    host, port = cfg["service"]["host"], int(cfg["service"]["port"])
    if host not in me_setup.LOOPBACK_HOSTS:
        err(f"error: refusing non-loopback host {host}; dev lifecycle binds loopback only")
        return 2
    blocked = incomplete_journal(data_dir)
    if blocked is not None:
        err(f"error: refusing to start: interrupted full restore (journal "
            f"{blocked.name}); live data may be mixed. Run `restore-recover "
            f"--data-dir {data_dir}` first, then retry.")
        return 1
    state, record = managed_state(data_dir, cfg)
    if state == "running":
        out(f"already running (pid {record['pid']}); nothing started")
        return 0
    if state == "stale":
        err("error: stale pidfile/port state; refusing to start over an unknown "
            "process. Inspect with `status`, stop the foreign listener, remove "
            f"{pidfile_path(data_dir)} only once verified, then retry.")
        return 1
    try:
        node_bin = resolve_node(node_explicit)
        _, entrypoint = resolve_home_cli(infra_explicit)
    except me_setup.SetupError as exc:
        err(f"error: {exc}")
        return 3
    db_path = Path(cfg["service"]["db_path"])
    try:
        db_path.parent.mkdir(parents=True, exist_ok=True)
        Path(cfg["service"]["log_dir"]).mkdir(parents=True, exist_ok=True)
        (data_dir / "run").mkdir(parents=True, exist_ok=True)
    except OSError as exc:
        err(f"error: cannot prepare destination: {exc}")
        return 1
    free, note = me_setup.port_free(host, port)
    if not free:
        err(f"error: {host}:{port} not bindable ({note}); something else listens. "
            "Refusing to share the port.")
        return 1
    argv: list = []
    try:
        argv, runtime_env, cwd = service_command(node_bin, entrypoint, cfg)
    except me_setup.SetupError as exc:
        err(f"error: {exc}")
        return 1
    env = dict(os.environ)
    env.update(runtime_env)
    # Secrets stay inherited-only: service_command strips persisted secrets;
    # re-attach the operator shell's authorized keys for this live process.
    if os.environ.get("ME_RUNTIME_MODEL_API_KEY"):
        env["ME_RUNTIME_MODEL_API_KEY"] = os.environ["ME_RUNTIME_MODEL_API_KEY"]
    if os.environ.get("HOME_EXPO_ACCESS_TOKEN"):
        env["HOME_EXPO_ACCESS_TOKEN"] = os.environ["HOME_EXPO_ACCESS_TOKEN"]
    # Trusted runtime/model/capability env from generated config wins over the
    # operator shell for the managed key set (the shell keeps PATH and remains
    # the only source of secret values, which setup never persists).
    applied = sorted(k for k, v in runtime_env.items() if v != os.environ.get(k))
    if applied:
        me_setup.log(f"home env from config: {', '.join(applied)}"
                     + (" (+operator-provided secret)"
                        if (os.environ.get("ME_RUNTIME_MODEL_API_KEY")
                            or os.environ.get("HOME_EXPO_ACCESS_TOKEN")) else ""))
    # S7: coordinator wiring is a non-secret file reference; the home (H8)
    # heartbeats automatically once HOME_COORDINATOR_CREDENTIALS_FILE points
    # at the 0600 file. Changing it requires a service reload (done here via
    # start); never auto-restart active jobs elsewhere.
    if (cfg.get("coordinator", {}) or {}).get("enabled"):
        me_setup.log("coordinator: enabled (HOME_COORDINATOR_CREDENTIALS_FILE wired; "
                     "home heartbeats automatically; file stays 0600, never logged)")
    if (cfg.get("notifications", {}) or {}).get("enabled"):
        me_setup.log("notifications: enabled (opt-in; provider token from operator "
                     "shell only, never persisted)")
    log_path = Path(cfg["service"]["log_dir"]) / "home-service.log"
    cli_args = argv[argv.index(str(entrypoint)) + 1:]
    plain_flags = argv[1:argv.index(str(entrypoint))]
    attempts = [plain_flags]
    proc, argv = spawn_home(node_bin, entrypoint, plain_flags, cli_args,
                            env, cwd, log_path)
    body = wait_for_healthz(host, port, START_READY_SECONDS)
    if (body is None or body.get("contract") != me_setup.CONTRACT_VERSION):
        log_tail = tail_of(log_path)
        if ("ERR_UNSUPPORTED_TYPESCRIPT_SYNTAX" in log_tail
                and "--experimental-transform-types" not in plain_flags):
            # H1 is mid-migration: transitive .ts import needs the transform
            # flags its own spike scripts use. One retry, then honest failure.
            try:
                proc.terminate()
            except OSError:
                pass
            me_setup.log("home entrypoint needs TypeScript transform flags "
                         "(transitive .ts import); retrying once with "
                         "--experimental-transform-types")
            ts_flags = list(me_setup.NODE_TS_FLAGS)
            proc, argv = spawn_home(node_bin, entrypoint, ts_flags, cli_args,
                                    env, cwd, log_path)
            body = wait_for_healthz(host, port, START_READY_SECONDS)
            attempts = [ts_flags]
    if body is None or body.get("contract") != me_setup.CONTRACT_VERSION:
        try:
            proc.terminate()
        except OSError:
            pass
        err(f"error: home service did not become ready at http://{host}:{port}/healthz "
            f"(see {log_path}); spawned process terminated, nothing left running. "
            "If the log shows H1 import errors, H1 may still be modifying home; "
            "rerun when stable.")
        return 1
    used_flags = attempts[0]
    _record_start_flags(data_dir, cfg, node_bin, used_flags)
    live_id = body.get("installation_id") or ""
    record_out = {"pid": proc.pid, "exe": node_bin,
                  "argv": argv, "db": str(db_path), "host": host, "port": port,
                  "started_at": datetime.datetime.now(datetime.timezone.utc).isoformat(),
                  "installation_id": live_id}
    pidfile_path(data_dir).write_text(json.dumps(record_out, indent=2) + "\n",
                                      encoding="utf-8")
    # Adopt the authoritative installation_id minted by the home database.
    try:
        if live_id and live_id != cfg.get("installation_id"):
            backup_config(data_dir, "first start adopted authoritative id")
            cfg["installation_id"] = live_id
            cfg["installation_source"] = "home-database"
            cfg["updated_at"] = datetime.datetime.now(datetime.timezone.utc).isoformat()
            me_setup.write_atomic(me_setup.config_path(data_dir),
                                  json.dumps(cfg, indent=2, sort_keys=True) + "\n")
    except (OSError, me_setup.SetupError) as exc:
        err(f"warning: service is up but config adopt failed: {exc}")
    out(f"home service started: pid {proc.pid} on http://{host}:{port} "
        f"(installation_id={live_id or 'unknown'}, log {log_path})")
    if detach_note:
        out("detached (new session); manage it only with `status`/`stop`")
    return 0


def do_status(data_dir: Path, *, infra_explicit=None) -> int:
    try:
        data_dir, cfg = load_cfg(data_dir)
    except me_setup.SetupError as exc:
        err(f"error: {exc}")
        return 2
    host, port = cfg["service"]["host"], int(cfg["service"]["port"])
    state, record = managed_state(data_dir, cfg)
    out(f"config installation_id={cfg.get('installation_id')} "
        f"(source: {cfg.get('installation_source', 'unknown')})")
    out(f"service: {cfg['service']['base_url']} db={cfg['service']['db_path']}")
    blocked = incomplete_journal(data_dir)
    if blocked is not None:
        err(f"warning: interrupted full restore (journal {blocked.name}); live "
            f"data may be mixed -- run `restore-recover --data-dir {data_dir}` "
            f"before starting the service")
    if state == "running":
        assert record is not None
        body, _ = me_setup.fetch_healthz(host, port)
        health = "ok" if body and body.get("status") == "ok" else "unreachable"
        match = ""
        if body:
            match = ("match" if body.get("installation_id") == cfg.get("installation_id")
                     and body.get("contract") == me_setup.CONTRACT_VERSION else "MISMATCH")
        out(f"state: running (pid {record['pid']}, healthz {health} {match})".rstrip())
        return 0 if (body and body.get("status") == "ok" and not match.startswith("MIS")) else 1
    if state == "stale":
        if record and isinstance(record.get("pid"), int) and pid_alive(record["pid"]):
            cmd = pid_cmdline(record["pid"])
            err(f"state: STALE pidfile (pid {record['pid']} is alive but not our "
                f"managed process: {cmd!r}); refusing to touch it")
        elif record and record.get("corrupt"):
            err("state: STALE pidfile (unparseable); refusing to touch it")
        else:
            err(f"state: stale (pidfile points at dead process or port {port} is "
                "held by an unknown listener); refusing to touch it")
        return 1
    out("state: stopped")
    return 1


def do_stop(data_dir: Path, *, force: bool = False) -> int:
    try:
        data_dir, cfg = load_cfg(data_dir)
    except me_setup.SetupError as exc:
        err(f"error: {exc}")
        return 2
    state, record = managed_state(data_dir, cfg)
    if state == "stopped":
        out("already stopped (no pidfile); nothing to do")
        return 0
    if state == "stale" or record is None or not isinstance(record.get("pid"), int):
        err("error: stale pidfile (dead, unparseable, or foreign process); "
            "refusing to signal anything. Verify with `status`, then remove "
            f"{pidfile_path(data_dir)} by hand only once confirmed.")
        return 1
    pid = record["pid"]
    cmdline = pid_cmdline(pid)
    if not pid_alive(pid):
        err("error: process already gone but pidfile is stale; refusing to act "
            "further. Remove the pidfile by hand once confirmed.")
        return 1
    if not fingerprint_matches(record, cmdline):
        err(f"error: pid {pid} cmdline does not match our managed process "
            f"({cmdline!r}); refusing to signal a possibly unrelated process.")
        return 1
    try:
        os.kill(pid, signal.SIGTERM)
    except OSError as exc:
        err(f"error: SIGTERM to managed pid {pid} failed: {exc}")
        return 1
    if wait_for_exit(pid, STOP_GRACE_SECONDS):
        pidfile_path(data_dir).unlink(missing_ok=True)
        out(f"stopped managed home service (pid {pid})")
        return 0
    if not force:
        err(f"error: pid {pid} still alive after SIGTERM; still OUR verified "
            "process. Re-run with --force to SIGKILL, or investigate.")
        return 1
    try:
        os.kill(pid, signal.SIGKILL)
    except OSError as exc:
        err(f"error: SIGKILL to managed pid {pid} failed: {exc}")
        return 1
    if wait_for_exit(pid, STOP_GRACE_SECONDS):
        pidfile_path(data_dir).unlink(missing_ok=True)
        out(f"force-stopped managed home service (pid {pid})")
        return 0
    err(f"error: pid {pid} survived SIGKILL; escalate manually")
    return 1


# --- bootstrap / enrollment ----------------------------------------------------

PAIRING_PROTOCOL = "home-pairing-v1"


def resolve_pairing_url(cfg: dict, *, explicit: str = "",
                        allow_http_loopback: bool = False) -> str:
    """Resolve the LOCAL home URL printed into a pairing invitation.

    Trusted local config only: explicit flag > ME_HOME_PUBLIC_URL env >
    coordinator.public_home_url > named-tunnel hostname. Never any backend
    endpointHint. https:// always; http:// loopback only with explicit
    dev/test opt-in.
    """
    import me_coordinator as _coord
    coord = (cfg.get("coordinator", {}) or {}) if isinstance(cfg, dict) else {}
    if not allow_http_loopback:
        allow_http_loopback = _coord.allow_http_loopback_effective(coord)
    candidates = [
        (explicit or "").strip(),
        (os.environ.get("ME_HOME_PUBLIC_URL", "") or "").strip(),
        str(coord.get("public_home_url", "") or "").strip(),
    ]
    tunnel_host = ""
    try:
        tunnel_host = str((cfg.get("tunnel", {}) or {}).get("hostname", "") or "").strip()
    except AttributeError:
        tunnel_host = ""
    if tunnel_host:
        candidates.append(f"https://{tunnel_host}")
    for cand in candidates:
        if cand:
            return me_setup.validate_https_url(
                cand, field="pairing home_url",
                allow_http_loopback=allow_http_loopback)
    raise me_setup.SetupError(
        "no local public home URL for pairing: pass --public-url, set "
        "ME_HOME_PUBLIC_URL, run `setup --public-home-url https://<host>`, or "
        "`tunnel configure --hostname <stable-name>` first (named tunnel, "
        "stable hostname; never Quick Tunnel; never a backend hint)")


def do_bootstrap(data_dir: Path, *, user: str, ttl_min: int = 15,
                 name: str = "", node_explicit=None, infra_explicit=None,
                 format: str = "raw", public_url: str = "",
                 allow_http_loopback: bool = False) -> int:
    try:
        data_dir, cfg = load_cfg(data_dir)
    except me_setup.SetupError as exc:
        err(f"error: {exc}")
        return 2
    if not user or not user.strip():
        err("error: --user is required (household user id, e.g. alice)")
        return 2
    try:
        node_bin = resolve_node(node_explicit)
        _, entrypoint = resolve_home_cli(infra_explicit)
    except me_setup.SetupError as exc:
        err(f"error: {exc}")
        return 3
    db_path = Path(cfg["service"]["db_path"])
    try:
        db_path.parent.mkdir(parents=True, exist_ok=True)
    except OSError as exc:
        err(f"error: cannot prepare db parent: {exc}")
        return 1
    env = dict(os.environ)
    env["HOME_DB"] = str(db_path)
    try:
        proc = run_home_cli(node_bin, entrypoint,
                            ["bootstrap", f"--user={user}", f"--db={db_path}",
                             f"--ttl-ms={ttl_min * 60 * 1000}"]
                            + ([f"--name={name}"] if name else []),
                            env=env, cwd=str(entrypoint.parent.parent))
    except me_setup.SetupError as exc:
        err(f"error: {exc}")
        return 1
    if proc.returncode != 0:
        tail = (proc.stderr.strip() or proc.stdout.strip())[-800:]
        err(f"error: home bootstrap exited {proc.returncode}: {tail}")
        return 1
    lines = [ln for ln in proc.stdout.splitlines() if ln.strip()]
    try:
        invitation = json.loads(lines[-1])
    except (IndexError, json.JSONDecodeError):
        err(f"error: home bootstrap printed no invitation JSON: {proc.stdout[-400:]!r}")
        return 1
    # Operator-only display: the JSON goes to stdout alone (pipeable); every
    # warning goes to stderr. Nothing is appended to log files.
    if format == "pairing-v1":
        # Trusted LOCAL invitation (home-pairing-v1): wraps the home's actual
        # local bootstrap output with our own locally configured public URL.
        # No backend endpoint-hint is ever trusted here.
        try:
            home_url = resolve_pairing_url(
                cfg, explicit=public_url,
                allow_http_loopback=allow_http_loopback)
        except me_setup.SetupError as exc:
            err(f"error: {exc}")
            return 2
        try:
            invitation_id = invitation["invitation_id"]
            invitation_secret = invitation["invitation_secret"]
        except (KeyError, TypeError):
            err("error: home bootstrap printed no invitation_id/invitation_secret")
            return 1
        if not isinstance(invitation_id, str) or not invitation_id.strip():
            err("error: home bootstrap printed an invalid invitation_id")
            return 1
        if not isinstance(invitation_secret, str) or not invitation_secret.strip():
            err("error: home bootstrap printed an invalid invitation_secret")
            return 1
        paired = {
            "protocol": PAIRING_PROTOCOL,
            "home_url": home_url,
            "installation_id": invitation.get("installation_id") or cfg.get("installation_id", ""),
            "invitation_id": invitation_id,
            "invitation_secret": invitation_secret,
            "user_id": invitation.get("user_id") or user,
        }
        if invitation.get("expires_at") is not None:
            paired["expires_at"] = invitation["expires_at"]
        out(json.dumps(paired, indent=2))
    else:
        out(json.dumps(invitation, indent=2))
    err("ONE-TIME invitation above (stdout only, never logged): deliver it to the "
        f"intended phone now. Default TTL ~{ttl_min} min, single-use; a second "
        "phone racing it loses with invitation_consumed. Each phone gets its own "
        "revocable device credential -- the invitation secret is not reuseable "
        "and is never a tunnel/admin credential.")
    return 0


# --- backup / restore (SQLite/WAL) -----------------------------------------------

@contextlib.contextmanager
def sqlite_conn(path: Path, *, read_only: bool = False, timeout: int = 30):
    """Yield a sqlite3 connection that is always closed on exit.

    NOTE: `with sqlite3.connect(...) as conn` only commits -- it does NOT
    close. Leaked connections hold file locks that break later finalize or
    restore steps (seen as "database is locked" after a 30s wait), so every
    lifecycle database access goes through this helper.
    """
    uri = f"file:{path}?mode=ro" if read_only else str(path)
    conn = sqlite3.connect(uri, uri=read_only, timeout=timeout)
    try:
        yield conn
        conn.commit()
    finally:
        conn.close()


def sqlite_finalize(db_path: Path, journal_mode: str) -> None:
    """Make a database file self-contained and verified (read-write, owned).

    Checkpoints any WAL frames into the main image, sets the requested journal
    mode, and raises on integrity failure. Backup files are finalised to DELETE
    (no sidecar dependence, robust to plain copies); live restores go back to
    WAL (H1 also enables WAL on open). Call only when no service uses the file.
    """
    try:
        with sqlite_conn(db_path, timeout=30) as conn:
            conn.execute(f"PRAGMA journal_mode={journal_mode}")
            conn.execute("PRAGMA wal_checkpoint(TRUNCATE)")
            row = conn.execute("PRAGMA integrity_check").fetchone()
            if not row or row[0] != "ok":
                raise sqlite3.DatabaseError(f"integrity_check failed: {row}")
    except sqlite3.Error as exc:
        raise sqlite3.DatabaseError(f"finalize failed: {exc}")
    if journal_mode == "DELETE":
        for suffix in ("-wal", "-shm", "-journal"):
            try:
                (Path(str(db_path) + suffix)).unlink(missing_ok=True)
            except OSError:
                pass


def sqlite_verify(db_path: Path) -> tuple[bool, str]:
    """Read-only header + integrity + installation_id checks. Never modifies."""
    try:
        with open(db_path, "rb") as f:
            magic = f.read(16)
    except OSError as exc:
        return False, f"unreadable: {exc}"
    if magic != b"SQLite format 3\0":
        return False, "not a SQLite database file (bad magic)"
    try:
        uri = f"file:{db_path}?mode=ro"
        with sqlite_conn(db_path, read_only=True, timeout=10) as conn:
            row = conn.execute("PRAGMA integrity_check").fetchone()
            if not row or row[0] != "ok":
                return False, f"integrity_check failed: {row}"
            meta = conn.execute(
                "SELECT value FROM meta WHERE key = 'installation_id'").fetchone()
    except sqlite3.Error as exc:
        return False, f"sqlite error: {exc}"
    if not meta or not meta[0]:
        return False, "no installation_id in meta (not a home database?)"
    return True, f"ok (installation_id={meta[0]})"


# --- full backup / restore (SQLite + task workspaces + household files) --------
#
# Scope vocabulary (explicit, never guessed):
# - scope=db: legacy online-safe SQLite snapshot only. Task workspaces
#   (<dbdir>/tasks, incl. .me_runtime/graph.db checkpoints) and household
#   files are NOT included. Fast, works while the service runs.
# - scope=full: stopped-service filesystem archive (.tar.gz): SQLite snapshot
#   (backup API) + per-task workspaces + household files + manifest.json.
#   Config, logs, secrets/, run/, backups/, tmp/ and service.env are NEVER
#   read into the archive (no operator env keys, tunnel/admin credentials,
#   or host paths). Workspace files ARE private household data and may hold
#   user/agent-written secrets or browser sessions: no secret scanning,
#   redaction, or encryption is performed or claimed -- archive is mode 0600,
#   local-only, never uploaded. This tool never uploads an archive anywhere.
#
# Layout is read from the live config (db_path sibling `tasks/` per H1
# server.mjs, household_dir from config); no arbitrary user dirs are guessed.

FULL_FORMAT_VERSION = "me-home-full-backup-v1"
FULL_MAX_FILES = 20000
FULL_MAX_TOTAL_BYTES = 1 * 1024**3  # 1 GiB unpacked payload cap
FULL_MAX_FILE_BYTES = 100 * 1024**2  # 100 MiB single-file cap
FULL_MAX_ARCHIVE_BYTES = 1 * 1024**3  # 1 GiB compressed archive cap
FULL_MAX_MANIFEST_BYTES = 16 * 1024**2  # 16 MiB manifest cap
FULL_MAX_PENDING_BYTES = 1 * 1024**2  # 1 MiB per pending.json cap
FULL_MAX_NAME_LEN = 1024  # archive member name cap (longname/PAX bomb guard)
FULL_MAX_PAX_BYTES = 64 * 1024  # PAX extended-header cap per member
_HASH_CHUNK = 1024 * 1024
_STREAM_CHUNK = 64 * 1024  # streaming payload reads never exceed this


class _ArchiveReject(Exception):
    """Internal: archive member/payload violates a restore bound."""


def full_limits() -> dict:
    """Effective restore bounds. Module constants are the safe defaults; the
    trusted operator may raise them via ME_HOME_FULL_MAX_* env (their own
    shell only, never persisted) for households legitimately over 1 GiB.
    Invalid values fail closed instead of being guessed.
    """
    spec = (("ME_HOME_FULL_MAX_FILES", "files", FULL_MAX_FILES),
            ("ME_HOME_FULL_MAX_TOTAL_BYTES", "total", FULL_MAX_TOTAL_BYTES),
            ("ME_HOME_FULL_MAX_FILE_BYTES", "per_file", FULL_MAX_FILE_BYTES),
            ("ME_HOME_FULL_MAX_ARCHIVE_BYTES", "archive", FULL_MAX_ARCHIVE_BYTES),
            ("ME_HOME_FULL_MAX_MANIFEST_BYTES", "manifest", FULL_MAX_MANIFEST_BYTES),
            ("ME_HOME_FULL_MAX_PENDING_BYTES", "pending", FULL_MAX_PENDING_BYTES))
    out = {"files": FULL_MAX_FILES, "total": FULL_MAX_TOTAL_BYTES,
           "per_file": FULL_MAX_FILE_BYTES, "archive": FULL_MAX_ARCHIVE_BYTES,
           "manifest": FULL_MAX_MANIFEST_BYTES, "pending": FULL_MAX_PENDING_BYTES}
    for env_name, key, _default in spec:
        raw = os.environ.get(env_name)
        if raw is None or raw == "":
            continue
        try:
            value = int(raw)
        except ValueError:
            raise me_setup.SetupError(
                f"{env_name}={raw!r} is not an integer; refusing to guess bounds")
        if value <= 0:
            raise me_setup.SetupError(
                f"{env_name}={raw!r} must be a positive byte/file count")
        out[key] = value
    return out


def _check_archive_member(m, seen: set, acc: list, limits: dict) -> str:
    """Validate one streamed tar member header. No payload is read here, so
    this is safe to run in the write-free preflight pass.

    acc is [file_count, unpacked_total]; mutated in place. Raises
    _ArchiveReject with a human message on any violation.
    """
    import tarfile
    name = m.name
    if not name:
        raise _ArchiveReject("archive has an empty entry name")
    if name in seen:
        raise _ArchiveReject(f"archive has duplicate entry {name!r}")
    seen.add(name)
    if len(name) > FULL_MAX_NAME_LEN:
        raise _ArchiveReject(
            f"archive entry name over {FULL_MAX_NAME_LEN} chars "
            f"({name[:60]!r}...); longname/PAX bomb refused")
    if "\0" in name:
        raise _ArchiveReject(f"archive entry has NUL byte; refused")
    if os.path.isabs(name) or name.startswith("\\"):
        raise _ArchiveReject(f"archive has absolute entry {name!r}")
    stripped = name[:-1] if name.endswith("/") and len(name) > 1 else name
    parts = stripped.split("/")
    if any(p in ("", ".", "..") for p in parts):
        raise _ArchiveReject(f"archive has traversal/empty entry {name!r}")
    if m.issym() or m.islnk():
        raise _ArchiveReject(f"archive has link entry {name!r}; links are never restored")
    if m.ischr() or m.isblk() or m.isfifo() or m.isdev():
        raise _ArchiveReject(f"archive has device entry {name!r}")
    try:
        pax_size = sum(len(str(k)) + len(str(v)) for k, v in m.pax_headers.items())
    except (AttributeError, TypeError):
        pax_size = 0
    if pax_size > FULL_MAX_PAX_BYTES:
        raise _ArchiveReject(
            f"archive entry {name!r} has oversize PAX headers; refused")
    if m.isdir():
        if not (name == "tasks" or name.startswith("tasks/")
                or name == "household" or name.startswith("household/")
                or name == "database" or name.startswith("database/")):
            raise _ArchiveReject(f"archive has unexpected directory {name!r}")
        return name
    if not m.isfile():
        raise _ArchiveReject(f"archive has non-file entry {name!r}")
    if not (name == "manifest.json" or name == "database/home.sqlite"
            or name.startswith("tasks/") or name.startswith("household/")):
        raise _ArchiveReject(f"archive has unexpected entry {name!r} (allowed: "
                             "manifest.json, database/home.sqlite, tasks/..., "
                             "household/...)")
    if m.size > limits["per_file"]:
        raise _ArchiveReject(f"archive entry {name!r} over per-file cap")
    acc[0] += 1
    acc[1] += m.size
    if acc[0] > limits["files"] or acc[1] > limits["total"]:
        raise _ArchiveReject("archive over file-count/unpacked-size caps")
    return name


def _stream_copy_bounded(src_f, dest_path: Path, expected: int, acc: list,
                         limits: dict, label: str) -> int:
    """Copy one member payload in 64 KiB chunks, enforcing per-file and total
    unpacked caps on ACTUAL bytes (declared sizes may lie). Returns bytes
    written. Raises _ArchiveReject on violation (caller cleans staging).
    """
    written = 0
    with open(dest_path, "wb") as out_f:
        while True:
            chunk = src_f.read(_STREAM_CHUNK)
            if not chunk:
                break
            written += len(chunk)
            acc[1] += len(chunk)
            if written > expected or written > limits["per_file"]:
                raise _ArchiveReject(
                    f"archive entry {label!r} over per-file cap during streaming")
            if acc[1] > limits["total"]:
                raise _ArchiveReject(
                    "archive over unpacked-size cap during streaming "
                    "(possible decompression bomb)")
            out_f.write(chunk)
    return written


def _read_bounded(path: Path, cap: int, label: str) -> bytes:
    """Read a small staged file with an explicit cap before parsing."""
    data = b""
    with open(path, "rb") as f:
        while True:
            chunk = f.read(_STREAM_CHUNK)
            if not chunk:
                break
            data += chunk
            if len(data) > cap:
                raise _ArchiveReject(f"{label} over size cap ({cap} bytes)")
    return data


def tasks_root_for(cfg: dict) -> Path:
    """Per-task workspace root: <dbdir>/tasks (H1 server.mjs default)."""
    try:
        return Path(str(cfg["service"]["db_path"])).parent / "tasks"
    except KeyError:
        raise me_setup.SetupError("config has no service.db_path; re-run setup")


def household_dir_for(cfg: dict, data_dir: Path) -> Path:
    try:
        return Path(str(cfg["service"].get("household_dir") or (data_dir / "data" / "household")))
    except (KeyError, TypeError):
        return data_dir / "data" / "household"


def sha256_file(path: Path) -> str:
    import hashlib
    h = hashlib.sha256()
    with open(path, "rb") as f:
        while True:
            chunk = f.read(_HASH_CHUNK)
            if not chunk:
                break
            h.update(chunk)
    return h.hexdigest()


def full_stopped_gate(data_dir: Path, cfg: dict, action: str) -> int | None:
    """Refuse full backup/restore unless the managed home is fully STOPPED.

    Returns None when quiescent, else the exit code (1 state / 2 usage).
    A stale pidfile or any listener on the port refuses: a full snapshot
    cannot be atomic while writers may run, so we refuse instead of faking
    one. `stop` the managed service first and clear foreign listeners.
    """
    host, port = cfg["service"]["host"], int(cfg["service"]["port"])
    state, record = managed_state(data_dir, cfg)
    if state != "stopped":
        if state == "running" and record is not None:
            err(f"error: cannot {action}: managed home service is running "
                f"(pid {record.get('pid')}); stop it first (`stop`). Full "
                "snapshots require a stopped service for file consistency.")
        else:
            err(f"error: cannot {action}: home state is {state} (stale pidfile "
                f"or unknown listener); verify with `status`, stop the managed "
                "service, remove no pidfile by hand until verified, then retry. "
                "Full snapshots refuse rather than guess.")
        return 1
    free, note = me_setup.port_free(host, port)
    if not free:
        err(f"error: cannot {action}: {host}:{port} is held ({note}); an unknown "
            "service may be writing this data. Refusing full file snapshot.")
        return 1
    return None


def collect_tree_files(root: Path, prefix: str, limits: dict | None = None
                     ) -> tuple[list, int]:
    """Walk one included tree, streaming stats only (no file reads beyond stat).

    Policy (explicit, fail-closed): symlinks, hardlinks (nlink>1), and
    non-regular files (fifo/socket/device) are REFUSED with an error --
    never silently followed, copied, or skipped. Callers abort the backup
    with nothing written and original data untouched. Bounds come from
    full_limits() (operator-overridable) so large-but-legitimate households
    are not stuck at defaults in either direction.

    Returns (entries, total_bytes). Each entry is (abs_path, arcname, size).
    """
    if limits is None:
        limits = {"files": FULL_MAX_FILES, "total": FULL_MAX_TOTAL_BYTES,
                  "per_file": FULL_MAX_FILE_BYTES}
    entries: list = []
    total = 0
    if not root.exists():
        return entries, total
    if not root.is_dir() or root.is_symlink():
        raise me_setup.SetupError(f"refusing to back up non-directory tree: {root}")
    for dirpath, dirnames, filenames in os.walk(root, topdown=True, followlinks=False):
        # Prune symlinked dirs first: os.walk lists them in dirnames.
        for d in list(dirnames):
            full = Path(dirpath) / d
            try:
                st = full.lstat()
            except OSError as exc:
                raise me_setup.SetupError(f"cannot stat {full}: {exc}")
            if stat.S_ISLNK(st.st_mode):
                raise me_setup.SetupError(
                    f"refusing full backup: symlink directory at {full} "
                    "(resolve or remove it first; links are never followed)")
            if not stat.S_ISDIR(st.st_mode):
                raise me_setup.SetupError(
                    f"refusing full backup: non-directory at {full}")
        for name in filenames:
            full = Path(dirpath) / name
            try:
                st = full.lstat()
            except OSError as exc:
                raise me_setup.SetupError(f"cannot stat {full}: {exc}")
            mode = st.st_mode
            if stat.S_ISLNK(mode):
                raise me_setup.SetupError(
                    f"refusing full backup: symlink at {full} "
                    "(resolve or remove it first; links are never archived)")
            if stat.S_ISDIR(mode):
                continue
            if not stat.S_ISREG(mode):
                raise me_setup.SetupError(
                    f"refusing full backup: non-regular file at {full} "
                    "(device/fifo/socket files are never archived)")
            if st.st_nlink > 1:
                raise me_setup.SetupError(
                    f"refusing full backup: hardlink at {full} "
                    f"(nlink={st.st_nlink}; links are never archived)")
            if st.st_size > limits["per_file"]:
                raise me_setup.SetupError(
                    f"refusing full backup: {full} is {st.st_size} bytes "
                    f"(over per-file cap {limits['per_file']})")
            rel = full.relative_to(root)
            arc = f"{prefix}/{rel.as_posix()}"
            entries.append((full, arc, st.st_size))
            total += st.st_size
            if len(entries) > limits["files"]:
                raise me_setup.SetupError(
                    f"refusing full backup: over file-count cap {limits['files']}")
            if total > limits["total"]:
                raise me_setup.SetupError(
                    f"refusing full backup: over total-size cap {limits['total']}")
    entries.sort(key=lambda e: e[1])
    return entries, total


def do_backup(data_dir: Path, *, output: str | None = None, scope: str = "db") -> int:
    if scope not in ("db", "full"):
        err(f"error: --scope must be db or full (got {scope!r})")
        return 2
    if scope == "full":
        return do_backup_full(data_dir, output=output)
    try:
        data_dir, cfg = load_cfg(data_dir)
    except me_setup.SetupError as exc:
        err(f"error: {exc}")
        return 2
    src = Path(cfg["service"]["db_path"])
    if not src.is_file():
        err(f"error: no home database yet at {src}; start the service (or seed) first")
        return 1
    dest = Path(output).expanduser() if output else data_dir / "backups" / f"home-{utc_stamp()}.sqlite"
    try:
        dest.parent.mkdir(parents=True, exist_ok=True)
        with sqlite_conn(src) as src_conn, sqlite_conn(dest) as dst_conn:
            src_conn.backup(dst_conn)  # online-safe; folds WAL into one file
        # Self-contained file: checkpoint frames, DELETE mode, verified.
        sqlite_finalize(dest, "DELETE")
    except (OSError, sqlite3.Error, sqlite3.DatabaseError) as exc:
        err(f"error: backup failed: {exc}")
        return 1
    ok, detail = sqlite_verify(dest)
    if not ok:
        err(f"error: backup written but FAILED verification ({detail}); inspect {dest}")
        return 1
    try:
        size = dest.stat().st_size
    except OSError:
        size = -1
    out(f"backup complete (scope=db: SQLite database only; task workspaces, "
        f"runtime checkpoints and household files NOT included -- use "
        f"--scope full while stopped for those): {dest} ({size} bytes, {detail})")
    return 0


def do_backup_full(data_dir: Path, *, output: str | None = None) -> int:
    """Stopped-service full archive: SQLite + tasks + household + manifest."""
    import tarfile
    try:
        data_dir, cfg = load_cfg(data_dir)
    except me_setup.SetupError as exc:
        err(f"error: {exc}")
        return 2
    gate = full_stopped_gate(data_dir, cfg, "full backup")
    if gate is not None:
        return gate
    src_db = Path(cfg["service"]["db_path"])
    if not src_db.is_file():
        err(f"error: no home database yet at {src_db}; start the service (or seed) first")
        return 1
    try:
        limits = full_limits()
    except me_setup.SetupError as exc:
        err(f"error: {exc}")
        return 2
    tasks_root = tasks_root_for(cfg)
    household_dir = household_dir_for(cfg, data_dir)
    dest = Path(output).expanduser() if output else data_dir / "backups" / f"home-full-{utc_stamp()}.tar.gz"
    if dest.suffixes[-2:] != [".tar", ".gz"] and dest.suffix != ".tgz":
        err(f"error: full backup output must end .tar.gz or .tgz (got {dest.name}); "
            "refusing to guess the archive type")
        return 2
    try:
        dest.parent.mkdir(parents=True, exist_ok=True)
    except OSError as exc:
        err(f"error: cannot prepare output dir: {exc}")
        return 1
    # Collect file lists first (stat-only streaming) for bounds + disk gate.
    try:
        task_entries, task_bytes = collect_tree_files(tasks_root, "tasks", limits)
        house_entries, house_bytes = collect_tree_files(household_dir, "household",
                                                       limits)
    except me_setup.SetupError as exc:
        err(f"error: {exc}")
        return 1
    try:
        db_bytes = src_db.stat().st_size
    except OSError as exc:
        err(f"error: cannot stat home database: {exc}")
        return 1
    payload_estimate = db_bytes + task_bytes + house_bytes
    try:
        free = shutil.disk_usage(dest.parent).free
    except OSError as exc:
        err(f"error: cannot check disk space: {exc}")
        return 1
    if free < payload_estimate + 100 * 1024**2:
        err(f"error: insufficient disk for full backup (need ~{payload_estimate} bytes "
            f"payload + 100 MiB margin, have {free} free under {dest.parent})")
        return 1
    staging = data_dir / "tmp" / f".full-backup-{utc_stamp()}"
    try:
        staging.mkdir(parents=True, exist_ok=False)
        os.chmod(staging, 0o700)
    except OSError as exc:
        err(f"error: cannot prepare staging dir: {exc}")
        return 1
    # From here on, failures clean staging but NEVER touch original data.
    try:
        staged_db = staging / "home.sqlite"
        with sqlite_conn(src_db) as src_conn, sqlite_conn(staged_db) as dst_conn:
            src_conn.backup(dst_conn)
        sqlite_finalize(staged_db, "DELETE")
        ok, detail = sqlite_verify(staged_db)
        if not ok:
            err(f"error: staged database FAILED verification ({detail}); nothing archived")
            return 1
        installation_id = (detail.split("installation_id=")[-1].rstrip(")")
                           if "installation_id=" in detail else "")
        if not installation_id:
            installation_id = me_setup.read_db_installation_id(staged_db) or ""
        # Hash payload files (streaming, chunked -- never readall).
        manifest_tasks = []
        for full, arc, size in task_entries:
            manifest_tasks.append({"path": arc, "sha256": sha256_file(full), "size": size})
        manifest_house = []
        for full, arc, size in house_entries:
            manifest_house.append({"path": arc, "sha256": sha256_file(full), "size": size})
        db_sha = sha256_file(staged_db)
        try:
            db_size = staged_db.stat().st_size
        except OSError:
            db_size = -1
        manifest = {
            "format_version": FULL_FORMAT_VERSION,
            "scope": "full",
            "created_at": datetime.datetime.now(datetime.timezone.utc).isoformat(),
            "installation_id": installation_id,
            "source": {"db_path": str(src_db), "tasks_root": str(tasks_root),
                       "household_dir": str(household_dir)},
            "database": {"path": "database/home.sqlite", "sha256": db_sha, "size": db_size},
            "tasks": manifest_tasks,
            "household": manifest_house,
            "counts": {"tasks": len(manifest_tasks), "household": len(manifest_house)},
            "total_bytes": task_bytes + house_bytes,
            "excludes": ["config/", "config/service.env", "logs/", "secrets/",
                         "run/", "backups/", "tmp/",
                         "operator environment, tunnel credential files, "
                         "provider keys (setup never reads them)"],
            "includes_private_workspace_data": True,
            "note": "Full household filesystem archive (SQLite + task workspaces "
                    "incl. .me_runtime checkpoints + household files). Workspaces "
                    "are private household data and MAY contain user/agent-written "
                    "secrets, pasted keys, and browser cookies/sessions: no secret "
                    "scanning, redaction, or encryption is performed or claimed. "
                    "Protect the archive (mode 0600, local-only, never uploaded). "
                    "Not a bare-metal image: host config, logs, secrets, and "
                    "service units are excluded by design.",
        }
        (staging / "manifest.json").write_text(
            json.dumps(manifest, indent=2, sort_keys=True) + "\n", encoding="utf-8")
        tmp_dest = dest.parent / (dest.name + f".tmp-{os.getpid()}")
        with tarfile.open(tmp_dest, "w:gz", format=tarfile.PAX_FORMAT,
                           compresslevel=6) as tar:
            for name in ("manifest.json",):
                ti = tar.gettarinfo(str(staging / name), arcname=name)
                ti.uid, ti.gid, ti.uname, ti.gname = 0, 0, "", ""
                ti.mtime = int(time.time())
                with open(staging / name, "rb") as f:
                    tar.addfile(ti, f)
            db_ti = tar.gettarinfo(str(staged_db), arcname="database/home.sqlite")
            db_ti.uid, db_ti.gid, db_ti.uname, db_ti.gname = 0, 0, "", ""
            db_ti.mtime = int(time.time())
            with open(staged_db, "rb") as f:
                tar.addfile(db_ti, f)
            for full, arc, _size in ([(f, a, s) for f, a, s in task_entries]
                                     + [(f, a, s) for f, a, s in house_entries]):
                ti = tar.gettarinfo(str(full), arcname=arc)
                ti.uid, ti.gid, ti.uname, ti.gname = 0, 0, "", ""
                with open(full, "rb") as f:
                    tar.addfile(ti, f)
        os.chmod(tmp_dest, 0o600)
        # Flush + fsync the complete archive and its directory before
        # reporting success: a crash after return must not leave a truncated
        # archive presented as complete.
        _fsync_file_path(tmp_dest)
        _fsync_parent_dir(tmp_dest)
        os.replace(tmp_dest, dest)
        os.chmod(dest, 0o600)
        _fsync_file_path(dest)
        _fsync_parent_dir(dest)
    except (OSError, sqlite3.Error, sqlite3.DatabaseError, tarfile.TarError,
            me_setup.SetupError) as exc:
        err(f"error: full backup failed: {exc} (original data untouched)")
        return 1
    finally:
        shutil.rmtree(staging, ignore_errors=True)
    try:
        size = dest.stat().st_size
    except OSError:
        size = -1
    out(f"full backup complete (scope=full: SQLite + {len(task_entries)} task files "
        f"+ {len(house_entries)} household files; config/logs/secrets excluded, "
        f"local-only): {dest} ({size} bytes, installation_id={installation_id or '?'})")
    return 0


def do_restore(data_dir: Path, *, source: str, confirm_destructive: bool = False,
               scope: str = "auto") -> int:
    if scope not in ("auto", "db", "full"):
        err(f"error: --scope must be auto, db, or full (got {scope!r})")
        return 2
    resolved = scope
    if resolved == "auto":
        low = str(source).lower()
        resolved = "full" if (low.endswith(".tar.gz") or low.endswith(".tgz")) else "db"
    else:
        low = str(source).lower()
        is_tar = low.endswith(".tar.gz") or low.endswith(".tgz")
        if resolved == "db" and is_tar:
            err("error: --scope db expects a SQLite snapshot (.sqlite), not a "
                "full archive; re-run with --scope full")
            return 2
        if resolved == "full" and not is_tar:
            err("error: --scope full expects a full archive (.tar.gz); re-run with "
                "--scope db for a SQLite snapshot")
            return 2
    if resolved == "full":
        return do_restore_full(data_dir, source=source,
                               confirm_destructive=confirm_destructive)
    try:
        data_dir, cfg = load_cfg(data_dir)
    except me_setup.SetupError as exc:
        err(f"error: {exc}")
        return 2
    if not confirm_destructive:
        err("error: restore replaces the live home database; re-run with "
            "--confirm-destructive once you have a backup")
        return 2
    src = Path(source).expanduser()
    if not src.is_file():
        err(f"error: restore source not found: {src}")
        return 2
    host, port = cfg["service"]["host"], int(cfg["service"]["port"])
    state, _ = managed_state(data_dir, cfg)
    if state == "running":
        err("error: managed home service is running; stop it first (`stop`). "
            "Restore refuses to swap a live database.")
        return 1
    free, note = me_setup.port_free(host, port)
    if not free:
        err(f"error: {host}:{port} is held ({note}); an unknown service may be "
            "using this database. Refusing restore.")
        return 1
    ok, detail = sqlite_verify(src)
    if not ok:
        err(f"error: restore source FAILED verification, nothing touched ({detail})")
        return 1
    db_path = Path(cfg["service"]["db_path"])
    if db_path.is_file():
        pre = data_dir / "backups" / f"pre-restore-{utc_stamp()}.sqlite"
        try:
            shutil.copy2(db_path, pre)
        except OSError as exc:
            err(f"error: cannot back up current db before restore: {exc}")
            return 1
        out(f"current database preserved at {pre}")
    try:
        # Always copy: the operator's backup file must survive the restore.
        shutil.copy2(src, db_path)
        # Stale sidecars belong to the REPLACED image; recovery must never
        # apply them onto the restored image. Remove first, then finalize.
        for suffix in ("-wal", "-shm", "-journal"):
            try:
                (Path(str(db_path) + suffix)).unlink(missing_ok=True)
            except OSError:
                pass
        # Checkpoint, return to WAL, verify (owned file, service is stopped).
        sqlite_finalize(db_path, "WAL")
    except (OSError, sqlite3.DatabaseError) as exc:
        err(f"error: restore copy/finalize failed: {exc}")
        return 1
    ok, detail = sqlite_verify(db_path)
    if not ok:
        err(f"error: restored database FAILED readiness ({detail}); "
            "previous copy is in backups/ as pre-restore-*.sqlite")
        return 1
    restored_id = me_setup.read_db_installation_id(db_path)
    if restored_id and restored_id != cfg.get("installation_id"):
        backup_config(data_dir, "restore adopted authoritative id")
        cfg["installation_id"] = restored_id
        cfg["installation_source"] = "restored-database"
        cfg["updated_at"] = datetime.datetime.now(datetime.timezone.utc).isoformat()
        me_setup.write_atomic(me_setup.config_path(data_dir),
                              json.dumps(cfg, indent=2, sort_keys=True) + "\n")
    out(f"restore complete + ready (scope=db legacy: SQLite only; sessions/devices "
        f"preserved as archived, task workspaces untouched): {db_path} ({detail})")
    return 0


def scrub_restored_auth(db_path: Path) -> tuple[int, int, int]:
    """Revoke restored credentials so a revived revoked phone stays revoked.

    A full archive rolls back the auth tables to backup time: without a scrub,
    restoring an older copy would resurrect sessions/devices/invitations the
    user has since revoked. Safe restore therefore expires everything that
    grants access -- all live sessions, all live devices, all unconsumed
    invitations -- while preserving identity (installation_id, users),
    household data (conversations/messages/tasks/artifacts) and runtime
    checkpoints. The operator pairs fresh devices afterwards (see docs).

    Returns (devices_revoked, sessions_revoked, invitations_consumed).
    Never invents or accepts an external identity: installation_id/users are
    untouched.
    """
    now_ms = int(time.time() * 1000)
    with sqlite_conn(db_path, timeout=30) as conn:
        dev_n, sess_n, inv_n = 0, 0, 0
        try:
            cur = conn.execute("UPDATE devices SET revoked_at = ? WHERE revoked_at IS NULL",
                               (now_ms,))
            dev_n = cur.rowcount if cur.rowcount and cur.rowcount > 0 else 0
        except sqlite3.Error:
            dev_n = 0
        try:
            cur = conn.execute("UPDATE sessions SET revoked_at = ? WHERE revoked_at IS NULL",
                               (now_ms,))
            sess_n = cur.rowcount if cur.rowcount and cur.rowcount > 0 else 0
        except sqlite3.Error:
            sess_n = 0
        try:
            cur = conn.execute("UPDATE invitations SET consumed_at = ? "
                               "WHERE consumed_at IS NULL", (now_ms,))
            inv_n = cur.rowcount if cur.rowcount and cur.rowcount > 0 else 0
        except sqlite3.Error:
            inv_n = 0
        conn.commit()
    return dev_n, sess_n, inv_n


def is_known_checkpoint(arc: str) -> bool:
    """True for paths the runtime treats as checkpoint SQLite files.

    The R2 bridge persists its LangGraph SqliteSaver at
    `<workspace>/.me_runtime/graph.db` (thread_id = run_id); any `*.db`
    directly under a `.me_runtime/` dir is checkpoint-class. Other files
    (output/, input/, diagnostics logs) are ordinary payload.
    """
    lowered = arc.replace("\\", "/")
    return ("/.me_runtime/" in lowered and lowered.endswith(".db")) or \
        lowered.endswith("/.me_runtime/graph.db")


def checkpoint_sqlite_ok(path: Path, *, strict: bool = False) -> tuple[bool, str]:
    """Read-only integrity check for a runtime checkpoint SQLite file.

    strict=True (required for known checkpoint paths): the file MUST be a
    valid SQLite database and MUST pass integrity_check; garbage magic or
    corruption denies the restore. strict=False preserves the legacy
    lenient behavior for non-checkpoint files. Never modifies.
    """
    try:
        with open(path, "rb") as f:
            magic = f.read(16)
    except OSError as exc:
        return False, f"unreadable: {exc}"
    if magic != b"SQLite format 3\0":
        if strict:
            return False, "not a SQLite database (checkpoint must be valid SQLite)"
        return True, "not sqlite, skipped"
    try:
        with sqlite_conn(path, read_only=True, timeout=10) as conn:
            row = conn.execute("PRAGMA integrity_check").fetchone()
            if not row or row[0] != "ok":
                return False, f"integrity_check failed: {row}"
    except sqlite3.Error as exc:
        return False, f"sqlite error: {exc}"
    return True, "ok"


def checkpoint_thread_ok(path: Path, run_id: str) -> tuple[bool, str]:
    """Best-effort binding check: the checkpoint graph must belong to run_id.

    The R2 harness keys its SqliteSaver rows by thread_id == run_id. If the
    staged graph.db carries a `checkpoints` table, at least one row must
    match run_id; a present-but-foreign checkpoint graph denies the restore
    (it would resume the wrong run). If the table is absent (harness schema
    drift), the check is skipped rather than guessed -- magic + integrity
    (strict) remain the gate. Read-only; never modifies.
    """
    try:
        with sqlite_conn(path, read_only=True, timeout=10) as conn:
            tables = {r[0] for r in
                      conn.execute("SELECT name FROM sqlite_master WHERE type='table'")}
            if "checkpoints" not in tables:
                return True, "no checkpoints table; thread check skipped"
            row = conn.execute(
                "SELECT 1 FROM checkpoints WHERE thread_id = ? LIMIT 1",
                (run_id,)).fetchone()
    except sqlite3.Error as exc:
        return False, f"checkpoint thread lookup failed: {exc}"
    if not row:
        return False, (f"checkpoint graph has no thread for run {run_id!r}; "
                       "foreign checkpoint refused")
    return True, "ok"


RESTORE_JOURNAL_PREFIX = ".restore-journal-"
RESTORE_JOURNAL_VERSION = 1


def restore_journals(data_dir: Path) -> list:
    """All restore journals, oldest first. Read-only."""
    try:
        found = sorted((data_dir / "backups").glob(f"{RESTORE_JOURNAL_PREFIX}*.json"),
                       key=lambda p: p.name)
    except OSError:
        return []
    return found


def incomplete_journal(data_dir: Path) -> Path | None:
    """Newest journal with status 'started' (interrupted restore), if any."""
    for path in reversed(restore_journals(data_dir)):
        try:
            doc = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError):
            return path  # unreadable journal: treat as blocking, recover decides
        if isinstance(doc, dict) and doc.get("status") == "started":
            return path
    return None


def _fsync_file_path(path: Path) -> None:
    """fsync a regular file. Best-effort on non-POSIX (ignored)."""
    try:
        with open(path, "rb") as f:
            try:
                os.fsync(f.fileno())
            except OSError:
                pass
    except OSError:
        pass


def _fsync_parent_dir(path: Path) -> None:
    """fsync the parent directory so a rename/link is durable (POSIX).

    Best-effort: platforms without directory fsync (e.g. Windows) ignore
    failures; callers still treat the write as complete there.
    """
    try:
        parent = str(path.parent)
        fd = os.open(parent, os.O_RDONLY)
    except OSError:
        return
    try:
        try:
            os.fsync(fd)
        except OSError:
            pass
    finally:
        try:
            os.close(fd)
        except OSError:
            pass


def _durable_write_json(path: Path, obj: dict, mode: int = 0o600) -> None:
    """Atomically write JSON then fsync file + parent dir before returning.

    Uses a temp file in the same directory, fsyncs it, renames, then fsyncs
    the parent directory (POSIX durability: a crash after return cannot lose
    the rename). Raises OSError on failure.
    """
    import tempfile as _tf
    path.parent.mkdir(parents=True, exist_ok=True)
    fd, tmp = _tf.mkstemp(dir=str(path.parent), prefix=path.name + ".")
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as f:
            f.write(json.dumps(obj, indent=2, sort_keys=True) + "\n")
            try:
                f.flush()
                os.fsync(f.fileno())
            except OSError:
                pass
        try:
            os.chmod(tmp, mode)
        except OSError:
            pass
        os.replace(tmp, path)
    except BaseException:
        try:
            os.unlink(tmp)
        except OSError:
            pass
        raise
    _fsync_parent_dir(path)


def _same_filesystem(a: Path, b_parent: Path) -> bool:
    """True when a and b_parent live on the same st_dev (rename-safe)."""
    try:
        return os.stat(a).st_dev == os.stat(b_parent).st_dev
    except OSError:
        return False


def _rename_or_copy(src: Path, dst: Path) -> str:
    """Move src onto dst via atomic os.replace only.

    Cross-filesystem moves (EXDEV) are REFUSED with a clear error instead of
    a copy+delete fallback: the fallback is not crash-atomic and would
    masquerade as a safe rename. The default generated layout keeps every
    journaled path under the same data_dir (same filesystem), so this only
    fires when the operator placed parts of the home on different mounts.
    Raises OSError on failure (never half-reports).
    """
    try:
        os.replace(src, dst)
        return "rename"
    except OSError as exc:
        if exc.errno == errno.EXDEV:
            raise OSError(
                f"cross-filesystem move refused (EXDEV): {src} -> {dst}; "
                "keep the home data_dir on a single filesystem so restore "
                "renames stay atomic; nothing was mutated") from exc
        raise


def _lexists(p: Path) -> bool:
    return os.path.lexists(str(p))


def _rollback_moves(moves: list, set_config: dict | None = None) -> list:
    """Reverse journaled renames (latest first), then optionally restore the
    recorded config identity. Completed reversals are marked done=False in
    place so a later `restore-recover` resumes only what remains. Returns a
    list of error strings (empty on success). Never raises: every failure is
    reported, never swallowed into a false 'rolled back' claim.

    Idempotent and non-destructive: when the rollback source is already gone
    but the destination is present, the move is already undone (mark False,
    no error). When both ends exist, refuse instead of overwriting live data
    with os.replace.
    """
    errors: list = []
    for mv in reversed([m for m in moves if m.get("done")]):
        try:
            rsrc, rdst = Path(mv["dst"]), Path(mv["src"])
            if not _lexists(rsrc) and _lexists(rdst):
                mv["done"] = False
                continue
            if _lexists(rsrc) and _lexists(rdst):
                errors.append(
                    f"move back {mv['dst']} -> {mv['src']}: both ends exist; "
                    "refusing to overwrite live data")
                continue
            _rename_or_copy(rsrc, rdst)
            mv["done"] = False
        except OSError as exc:
            errors.append(f"move back {mv['dst']} -> {mv['src']}: {exc}")
    if set_config is not None:
        try:
            cfg_path = Path(set_config["path"])
            cfg = json.loads(cfg_path.read_text(encoding="utf-8"))
            cfg["installation_id"] = set_config["old_id"]
            cfg["installation_source"] = set_config["old_source"]
            cfg["updated_at"] = datetime.datetime.now(
                datetime.timezone.utc).isoformat()
            me_setup.write_atomic(cfg_path,
                                  json.dumps(cfg, indent=2, sort_keys=True) + "\n")
            try:
                _fsync_file_path(cfg_path)
                _fsync_parent_dir(cfg_path)
            except OSError:
                pass
        except (OSError, json.JSONDecodeError, KeyError, me_setup.SetupError) as exc:
            errors.append(f"config restore: {exc}")
    return errors


def _reconcile_intents(journal: dict) -> list:
    """Reconcile write-ahead intents (done=False) against the filesystem.

    A crash can land between the durable intent write and the rename, or
    between the rename and the done=True write. For same-filesystem atomic
    renames there are only two stable states:
      src present + dst absent  -> move never started (no rollback needed)
      src absent + dst present  -> move completed but not journaled as done
    Both-present or neither-present are ambiguous: retain the journal and
    report problems instead of deleting original data. Completed intents are
    flipped to done=True in place so the normal rollback replays them.

    Ephemeral install sources (ready tree under data_dir/tmp, cleaned in the
    `finally` after a Python-exception failure) are never flipped: when the
    staging source is gone, the install never completed durably and there is
    nothing to undo -- the preservation rollback already restores prestate.
    Returns problem strings (empty when every intent is classifiable).
    """
    problems: list = []
    for mv in journal.get("moves", []):
        if mv.get("done"):
            continue
        try:
            src, dst = Path(mv["src"]), Path(mv["dst"])
        except (KeyError, TypeError):
            problems.append("journal move entry malformed")
            continue
        s, d = _lexists(src), _lexists(dst)
        if s and not d:
            continue
        if d and not s:
            src_s = str(src)
            # Staging/ready sources are ephemeral: if the source is under a
            # tmp staging dir that no longer exists, the install never landed
            # (or staging was already cleaned); do not resurrect it.
            if ("/tmp/" in src_s.replace("\\", "/")
                    or ".full-restore-" in src_s
                    or "/.full-backup-" in src_s):
                continue
            mv["done"] = True
            if not mv.get("method"):
                mv["method"] = "rename-recovered"
            continue
        if s and d:
            problems.append(
                f"in-progress move {mv.get('src')} -> {mv.get('dst')} has both "
                "ends present; refusing to guess which copy is authoritative")
            continue
        # Neither end present: if the source was ephemeral staging (cleaned),
        # the install never happened -- drop it, preservation rollback covers
        # prestate. Otherwise live data may be missing: block.
        src_s = str(mv.get("src", ""))
        if ("/tmp/" in src_s.replace("\\", "/")
                or ".full-restore-" in src_s):
            continue
        problems.append(
            f"in-progress move {mv.get('src')} -> {mv.get('dst')} has neither "
            "end present; live data may be missing")
    return problems


def _reconcile_config_intent(journal: dict) -> None:
    """Reconcile a config-adoption intent written before the config mutation.

    The journal records config_old durably BEFORE the config file is changed,
    then flips config_changed=True afterwards. If a crash lands in between,
    the on-disk journal shows config_old present but changed=False while the
    config file already carries the new id. Promote to changed=True in that
    case so recovery rolls it back; when the config still carries the old id
    the mutation never happened and no rollback is needed (rollback is a
    no-op that still clears the intent on success).
    """
    old = journal.get("config_old")
    if not isinstance(old, dict):
        return
    if journal.get("config_changed"):
        return
    try:
        cfg_path = Path(old["path"])
        cfg = json.loads(cfg_path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError, KeyError, TypeError):
        journal["config_changed"] = True
        return
    if cfg.get("installation_id") != old.get("old_id"):
        journal["config_changed"] = True


def _rollback_journal_moves(journal_path: Path, journal: dict) -> list:
    """Roll back per journal doc and persist the updated move states, so an
    interrupted rollback can be resumed by `restore-recover`. Returns errors.

    Reconciles write-ahead intents first (filesystem truth), persists the
    reconciliation durably, then replays. The journal write itself is durable
    (fsync file + parent dir) before any rollback mutation is claimed.
    """
    _reconcile_config_intent(journal)
    intent_problems = _reconcile_intents(journal)
    try:
        _durable_write_json(journal_path, journal, mode=0o600)
    except OSError:
        pass
    if intent_problems:
        return [f"in-progress intent: {p}" for p in intent_problems]
    set_config = journal.get("config_old") if journal.get("config_changed") else None
    # When an adoption was journaled but never flipped to changed (mutation
    # never reached the config file), there is still an old identity to
    # restore only if the file actually changed; _reconcile_config_intent
    # already promoted the real case. If not promoted, include the intent only
    # when the file differs (handled above); otherwise drop it after success.
    if journal.get("config_old") and not journal.get("config_changed"):
        # Mutation never happened: nothing to roll back, but keep the record
        # until prestate verifies, then clear below on success.
        set_config = None
    errors = _rollback_moves(journal.get("moves", []), set_config=set_config)
    if journal.get("config_old") and not journal.get("config_changed") and not errors:
        journal["config_old"] = None
    if set_config is not None and not any(e.startswith("config restore")
                                          for e in errors):
        journal["config_changed"] = False
        journal["config_old"] = None
    try:
        _durable_write_json(journal_path, journal, mode=0o600)
    except OSError:
        pass
    return errors


def _verify_prestate_swap(tasks_live: Path, house_live: Path, has_tasks: bool,
                          has_house: bool, prestate: dict) -> list:
    """Right-after-swap layout check: installed trees present, untouched
    trees undisturbed, nothing unexpected appeared. Returns problem strings.
    """
    problems: list = []
    if has_tasks:
        if not tasks_live.is_dir():
            problems.append(f"installed tasks tree missing at {tasks_live}")
    elif prestate.get("tasks_existed"):
        if not tasks_live.exists():
            problems.append(f"live tasks tree unexpectedly gone at {tasks_live}")
    elif tasks_live.exists():
        problems.append(f"unexpected tasks tree appeared at {tasks_live}")
    if has_house:
        if not house_live.is_dir():
            problems.append(f"installed household tree missing at {house_live}")
    elif prestate.get("household_existed"):
        if not house_live.exists():
            problems.append(f"live household tree unexpectedly gone at {house_live}")
    elif house_live.exists():
        problems.append(f"unexpected household tree appeared at {house_live}")
    return problems


def _verify_prestate(data_dir: Path, cfg: dict, prestate: dict) -> list:
    """Check live paths match the journaled prestate existence. Returns
    a list of mismatch strings (empty when prestate is fully restored)."""
    problems: list = []
    db_path = Path(cfg["service"]["db_path"])
    tasks_live = tasks_root_for(cfg)
    house_live = household_dir_for(cfg, data_dir)
    checks = ((str(db_path), prestate.get("db_existed")),
              (str(tasks_live), prestate.get("tasks_existed")),
              (str(house_live), prestate.get("household_existed")))
    for path, existed in checks:
        now_exists = Path(path).exists()
        if bool(existed) != now_exists:
            problems.append(
                f"{path}: expected {'present' if existed else 'absent'} "
                f"pre-restore, now {'present' if now_exists else 'absent'}")
    return problems


TASK_ID_RE = r"[A-Za-z0-9._-]{1,128}"


def _validate_task_ids(tasks_dir: Path) -> None:
    """Top-level task workspace names must be home-shaped identifiers
    (prefix_uuid per H1 ids.mjs; treated opaque, charset/length gated).
    Raises _ArchiveReject otherwise.
    """
    import re as _re
    if not tasks_dir.exists():
        return
    for child in sorted(tasks_dir.iterdir()):
        if not _re.fullmatch(TASK_ID_RE, child.name):
            raise _ArchiveReject(f"untrusted task workspace name {child.name!r}")


def _validate_and_rebase_pending(extracted: Path, manifest: dict,
                                 tasks_live: Path, limits: dict
                                 ) -> tuple[list, dict]:
    """Validate runtime inbox bindings and rebase absolute workspace paths.

    The R2 bridge records an ABSOLUTE `workspace` in
    `tasks/<tid>/.me_runtime/pending.json` and refuses a resume whose
    request workspace differs. A same-path restore needs no change; a
    cross-path restore (data dir B) must rewrite ONLY the workspace field to
    the canonical `tasks_live/<tid>`, preserving run/user/conversation/hash
    material, or the resumed answer would fail. Trust rule (validation
    phase, before any live mutation): pending `run_id` must equal the
    workspace directory id, and the old workspace must equal
    `manifest.source.tasks_root/<tid>` exactly (normpath-compared). Any
    mismatch rejects the archive. The graph.db checkpoint identifier
    (SqliteSaver thread_id == run_id) is path-independent and untouched.

    Returns (rebased_arc_paths, pending_by_task_id). Raises _ArchiveReject.
    """
    import re as _re
    src_root = ((manifest.get("source") or {}).get("tasks_root") or "")
    tasks_dir = extracted / "tasks"
    pending_paths = sorted(tasks_dir.rglob(".me_runtime/pending.json")) \
        if tasks_dir.exists() else []
    if pending_paths and not src_root:
        raise _ArchiveReject("archive holds pending checkpoints but manifest "
                             "lacks source.tasks_root; binding unverifiable")
    rebased: list = []
    pending_by_tid: dict = {}
    for pending_path in pending_paths:
        rel = pending_path.relative_to(tasks_dir).as_posix()
        parts = rel.split("/")
        if len(parts) != 3 or parts[1] != ".me_runtime":
            raise _ArchiveReject(f"pending checkpoint at unexpected path {rel!r}")
        tid = parts[0]
        if not _re.fullmatch(TASK_ID_RE, tid):
            raise _ArchiveReject(f"untrusted task id {tid!r}")
        try:
            record = json.loads(_read_bounded(
                pending_path, limits["pending"],
                f"pending.json for task {tid}").decode("utf-8"))
        except (OSError, UnicodeDecodeError, json.JSONDecodeError) as exc:
            raise _ArchiveReject(f"pending.json for task {tid} unreadable ({exc})")
        if not isinstance(record, dict):
            raise _ArchiveReject(f"pending.json for task {tid} is not an object")
        if record.get("run_id") != tid:
            raise _ArchiveReject(f"pending run_id mismatch for task {tid}; "
                                 "foreign checkpoint refused")
        old_ws = record.get("workspace")
        if not isinstance(old_ws, str) or not old_ws:
            raise _ArchiveReject(f"pending.json for task {tid} has no workspace")
        if os.path.normpath(old_ws) != os.path.normpath(os.path.join(src_root, tid)):
            raise _ArchiveReject(f"pending workspace binding mismatch for task {tid} "
                                 f"(expected under recorded tasks root); "
                                 "cross-binding restore refused")
        for field in ("user_id", "conversation_id"):
            if not record.get(field):
                raise _ArchiveReject(f"pending.json for task {tid} missing {field}; "
                                     "identity fields are never invented")
        pending_by_tid[tid] = record
        canonical = str(tasks_live / tid)
        if os.path.normpath(old_ws) == os.path.normpath(canonical):
            continue
        record["workspace"] = canonical
        try:
            pending_path.write_text(json.dumps(record, indent=2) + "\n",
                                    encoding="utf-8")
            os.chmod(pending_path, 0o600)
        except OSError as exc:
            raise _ArchiveReject(f"cannot rebase pending.json for task {tid} ({exc})")
        rebased.append(f"tasks/{tid}/.me_runtime/pending.json")
    return rebased, pending_by_tid


def _preflight_archive(src: Path, limits: dict) -> tuple:
    """Write-free header pass over the archive (streaming `r|gz`, member by
    member, payload skipped unread). Returns (file_count, unpacked_total).
    Raises _ArchiveReject before any payload byte is written anywhere, so a
    small compressed archive hiding a 1 GiB expansion is refused without
    filling the disk. Raises tarfile.TarError/OSError when the stream itself
    is unreadable.
    """
    import tarfile
    seen: set = set()
    acc = [0, 0]
    try:
        tar = tarfile.open(src, "r|gz")
    except (tarfile.TarError, OSError) as exc:
        raise _ArchiveReject(f"not a readable gzip tar ({exc})")
    with tar:
        while True:
            try:
                m = tar.next()
            except (tarfile.TarError, OSError, EOFError) as exc:
                raise _ArchiveReject(f"archive header unreadable ({exc})")
            if m is None:
                break
            _check_archive_member(m, seen, acc, limits)
    if "manifest.json" not in seen or "database/home.sqlite" not in seen:
        raise _ArchiveReject("archive missing manifest.json or database/home.sqlite")
    return acc[0], acc[1]


def _extract_archive(src: Path, extracted: Path, limits: dict) -> tuple:
    """Bounded streaming extract (second pass). Every payload is copied in
    64 KiB chunks with per-file and total unpacked caps enforced on ACTUAL
    bytes (declared sizes may lie); manifest.json is captured with its own
    cap before parsing. Returns (seen_names, actual_total, manifest_raw).
    Raises _ArchiveReject / tarfile.TarError / OSError; caller cleans staging.
    """
    import tarfile
    seen: set = set()
    declared = [0, 0]
    actual = [0, 0]
    manifest_raw: bytes | None = None
    try:
        tar = tarfile.open(src, "r|gz")
    except (tarfile.TarError, OSError) as exc:
        raise _ArchiveReject(f"not a readable gzip tar ({exc})")
    with tar:
        while True:
            try:
                m = tar.next()
            except (tarfile.TarError, OSError, EOFError) as exc:
                raise _ArchiveReject(f"archive header unreadable ({exc})")
            if m is None:
                break
            name = _check_archive_member(m, seen, declared, limits)
            dest_path = extracted / name
            try:
                dest_path.resolve().relative_to(extracted.resolve())
            except ValueError:
                raise _ArchiveReject(f"archive entry escapes staging {name!r}")
            if m.isdir():
                dest_path.mkdir(parents=True, exist_ok=True)
                try:
                    os.chmod(dest_path, 0o700)
                except OSError:
                    pass
                continue
            dest_path.parent.mkdir(parents=True, exist_ok=True)
            try:
                os.chmod(dest_path.parent, 0o700)
            except OSError:
                pass
            try:
                src_f = tar.extractfile(m)
            except (tarfile.TarError, OSError, EOFError) as exc:
                raise _ArchiveReject(f"cannot read archive entry {name!r} ({exc})")
            if src_f is None:
                raise _ArchiveReject(f"cannot read archive entry {name!r}")
            with src_f:
                if name == "manifest.json":
                    data = b""
                    while True:
                        try:
                            chunk = src_f.read(_STREAM_CHUNK)
                        except (tarfile.TarError, OSError, EOFError) as exc:
                            raise _ArchiveReject(
                                f"archive entry {name!r} unreadable ({exc})")
                        if not chunk:
                            break
                        data += chunk
                        actual[1] += len(chunk)
                        if len(data) > limits["manifest"]:
                            raise _ArchiveReject(
                                f"manifest.json over size cap {limits['manifest']}")
                        if actual[1] > limits["total"]:
                            raise _ArchiveReject(
                                "archive over unpacked-size cap during streaming "
                                "(possible decompression bomb)")
                    manifest_raw = data
                    try:
                        with open(dest_path, "wb") as out_f:
                            out_f.write(data)
                    except OSError as exc:
                        raise _ArchiveReject(f"cannot stage {name!r} ({exc})")
                    os.chmod(dest_path, 0o600)
                else:
                    try:
                        written = _stream_copy_bounded(
                            src_f, dest_path, m.size, actual, limits, name)
                    except (tarfile.TarError, OSError, EOFError) as exc:
                        raise _ArchiveReject(
                            f"archive entry {name!r} unreadable ({exc})")
                    if written != m.size:
                        raise _ArchiveReject(
                            f"archive entry {name!r} truncated "
                            f"({written}/{m.size} bytes)")
                    os.chmod(dest_path, 0o600)
    if "manifest.json" not in seen or "database/home.sqlite" not in seen:
        raise _ArchiveReject("archive missing manifest.json or database/home.sqlite")
    assert manifest_raw is not None
    return seen, actual[1], manifest_raw


def do_restore_full(data_dir: Path, *, source: str, confirm_destructive: bool = False) -> int:
    """Staged full restore: validate everything before mutating anything.

    Crash-safety model (honest, not atomic): validation is fully staged;
    mutation runs under a persisted 0600 journal
    (`backups/.restore-journal-<ts>-<pid>.json`) recording prestate and every
    rename. The multi-object swap is NOT one atomic transaction -- an
    interrupted restore leaves the journal `started`, and `start` refuses
    until `restore-recover` replays the rollback. Auto-rollback reports its
    own failures instead of claiming a recovery it did not perform.
    """
    import tarfile
    try:
        data_dir, cfg = load_cfg(data_dir)
    except me_setup.SetupError as exc:
        err(f"error: {exc}")
        return 2
    if not confirm_destructive:
        err("error: full restore replaces the live home database, task workspaces "
            "and household files; re-run with --confirm-destructive once you "
            "have a backup")
        return 2
    src = Path(source).expanduser()
    if not src.is_file():
        err(f"error: restore source not found: {src}")
        return 2
    try:
        limits = full_limits()
    except me_setup.SetupError as exc:
        err(f"error: {exc}")
        return 2
    try:
        if src.stat().st_size > limits["archive"]:
            err(f"error: archive over size cap {limits['archive']}; refusing")
            return 1
    except OSError as exc:
        err(f"error: cannot stat restore source: {exc}")
        return 2
    gate = full_stopped_gate(data_dir, cfg, "full restore")
    if gate is not None:
        return gate
    # ---- pass A: header-only preflight (no payload reads, no writes) ----
    try:
        _pre_count, pre_total = _preflight_archive(src, limits)
    except _ArchiveReject as exc:
        err(f"error: archive rejected in preflight, nothing touched ({exc})")
        return 1
    except (tarfile.TarError, OSError) as exc:
        err(f"error: restore source is not a valid full archive, nothing "
            f"touched ({exc})")
        return 1
    # Honest free-space estimate from the preflight UNPACKED total (a small
    # compressed archive may expand far beyond its own size).
    try:
        free = shutil.disk_usage(data_dir).free
    except OSError as exc:
        err(f"error: cannot check disk space: {exc}")
        return 1
    need = pre_total + 100 * 1024**2
    if free < need:
        err(f"error: insufficient disk for staged full restore (need ~{need} bytes "
            f"unpacked + margin, have {free} free under {data_dir}); nothing touched")
        return 1
    tag = f"{utc_stamp()}-{os.getpid()}"
    staging = data_dir / "tmp" / f".full-restore-{tag}"
    try:
        staging.mkdir(parents=True, exist_ok=False)
        os.chmod(staging, 0o700)
    except OSError as exc:
        err(f"error: cannot prepare staging dir: {exc}")
        return 1
    extracted = staging / "extracted"
    extracted.mkdir(parents=True, exist_ok=True)
    try:
        os.chmod(extracted, 0o700)
    except OSError:
        pass
    ready = staging / "ready"
    # ---- staged validation (no mutations to live data yet) ----
    try:
        # ---- pass B: bounded streaming extract ----
        try:
            seen, _actual_total, manifest_raw = _extract_archive(
                src, extracted, limits)
        except _ArchiveReject as exc:
            err(f"error: archive rejected during streaming extract, nothing "
                f"touched ({exc})")
            return 1
        except (tarfile.TarError, OSError) as exc:
            err(f"error: restore source is not a valid full archive, nothing "
                f"touched ({exc})")
            return 1
        # Manifest vs payload validation (manifest_raw was captured with an
        # explicit size cap during streaming, never read unbounded).
        try:
            manifest = json.loads(manifest_raw.decode("utf-8"))
        except (UnicodeDecodeError, json.JSONDecodeError) as exc:
            err(f"error: archive manifest is invalid, nothing touched ({exc})")
            return 1
        if not isinstance(manifest, dict):
            err("error: archive manifest is not an object; nothing touched")
            return 1
        if manifest.get("format_version") != FULL_FORMAT_VERSION:
            err(f"error: archive format_version {manifest.get('format_version')!r} "
                f"is not {FULL_FORMAT_VERSION!r}; nothing touched")
            return 1
        if manifest.get("scope") != "full":
            err("error: archive scope is not 'full'; nothing touched")
            return 1
        if not manifest.get("installation_id"):
            err("error: archive manifest has no installation_id; nothing touched")
            return 1
        expected: dict[str, dict] = {}
        for key in ("tasks", "household"):
            items = manifest.get(key)
            if not isinstance(items, list):
                err(f"error: archive manifest {key!r} is not a list; nothing touched")
                return 1
            for item in items:
                if not isinstance(item, dict) or not item.get("path"):
                    err(f"error: archive manifest {key!r} entry malformed; nothing touched")
                    return 1
                expected[item["path"]] = item
        db_info = manifest.get("database") or {}
        if db_info.get("path") != "database/home.sqlite":
            err("error: archive manifest database path unexpected; nothing touched")
            return 1
        expected["database/home.sqlite"] = db_info
        actual_files: set[str] = set()
        for dirpath, _dirnames, filenames in os.walk(extracted):
            for fn in filenames:
                full = Path(dirpath) / fn
                rel = full.relative_to(extracted).as_posix()
                if rel == "manifest.json":
                    continue
                actual_files.add(rel)
        if set(expected.keys()) != actual_files:
            err("error: archive payload does not match its manifest "
                f"(missing={sorted(set(expected) - actual_files)[:5]}, "
                f"extra={sorted(actual_files - set(expected))[:5]}); nothing touched")
            return 1
        for arc, item in expected.items():
            full = extracted / arc
            try:
                size = full.stat().st_size
            except OSError as exc:
                err(f"error: cannot stat staged {arc}: {exc}; nothing touched")
                return 1
            if item.get("size") != size or not item.get("sha256"):
                err(f"error: manifest size/hash entry malformed for {arc}; nothing touched")
                return 1
            if sha256_file(full) != item["sha256"]:
                err(f"error: hash mismatch for {arc}; archive corrupt, nothing touched")
                return 1
        staged_db = extracted / "database" / "home.sqlite"
        ok, detail = sqlite_verify(staged_db)
        if not ok:
            err(f"error: staged database FAILED verification, nothing touched ({detail})")
            return 1
        staged_id = me_setup.read_db_installation_id(staged_db) or ""
        if staged_id != manifest.get("installation_id"):
            err("error: staged database installation_id does not match manifest; "
                "nothing touched")
            return 1
        # Trusted task IDs: top-level workspace names must be home-shaped.
        try:
            _validate_task_ids(extracted / "tasks")
        except _ArchiveReject as exc:
            err(f"error: archive rejected, nothing touched ({exc})")
            return 1
        # Runtime inbox bindings: validate + rebase pending.json workspace
        # paths to this home (staged copy only; live untouched). Verified
        # hashes above cover the archived bytes; only `workspace` may change.
        try:
            rebased, pending_by_tid = _validate_and_rebase_pending(
                extracted, manifest, tasks_root_for(cfg), limits)
        except _ArchiveReject as exc:
            err(f"error: archive rejected in pending validation, nothing "
                f"touched ({exc})")
            return 1
        # Runtime checkpoint validation: known checkpoint SQLite files must
        # be valid SQLite with clean integrity; garbage magic denies the
        # restore even when the manifest hash matches (corrupt checkpoint,
        # not a corrupt archive, is still unrestorable).
        for arc in sorted(actual_files):
            if not is_known_checkpoint(arc):
                continue
            ok_c, detail_c = checkpoint_sqlite_ok(extracted / arc, strict=True)
            if not ok_c:
                err(f"error: runtime checkpoint {arc} FAILED validation "
                    f"({detail_c}); nothing touched")
                return 1
            parts = arc.split("/")
            if len(parts) >= 4 and parts[0] == "tasks" and parts[2] == ".me_runtime":
                ok_t, detail_t = checkpoint_thread_ok(
                    extracted / arc, parts[1])
                if not ok_t:
                    err(f"error: runtime checkpoint {arc} FAILED binding "
                        f"({detail_t}); nothing touched")
                    return 1
        # ---- build the ready tree (scrubbed + verified, still staged) ----
        # No live path is wiped or written until every ready copy validates.
        db_path = Path(cfg["service"]["db_path"])
        tasks_live = tasks_root_for(cfg)
        house_live = household_dir_for(cfg, data_dir)
        staged_db = extracted / "database" / "home.sqlite"
        ready_db = ready / "database" / "home.sqlite"
        try:
            ready_db.parent.mkdir(parents=True, exist_ok=True)
            shutil.copy2(staged_db, ready_db)
            # Auth scrub on the STAGED copy: restored sessions/devices/invites
            # are revoked so a rolled-back backup cannot revive revoked
            # phones. Identity and household/task data are preserved.
            dev_n, sess_n, inv_n = scrub_restored_auth(ready_db)
            sqlite_finalize(ready_db, "WAL")
        except (OSError, sqlite3.Error, sqlite3.DatabaseError) as exc:
            err(f"error: staged ready-database failed ({exc}); nothing touched")
            return 1
        ok, detail = sqlite_verify(ready_db)
        if not ok:
            err(f"error: staged ready-database FAILED readiness ({detail}); "
                "nothing touched")
            return 1
        has_tasks = (extracted / "tasks").exists()
        has_house = (extracted / "household").exists()
        try:
            if has_tasks:
                shutil.copytree(extracted / "tasks", ready / "tasks",
                                symlinks=False)
            if has_house:
                shutil.copytree(extracted / "household", ready / "household",
                                symlinks=False)
            for dirpath, _dirnames, filenames in os.walk(ready):
                try:
                    os.chmod(dirpath, 0o700)
                except OSError:
                    pass
                for fn in filenames:
                    try:
                        os.chmod(os.path.join(dirpath, fn), 0o600)
                    except OSError:
                        pass
        except OSError as exc:
            err(f"error: cannot stage ready tree ({exc}); nothing touched")
            return 1
        skipped = []
        if not has_tasks and tasks_live.exists():
            skipped.append("tasks tree not in archive; live tasks left untouched")
        if not has_house and house_live.exists():
            skipped.append("household tree not in archive; live household left untouched")
        # ---- journaled swap (renames, never recursive wipe of live data) --
        pre_dir = data_dir / "backups" / f"pre-restore-full-{tag}"
        journal_path = data_dir / "backups" / f"{RESTORE_JOURNAL_PREFIX}{tag}.json"
        try:
            pre_dir.mkdir(parents=True, exist_ok=False)
            os.chmod(pre_dir, 0o700)
        except OSError as exc:
            err(f"error: cannot prepare preservation dir ({exc}); nothing touched")
            return 1
        prestate = {
            "db_existed": db_path.is_file(),
            "tasks_existed": tasks_live.exists(),
            "household_existed": house_live.exists(),
            "sidecars": [s for s in ("-wal", "-shm", "-journal")
                         if Path(str(db_path) + s).is_file()],
            "config_installation_id": cfg.get("installation_id"),
            "config_installation_source": cfg.get("installation_source"),
        }
        journal = {
            "journal_version": RESTORE_JOURNAL_VERSION,
            "status": "started",
            "created_at": datetime.datetime.now(
                datetime.timezone.utc).isoformat(),
            "archive": str(src),
            "manifest_installation_id": manifest.get("installation_id"),
            "rebased_pending": rebased,
            "pre_dir": str(pre_dir),
            "prestate": prestate,
            "moves": [],
            "config_changed": False,
            "config_old": None,
        }

        def _write_journal() -> None:
            _durable_write_json(journal_path, journal, mode=0o600)

        def _log_move(op_src: Path, op_dst: Path) -> None:
            # Write-ahead intent: durably journal done=False BEFORE any
            # filesystem mutation, then rename, then mark done=True durably.
            # A power-kill between intent and done leaves a recoverable intent
            # (see _reconcile_intents); the old code renamed first and only
            # then journaled, losing the move on crash.
            intent = {"src": str(op_src), "dst": str(op_dst),
                      "done": False, "method": None}
            journal["moves"].append(intent)
            _write_journal()
            try:
                method = _rename_or_copy(op_src, op_dst)
            except Exception:
                # Python-exception path (not a power-kill): the rename never
                # happened, so drop the intent durably before propagating --
                # otherwise a later recover would see an ephemeral ready src
                # that staging cleanup already removed.
                try:
                    if journal["moves"] and journal["moves"][-1] is intent:
                        journal["moves"].pop()
                        _write_journal()
                except OSError:
                    pass
                raise
            intent["done"] = True
            intent["method"] = method
            _write_journal()

        def _preflight_same_fs(pairs: list) -> str | None:
            for s, d_parent in pairs:
                try:
                    if os.stat(s).st_dev != os.stat(d_parent).st_dev:
                        return (f"cross-filesystem move refused (EXDEV): {s} -> "
                                f"{d_parent}; keep the home data_dir on a single "
                                "filesystem so restore renames stay atomic; "
                                "nothing was mutated")
                except OSError as exc:
                    return f"cannot verify same-filesystem layout ({exc}); refusing"
            return None

        # EXDEV preflight before ANY live mutation (including the first
        # journaled rename). Default generated layout keeps everything under
        # data_dir (same mount) so this passes; split mounts are refused with
        # a clear error instead of a non-atomic copy fallback.
        try:
            _pairs: list = []
            if prestate["db_existed"]:
                _pairs.append((db_path, pre_dir))
            for _suffix in prestate["sidecars"]:
                _pairs.append((Path(str(db_path) + _suffix), pre_dir))
            _rt = has_tasks and prestate["tasks_existed"]
            _rh = has_house and prestate["household_existed"]
            if _rt:
                _pairs.append((tasks_live, pre_dir))
            if _rh:
                _pairs.append((house_live, pre_dir))
            _pairs.append((ready_db, db_path.parent))
            if has_tasks and (_rt or not prestate["tasks_existed"]):
                _pairs.append((ready / "tasks", tasks_live.parent))
            if has_house and (_rh or not prestate["household_existed"]):
                _pairs.append((ready / "household", house_live.parent))
            _exdev = _preflight_same_fs(
                [(s, d) for s, d in _pairs if os.path.lexists(str(s))])
        except (OSError, KeyError) as exc:
            err(f"error: cannot preflight restore layout ({exc}); nothing touched")
            try:
                shutil.rmtree(pre_dir, ignore_errors=True)
            except OSError:
                pass
            return 1
        if _exdev:
            err(f"error: {_exdev}")
            try:
                pre_dir.rmdir()
            except OSError:
                pass
            return 1
        try:
            _write_journal()
        except OSError as exc:
            err(f"error: cannot write restore journal ({exc}); nothing touched")
            return 1
        out(f"current data preserved at {pre_dir}")
        try:
            if prestate["db_existed"]:
                _log_move(db_path, pre_dir / "home.sqlite")
            for suffix in prestate["sidecars"]:
                _log_move(Path(str(db_path) + suffix),
                          pre_dir / f"home.sqlite{suffix}")
            replace_tasks = has_tasks and prestate["tasks_existed"]
            replace_house = has_house and prestate["household_existed"]
            if replace_tasks:
                _log_move(tasks_live, pre_dir / "tasks")
            if replace_house:
                _log_move(house_live, pre_dir / "household")
            _log_move(ready_db, db_path)
            if has_tasks and (replace_tasks or not prestate["tasks_existed"]):
                _log_move(ready / "tasks", tasks_live)
            if has_house and (replace_house or not prestate["household_existed"]):
                _log_move(ready / "household", house_live)
            ok_live, detail_live = sqlite_verify(db_path)
            if not ok_live:
                raise sqlite3.DatabaseError(
                    f"restored db failed readiness: {detail_live}")
            problems = _verify_prestate_swap(tasks_live, house_live, has_tasks,
                                             has_house, prestate)
            if problems:
                raise sqlite3.DatabaseError(
                    f"swap left unexpected layout: {'; '.join(problems)}")
        except (OSError, sqlite3.Error, sqlite3.DatabaseError) as exc:
            rerrs = _rollback_journal_moves(journal_path, journal)
            problems = _verify_prestate(data_dir, cfg, prestate)
            if not rerrs and not problems:
                journal["status"] = "rolled-back"
                try:
                    _write_journal()
                except OSError:
                    pass
                err(f"error: full restore failed during swap, rolled back to "
                    f"pre-restore state ({exc}); pre-restore copy at {pre_dir}")
            else:
                journal["status"] = "started"
                try:
                    _write_journal()
                except OSError:
                    pass
                detail_bits = []
                if rerrs:
                    detail_bits.append("rollback errors: " + "; ".join(rerrs))
                if problems:
                    detail_bits.append("prestate mismatches: " + "; ".join(problems))
                err(f"error: full restore failed during swap ({exc}) AND rollback "
                    f"is incomplete ({'; '.join(detail_bits)}). Live data may be "
                    f"mixed: do NOT start the service. Journal at {journal_path}; "
                    f"run `restore-recover --data-dir {data_dir}` or recover by "
                    f"hand from {pre_dir}.")
            return 1
        ok, detail = sqlite_verify(db_path)
        if not ok:
            rerrs = _rollback_journal_moves(journal_path, journal)
            problems = _verify_prestate(data_dir, cfg, prestate)
            if not rerrs and not problems:
                journal["status"] = "rolled-back"
                try:
                    _write_journal()
                except OSError:
                    pass
            err(f"error: restored database FAILED readiness ({detail}); "
                f"{'rolled back; ' if not rerrs and not problems else 'rollback incomplete; '}"
                f"previous copy is in {pre_dir}")
            return 1
        # Identity adoption is explicit: --confirm-destructive was required to
        # reach this point. The restored database is authoritative; the config
        # tracks it (old values stay in the journal for rollback/recovery).
        # If this home feeds a backend endpoint registration, update that
        # registration to the adopted installation_id (see docs); either way,
        # phones must re-pair against the restored home.
        restored_id = me_setup.read_db_installation_id(db_path)
        if restored_id and restored_id != cfg.get("installation_id"):
            journal["config_old"] = {
                "path": str(me_setup.config_path(data_dir)),
                "old_id": cfg.get("installation_id"),
                "old_source": cfg.get("installation_source"),
            }
            try:
                _write_journal()
            except OSError as exc:
                rerrs = _rollback_journal_moves(journal_path, journal)
                problems = _verify_prestate(data_dir, cfg, prestate)
                if not rerrs and not problems:
                    journal["status"] = "rolled-back"
                    try:
                        _write_journal()
                    except OSError:
                        pass
                err(f"error: cannot journal config adoption ({exc}); "
                    f"{'rolled back' if not rerrs and not problems else 'rollback incomplete'}; "
                    f"previous copy is in {pre_dir}")
                return 1
            try:
                backup_config(data_dir, "full restore adopted authoritative id")
                cfg["installation_id"] = restored_id
                cfg["installation_source"] = "restored-database"
                cfg["updated_at"] = datetime.datetime.now(
                    datetime.timezone.utc).isoformat()
                me_setup.write_atomic(me_setup.config_path(data_dir),
                                      json.dumps(cfg, indent=2, sort_keys=True) + "\n")
                try:
                    _fsync_file_path(me_setup.config_path(data_dir))
                    _fsync_parent_dir(me_setup.config_path(data_dir))
                except OSError:
                    pass
            except (OSError, me_setup.SetupError) as exc:
                rerrs = _rollback_journal_moves(journal_path, journal)
                problems = _verify_prestate(data_dir, cfg, prestate)
                journal["config_changed"] = False
                journal["config_old"] = None
                if not rerrs and not problems:
                    journal["status"] = "rolled-back"
                try:
                    _write_journal()
                except OSError:
                    pass
                err(f"error: config adoption failed ({exc}); "
                    f"{'rolled back to pre-restore data' if not rerrs and not problems else 'rollback incomplete'}; "
                    f"previous copy is in {pre_dir}")
                return 1
            journal["config_changed"] = True
            try:
                _write_journal()
            except OSError:
                pass
            # Durably fsync the completed journal state before unlinking below;
            # a crash after this point must still see completed-or-absent.
        journal["status"] = "completed"
        try:
            _durable_write_json(journal_path, journal, mode=0o600)
        except OSError:
            pass
        try:
            journal_path.unlink()
            _fsync_parent_dir(journal_path)
        except OSError:
            pass
        out(f"full restore complete + ready (scope=full: database + "
            f"{'task workspaces + ' if has_tasks else ''}"
            f"{'household files' if has_house else 'no household tree in archive'}; "
            f"{dev_n} devices revoked, {sess_n} sessions revoked, "
            f"{inv_n} invitations consumed -- pair fresh devices before use"
            f"{'; ' + '; '.join(skipped) if skipped else ''}"
            f"{'; rebased ' + str(len(rebased)) + ' pending workspace path(s)' if rebased else ''}): "
            f"{db_path} ({detail})")
        return 0
    finally:
        shutil.rmtree(staging, ignore_errors=True)


def do_restore_recover(data_dir: Path) -> int:
    """Resume an interrupted full restore from its persisted journal.

    Rolls back journaled renames and the recorded config identity, verifies
    the prestate, and clears the journal so `start` is allowed again. Refuses
    while the managed service (or anything on its port) is up. Never invents
    state: with no journal there is nothing to do.
    """
    try:
        data_dir, cfg = load_cfg(data_dir)
    except me_setup.SetupError as exc:
        err(f"error: {exc}")
        return 2
    journals = restore_journals(data_dir)
    if not journals:
        out("no interrupted restore journal; nothing to do")
        return 0
    journal_path = journals[-1]
    try:
        journal = json.loads(journal_path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        err(f"error: journal {journal_path} unreadable ({exc}); recover by hand "
            f"from the newest backups/pre-restore-full-*/ copy, then remove the "
            f"journal file only once verified")
        return 1
    if not isinstance(journal, dict) or \
            journal.get("journal_version") != RESTORE_JOURNAL_VERSION:
        err(f"error: journal {journal_path} has unknown format; recover by hand "
            f"from backups/pre-restore-full-*/ and remove it only once verified")
        return 1
    if journal.get("status") == "completed":
        try:
            journal_path.unlink()
        except OSError as exc:
            err(f"error: cannot clear completed journal ({exc})")
            return 1
        out("restore had completed; journal cleared")
        return 0
    if journal.get("status") == "rolled-back":
        problems = _verify_prestate(data_dir, cfg, journal.get("prestate", {}))
        if problems:
            err(f"error: journal says rolled back but prestate mismatches "
                f"({'; '.join(problems)}); recover by hand from "
                f"{journal.get('pre_dir')}")
            return 1
        try:
            journal_path.unlink()
        except OSError as exc:
            err(f"error: cannot clear journal ({exc})")
            return 1
        out("prior restore was already rolled back; journal cleared")
        return 0
    gate = full_stopped_gate(data_dir, cfg, "restore recovery")
    if gate is not None:
        return gate
    rerrs = _rollback_journal_moves(journal_path, journal)
    problems = _verify_prestate(data_dir, cfg, journal.get("prestate", {}))
    if not rerrs and not problems:
        try:
            journal_path.unlink()
            _fsync_parent_dir(journal_path)
        except OSError as exc:
            err(f"error: prestate restored but cannot clear journal ({exc}); "
                f"remove {journal_path} by hand once verified")
            return 1
        out(f"recovered pre-restore state from {journal.get('pre_dir')}; "
            f"journal cleared")
        return 0
    bits = []
    if rerrs:
        bits.append("rollback errors: " + "; ".join(rerrs))
    if problems:
        bits.append("prestate mismatches: " + "; ".join(problems))
    err(f"error: recovery incomplete ({'; '.join(bits)}). Live data may be "
        f"mixed: do NOT start the service. Journal retained at {journal_path}; "
        f"pre-restore copy at {journal.get('pre_dir')}.")
    return 1


# --- tunnel adapter (optional, named, fail-closed) -------------------------------

def discover_cloudflared(explicit: str | None = None) -> str | None:
    cand = explicit or os.environ.get("ME_HOME_CLOUDFLARED") or shutil.which("cloudflared")
    if cand and Path(cand).is_file() and os.access(cand, os.X_OK):
        return cand
    if cand and shutil.which(str(cand)):
        return shutil.which(str(cand))
    return None


def tunnel_config_path(data_dir: Path) -> Path:
    return data_dir / "config" / "cloudflared.yml"


TUNNEL_MODES = ("home-pairing", "cloudflare-access")


def verify_tunnel_preconditions(cfg: dict) -> str | None:
    """Fail-closed preconditions for any tunnel work. Returns error or None.

    The tunnel only ever forwards to the known loopback home API. An unknown
    contract version or a non-loopback binding means setup no longer
    understands what it would expose: refuse rather than publish.
    """
    try:
        service = cfg.get("service", {})
        host = service.get("host")
    except AttributeError:
        return "config has no service binding; re-run setup first"
    if cfg.get("home_api", {}).get("contract_status") != me_setup.CONTRACT_VERSION:
        return (f"home API contract {cfg.get('home_api', {}).get('contract_status')!r} "
                f"is not the known {me_setup.CONTRACT_VERSION!r}; refusing to expose "
                "an unverified API surface. Re-run setup after H1 publishes it.")
    if host not in me_setup.LOOPBACK_HOSTS:
        return (f"service host {host!r} is not loopback; the tunnel adapter only "
                "forwards to a loopback home API. Re-run setup with a loopback host.")
    return None


def do_tunnel_configure(data_dir: Path, *, hostname: str, credential_file: str,
                        protection: str = "home-pairing",
                        access_team: str = "", access_aud: str = "",
                        pairing_admission: str = "manual-external",
                        tunnel_name: str = "") -> int:
    """Write a named-tunnel config in one of two explicit protection modes.

    home-pairing (default, phone-compatible): cloudflared forwards HTTPS to
    the loopback home API with NO Access barrier. Protection is the home's
    own application auth, which the phone already speaks: one-time invitation
    enrollment, per-device revocable credentials, session auth on every
    private route. Public surface is only minimal health plus the H5
    rate-limited pair/session endpoints; anonymous private data never exists.

    cloudflare-access (optional, NOT phone-app-ready): adds the official
    originRequest.access block (required/teamName/audTag) so the connector
    validates the Access JWT before proxying. Native phone clients cannot
    complete Access login, so do not pretend this mode works with the current
    phone; edge auth here is explicitly manual/external.
    """
    try:
        data_dir, cfg = load_cfg(data_dir)
    except me_setup.SetupError as exc:
        err(f"error: {exc}")
        return 2
    if not hostname or "." not in hostname or hostname.startswith("."):
        err("error: --hostname is required and must be the intended stable "
            "public hostname (fail-closed); empty/bare names refused")
        return 2
    if hostname.endswith(".trycloudflare.com") or hostname == "quick":
        err("error: Quick Tunnels (trycloudflare.io) are development-only and "
            "refused here; production needs a named tunnel on your own hostname")
        return 2
    try:
        import ipaddress
        ipaddress.ip_address(hostname)
        err("error: --hostname must be a DNS name for a named tunnel, not an IP literal")
        return 2
    except ValueError:
        pass
    cred = Path(credential_file).expanduser()
    if not cred.is_file():
        err(f"error: --credential-file not found: {cred} (externally provisioned, "
            "least-privileged tunnel credential; setup never creates it)")
        return 2
    try:
        mode = stat.S_IMODE(cred.stat().st_mode)
    except OSError as exc:
        err(f"error: cannot stat credential file: {exc}")
        return 2
    if mode != 0o600:
        err(f"error: credential file mode is {oct(mode)}, must be 0600 "
            f"(run: chmod 0600 {cred}); refusing to use a group/world-readable secret")
        return 2
    try:
        cred_doc = json.loads(cred.read_text(encoding="utf-8"))
        tunnel_id = str(cred_doc.get("TunnelID", "") or tunnel_name or "")
    except (OSError, json.JSONDecodeError, UnicodeDecodeError) as exc:
        err(f"error: credential file is not readable JSON: {exc}")
        return 2
    if not tunnel_id:
        err("error: credential file has no TunnelID and no --tunnel-name given; "
            "cannot bind the named tunnel")
        return 2
    # Never log credential content: only the TunnelID (an identifier) is echoed.
    if protection not in TUNNEL_MODES:
        err(f"error: --protection must be one of {TUNNEL_MODES} (got {protection!r}); "
            "incompatible modes are denied, never guessed")
        return 2
    pre = verify_tunnel_preconditions(cfg)
    if pre is not None:
        err(f"error: fail-closed: {pre}")
        return 2
    if pairing_admission not in ("backend-mediated", "limited-pairing-service",
                                 "manual-external"):
        err("error: --pairing-admission must be backend-mediated, "
            "limited-pairing-service, or manual-external")
        return 2
    if pairing_admission != "manual-external":
        err("warning: no automated pairing admission is implemented in this repo; "
            "recording your declared intent, but enrollment remains a manual, "
            "out-of-band operator step until a backend-mediated flow exists. "
            "Per-device home auth stays mandatory regardless of edge admission.")
    aud_tags = [t.strip() for t in (access_aud or "").split(",") if t.strip()]
    if protection == "cloudflare-access":
        if not access_team or not aud_tags:
            err("error: fail-closed: cloudflare-access mode requires --access-team "
                "(Zero Trust team slug) AND --access-aud (Access AUD tag(s), "
                "comma-separated). The connector enforces these via "
                "originRequest.access; a team name alone is not protection. Get "
                "the AUD tag from the Access application overview.")
            return 2
    else:  # home-pairing: home application auth is the protection; no Access.
        if access_team or aud_tags:
            err("error: --access-team/--access-aud do not apply in home-pairing "
                "mode (no Access barrier by design; the home enforces auth). "
                "Use --protection cloudflare-access for the provider edge path.")
            return 2
    host, port = cfg["service"]["host"], int(cfg["service"]["port"])
    if protection == "cloudflare-access":
        aud_lines = "\n".join(f"        - {tag}" for tag in aud_tags)
        access_block = (
            "      access:\n"
            "        required: true\n"
            f"        teamName: {access_team}\n"
            "        audTag:\n"
            f"{aud_lines}\n"
        )
        protection_record = {
            "mode": protection,
            "access_team": access_team,
            "access_aud": aud_tags,
            "enforcement": "cloudflared originRequest.access "
                           "(connector validates Access JWT before proxying); "
                           "NOT phone-app-ready: native clients cannot complete "
                           "Access login, edge auth here is manual/external",
            "pairing_admission": pairing_admission,
            "pairing_status": ("manual-external: enrollment is a "
                               "manual out-of-band operator step; "
                               "no automated flow implemented"),
            "note": "Edge Access app + policy must exist before "
                    "the route carries traffic; per-device home "
                    "auth stays mandatory regardless of edge "
                    "admission."}
        rule_comment = ("# Protection: provider edge (cloudflare-access). Phone "
                        "clients cannot use this mode.")
    else:
        access_block = ""
        protection_record = {
            "mode": protection,
            "enforcement": "home application auth (one-time invitation "
                           "enrollment, per-device revocable credentials, "
                           "session auth on every private route) plus H5 "
                           "per-IP failure budgets on the public pair/session "
                           "endpoints (429 + Retry-After)",
            "public_surface": ["GET /healthz", "GET /readyz",
                               "POST /v1/pair", "POST /v1/sessions"],
            "pairing_admission": pairing_admission,
            "pairing_status": ("manual-external: enrollment is a "
                               "manual out-of-band operator step; "
                               "no automated flow implemented"),
            "note": "No Access barrier by design: the phone speaks only Me "
                    "per-device/session credentials. Anonymous private data "
                    "never exists; every private route requires session auth."}
        rule_comment = ("# Protection: home-pairing (phone-compatible). No Access "
                        "barrier; the home API enforces auth on every private "
                        "route and rate-limits pair/session attempts.")
    yml = (
        "# Generated by setup-infra tunnel configure (rerunnable).\n"
        "# The credential file below is referenced by PATH ONLY; its content\n"
        "# never appears in argv, logs, or phone material.\n"
        f"# Protection mode: {protection}.\n"
        f"{rule_comment}\n"
        f"tunnel: {tunnel_id}\n"
        f"credentials-file: {cred}\n"
        "ingress:\n"
        f"  - hostname: {hostname}\n"
        f"    service: http://{host}:{port}\n"
        "    originRequest:\n"
        "      connectTimeout: 10s\n"
        f"{access_block}"
        "  - service: http_status:404\n"
    )
    try:
        me_setup.write_atomic(tunnel_config_path(data_dir), yml, mode=0o600)
    except OSError as exc:
        err(f"error: cannot write tunnel config: {exc}")
        return 1
    try:
        backup_config(data_dir, "tunnel configure")
        cfg["tunnel"] = {"mode": "configured", "provider": "cloudflare",
                         "tunnel_kind": "named tunnel (production only; never Quick Tunnel)",
                         "hostname": hostname, "tunnel_id": tunnel_id,
                         "config": str(tunnel_config_path(data_dir)),
                         "protection": protection_record,
                         "note": "Credential-dependent live checks are parked for the "
                                 "user; this adapter only writes config."}
        me_setup.write_atomic(me_setup.config_path(data_dir),
                              json.dumps(cfg, indent=2, sort_keys=True) + "\n")
    except (OSError, me_setup.SetupError) as exc:
        err(f"error: cannot record tunnel config: {exc}")
        return 1
    out(f"tunnel configured (not running): {tunnel_config_path(data_dir)} "
        f"hostname={hostname} tunnel={tunnel_id} protection={protection}")
    if protection == "cloudflare-access":
        out("start it explicitly with `tunnel run` once Access protection is verified; "
            "this mode is NOT phone-app-ready")
    else:
        out("phone path: pair phones via the one-time invitation against "
            f"https://{hostname}/v1/pair, then use the API with session auth")
    return 0


def tunnel_protection_markers(yml_text: str, mode: str) -> tuple[list, list]:
    """Mode-appropriate markers. Returns (missing_required, forbidden_present).

    cloudflare-access: the official originRequest.access schema
    (required/teamName/audTag) must be present -- recording a team name was
    never enforcement. home-pairing: the phone-compatible marker must be
    present and NO access enforcement block may be (a mixed config would
    silently lock phones out). Either violation fails closed.
    """
    if mode == "cloudflare-access":
        missing = [m for m in ("access:", "required: true", "teamName:", "audTag:")
                   if m not in yml_text]
        return missing, []
    missing = [m for m in ("# Protection mode: home-pairing",
                           "http_status:404") if m not in yml_text]
    forbidden = [m for m in ("required: true", "audTag:") if m in yml_text]
    return missing, forbidden


def do_tunnel_run(data_dir: Path, *, detach: bool = False,
                 cloudflared_explicit: str | None = None) -> int:
    try:
        data_dir, cfg = load_cfg(data_dir)
    except me_setup.SetupError as exc:
        err(f"error: {exc}")
        return 2
    if cfg.get("tunnel", {}).get("mode") != "configured":
        err("error: no tunnel configured; run `tunnel configure` first (fail-closed)")
        return 2
    pre = verify_tunnel_preconditions(cfg)
    if pre is not None:
        err(f"error: fail-closed: {pre}")
        return 2
    prot_mode = cfg.get("tunnel", {}).get("protection", {}).get("mode", "")
    if prot_mode not in TUNNEL_MODES:
        err(f"error: fail-closed: stored tunnel protection mode {prot_mode!r} is "
            f"unknown (expected one of {TUNNEL_MODES}); re-run `tunnel configure`. "
            "No tunnel started.")
        return 2
    yml = tunnel_config_path(data_dir)
    if not yml.is_file():
        err(f"error: tunnel config missing at {yml}; re-run `tunnel configure`")
        return 1
    try:
        yml_text = yml.read_text(encoding="utf-8")
    except OSError as exc:
        err(f"error: cannot read tunnel config: {exc}")
        return 1
    missing, forbidden = tunnel_protection_markers(yml_text, prot_mode)
    if missing or forbidden:
        detail = ""
        if missing:
            detail += f"missing {missing}; "
        if forbidden:
            detail += f"forbidden markers present {forbidden} (mode mismatch); "
        err(f"error: FAIL-CLOSED: tunnel config does not match its declared "
            f"{prot_mode} protection ({detail}no tunnel started. Re-run "
            "`tunnel configure` with a single explicit protection mode.")
        return 2
    binary = discover_cloudflared(cloudflared_explicit)
    if not binary:
        err("PARKED: cloudflared is not installed/found (pass --cloudflared or set "
            "ME_HOME_CLOUDFLARED). Install the supported provider tooling, then "
            "re-run. No tunnel started, nothing provisioned.")
        return EXIT_PARKED
    argv = [binary, "tunnel", "--config", str(yml), "run"]
    if detach:
        log_path = data_dir / "logs" / "cloudflared.log"
        try:
            fh = open(log_path, "a", encoding="utf-8")
        except OSError as exc:
            err(f"error: cannot open log {log_path}: {exc}")
            return 1
        try:
            proc = subprocess.Popen(argv, stdout=fh, stderr=subprocess.STDOUT,
                                    start_new_session=True)
        except OSError as exc:
            err(f"error: failed to spawn cloudflared: {exc}")
            return 1
        (data_dir / "run").mkdir(parents=True, exist_ok=True)
        (data_dir / TUNNEL_PIDFILE_RELPATH).write_text(json.dumps(
            {"pid": proc.pid, "exe": binary, "argv": argv,
             "config": str(yml),
             "started_at": datetime.datetime.now(datetime.timezone.utc).isoformat()},
            indent=2) + "\n", encoding="utf-8")
        out(f"cloudflared detached: pid {proc.pid} (log {log_path})")
        return 0
    out(f"running foreground: {' '.join(shlex.quote(a) for a in argv)} "
        "(Ctrl-C stops; credential content never appears in argv/logs)")
    try:
        completed = subprocess.run(argv)
    except OSError as exc:
        err(f"error: failed to run cloudflared: {exc}")
        return 1
    return completed.returncode


def do_tunnel_status(data_dir: Path) -> int:
    try:
        data_dir, cfg = load_cfg(data_dir)
    except me_setup.SetupError as exc:
        err(f"error: {exc}")
        return 2
    tun = cfg.get("tunnel", {})
    out(f"tunnel mode: {tun.get('mode', 'disabled')}")
    prot = tun.get("protection", {})
    if prot.get("mode"):
        out(f"protection mode: {prot['mode']}")
    if tun.get("hostname"):
        out(f"hostname: {tun['hostname']} (tunnel {tun.get('tunnel_id', '?')})")
    yml = tunnel_config_path(data_dir)
    out(f"config file: {yml} ({'present' if yml.is_file() else 'absent'})")
    if yml.is_file():
        try:
            missing, forbidden = tunnel_protection_markers(
                yml.read_text(encoding="utf-8"), prot.get("mode", ""))
        except OSError:
            missing, forbidden = ["<unreadable>"], []
        if not missing and not forbidden and prot.get("mode") in TUNNEL_MODES:
            label = ("connector-enforced Access JWT validation"
                     if prot.get("mode") == "cloudflare-access"
                     else "home application auth (phone-compatible, no Access barrier)")
            out(f"connector protection: {label}")
        else:
            out(f"connector protection: MISMATCH missing={missing} forbidden={forbidden} "
                "-- run will refuse")
    binary = discover_cloudflared()
    out(f"cloudflared: {binary or 'not found (live run parked for the user)'}")
    if prot:
        if prot.get("mode") == "cloudflare-access":
            out(f"protection: Access team {prot.get('access_team')}, "
                f"AUD {prot.get('access_aud')} (NOT phone-app-ready; manual external edge auth), "
                f"pairing via {prot.get('pairing_admission')} "
                f"({prot.get('pairing_status', '')})")
        else:
            out(f"protection: home-pairing (phone path): {prot.get('enforcement', '')} "
                f"pairing via {prot.get('pairing_admission')} "
                f"({prot.get('pairing_status', '')})")
    if binary and yml.is_file():
        out("operator validation (needs no tunnel running):\n"
            f"  cloudflared tunnel --config {yml} ingress validate\n"
            f"  cloudflared tunnel --config {yml} ingress rule https://<hostname>/")
    return 0


# --- service unit generation (files only, never installed) ----------------------

SERVICE_GUARD_FILENAME = "me-home.exec.py"


def service_guard_source() -> Path:
    """Absolute path of the shared guard implementation in this checkout."""
    return Path(__file__).resolve().parent / "me_service_exec.py"


def write_service_guard(data_dir: Path) -> Path:
    """Copy the shared guard into <data-dir>/config (generated, no install).

    Generated units exec this copy, so they keep working even if the
    setup-infra checkout moves. The file contains no secrets and is
    space-safe (referenced by argv list, never by shell).
    """
    src = service_guard_source()
    dest = data_dir / "config" / SERVICE_GUARD_FILENAME
    try:
        text = src.read_text(encoding="utf-8")
    except OSError as exc:
        raise me_setup.SetupError(f"guard source missing at {src}: {exc}")
    # Bake the originating scripts dir as an import fallback so the generated
    # copy still finds me_setup/me_lifecycle even though it lives in config/.
    text = text.replace("@SETUP_SCRIPTS_DIR@", str(src.parent))
    dest.parent.mkdir(parents=True, exist_ok=True)
    import tempfile as _tf
    fd, tmp = _tf.mkstemp(dir=str(dest.parent), prefix=dest.name + ".")
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as f:
            f.write(text)
            try:
                f.flush()
                os.fsync(f.fileno())
            except OSError:
                pass
        os.chmod(tmp, 0o755)
        os.replace(tmp, dest)
    except BaseException:
        try:
            os.unlink(tmp)
        except OSError:
            pass
        raise
    _fsync_parent_dir(dest)
    try:
        os.chmod(dest, 0o755)
    except OSError:
        pass
    return dest


def service_guard_argv(python_bin: str, guard_path: Path, data_dir: Path,
                       node_bin: str, entrypoint: Path) -> list:
    """Argv for generated units: [python, guard, --data-dir .., --node .., ...].

    The guard re-derives Node TS flags via node_args_for and execs Node, so
    PID/signal/argv/env semantics are preserved (os.execv, no shell).
    """
    return [python_bin, str(guard_path),
            "--data-dir", str(data_dir),
            "--node", str(node_bin),
            "--entrypoint", str(entrypoint)]


def service_command(node_bin: str, entrypoint: Path, cfg: dict) -> tuple[list, dict, str]:
    """The exact managed command + env + workdir shared by start and service units.

    Returns (argv, env-delta, workdir). Env excludes secrets: generated unit
    files must never bake in ME_RUNTIME_MODEL_API_KEY; if the operator needs a
    remote model under a service manager they export the key in that service
    context themselves (warned at generation time).
    """
    db_path = cfg["service"]["db_path"]
    host, port = cfg["service"]["host"], int(cfg["service"]["port"])
    flags = me_setup.node_args_for(node_bin, entrypoint)[1:]
    argv = [node_bin, *flags, str(entrypoint), "start",
            f"--db={db_path}", f"--host={host}", f"--port={port}"]
    # Checkout root: entrypoint is <checkout>/src/cli.mjs. (Triple-parent
    # would land on the checkout's PARENT; the service and its relative
    # paths belong to the checkout itself.)
    workdir = str(entrypoint.parent.parent)
    env = {"HOME_DB": str(db_path), "HOME_HOST": host, "HOME_PORT": str(port)}
    env.update(build_home_env(cfg))
    for secret in (*RUNTIME_SECRET_ALLOWLIST, *PUSH_SECRET_ALLOWLIST):
        env.pop(secret, None)
    # Coordinator/notification references are non-secret and stay in the unit;
    # the home reads the 0600 file / shell-provided token at runtime.
    return argv, env, workdir


def systemd_escape(value: str) -> str:
    """Escape a value for systemd Environment="NAME=value"."""
    return value.replace("\\", "\\\\").replace('"', '\\"').replace("\n", "")


def do_service_generate(data_dir: Path, *, format: str,
                        output: str | None = None, node_explicit=None,
                        infra_explicit=None) -> int:
    try:
        data_dir, cfg = load_cfg(data_dir)
    except me_setup.SetupError as exc:
        err(f"error: {exc}")
        return 2
    if format not in ("launchd", "systemd"):
        err("error: --format must be launchd or systemd")
        return 2
    try:
        node_bin = resolve_node(node_explicit)
        checkout, entrypoint = resolve_home_cli(infra_explicit)
    except me_setup.SetupError as exc:
        err(f"error: {exc}")
        return 3
    host, port = cfg["service"]["host"], int(cfg["service"]["port"])
    try:
        argv, env, workdir = service_command(node_bin, entrypoint, cfg)
    except me_setup.SetupError as exc:
        err(f"error: {exc}")
        return 2
    _ = checkout
    _ = argv  # direct Node argv retained for `start`; units use the guard below
    try:
        guard_path = write_service_guard(data_dir)
    except (OSError, me_setup.SetupError) as exc:
        err(f"error: cannot write service guard ({exc})")
        return 1
    guard_argv = service_guard_argv(sys.executable, guard_path, data_dir,
                                    node_bin, entrypoint)
    log_path = Path(cfg["service"]["log_dir"]) / "home-service.log"
    default_name = ("me-home.launchd.plist" if format == "launchd"
                    else "me-home.systemd.unit")
    dest = Path(output).expanduser() if output else data_dir / "config" / default_name
    secret_needed = bool(os.environ.get("ME_RUNTIME_MODEL_API_KEY")
                         or os.environ.get("HOME_EXPO_ACCESS_TOKEN"))
    if format == "launchd":
        import plistlib
        doc = {
            "Label": f"ai.mehome.home-{port}",
            "ProgramArguments": guard_argv,
            "EnvironmentVariables": env,
            "WorkingDirectory": workdir,
            "StandardOutPath": str(log_path),
            "StandardErrorPath": str(log_path),
            "RunAtLoad": False,
        }
        try:
            data = plistlib.dumps(doc, fmt=plistlib.FMT_XML)
        except (ValueError, TypeError) as exc:
            err(f"error: cannot encode launchd plist: {exc}")
            return 1
        try:
            dest.parent.mkdir(parents=True, exist_ok=True)
            with open(dest, "wb") as f:
                f.write(data)
        except OSError as exc:
            err(f"error: cannot write unit file: {exc}")
            return 1
        install_hint = ("generated only -- NOT installed. To enable for your login:\n"
                        f"  cp {dest} ~/Library/LaunchAgents/ai.mehome.home-{port}.plist\n"
                        f"  launchctl load ~/Library/LaunchAgents/ai.mehome.home-{port}.plist")
    else:
        import getpass
        user = getpass.getuser()
        env_lines = "\n".join(f'Environment="{k}={systemd_escape(v)}"'
                              for k, v in sorted(env.items()))
        text = f"""[Unit]
Description=Me home service (dev, loopback :{port})
After=network-online.target

[Service]
Type=simple
ExecStart={shlex.join(guard_argv)}
WorkingDirectory={workdir}
{env_lines}
StandardOutput=append:{log_path}
StandardError=append:{log_path}
Restart=on-failure
User={user}

[Install]
WantedBy=default.target
"""
        try:
            me_setup.write_atomic(dest, text)
        except OSError as exc:
            err(f"error: cannot write unit file: {exc}")
            return 1
        install_hint = ("generated only -- NOT installed. To enable as a user unit:\n"
                        f"  cp {dest} ~/.config/systemd/user/me-home.service\n"
                        "  systemctl --user daemon-reload && systemctl --user enable --now me-home.service")
    if secret_needed:
        install_hint += ("\nNOTE: ME_RUNTIME_MODEL_API_KEY and/or HOME_EXPO_ACCESS_TOKEN are set in this shell but were "
                         "NOT baked into the unit (secrets are never persisted). Export "
                         "it in the service context if a remote model is required.")
    out(f"service unit generated (not installed): {dest}\n{install_hint}")
    return 0


# --- CLI -------------------------------------------------------------------------

def add_common(p: argparse.ArgumentParser) -> None:
    p.add_argument("--data-dir", default=os.environ.get(
        "ME_HOME_DATA_DIR", str(me_setup.default_data_dir())))
    p.add_argument("--infra-checkout", default=os.environ.get("ME_HOME_INFRA_CHECKOUT", ""))
    p.add_argument("--node", default=os.environ.get("ME_HOME_NODE", ""))


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        description="Me home dev lifecycle: start/status/stop/bootstrap/coordinator/backup/restore/tunnel/service")
    sub = p.add_subparsers(dest="cmd", required=True)

    s = sub.add_parser("start", help="start the managed home service (loopback only)")
    add_common(s)

    s = sub.add_parser("status", help="report managed service + contract/bridge state")
    add_common(s)

    s = sub.add_parser("stop", help="stop ONLY the verified managed process")
    add_common(s)
    s.add_argument("--force", action="store_true", help="SIGKILL after SIGTERM grace")

    s = sub.add_parser("bootstrap", help="create a one-time pairing invitation via the home CLI")
    add_common(s)
    s.add_argument("--user", required=True, help="household user id (e.g. alice)")
    s.add_argument("--ttl-min", type=int, default=15)
    s.add_argument("--name", default="")
    s.add_argument("--format", default="raw", choices=("raw", "pairing-v1"),
                   help="raw (default, home CLI JSON, backward compatible) or "
                        "pairing-v1 (trusted LOCAL home-pairing-v1 JSON with "
                        "home_url from local config, never a backend hint)")
    s.add_argument("--public-url", default="",
                   help="explicit local public home URL for pairing-v1 "
                        "(else ME_HOME_PUBLIC_URL, coordinator.public_home_url, "
                        "or named-tunnel hostname)")
    s.add_argument("--allow-http-loopback", action="store_true",
                   help="explicit dev/test opt-in: allow http:// loopback "
                        "pairing/coordinator URLs (never for production)")

    c = sub.add_parser("coordinator", help="S7 cloud-coordination activation "
                                           "(prepare/activate/status/check)")
    csub = c.add_subparsers(dest="coordinator_cmd", required=True)
    pp = csub.add_parser("prepare", help="record authoritative install + local "
                                         "public URL (no network, no secrets)")
    pp.add_argument("--data-dir", default=os.environ.get(
        "ME_HOME_DATA_DIR", str(me_setup.default_data_dir())))
    pp.add_argument("--public-url", default="",
                    help="local public home base URL (https://; http:// loopback "
                         "only with --allow-http-loopback)")
    pp.add_argument("--backend-url", default="",
                    help="known backend base URL (recorded non-secret; activate "
                         "must match when set)")
    pp.add_argument("--credentials-file", default="",
                    help="absolute path of the private 0600 credentials file")
    pp.add_argument("--allow-http-loopback", action="store_true",
                    help="explicit dev/test opt-in for http:// loopback URLs")
    a = csub.add_parser("activate", help="redeem the STDIN one-time ticket "
                                         "once (ticket-only, no account JWT) "
                                         "and persist the 0600 file")
    a.add_argument("--data-dir", default=os.environ.get(
        "ME_HOME_DATA_DIR", str(me_setup.default_data_dir())))
    a.add_argument("--timeout-ms", type=int, default=me_coordinator.REQUEST_TIMEOUT_DEFAULT_MS,
                   help="single-attempt HTTPS timeout in ms "
                        f"({me_coordinator.REQUEST_TIMEOUT_MIN_MS}..{me_coordinator.REQUEST_TIMEOUT_MAX_MS}, "
                        "no retries)")
    a.add_argument("--allow-http-loopback", action="store_true",
                   help="explicit dev/test opt-in for http:// loopback backend")
    st = csub.add_parser("status", help="redacted coordinator state (never "
                                        "token/secret/file content)")
    st.add_argument("--data-dir", default=os.environ.get(
        "ME_HOME_DATA_DIR", str(me_setup.default_data_dir())))
    ck = csub.add_parser("check", help="strict local validation (no network)")
    ck.add_argument("--data-dir", default=os.environ.get(
        "ME_HOME_DATA_DIR", str(me_setup.default_data_dir())))

    s = sub.add_parser("backup", help="SQLite snapshot (scope=db, online-safe) "
                         "or full household archive (scope=full, stopped)")
    add_common(s)
    s.add_argument("--output", default="")
    s.add_argument("--scope", default="db", choices=("db", "full"),
                   help="db (default): online-safe SQLite snapshot only -- task "
                        "workspaces/checkpoints and household files NOT included. "
                        "full: stopped-service .tar.gz archive of SQLite + task "
                        "workspaces (incl. .me_runtime checkpoints) + household "
                        "files + manifest; config/logs/secrets excluded, local-only.")

    s = sub.add_parser("restore", help="restore a verified backup (service must be stopped)")
    add_common(s)
    s.add_argument("--from", dest="source", required=True)
    s.add_argument("--confirm-destructive", action="store_true")
    s.add_argument("--scope", default="auto", choices=("auto", "db", "full"),
                   help="auto (default): detect by suffix (.tar.gz/.tgz -> full, "
                        "else db). db: legacy SQLite-only restore (sessions/devices "
                        "preserved as archived). full: staged validate-then-swap of "
                        "database + workspaces + household files with credential "
                        "scrub (fresh pairing required after).")

    s = sub.add_parser("restore-recover", help="roll back an interrupted full "
                       "restore from its persisted journal (service must be stopped)")
    add_common(s)

    t = sub.add_parser("tunnel", help="optional named-tunnel adapter (fail-closed)")
    tsub = t.add_subparsers(dest="tunnel_cmd", required=True)
    c = tsub.add_parser("configure", help="write named-tunnel config (starts nothing)")
    c.add_argument("--data-dir", default=os.environ.get(
        "ME_HOME_DATA_DIR", str(me_setup.default_data_dir())))
    c.add_argument("--hostname", default="")
    c.add_argument("--credential-file", default=os.environ.get("ME_HOME_TUNNEL_CREDENTIALS", ""))
    c.add_argument("--tunnel-name", default="")
    c.add_argument("--protection", default="home-pairing",
                   choices=("home-pairing", "cloudflare-access"),
                   help="protection mode: home-pairing (default, phone-compatible, "
                        "home application auth) or cloudflare-access (optional "
                        "provider edge path, NOT phone-app-ready)")
    c.add_argument("--access-team", default="",
                   help="Cloudflare Zero Trust team slug (cloudflare-access only)")
    c.add_argument("--access-aud", default="",
                   help="Access application AUD tag(s), comma-separated (cloudflare-access only)")
    c.add_argument("--pairing-admission", default="manual-external",
                   help="{manual-external|backend-mediated|limited-pairing-service}; "
                        "only manual-external is honest today")
    r = tsub.add_parser("run", help="launch cloudflared with the stored config")
    r.add_argument("--data-dir", default=os.environ.get(
        "ME_HOME_DATA_DIR", str(me_setup.default_data_dir())))
    r.add_argument("--detach", action="store_true")
    r.add_argument("--cloudflared", default="")
    st = tsub.add_parser("status", help="show tunnel config/tooling state")
    st.add_argument("--data-dir", default=os.environ.get(
        "ME_HOME_DATA_DIR", str(me_setup.default_data_dir())))

    s = sub.add_parser("service", help="generate service units (files only, never install)")
    add_common(s)
    s.add_argument("--format", required=True, choices=("launchd", "systemd"))
    s.add_argument("--output", default="")
    return p


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    common = {"node_explicit": getattr(args, "node", "") or None,
              "infra_explicit": getattr(args, "infra_checkout", "") or None}
    try:
        if args.cmd == "start":
            return do_start(Path(args.data_dir), **common)
        if args.cmd == "status":
            return do_status(Path(args.data_dir),
                             infra_explicit=args.infra_checkout or None)
        if args.cmd == "stop":
            return do_stop(Path(args.data_dir), force=args.force)
        if args.cmd == "bootstrap":
            return do_bootstrap(Path(args.data_dir), user=args.user,
                                ttl_min=args.ttl_min, name=args.name, **common,
                                format=args.format, public_url=args.public_url or "",
                                allow_http_loopback=args.allow_http_loopback)
        if args.cmd == "coordinator":
            if args.coordinator_cmd == "prepare":
                try:
                    dd, cfg = load_cfg(Path(args.data_dir))
                except me_setup.SetupError as exc:
                    err(f"error: {exc}")
                    return 2
                return me_coordinator.do_prepare(
                    dd, cfg, public_url=args.public_url or "",
                    backend_url=args.backend_url or "",
                    credentials_file=args.credentials_file or "",
                    allow_http_loopback=args.allow_http_loopback)
            if args.coordinator_cmd == "activate":
                try:
                    dd, cfg = load_cfg(Path(args.data_dir))
                except me_setup.SetupError as exc:
                    err(f"error: {exc}")
                    return 2
                return me_coordinator.do_activate(
                    dd, cfg, timeout_ms=int(args.timeout_ms),
                    allow_http_loopback=args.allow_http_loopback)
            if args.coordinator_cmd == "status":
                return me_coordinator.do_status(Path(args.data_dir))
            if args.coordinator_cmd == "check":
                return me_coordinator.do_check(Path(args.data_dir))
        if args.cmd == "backup":
            return do_backup(Path(args.data_dir), output=args.output or None,
                             scope=args.scope)
        if args.cmd == "restore":
            return do_restore(Path(args.data_dir), source=args.source,
                              confirm_destructive=args.confirm_destructive,
                              scope=args.scope)
        if args.cmd == "restore-recover":
            return do_restore_recover(Path(args.data_dir))
        if args.cmd == "tunnel":
            if args.tunnel_cmd == "configure":
                return do_tunnel_configure(
                    Path(args.data_dir), hostname=args.hostname,
                    credential_file=args.credential_file, protection=args.protection,
                    access_team=args.access_team, access_aud=args.access_aud,
                    pairing_admission=args.pairing_admission, tunnel_name=args.tunnel_name)
            if args.tunnel_cmd == "run":
                return do_tunnel_run(Path(args.data_dir), detach=args.detach,
                                     cloudflared_explicit=args.cloudflared or None)
            if args.tunnel_cmd == "status":
                return do_tunnel_status(Path(args.data_dir))
        if args.cmd == "service":
            return do_service_generate(Path(args.data_dir), format=args.format,
                                       output=args.output or None, **common)
    except me_setup.SetupError as exc:
        err(f"error: {exc}")
        return 2
    raise AssertionError("unreachable")


if __name__ == "__main__":
    sys.exit(main())
