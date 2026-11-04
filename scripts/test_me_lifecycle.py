#!/usr/bin/env python3
"""Tests for the S2 dev lifecycle (scripts/me_lifecycle.py).

Lightweight by coordinator constraint: stdlib only, no downloads, no browser
or model binaries. The H1 integration test runs the real home CLI locally and
is skipped with a transient-dependency message when the checkout or Node is
unavailable (H1/H2 may still be modifying home); rerun when stable.

Run: python3 -m unittest discover -s scripts -p 'test_me_lifecycle.py' -v
"""

import contextlib
import io
import json
import os
import shlex
import shutil
import stat
import subprocess
import sys
import tempfile
import time
import unittest
from pathlib import Path
from unittest import mock

sys.path.insert(0, str(Path(__file__).resolve().parent))

import me_lifecycle
import me_setup


def setUpModule():
    import collections
    usage = collections.namedtuple("usage", ["total", "used", "free"])
    patcher = mock.patch.object(
        shutil, "disk_usage",
        return_value=usage(total=100 * 1024**3, used=10 * 1024**3, free=90 * 1024**3))
    patcher.start()
    setUpModule._patcher = patcher
    os.environ["ME_HOME_SKIP_BRIDGE_PROBE"] = "1"


def tearDownModule():
    setUpModule._patcher.stop()


def free_port() -> int:
    import socket
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


def require_h1(testcase) -> tuple[Path, str]:
    """Return (infra checkout, node) or skip with a transient-dependency note."""
    checkout = me_setup.resolve_checkout(
        os.environ.get("ME_HOME_INFRA_CHECKOUT") or None,
        "ME_HOME_INFRA_CHECKOUT", "infra-server",
        ("src/cli.mjs", "src/server.mjs"), "home service")
    node, _ = me_setup.find_node(os.environ.get("ME_HOME_NODE") or None)
    if checkout is None or node is None:
        testcase.skipTest(
            "transient dependency: infra-server checkout and/or compatible Node "
            "unavailable (H1/H2 may still be modifying home); rerun when stable")
    assert checkout is not None and node is not None
    return checkout, node


class LifecycleUnit(unittest.TestCase):
    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp(prefix="me-lc-unit-"))
        self.addCleanup(lambda: shutil.rmtree(self.tmp, ignore_errors=True))
        self.data_dir = self.tmp / "home dir with spaces"
        self.node_patch = mock.patch.object(me_setup, "find_node",
                                             return_value=("/fake/node", "fake"))
        self.node_patch.start()
        self.addCleanup(self.node_patch.stop)
        self.port = free_port()
        self.assertEqual(me_setup.do_setup(self.data_dir, "127.0.0.1", self.port), 0)

    def test_status_stopped_exit_1(self):
        self.assertEqual(me_lifecycle.do_status(self.data_dir), 1)

    def test_stop_without_pidfile_is_idempotent(self):
        self.assertEqual(me_lifecycle.do_stop(self.data_dir), 0)

    def test_graceful_stop_cooperative_service(self):
        """do_stop's SIGTERM path against a well-behaved local service.

        Current H1 hangs in broker.stop() on SIGTERM (transient H1/H2 issue,
        see handoff); this test proves setup's graceful logic with a fake
        managed process that does exit on SIGTERM.
        """
        import sys as _sys
        code = ("_marker = 'cli.mjs managed-service marker';"
                "import http.server, sys;"
                "port = [int(a.split('=')[1]) for a in sys.argv if a.startswith('--port=')][0];"
                "http.server.HTTPServer(('127.0.0.1', port), "
                "http.server.SimpleHTTPRequestHandler).serve_forever()")
        argv = [_sys.executable, "-c", code, f"--db={self.db_fake()}",
                f"--port={self.port}"]
        proc = subprocess.Popen(argv, stdout=subprocess.DEVNULL,
                                stderr=subprocess.DEVNULL, start_new_session=True)
        self.addCleanup(lambda: (proc.kill(), proc.wait()))
        pf = self.data_dir / "run" / "home-service.pid"
        pf.parent.mkdir(parents=True, exist_ok=True)
        pf.write_text(json.dumps({"pid": proc.pid, "exe": _sys.executable,
                                  "argv": argv, "db": self.db_fake(),
                                  "host": "127.0.0.1", "port": self.port}),
                      encoding="utf-8")
        for _ in range(50):
            import socket as _s
            try:
                with _s.create_connection(("127.0.0.1", self.port), timeout=1):
                    break
            except OSError:
                time.sleep(0.1)
        self.assertEqual(me_lifecycle.do_stop(self.data_dir), 0)
        self.assertFalse(pf.exists())
        self.assertIsNotNone(proc.wait(timeout=10))

    def db_fake(self) -> str:
        return str(self.tmp / "fake.sqlite")

    def test_stale_pidfile_dead_pid(self):
        pf = self.data_dir / "run" / "home-service.pid"
        pf.parent.mkdir(parents=True, exist_ok=True)
        pf.write_text(json.dumps({"pid": 999999999, "exe": "/fake/node",
                                  "db": "x", "port": self.port}), encoding="utf-8")
        self.assertEqual(me_lifecycle.do_status(self.data_dir), 1)
        self.assertEqual(me_lifecycle.do_stop(self.data_dir), 1)

    def test_stale_pidfile_foreign_live_process_never_signalled(self):
        proc = subprocess.Popen(["sleep", "60"])
        self.addCleanup(lambda: (proc.kill(), proc.wait()))
        pf = self.data_dir / "run" / "home-service.pid"
        pf.parent.mkdir(parents=True, exist_ok=True)
        pf.write_text(json.dumps({"pid": proc.pid, "exe": "/fake/node",
                                  "argv": ["node", "cli.mjs"],
                                  "db": "/elsewhere/home.sqlite",
                                  "port": self.port}), encoding="utf-8")
        self.assertEqual(me_lifecycle.do_stop(self.data_dir), 1)
        self.assertIsNone(proc.poll(), "foreign process must survive a stale stop")

    def test_start_refuses_occupied_port(self):
        import socket
        blocker = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        blocker.bind(("127.0.0.1", self.port))
        self.addCleanup(blocker.close)
        self.assertEqual(me_lifecycle.do_start(self.data_dir), 1)
        self.assertFalse((self.data_dir / "run" / "home-service.pid").exists())

    def _tunnel_base(self, protection="home-pairing"):
        cred = self.tmp / "cred.json"
        cred.write_text(json.dumps({"TunnelID": "tid", "AccountTag": "a",
                                    "TunnelSecret": "s"}), encoding="utf-8")
        os.chmod(cred, 0o600)
        return ["tunnel", "configure", "--data-dir", str(self.data_dir),
                "--credential-file", str(cred),
                "--protection", protection]

    def test_tunnel_home_pairing_default_phone_path(self):
        base = self._tunnel_base()  # home-pairing default, no Access flags
        rc = me_lifecycle.main(base + ["--hostname", "home.example.com"])
        self.assertEqual(rc, 0)
        yml = self.data_dir / "config" / "cloudflared.yml"
        text = yml.read_text(encoding="utf-8")
        self.assertIn("# Protection mode: home-pairing", text)
        self.assertIn("home.example.com", text)
        self.assertIn("http_status:404", text)
        self.assertNotIn("audTag:", text)
        self.assertNotIn("required: true", text)
        self.assertNotIn("TunnelSecret", text)
        cfg = me_setup.load_config(self.data_dir)
        self.assertEqual(cfg["tunnel"]["protection"]["mode"], "home-pairing")
        self.assertEqual(cfg["tunnel"]["protection"]["public_surface"],
                         ["GET /healthz", "GET /readyz",
                          "POST /v1/pair", "POST /v1/sessions"])
        # Access flags do not apply here: mixing modes is denied, not merged.
        self.assertEqual(me_lifecycle.main(
            base + ["--hostname", "home.example.com",
                    "--access-team", "t", "--access-aud", "a1"]), 2)
        # Quick tunnels and bare names still refused in both modes.
        self.assertEqual(me_lifecycle.main(
            base + ["--hostname", "x.trycloudflare.com"]), 2)

    def test_tunnel_configure_fail_closed(self):
        base = self._tunnel_base("cloudflare-access")
        self.assertEqual(me_lifecycle.main(base + ["--hostname", "h.example.com",
                                                   "--access-team", "t",
                                                   "--access-aud", "aud1"]), 0)
        (self.data_dir / "config" / "cloudflared.yml").unlink()
        base2 = self._tunnel_base("cloudflare-access")
        self.assertEqual(me_lifecycle.main(base2 + ["--hostname", "h.example.com",
                                                    "--access-aud", "aud1"]), 2)  # no team
        self.assertEqual(me_lifecycle.main(base2 + ["--hostname", "h.example.com",
                                                    "--access-team", "t"]), 2)  # no aud
        self.assertEqual(me_lifecycle.main(base2 + ["--hostname", "h.example.com",
                                                    "--access-team", "t",
                                                    "--access-aud", "aud1"]), 0)
        (self.data_dir / "config" / "cloudflared.yml").unlink()
        self.assertEqual(me_lifecycle.main(base2 + ["--credential-file", str(self.tmp / "nope"),
                                                    "--hostname", "h.example.com",
                                                    "--access-team", "t",
                                                    "--access-aud", "aud1"]), 2)
        bad = self.tmp / "bad.json"
        bad.write_text("{}")
        os.chmod(bad, 0o644)
        self.assertEqual(me_lifecycle.main(base2 + ["--hostname", "h.example.com",
                                                    "--credential-file", str(bad),
                                                    "--access-team", "t",
                                                    "--access-aud", "aud1"]), 2)
        # Unknown protection modes are denied, never guessed.
        self.assertEqual(me_lifecycle.do_tunnel_configure(
            self.data_dir, hostname="h.example.com",
            credential_file=str(self.tmp / "cred.json"),
            protection="zero-trust-magic"), 2)
        self.assertFalse((self.data_dir / "config" / "cloudflared.yml").exists())

    def test_tunnel_emits_connector_enforcement_and_run_refuses_without_it(self):
        base = self._tunnel_base("cloudflare-access")
        rc = me_lifecycle.main(base + ["--hostname", "home.example.com",
                                       "--access-team", "team1",
                                       "--access-aud", "aud-1,aud-2",
                                       "--pairing-admission", "manual-external"])
        self.assertEqual(rc, 0)
        yml = self.data_dir / "config" / "cloudflared.yml"
        text = yml.read_text(encoding="utf-8")
        for marker in ("access:", "required: true", "teamName: team1", "audTag:",
                       "- aud-1", "- aud-2", "home.example.com",
                       "http_status:404"):
            self.assertIn(marker, text)
        self.assertNotIn("TunnelSecret", text)
        self.assertEqual(stat.S_IMODE(yml.stat().st_mode), 0o600)
        cfg = me_setup.load_config(self.data_dir)
        self.assertEqual(cfg["tunnel"]["protection"]["access_aud"], ["aud-1", "aud-2"])
        self.assertEqual(cfg["tunnel"]["protection"]["mode"], "cloudflare-access")
        # cloudflared absent here -> parked (exit 4), nothing started.
        with mock.patch.object(me_lifecycle, "discover_cloudflared", return_value=None):
            self.assertEqual(me_lifecycle.main(
                ["tunnel", "run", "--data-dir", str(self.data_dir)]), 4)
        # Tampered config without the access block -> run refuses (fail-closed),
        # before any spawn is attempted.
        yml.write_text("tunnel: tid\ncredentials-file: /x\n"
                       "ingress:\n  - hostname: home.example.com\n"
                       "    service: http://127.0.0.1:1\n  - service: http_status:404\n")
        with mock.patch.object(me_lifecycle, "discover_cloudflared",
                               return_value="/fake/cloudflared"), \
             mock.patch.object(me_lifecycle.subprocess, "Popen") as popen, \
             mock.patch.object(me_lifecycle.subprocess, "run") as run:
            self.assertEqual(me_lifecycle.main(
                ["tunnel", "run", "--data-dir", str(self.data_dir)]), 2)
            popen.assert_not_called()
            run.assert_not_called()

    def test_tunnel_home_pairing_run_guard_and_mixed_mode_deny(self):
        base = self._tunnel_base()  # home-pairing
        self.assertEqual(me_lifecycle.main(base + ["--hostname", "home.example.com"]), 0)
        # Fake binary present -> run proceeds to spawn (mocked), not refused.
        with mock.patch.object(me_lifecycle, "discover_cloudflared",
                               return_value="/fake/cloudflared"), \
             mock.patch.object(me_lifecycle.subprocess, "run",
                               return_value=mock.Mock(returncode=0)) as run:
            self.assertEqual(me_lifecycle.main(
                ["tunnel", "run", "--data-dir", str(self.data_dir)]), 0)
            run.assert_called_once()
            argv = run.call_args[0][0]
            self.assertNotIn("aud-1", " ".join(argv))
        # Mixed config (Access block inside a home-pairing record) is denied.
        yml = self.data_dir / "config" / "cloudflared.yml"
        yml.write_text(yml.read_text(encoding="utf-8") +
                       "\n# sneaked\n        required: true\n        audTag:\n")
        with mock.patch.object(me_lifecycle, "discover_cloudflared",
                               return_value="/fake/cloudflared"), \
             mock.patch.object(me_lifecycle.subprocess, "run") as run:
            self.assertEqual(me_lifecycle.main(
                ["tunnel", "run", "--data-dir", str(self.data_dir)]), 2)
            run.assert_not_called()

    def test_tunnel_preconditions_unknown_contract_and_non_loopback(self):
        base = self._tunnel_base()
        self.assertEqual(me_lifecycle.main(base + ["--hostname", "home.example.com"]), 0)
        cfg = me_setup.load_config(self.data_dir)
        # Unknown contract -> run refuses even with a perfect yml.
        cfg["home_api"]["contract_status"] = "pending-h1"
        me_setup.write_atomic(me_setup.config_path(self.data_dir),
                              json.dumps(cfg, indent=2, sort_keys=True) + "\n")
        self.assertEqual(me_lifecycle.main(
            ["tunnel", "run", "--data-dir", str(self.data_dir)]), 2)
        # Non-loopback binding -> configure refuses (would expose more than the
        # verified loopback API).
        other = self.tmp / "other"
        self.assertEqual(me_setup.do_setup(other, "127.0.0.1", free_port()), 0)
        cfg2 = me_setup.load_config(other)
        cfg2["service"]["host"] = "0.0.0.0"
        me_setup.write_atomic(me_setup.config_path(other),
                              json.dumps(cfg2, indent=2, sort_keys=True) + "\n")
        cred = self.tmp / "cred.json"
        self.assertEqual(me_lifecycle.main(
            ["tunnel", "configure", "--data-dir", str(other),
             "--hostname", "home.example.com",
             "--credential-file", str(cred)]), 2)

    def test_service_generate_files_only(self):
        for fmt in ("launchd", "systemd"):
            rc = me_lifecycle.main(["service", "--data-dir", str(self.data_dir),
                                    "--format", fmt, "--node", "/fake/node",
                                    "--infra-checkout", str(self.tmp)])
            # checkout marker missing -> exit 3 before writing
            self.assertEqual(rc, 3)
        # Point at a fake checkout with the marker files (space in path included).
        co = self.tmp / "fake infra"
        (co / "src").mkdir(parents=True)
        (co / "src" / "cli.mjs").write_text("// fake")
        (co / "src" / "server.mjs").write_text("// fake")
        with mock.patch.dict(os.environ, {"ME_RUNTIME_MODEL_API_KEY": "shh-test-key"}):
            for fmt, name in (("launchd", "me-home.launchd.plist"),
                              ("systemd", "me-home.systemd.unit")):
                rc = me_lifecycle.main(["service", "--data-dir", str(self.data_dir),
                                        "--format", fmt, "--node", "/fake/node",
                                        "--infra-checkout", str(co)])
                self.assertEqual(rc, 0)
                dest = self.data_dir / "config" / name
                self.assertTrue(dest.is_file())
                text = dest.read_bytes().decode("utf-8", errors="replace")
                self.assertIn(str(self.data_dir / "data" / "home.sqlite"), text)
                # Secrets are never baked into generated units, even when set.
                self.assertNotIn("shh-test-key", text)
                self.assertNotIn("ME_RUNTIME_MODEL_API_KEY", text)
            # launchd plist routes through the shared pre-exec guard (no direct
            # Node exec, so autostart cannot bypass the journal check).
            import plistlib
            doc = plistlib.loads((self.data_dir / "config" / "me-home.launchd.plist").read_bytes())
            pargs = doc["ProgramArguments"]
            # [python, guard, --data-dir DIR, --node /fake/node, --entrypoint ...]
            self.assertTrue(pargs[0].endswith("python3") or "python" in pargs[0])
            self.assertTrue(pargs[1].endswith("me-home.exec.py"))
            self.assertIn("--data-dir", pargs)
            self.assertIn(str(self.data_dir), pargs)
            self.assertIn("--node", pargs)
            self.assertIn("/fake/node", pargs)
            self.assertIn("--entrypoint", pargs)
            self.assertTrue(any(str(co) in a for a in pargs))
            # Guard carries env/workdir; Node flags are re-derived at exec time
            # (os.execv, same PID, no shell).
            self.assertEqual(doc["WorkingDirectory"], str(co))
            self.assertEqual(doc["EnvironmentVariables"]["HOME_MODEL_PROVIDER"], "local")
            self.assertEqual(int(doc["EnvironmentVariables"]["HOME_PORT"]), self.port)
            guard = self.data_dir / "config" / "me-home.exec.py"
            self.assertTrue(guard.is_file())
            gtext = guard.read_text(encoding="utf-8")
            self.assertIn("incomplete_journal", gtext)
            self.assertIn("os.execv", gtext)
            self.assertNotIn("shh-test-key", gtext)
            self.assertNotIn("ME_RUNTIME_MODEL_API_KEY=", gtext)
            # systemd unit: same guard via ExecStart, env via escaped lines.
            unit = (self.data_dir / "config" / "me-home.systemd.unit").read_text(encoding="utf-8")
            self.assertIn("ExecStart=", unit)
            self.assertIn("me-home.exec.py", unit)
            self.assertIn("--node", unit)
            self.assertIn("HOME_MODEL_PROVIDER=local", unit)
            self.assertIn(f"WorkingDirectory={co}", unit)
            self.assertNotIn("shh-test-key", unit)
        self.assertFalse((Path.home() / "Library" / "LaunchAgents").exists()
                         and (Path.home() / "Library" / "LaunchAgents" /
                              f"ai.mehome.home-{self.port}.plist").exists(),
                         "service generate must never install globally")

    def test_node_args_for_entrypoints(self):
        # Known home CLI always transitively imports vendor worker.ts with
        # non-erasable syntax: needs transform flags upfront despite .mjs.
        cli_flags = me_lifecycle.me_setup.node_args_for("node", Path("cli.mjs"))
        self.assertIn("--experimental-transform-types", cli_flags)
        self.assertEqual(cli_flags[0], "node")
        # Generic plain ESM stays flag-free (no bogus guess for unknown .mjs).
        self.assertEqual(me_lifecycle.me_setup.node_args_for(
            "node", Path("server.mjs")), ["node"])
        ts_flags = me_lifecycle.me_setup.node_args_for("node", Path("bridge.ts"))
        self.assertIn("--experimental-transform-types", ts_flags)
        with self.assertRaises(me_setup.SetupError):
            me_lifecycle.me_setup.node_args_for("node", Path("run.exe"))


class GeneratedServiceLive(unittest.TestCase):
    """Generated units must boot the real home on FIRST try (no retry path).

    Extracts the REAL guard ProgramArguments + EnvironmentVariables +
    WorkingDirectory from the generated launchd plist and spawns that exact
    guard command as a child (no global install). The guard re-derives
    node_args_for (transform flags) and execs Node, so both manual start and
    generated units share one correct argv. Spaces in the data-dir path are
    covered. Cleanup is SIGTERM + wait (pid_exited handles zombies; no sleeps
    invented).
    """

    def test_generated_plist_argv_boots_real_home_first_try(self):
        checkout, node = require_h1(self)
        tmp = Path(tempfile.mkdtemp(prefix="me-lc-genlive-")).resolve()
        self.addCleanup(lambda: shutil.rmtree(tmp, ignore_errors=True))
        data_dir = tmp / "home dir with spaces"
        port = free_port()
        with mock.patch.dict(os.environ, {"ME_HOME_INFRA_CHECKOUT": str(checkout),
                                          "ME_HOME_NODE": node}):
            self.assertEqual(me_setup.do_setup(data_dir, "127.0.0.1", port), 0)
            cfg = me_setup.load_config(data_dir)
            # Manual hint and recorded node_args carry the flags upfront.
            self.assertIn("--experimental-transform-types",
                          cfg["home_api"]["launch"]["start"])
            self.assertIn("--experimental-transform-types",
                          cfg["home_api"]["launch"]["node_args"])
            for fmt in ("launchd", "systemd"):
                rc = me_lifecycle.main(["service", "--data-dir", str(data_dir),
                                        "--format", fmt, "--node", node,
                                        "--infra-checkout", str(checkout)])
                self.assertEqual(rc, 0)
            import plistlib
            doc = plistlib.loads(
                (data_dir / "config" / "me-home.launchd.plist").read_bytes())
            argv = doc["ProgramArguments"]
            # Guard, not direct Node: [python, me-home.exec.py, --data-dir ...].
            self.assertTrue(argv[1].endswith("me-home.exec.py"))
            self.assertIn("--data-dir", argv)
            self.assertIn(str(data_dir), argv)
            self.assertIn("--node", argv)
            self.assertIn(node, argv)
            self.assertIn("--entrypoint", argv)
            guard_text = (data_dir / "config" / "me-home.exec.py").read_text(
                encoding="utf-8")
            self.assertIn("incomplete_journal", guard_text)
            self.assertIn("os.execv", guard_text)
            unit = (data_dir / "config" / "me-home.systemd.unit").read_text(
                encoding="utf-8")
            self.assertIn("me-home.exec.py", unit)
            self.assertIn("ExecStart=", unit)
            env = {k: str(v) for k, v in doc["EnvironmentVariables"].items()}
            self.assertEqual(str(env.get("HOME_PORT")), str(port))
            self.assertNotIn("ME_RUNTIME_MODEL_API_KEY", env)
            workdir = doc["WorkingDirectory"]
            self.assertEqual(workdir, str(checkout))
            log_path = Path(cfg["service"]["log_dir"]) / "home-service.log"
            full_env = dict(os.environ)
            full_env.update(env)
            if os.environ.get("ME_RUNTIME_MODEL_API_KEY"):
                full_env["ME_RUNTIME_MODEL_API_KEY"] = os.environ[
                    "ME_RUNTIME_MODEL_API_KEY"]
            with open(log_path, "a", encoding="utf-8") as fh:
                proc = subprocess.Popen(argv, stdout=fh, stderr=subprocess.STDOUT,
                                        start_new_session=True, env=full_env,
                                        cwd=workdir)
            try:
                body = me_lifecycle.wait_for_healthz("127.0.0.1", port, timeout=15)
                self.assertIsNotNone(body, "generated plist argv must reach healthy on first try")
                assert body is not None
                self.assertEqual(body.get("status"), "ok")
                self.assertEqual(body.get("contract"), me_setup.CONTRACT_VERSION)
            finally:
                try:
                    os.kill(proc.pid, 15)  # SIGTERM
                except OSError:
                    pass
                exited = me_lifecycle.wait_for_exit(proc.pid, 10)
                # Reap to avoid zombie; pid_exited treats zombies as exited.
                try:
                    proc.wait(timeout=5)
                except Exception:
                    pass
                self.assertTrue(exited or me_lifecycle.pid_exited(proc.pid),
                                "home child must exit after SIGTERM (no hang)")
            self.assertFalse((Path.home() / "Library" / "LaunchAgents" /
                              f"ai.mehome.home-{port}.plist").exists(),
                             "service generate must never install globally")


class BackupRestore(unittest.TestCase):
    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp(prefix="me-lc-bak-"))
        self.addCleanup(lambda: shutil.rmtree(self.tmp, ignore_errors=True))
        self.data_dir = self.tmp / "home"
        self.port = free_port()
        self.node_patch = mock.patch.object(me_setup, "find_node",
                                             return_value=("/fake/node", "fake"))
        self.node_patch.start()
        self.addCleanup(self.node_patch.stop)
        self.assertEqual(me_setup.do_setup(self.data_dir, "127.0.0.1", self.port), 0)
        self.db = Path(me_setup.load_config(self.data_dir)["service"]["db_path"])
        self.db.parent.mkdir(parents=True, exist_ok=True)
        with me_lifecycle.sqlite_conn(self.db) as conn:
            conn.execute("PRAGMA journal_mode=WAL")
            conn.execute("CREATE TABLE meta (key TEXT PRIMARY KEY, value TEXT)")
            conn.execute("INSERT INTO meta VALUES ('installation_id', 'db-id-1')")
            conn.execute("CREATE TABLE kv (k TEXT PRIMARY KEY, v TEXT)")
            conn.execute("INSERT INTO kv VALUES ('a', '1')")
            conn.commit()

    def test_backup_verifies_and_restore_roundtrip(self):
        self.assertEqual(me_lifecycle.do_backup(self.data_dir), 0)
        backups = sorted((self.data_dir / "backups").glob("home-*.sqlite"))
        self.assertTrue(backups)
        with me_lifecycle.sqlite_conn(self.db) as conn:
            conn.execute("INSERT INTO kv VALUES ('b', '2')")
            conn.commit()
        rc = me_lifecycle.main(["restore", "--data-dir", str(self.data_dir),
                                "--from", str(backups[-1])])
        self.assertEqual(rc, 2)  # missing --confirm-destructive
        rc = me_lifecycle.main(["restore", "--data-dir", str(self.data_dir),
                                "--from", str(backups[-1]), "--confirm-destructive"])
        self.assertEqual(rc, 0)
        with me_lifecycle.sqlite_conn(self.db) as conn:
            rows = dict(conn.execute("SELECT k, v FROM kv").fetchall())
        self.assertEqual(rows, {"a": "1"})
        self.assertTrue(list((self.data_dir / "backups").glob("pre-restore-*.sqlite")))

    def test_restore_refuses_while_running_and_bad_source(self):
        proc = subprocess.Popen(["sleep", "60"])
        self.addCleanup(lambda: (proc.kill(), proc.wait()))
        pf = self.data_dir / "run" / "home-service.pid"
        pf.parent.mkdir(parents=True, exist_ok=True)
        pf.write_text(json.dumps({"pid": proc.pid, "exe": "sleep",
                                  "argv": ["sleep", "60"], "db": str(self.db),
                                  "host": "127.0.0.1", "port": self.port}),
                      encoding="utf-8")
        good = self.tmp / "good.sqlite"
        shutil.copy2(self.db, good)
        # Fingerprint is sleep, not our node process -> stale, not "running";
        # restore must still refuse because the port check below is bypassed...
        # craft a truly "running" record instead:
        pf.write_text(json.dumps({"pid": proc.pid, "exe": "sleep",
                                  "argv": ["sleep", "60", "cli.mjs",
                                           f"--db={self.db}",
                                           f"--port={self.port}"],
                                  "db": str(self.db), "host": "127.0.0.1",
                                  "port": self.port}), encoding="utf-8")
        with mock.patch.object(me_lifecycle, "managed_state",
                               return_value=("running", {"pid": proc.pid})):
            rc = me_lifecycle.main(["restore", "--data-dir", str(self.data_dir),
                                    "--from", str(good), "--confirm-destructive"])
        self.assertEqual(rc, 1)
        self.assertIsNone(proc.poll(), "restore must not kill anything")
        bad = self.tmp / "bad.sqlite"
        bad.write_text("not a database", encoding="utf-8")
        rc = me_lifecycle.main(["restore", "--data-dir", str(self.data_dir),
                                "--from", str(bad), "--confirm-destructive"])
        self.assertEqual(rc, 1)
        with me_lifecycle.sqlite_conn(self.db) as conn:
            rows = dict(conn.execute("SELECT k, v FROM kv").fetchall())
        self.assertEqual(rows, {"a": "1"}, "failed restore must leave db untouched")


class HomeApiIntegration(unittest.TestCase):
    """Real end-to-end against the H1 home service (fast, local, no downloads)."""

    def setUp(self):
        checkout, node = require_h1(self)
        self.checkout, self.node = checkout, node
        # realpath-resolved: H3 artifact ingest compares a lexical workspace
        # root against realpath-resolved files (see fixture-task note).
        self.tmp = Path(tempfile.mkdtemp(prefix="me-lc-e2e-")).resolve()
        self.addCleanup(lambda: shutil.rmtree(self.tmp, ignore_errors=True))
        self.data_dir = self.tmp / "home dir"
        self.port = free_port()
        self.addCleanup(self._ensure_stopped)

    def _ensure_stopped(self):
        try:
            me_lifecycle.do_stop(self.data_dir, force=True)
        except Exception:
            pass

    def _api(self, method, path, body=None, token=None):
        import urllib.request
        import urllib.error
        data = json.dumps(body).encode() if body is not None else None
        headers = {"Content-Type": "application/json"}
        if token:
            headers["Authorization"] = f"Bearer {token}"
        req = urllib.request.Request(f"http://127.0.0.1:{self.port}{path}",
                                     data=data, headers=headers, method=method)
        try:
            with urllib.request.urlopen(req, timeout=10) as r:
                return r.status, json.loads(r.read().decode())
        except urllib.error.HTTPError as e:
            return e.code, json.loads(e.read().decode())

    def test_lifecycle_pair_converse_rerun_preserves(self):
        env = {"ME_HOME_INFRA_CHECKOUT": str(self.checkout),
               "ME_HOME_NODE": self.node}
        with mock.patch.dict(os.environ, env):
            self.assertEqual(me_setup.do_setup(self.data_dir, "127.0.0.1", self.port), 0)
            self.assertEqual(me_lifecycle.do_start(self.data_dir), 0)
            buf = io.StringIO()
            with contextlib.redirect_stdout(buf):
                rc = me_lifecycle.main(["bootstrap", "--data-dir", str(self.data_dir),
                                        "--user", "alice"])
            self.assertEqual(rc, 0)
            inv = json.loads(buf.getvalue())
            self.assertIn("invitation_secret", inv)
            s, paired = self._api("POST", "/v1/pair",
                                  {"invitation_id": inv["invitation_id"],
                                   "invitation_secret": inv["invitation_secret"],
                                   "device_label": "e2e", "installation_id": inv["installation_id"]})
            self.assertEqual(s, 201)
            s, sess = self._api("POST", "/v1/sessions",
                                {"device_id": paired["device_id"],
                                 "device_secret": paired["device_secret"]})
            self.assertEqual(s, 201)
            tok = sess["token"]
            s, conv = self._api("POST", "/v1/conversations", {"title": "e2e"}, token=tok)
            self.assertEqual(s, 201)
            (self.data_dir / "data" / "household" / "probe.txt").write_text(
                "household", encoding="utf-8")
            # Graceful SIGTERM currently hangs inside H1's broker.stop()
            # (src/server.mjs:644; transient H1/H2 issue, see handoff), so the
            # integration exercises the verified --force path; the graceful
            # path is covered by test_graceful_stop_cooperative_service.
            self.assertEqual(me_lifecycle.do_stop(self.data_dir, force=True), 0)
            # Idempotent rerun preserves household records + conversation.
            self.assertEqual(me_setup.do_setup(self.data_dir, "127.0.0.1", self.port), 0)
            self.assertEqual((self.data_dir / "data" / "household" / "probe.txt").read_text(
                encoding="utf-8"), "household")
            self.assertEqual(me_lifecycle.do_start(self.data_dir), 0)
            s, convs = self._api("GET", "/v1/conversations", token=tok)
            self.assertEqual(s, 200)
            self.assertTrue(any(c["id"] == conv["id"] for c in convs["conversations"]))
            self.assertEqual(me_lifecycle.do_stop(self.data_dir, force=True), 0)


    def test_fixture_task_via_real_bridge(self):
        """Agent smoke: submit a fixture task, real H2 runtime executes, result returns.

        Uses the actual me_runtime.bridge (not H3's test stub) with the
        synthetic fixture model. Skips with a transient note when the bridge
        venv cannot import the runtime (H2 still modifying home).

        NOTE: tmp dir is realpath-resolved: H3's artifact ingest compares a
        lexical workspace root against realpath-resolved files, which rejects
        everything under symlinked parents (e.g. macOS /var -> /private/var).
        That is H3's bug to fix (handoff); the production layout
        (~/.local/share/...) has no symlinked components, and neither does a
        resolved tmp dir.
        """
        checkout, node = require_h1(self)
        framework = me_setup.resolve_checkout(
            os.environ.get("ME_HOME_FRAMEWORK_CHECKOUT") or None,
            "ME_HOME_FRAMEWORK_CHECKOUT", "agentic-framework",
            ("docs/runtime-bridge-v1.md",), "agent framework")
        if framework is None:
            self.skipTest("transient dependency: agentic-framework checkout missing; rerun when stable")
        env = {"ME_HOME_INFRA_CHECKOUT": str(checkout),
               "ME_HOME_NODE": node,
               "ME_HOME_FRAMEWORK_CHECKOUT": str(framework)}
        with mock.patch.dict(os.environ, env):
            with mock.patch.dict(os.environ):
                os.environ.pop("ME_HOME_SKIP_BRIDGE_PROBE", None)
                # Legacy H2 bridge smoke test: FULL routes new tasks native
                # (503 without upstream), so this explicitly selects the
                # non-full dev profile where the legacy broker serves.
                rc = me_setup.do_setup(
                    self.data_dir, "127.0.0.1", self.port,
                    model_provider="fixture", allow_fixture_model=True,
                    upstream_mode="core")
            self.assertEqual(rc, 0)
            bridge = me_setup.load_config(self.data_dir)["runtime_bridge"]
            if bridge.get("status") != "importable":
                self.skipTest(f"transient dependency: {bridge.get('detail')}; rerun when stable")
            self.assertEqual(me_lifecycle.do_start(self.data_dir), 0)
            buf = io.StringIO()
            with contextlib.redirect_stdout(buf):
                rc = me_lifecycle.main(["bootstrap", "--data-dir", str(self.data_dir),
                                        "--user", "alice"])
            self.assertEqual(rc, 0)
            inv = json.loads(buf.getvalue())
            s, paired = self._api("POST", "/v1/pair",
                                  {"invitation_id": inv["invitation_id"],
                                   "invitation_secret": inv["invitation_secret"],
                                   "device_label": "e2e-task", "installation_id": inv["installation_id"]})
            self.assertEqual(s, 201)
            s, sess = self._api("POST", "/v1/sessions",
                                {"device_id": paired["device_id"],
                                 "device_secret": paired["device_secret"]})
            self.assertEqual(s, 201)
            tok = sess["token"]
            s, conv = self._api("POST", "/v1/conversations", {"title": "task"}, token=tok)
            self.assertEqual(s, 201)
            s, task = self._api("POST", f"/v1/conversations/{conv['id']}/tasks",
                                {"title": "hello", "request": "say hello"}, token=tok)
            self.assertEqual(s, 201, task)
            task_id = task["id"]
            done = None
            for _ in range(120):
                s, cur = self._api("GET", f"/v1/tasks/{task_id}", token=tok)
                self.assertEqual(s, 200, cur)
                if cur.get("status") in ("succeeded", "failed", "cancelled"):
                    done = cur
                    break
                time.sleep(1)
            self.assertIsNotNone(done, "fixture task never reached a terminal state")
            self.assertEqual(done.get("status"), "succeeded", done)
            # Real H2 fixture harness output (not H3 stub vocabulary).
            self.assertEqual(done.get("output"), "fixture completed request")
            self.assertEqual(done.get("model", {}).get("provider"), "fixture")
            self.assertTrue(done.get("artifact_ids"),
                            "fixture artifact must be ingested with sha256")
            self.assertEqual(me_lifecycle.do_stop(self.data_dir, force=True), 0)


class HomeEnvConfig(unittest.TestCase):
    """Trusted env construction from generated config (exact H3/H2 key names)."""

    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp(prefix="me-lc-env-"))
        self.addCleanup(lambda: shutil.rmtree(self.tmp, ignore_errors=True))
        self.data_dir = self.tmp / "home dir"
        self.port = free_port()
        self.node_patch = mock.patch.object(me_setup, "find_node",
                                             return_value=("/fake/node", "fake"))
        self.node_patch.start()
        self.addCleanup(self.node_patch.stop)

    def _setup(self, **kw):
        kw.setdefault("model_provider", "local")
        self.assertEqual(me_setup.do_setup(self.data_dir, "127.0.0.1", self.port, **kw), 0)
        return me_setup.load_config(self.data_dir)

    def test_local_env_exact_and_chatollama_base(self):
        cfg = self._setup()
        env = me_lifecycle.build_home_env(cfg)
        self.assertEqual(env["HOME_MODEL_PROVIDER"], "local")
        self.assertEqual(env["HOME_MODEL_NAME"], "llama3.1")
        # ChatOllama base_url: NO /v1 (H3's /v1 default would misconfigure it).
        self.assertEqual(env["HOME_MODEL_ENDPOINT"], "http://127.0.0.1:11434")
        self.assertNotIn("HOME_ALLOW_FIXTURE_MODEL", env)
        self.assertNotIn("ME_RUNTIME_ALLOW_REMOTE", env)
        self.assertNotIn("ME_RUNTIME_MODEL_API_KEY", env)
        # Native local route: container base + NONSECRET placeholder (never
        # a personal key; SDK requires non-empty).
        self.assertEqual(env["OPENAI_BASE_URL"], "http://host.docker.internal:11434/v1")
        self.assertEqual(env["OPENAI_API_KEY"], "ollama")

    def test_local_placeholder_is_not_a_credential(self):
        # The placeholder is the documented constant, present even with no
        # operator keys anywhere; nothing personal is read or fabricated.
        with mock.patch.dict(os.environ, {}, clear=False):
            os.environ.pop("OPENAI_API_KEY", None)
            os.environ.pop("ME_RUNTIME_MODEL_API_KEY", None)
            cfg = self._setup()
            env = me_lifecycle.build_home_env(cfg)
        self.assertEqual(env["OPENAI_API_KEY"], "ollama")
        raw = (self.data_dir / "config" / "config.json").read_text(encoding="utf-8")
        for line in (self.data_dir / "config" / "service.env").read_text(
                encoding="utf-8").splitlines():
            if line.startswith("OPENAI_API_KEY=") and "ollama" not in line:
                raise AssertionError("local key must be the placeholder only")

    def test_remote_generic_key_binds_provider_key_at_launch(self):
        cfg = self._setup(model_provider="openai", model_name="gpt-4o-mini",
                          allow_remote_model=True)
        # Generic-only operator key binds to the native provider key in the
        # spawned process env (never files, never logs).
        with mock.patch.dict(os.environ, {"ME_RUNTIME_MODEL_API_KEY": "op-key-1",
                                           "OPENAI_API_KEY": ""}):
            os.environ.pop("OPENAI_API_KEY", None)
            env = me_lifecycle.build_home_env(cfg)
        self.assertEqual(env["OPENAI_API_KEY"], "op-key-1")
        raw = (self.data_dir / "config" / "config.json").read_text(encoding="utf-8")
        self.assertNotIn("op-key-1", raw)
        svc = (self.data_dir / "config" / "service.env").read_text(encoding="utf-8")
        self.assertNotIn("op-key-1", svc)
        # Explicit provider-specific shell value wins over the generic.
        with mock.patch.dict(os.environ, {"ME_RUNTIME_MODEL_API_KEY": "op-key-1",
                                           "OPENAI_API_KEY": "op-key-2"}):
            env2 = me_lifecycle.build_home_env(cfg)
        self.assertEqual(env2["OPENAI_API_KEY"], "op-key-2")

    def test_remote_missing_key_left_unset_for_honest_gate(self):
        cfg = self._setup(model_provider="anthropic", allow_remote_model=True)
        with mock.patch.dict(os.environ, {}, clear=False):
            os.environ.pop("ANTHROPIC_API_KEY", None)
            os.environ.pop("ME_RUNTIME_MODEL_API_KEY", None)
            env = me_lifecycle.build_home_env(cfg)
        self.assertNotIn("ANTHROPIC_API_KEY", env)
        self.assertNotIn("ME_RUNTIME_MODEL_API_KEY", env)

    def test_fixture_requires_explicit_opt_in(self):
        with self.assertRaises(me_setup.SetupError):
            me_setup.build_models(provider="fixture")
        cfg = self._setup(model_provider="fixture", allow_fixture_model=True)
        env = me_lifecycle.build_home_env(cfg)
        self.assertEqual(env["HOME_ALLOW_FIXTURE_MODEL"], "1")
        self.assertNotIn("HOME_MODEL_ENDPOINT", env)

    def test_remote_requires_opt_in_and_key_never_persisted(self):
        with self.assertRaises(me_setup.SetupError):
            me_setup.build_models(provider="openai")
        with mock.patch.dict(os.environ, {"ME_RUNTIME_MODEL_API_KEY": "live-key-9"}):
            cfg = self._setup(model_provider="openai", model_name="gpt-4o-mini",
                              allow_remote_model=True)
            env = me_lifecycle.build_home_env(cfg)
            self.assertEqual(env["ME_RUNTIME_ALLOW_REMOTE"], "1")
            self.assertEqual(env["ME_RUNTIME_MODEL_API_KEY"], "live-key-9")
        raw = (self.data_dir / "config" / "config.json").read_text(encoding="utf-8")
        self.assertNotIn("live-key-9", raw)
        svc = (self.data_dir / "config" / "service.env").read_text(encoding="utf-8")
        self.assertNotIn("live-key-9", svc)
        self.assertIn("ME_RUNTIME_MODEL_API_KEY", svc)  # name in a comment only
        for line in svc.splitlines():
            if line.startswith("ME_RUNTIME_MODEL_API_KEY="):
                raise AssertionError("key must never be assigned in service.env")

    def test_capabilities_map_to_exact_home_keys(self):
        cfg = self._setup(cap_web_fetch=True, cap_browser=True,
                          cap_animation=True, cap_code_exec=True,
                          allow_code_exec=True, cap_egress="a.example,b.example")
        env = me_lifecycle.build_home_env(cfg)
        for key in ("HOME_CAP_WEB_FETCH", "HOME_CAP_BROWSER", "HOME_CAP_ANIMATION",
                    "HOME_CAP_CODE_EXEC", "ME_RUNTIME_ALLOW_CODE_EXEC",
                    "ME_RUNTIME_SANDBOX"):
            self.assertEqual(env.get(key), "1" if key != "ME_RUNTIME_SANDBOX" else "docker")
        self.assertEqual(env.get("HOME_CAP_EGRESS"), "a.example,b.example")

    def test_code_sandbox_docker_only_when_both_gates(self):
        # Both gates -> Docker sandbox auto-configured (R5 needs =docker).
        cfg = self._setup(allow_code_exec=True, cap_code_exec=True)
        self.assertEqual(cfg["models"].get("code_sandbox"), "docker")
        env = me_lifecycle.build_home_env(cfg)
        self.assertEqual(env.get("ME_RUNTIME_SANDBOX"), "docker")
        svc = (self.data_dir / "config" / "service.env").read_text(encoding="utf-8")
        self.assertIn("ME_RUNTIME_SANDBOX=docker", svc)
        # Single gate alone -> no sandbox (honest denial, no host fallback).
        for kw in ({"allow_code_exec": True}, {"cap_code_exec": True}):
            other = self.tmp / f"sandbox-{len(str(kw))}-{hash(str(sorted(kw))) % 10000}"
            other_port = free_port()
            self.assertEqual(me_setup.do_setup(other, "127.0.0.1", other_port, **kw), 0)
            env2 = me_lifecycle.build_home_env(me_setup.load_config(other))
            self.assertNotIn("ME_RUNTIME_SANDBOX", env2)
            svc2 = (other / "config" / "service.env").read_text(encoding="utf-8")
            self.assertNotIn("ME_RUNTIME_SANDBOX", svc2)
        # Default off -> absent everywhere.
        cfg_off = self._setup()
        self.assertNotIn("ME_RUNTIME_SANDBOX", me_lifecycle.build_home_env(cfg_off))

    def test_code_sandbox_explicit_choice_validated(self):
        # Explicit docker requires both gates.
        with self.assertRaises(me_setup.SetupError):
            me_setup.build_models(allow_code_exec=True, code_sandbox="docker")
        with self.assertRaises(me_setup.SetupError):
            me_setup.build_models(cap_code_exec=True, code_sandbox="docker")
        with self.assertRaises(me_setup.SetupError):
            me_setup.build_models(allow_code_exec=True, cap_code_exec=True,
                                  code_sandbox="lxc")
        m = me_setup.build_models(allow_code_exec=True, cap_code_exec=True,
                                  code_sandbox="docker")
        self.assertEqual(m.get("code_sandbox"), "docker")

    def test_runtime_argv_json_round_trip_with_spaces(self):
        cfg = self._setup()
        cfg["runtime_bridge"] = {"status": "importable",
                                 "python": "/tmp/with space/py",
                                 "import_cwd": "/tmp/with space/fw"}
        env = me_lifecycle.build_home_env(cfg)
        argv = json.loads(env["ME_RUNTIME_ARGV"])
        self.assertEqual(argv, ["/tmp/with space/py", "-m", "me_runtime.bridge"])
        self.assertEqual(env["ME_RUNTIME_CWD"], "/tmp/with space/fw")

    def test_service_env_shell_safe_quoting(self):
        cfg = self._setup()
        svc = (self.data_dir / "config" / "service.env").read_text(encoding="utf-8")
        parsed = {}
        for line in svc.splitlines():
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            key, _, rest = line.partition("=")
            parsed[key] = shlex.split(rest)[0] if rest else ""
        self.assertEqual(parsed["HOME_DB"], str(self.data_dir / "data" / "home.sqlite"))
        self.assertNotIn("ME_RUNTIME_MODEL_API_KEY", parsed)

    def test_disk_guard_stands_with_labelled_dev_override(self):
        import collections
        small = collections.namedtuple("usage", ["total", "used", "free"])(
            10 * 1024**3, 9 * 1024**3, 64 * 1024**2)
        other = self.tmp / "other"
        with mock.patch.object(shutil, "disk_usage", return_value=small):
            self.assertEqual(me_setup.do_setup(other, "127.0.0.1", self.port), 3)
            self.assertFalse((other / "config" / "config.json").exists())
            rc = me_setup.do_setup(other, "127.0.0.1", self.port, min_disk_mib=32)
            self.assertEqual(rc, 0)
            self.assertTrue((other / "config" / "config.json").is_file())


if __name__ == "__main__":
    unittest.main()
