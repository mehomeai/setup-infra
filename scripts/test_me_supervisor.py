#!/usr/bin/env python3
"""Tests for the OpenCode supervisor (scripts/me_supervisor.py).

Proves the PARENT (real filesystem/health verifiers) controls completion:
- fake OpenCode CLI that first replies done/no-effect then performs a real
  fix on the next turn -> supervisor loops and only reaches READY after the
  real fix lands on disk;
- failing checks never READY (chat-only Done ignored);
- NEEDS_INPUT for missing binary without --allow-install;
- STALLED budget on repeated chat-only turns;
- resume keeps attempts/session after interruption;
- concurrent lock refuses a second run;
- output flood truncated + stalled process killed/reaped (no orphans);
- credential redaction in persisted state;
- real home API/SQLite: /healthz against a real loopback HTTP server +
  real SQLite installation_id (not a mocked True).

No live external API calls. No heavy installs. Fixtures are ephemeral and
clearly test-only (names prefixed test-).
"""

import http.server
import json
import os
import shutil
import signal
import socket
import sqlite3
import stat
import subprocess
import sys
import tempfile
import threading
import time
import unittest
from pathlib import Path
from unittest import mock

sys.path.insert(0, str(Path(__file__).resolve().parent))

import me_setup
import me_supervisor


def setUpModule():
    import shutil as _shutil
    import collections
    usage = collections.namedtuple("usage", ["total", "used", "free"])
    patcher = mock.patch.object(
        _shutil, "disk_usage",
        return_value=usage(total=100 * 1024**3, used=10 * 1024**3,
                           free=90 * 1024**3))
    patcher.start()
    setUpModule._patcher = patcher
    os.environ["ME_HOME_SKIP_BRIDGE_PROBE"] = "1"


def tearDownModule():
    setUpModule._patcher.stop()


FAKE_NODE = ("/fake/node", "ok")


def free_port() -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


def make_data_dir(base: Path, port: int) -> Path:
    data_dir = base / "home"
    with mock.patch.object(me_supervisor.me_setup, "find_node",
                           return_value=FAKE_NODE):
        rc = me_setup.do_setup(data_dir, "127.0.0.1", port)
    assert rc == 0, "setup failed in fixture"
    # Mint a REAL authoritative installation id in the home SQLite db.
    db_path = data_dir / "data" / "home.sqlite"
    cfg = me_setup.load_config(data_dir)
    installation_id = cfg["installation_id"]
    with sqlite3.connect(str(db_path)) as conn:
        conn.execute("CREATE TABLE IF NOT EXISTS meta (key TEXT PRIMARY KEY, value TEXT)")
        conn.execute("INSERT OR REPLACE INTO meta (key, value) VALUES ('installation_id', ?)",
                     (installation_id,))
        conn.commit()
    return data_dir


class HealthHandler(http.server.BaseHTTPRequestHandler):
    body: dict = {}

    def do_GET(self):
        if self.path == "/healthz":
            payload = json.dumps(self.__class__.body).encode()
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(payload)))
            self.end_headers()
            self.wfile.write(payload)
        else:
            self.send_response(404)
            self.end_headers()

    def log_message(self, *a):
        pass


def start_health_server(body: dict):
    HealthHandler.body = body
    srv = http.server.HTTPServer(("127.0.0.1", 0), HealthHandler)
    t = threading.Thread(target=srv.serve_forever, kwargs={"poll_interval": 0.05},
                         daemon=True)
    t.start()
    return srv


class SupervisorCases(unittest.TestCase):
    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp(prefix="me-sup-test-"))
        self.addCleanup(lambda: shutil.rmtree(self.tmp, ignore_errors=True))
        self.port = free_port()
        self.data_dir = make_data_dir(self.tmp, self.port)
        self.ws = self.tmp / "ws"
        self.ws.mkdir()

    def _test_opts(self, **extra) -> dict:
        """Hermetic TEST-profile opts: fixture provider, no service bar.

        Production requires live ollama/doctor/volumes (operator gates);
        unit drive tests prove parent filesystem control in the named TEST
        profile (profile=test, provider=fixture), where the full platform
        bar is explicitly OPTIONAL. This keeps tests hermetic (no live API)
        while production still enforces the real bar.
        """
        opts = {"workspace": str(self.ws), "require_service": False,
                "profile": "test",
                "allow_install": False, "opencode_bin": "",
                "max_attempts": 5, "max_stagnant": 5,
                "wall_timeout_s": 300, "attempt_timeout_s": 60,
                "prompt_scope": "test", "model": ""}
        opts.update(extra)
        return opts

    def _use_fixture_provider(self) -> None:
        cfg = me_setup.load_config(self.data_dir)
        cfg["models"] = {"provider": "fixture", "name": "fixture-echo",
                         "endpoint": "", "allow_fixture": True,
                         "allow_remote": False, "allow_code_exec": False,
                         "code_sandbox": "", "use_responses_api": False,
                         "capabilities": {}}
        me_setup.write_atomic(me_setup.config_path(self.data_dir),
                              json.dumps(cfg, indent=2, sort_keys=True) + "\n")

    def _fake_bin(self, name: str, script_body: str) -> str:
        path = self.tmp / name
        path.write_text("#!/usr/bin/env python3\n" + script_body, encoding="utf-8")
        os.chmod(path, 0o755)
        return str(path)

    def _run(self, *argv) -> int:
        return me_supervisor.main(list(argv))

    def test_fake_cli_done_then_real_fix_controls_ready(self):
        """Turn 1: chat-only Done (no fs change). Turn 2: real fix => READY.

        Uses the REAL run_opencode_turn subprocess runner against a fake
        OpenCode binary, proving the parent's filesystem verifiers (not the
        agent's words) control completion. TEST profile + fixture provider
        keep this hermetic; production still enforces live gates.
        """
        self._use_fixture_provider()
        counter = self.tmp / "count.txt"
        counter.write_text("0")
        data_dir_str = str(self.data_dir)
        fake = self._fake_bin("fake-opencode", f"""
import json, sys
counter_p = {str(counter)!r}
marker_p = {str(self.data_dir / 'agent-fixed.txt')!r}
n = int(open(counter_p).read().strip() or "0")
open(counter_p, "w").write(str(n + 1))
if n == 0:
    print(json.dumps({{"sessionID": "test-ses-1", "text": "Done! All set."}}))
else:
    open(marker_p, "w").write("fixed-by-agent-turn-2")
    print(json.dumps({{"sessionID": "test-ses-1", "text": "applied fix"}}))
""")
        me_supervisor.register_check(
            "test_marker", required=True,
            description="test-only: agent fix marker",
            handler=lambda dd, cfg, opts: me_supervisor.CheckResult(
                "test_marker",
                "PASS" if (Path(str(dd)) / "agent-fixed.txt").is_file()
                else "FAIL",
                evidence=("marker present" if (Path(str(dd)) / "agent-fixed.txt").is_file()
                          else "marker agent-fixed.txt missing (chat Done is NOT evidence)"),
                next_action="Have the agent create agent-fixed.txt in the data dir."))
        self.addCleanup(lambda: me_supervisor.CHECKS.pop("test_marker", None))
        opts = self._test_opts(opencode_bin=fake,
                               max_attempts=5, max_stagnant=5)
        state = me_supervisor.new_run_state(
            data_dir=self.data_dir, workspace=self.ws, opts=opts)
        rc = me_supervisor.drive(state, data_dir=self.data_dir, binary=fake)
        self.assertEqual(rc, 0)
        self.assertIn(state["status"], me_supervisor.TERMINAL_OK)
        self.assertEqual(state["status"], "TEST_READY")
        self.assertTrue((self.data_dir / "agent-fixed.txt").is_file())
        self.assertGreaterEqual(int(counter.read_text().strip()), 2)

    def test_drive_with_patched_turns_proves_fs_control(self):
        target = self.data_dir / "agent-fixed.txt"
        calls = {"n": 0}

        def fake_turn(*, binary, workspace, prompt, session_id, timeout_s,
                       max_output=256 * 1024, **kw):
            calls["n"] += 1
            if calls["n"] == 1:
                return 0, "Done! everything is complete.", "", "ses-1"
            target.write_text("fixed-for-real", encoding="utf-8")
            return 0, "applied real fix to agent-fixed.txt", "", "ses-1"

        me_supervisor.register_check(
            "test_marker2", required=True, description="test-only marker",
            handler=lambda dd, cfg, opts: me_supervisor.CheckResult(
                "test_marker2",
                "PASS" if (Path(str(dd)) / "agent-fixed.txt").is_file() else "FAIL",
                evidence="marker ok" if (Path(str(dd)) / "agent-fixed.txt").is_file()
                else "agent-fixed.txt missing (chat Done is NOT evidence)",
                next_action="Create agent-fixed.txt in the data dir with real content."))
        self.addCleanup(lambda: me_supervisor.CHECKS.pop("test_marker2", None))
        self._use_fixture_provider()
        opts = self._test_opts(opencode_bin="/fake/bin",
                               max_attempts=5, max_stagnant=4)
        import uuid as _uuid
        state = me_supervisor.new_run_state(
            data_dir=self.data_dir, workspace=self.ws, opts=opts)
        with mock.patch.object(me_supervisor, "run_opencode_turn", side_effect=fake_turn):
            rc = me_supervisor.drive(state, data_dir=self.data_dir, binary="/fake/bin")
        self.assertEqual(rc, 0)
        self.assertIn(state["status"], me_supervisor.TERMINAL_OK)
        self.assertEqual(state["status"], "TEST_READY")
        self.assertTrue(target.is_file())
        self.assertGreaterEqual(calls["n"], 2)  # chat-only turn did not finish it

    def test_failing_checks_never_ready(self):
        # Break config: point db at a fresh empty sqlite (no installation_id).
        cfg = me_setup.load_config(self.data_dir)
        bad_db = self.tmp / "empty.sqlite"
        with sqlite3.connect(str(bad_db)) as conn:
            conn.execute("CREATE TABLE meta (key TEXT PRIMARY KEY, value TEXT)")
            conn.commit()
        cfg["service"]["db_path"] = str(bad_db)
        me_setup.write_atomic(me_setup.config_path(self.data_dir),
                              json.dumps(cfg, indent=2, sort_keys=True) + "\n")
        results, _ = me_supervisor.run_checks(
            self.data_dir, {"require_service": True, "opencode_bin": ""})
        status, _ = me_supervisor.overall_status(results)
        self.assertNotEqual(status, "READY")
        failing = [r for r in results if r.status == "FAIL"]
        self.assertTrue(failing)

    def test_needs_input_missing_binary(self):
        with mock.patch.object(me_supervisor, "discover_opencode", return_value=None):
            rc = me_supervisor.cmd_install_check(
                mock.Mock(opencode_bin="", allow_install=False))
        self.assertEqual(rc, 4)

    def test_stalled_on_chat_only_replies(self):
        def chat_only(*, binary, workspace, prompt, session_id, timeout_s,
                       max_output=256 * 1024, **kw):
            return 0, "Done! All set, everything complete.", "", "ses-x"

        me_supervisor.register_check(
            "test_never", required=True, description="test-only never passes",
            handler=lambda dd, cfg, opts: me_supervisor.CheckResult(
                "test_never", "FAIL", evidence="always failing",
                next_action="Impossible fix (test asserts STALLED)."))
        self.addCleanup(lambda: me_supervisor.CHECKS.pop("test_never", None))
        self._use_fixture_provider()
        opts = self._test_opts(opencode_bin="/fake/bin",
                               max_attempts=10, max_stagnant=2)
        state = me_supervisor.new_run_state(
            data_dir=self.data_dir, workspace=self.ws, opts=opts)
        with mock.patch.object(me_supervisor, "run_opencode_turn", side_effect=chat_only):
            rc = me_supervisor.drive(state, data_dir=self.data_dir, binary="/fake/bin")
        self.assertEqual(rc, 1)
        self.assertEqual(state["status"], "STALLED")

    def test_resume_keeps_attempts_and_session(self):
        state = me_supervisor.new_run_state(
            data_dir=self.data_dir, workspace=self.ws,
            opts={"workspace": str(self.ws), "require_service": False,
                  "allow_install": False, "opencode_bin": "",
                  "max_attempts": 6, "max_stagnant": 6,
                  "wall_timeout_s": 300, "attempt_timeout_s": 60,
                  "prompt_scope": "test", "model": ""})
        state["attempts"] = 2
        state["opencode_session"] = "ses-persist-1"
        state["status"] = "STALLED"
        me_supervisor.ensure_private_dir(me_supervisor.supervisor_dir(self.data_dir))
        me_supervisor.save_state(self.data_dir, state)
        loaded = me_supervisor.load_state(self.data_dir)
        self.assertEqual(loaded["attempts"], 2)
        self.assertEqual(loaded["opencode_session"], "ses-persist-1")

    def test_concurrent_lock_refused(self):
        me_supervisor.ensure_private_dir(me_supervisor.supervisor_dir(self.data_dir))
        me_supervisor.acquire_lock(self.data_dir, token="holder-1")
        try:
            with self.assertRaises(RuntimeError):
                me_supervisor.acquire_lock(self.data_dir, token="second")
        finally:
            me_supervisor.release_lock(self.data_dir, "holder-1")

    def test_output_flood_truncated(self):
        flood = self._fake_bin("flood", "import sys; sys.stdout.write('Z' * 100000)\n")
        rc2, out2, serr2, _ = me_supervisor.run_opencode_turn(
            binary=flood, workspace=self.ws, prompt="ignored-prompt",
            session_id="", timeout_s=60, max_output=4096)
        self.assertTrue(len(out2.encode("utf-8")) <= 4096 + 200)
        self.assertIn("truncated", serr2)

    def test_stalled_process_killed_and_reaped(self):
        sleeper = self._fake_bin("sleeper", "import time; time.sleep(60)\n")
        t0 = __import__("time").time()
        rc, out, serr, _ = me_supervisor.run_opencode_turn(
            binary=sleeper, workspace=self.ws, prompt="p",
            session_id="", timeout_s=2)
        dt = __import__("time").time() - t0
        self.assertLess(dt, 30)
        self.assertIn("terminat", out + serr)
        # No orphan: the sleeper child must be reaped (poll returns, no zombie
        # holding our unique tmp path alive as a live process).
        ps = subprocess.run(["ps", "-eo", "args"], capture_output=True,
                            text=True, timeout=10).stdout
        self.assertNotIn(str(self.tmp / "sleeper"),
                         [ln for ln in ps.splitlines()
                          if "sleeper" in ln and "ps " not in ln])

    def test_credential_redaction_in_state(self):
        state = me_supervisor.new_run_state(
            data_dir=self.data_dir, workspace=self.ws,
            opts={"workspace": str(self.ws), "max_attempts": 3,
                  "max_stagnant": 3, "wall_timeout_s": 60,
                  "attempt_timeout_s": 30, "prompt_scope": "test", "model": ""})
        secret = "me_home_" + "A" * 40
        me_supervisor.append_event(state, "attempt_end", f"token={secret} done")
        me_supervisor.save_state(self.data_dir, state)
        raw = me_supervisor.state_path(self.data_dir).read_text(encoding="utf-8")
        self.assertNotIn(secret, raw)
        self.assertIn("redacted", raw)
        mode = stat.S_IMODE(os.stat(me_supervisor.state_path(self.data_dir)).st_mode)
        self.assertEqual(mode, 0o600)
        dmode = stat.S_IMODE(os.stat(me_supervisor.supervisor_dir(self.data_dir)).st_mode)
        self.assertEqual(dmode, 0o700)

    def test_real_healthz_against_real_service(self):
        cfg = me_setup.load_config(self.data_dir)
        body = {"status": "ok", "contract": me_setup.CONTRACT_VERSION,
                "installation_id": cfg["installation_id"]}
        srv = start_health_server(body)
        self.addCleanup(srv.shutdown)
        port = srv.server_address[1]
        cfg["service"]["port"] = port
        me_setup.write_atomic(me_setup.config_path(self.data_dir),
                              json.dumps(cfg, indent=2, sort_keys=True) + "\n")
        results, _ = me_supervisor.run_checks(
            self.data_dir, {"require_service": True, "opencode_bin": ""})
        by_id = {r.id: r for r in results}
        self.assertEqual(by_id["home_health"].status, "PASS")
        self.assertEqual(by_id["db_identity"].status, "PASS")

    def test_fixture_never_claims_upstream_ready(self):
        cfg = me_setup.load_config(self.data_dir)
        cfg["models"] = {"provider": "fixture", "name": "fixture-echo",
                         "endpoint": "", "allow_fixture": True,
                         "allow_remote": False, "allow_code_exec": False,
                         "code_sandbox": "", "use_responses_api": False,
                         "capabilities": {}}
        me_setup.write_atomic(me_setup.config_path(self.data_dir),
                              json.dumps(cfg, indent=2, sort_keys=True) + "\n")
        # Production: fixture can NEVER be production READY (honest FAIL).
        results, _ = me_supervisor.run_checks(
            self.data_dir, {"profile": "production", "require_service": False,
                            "opencode_bin": ""})
        by_id = {r.id: r for r in results}
        self.assertEqual(by_id["model_profile"].status, "FAIL")
        self.assertIn("TEST", by_id["model_profile"].evidence)
        self.assertNotEqual(by_id["upstream_platform"].status, "PASS")
        # Named TEST profile: fixture completes as clearly-labelled
        # TEST_READY (synthetic only, never production READY).
        results_t, cfg_t = me_supervisor.run_checks(
            self.data_dir, {"profile": "test", "require_service": False,
                            "opencode_bin": ""})
        by_t = {r.id: r for r in results_t}
        self.assertEqual(by_t["model_profile"].status, "PASS")
        self.assertIn("TEST", by_t["model_profile"].evidence)
        self.assertNotEqual(by_t["upstream_platform"].status, "PASS")
        status_t, _ = me_supervisor.overall_status(
            results_t, {"profile": "test"}, cfg_t)
        self.assertEqual(status_t, "TEST_READY")


class DoctorIntegrityCases(unittest.TestCase):
    """Trusted upstream-doctor: live subprocess only, strict schema, anchored.

    No cached/operator JSON report can authorize READY. Garbage license,
    arbitrary 200s, no-probe reports, and forged fixtures must fail; a
    tampered doctor emitting syntactically valid READY fails the integrity
    gate. No live external APIs; fixture doctors are ephemeral and
    clearly test-only.
    """

    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp(prefix="me-doc-test-")).resolve()
        self.addCleanup(lambda: shutil.rmtree(self.tmp, ignore_errors=True))
        self.port = free_port()
        self.data_dir = make_data_dir(self.tmp, self.port)
        self.ws = self.tmp / "ws"
        self.ws.mkdir()

    def _write_doctor(self, name: str, report: dict) -> str:
        path = self.tmp / name
        path.write_text("#!/usr/bin/env python3\nimport json,sys\n"
                        f"sys.stdout.write({json.dumps(json.dumps(report))})\n",
                        encoding="utf-8")
        os.chmod(path, 0o755)
        return str(path)

    def _pin_for(self, doc: str) -> mock._patch_dict:
        """Operator trust pinning for a fixture doctor closure (test-only).

        Real deployments pin the A-published release via
        ME_UPSTREAM_DOCTOR_SHA256 (or provide ME_UPSTREAM_DOCTOR_MANIFEST).
        Fixtures compute the closure digest the same way the supervisor
        does, simulating explicit operator provisioning -- never silent TOFU.
        """
        files = me_supervisor._doctor_closure_files(Path(doc))
        digest, _, _ = me_supervisor._hash_closure(files)
        assert digest, "fixture closure unhashable"
        return mock.patch.dict(os.environ,
                               {me_supervisor.ENV_UPSTREAM_DOCTOR_SHA: digest})

    def _ready_report(self, **over) -> dict:
        # Mirrors the ACTUAL live doctor schema (infra-server
        # src/upstream-doctor.mjs) AND the final setup-doctor contract
        # (ready_evidence_required): top-level protocol + versioned
        # full-evidence contract marker + every required evidence name,
        # INCLUDING every nested field the contract names (sourcePin
        # .deployed, nativeAuth fleet/roleGate, intelligence entitlement/
        # licensed/sdkVersion, model.selectedServed, postgres reachable/
        # live, upstreamServer.capabilities, telemetry.enforced, datastore
        # bindings + recorded modes). Minimal/forged variants are built by
        # deleting from this (see tests below) -- never by inventing shapes.
        checks: dict = {
            "doctor_contract": me_supervisor.DOCTOR_CONTRACT_REQUIRED,
            "mode": "full",
            "upstream": {"repo": me_supervisor.UPSTREAM_REPO,
                         "ref": me_supervisor.UPSTREAM_PIN},
            "sourcePin": {"repo": me_supervisor.UPSTREAM_REPO,
                          "ref": me_supervisor.UPSTREAM_PIN,
                          "files": 42, "verified": "lock-format",
                          "deployed": {"configured": True,
                                       "head": me_supervisor.UPSTREAM_PIN,
                                       "filesOk": 40,
                                       "manifestOk": 3,
                                       "patchApplied": True,
                                       "ok": True}},
            "config": {"missing": [], "gate": "pass"},
            "supervisor": {"url": "http://127.0.0.1:4500",
                           "health": {"status": "ok", "docker": True},
                           "list": "ok (1)"},
            "perUserBoundary": "id-rules-loaded (names.ts ALLOWED)",
            "nativeAuth": {"probed": True, "authenticated": True,
                           "agents": 2, "perPersonRoster": True,
                           "fleet": {"computers": 2,
                                     "isolation": "per-person",
                                     "personKeys": 2},
                           "roleGate": "user-denied", "perPerson": True},
            "versions": {"computerImage": "openbot-agent-computer:pinned",
                         "namespace": "openbot",
                         "checkout": "/opt/openbot",
                         "pin": me_supervisor.UPSTREAM_PIN},
            "license": {"required": True, "keyPresent": True,
                        "managedOptIn": False,
                        "note": "licensed self-hosted Intelligence"},
            "upstreamServer": {"url": "http://127.0.0.1:3001",
                               "health": {"status": "ok"},
                               "capabilities": {"mode": "full",
                                                "durableHistory": True}},
            "postgres": {"configured": True,
                         "binding": "postgres-data:/var/lib/postgresql/data "
                                    "(pgvector/pg17)",
                         "reachable": True,
                         "live": "127.0.0.1:5432 answers TCP (SQL layer "
                                 "proven by migrate + server /health)"},
            # Native model single source (BOT_PROVIDER/BOT_MODEL): the
            # local Ollama route is provider "openai" with a local
            # OPENAI_BASE_URL and no key (keyEnv present, key not needed).
            "model": {"provider": "openai", "model": "llama3.1",
                      "endpoint": "http://host.docker.internal:11434/v1",
                      "keyEnv": "OPENAI_API_KEY", "keyPresent": False,
                      "served": ["llama3.1"], "selectedServed": True},
            "intelligence": {"apiHost": "127.0.0.1:4201",
                             "gatewayHost": "127.0.0.1:4401",
                             "keyPresent": True,
                             "licenseTokenPresent": True,
                             "selfHosted": True,
                             "entitlement": "ready",
                             "sdkVersion":
                                 me_supervisor.DOCTOR_INTELLIGENCE_SDK_VERSION,
                             "licensed": True},
            "telemetry": {"doNotTrack": "1",
                          "disabled": "1",
                          "product": "0",
                          "enforced": "upstream telemetry must stay "
                                      "disabled (DO_NOT_TRACK=1 or "
                                      "COPILOTKIT_TELEMETRY_DISABLED=1)"},
            "datastore": {"volumes": ["postgres-data:/var/lib/postgresql/data",
                                      "agent-workspace:/workspace",
                                      "agent-profiles:/profiles"],
                          "note": "full backup must include Postgres + "
                                  "Intelligence threads + computer files; "
                                  "see results/datastorage-contract.json",
                          "home-data": "/opt/me/data (mode 700)",
                          "checkout": "/opt/openbot (mode 755)"},
            "probe": True,
        }
        checks.update(over.get("checks", {}))
        report = {"protocol": me_supervisor.UPSTREAM_DOCTOR_PROTOCOL,
                  "doctor_contract": me_supervisor.DOCTOR_CONTRACT_REQUIRED,
                  "state": "READY", "checks": checks}
        report.update({k: v for k, v in over.items() if k != "checks"})
        return report

    def _opts(self, doctor: str) -> dict:
        return {"profile": "production", "require_service": False,
                "opencode_bin": "", "upstream_doctor": doctor}

    def test_live_ready_doctor_passes(self):
        doc = self._write_doctor("doc-ready", self._ready_report())
        with self._pin_for(doc):
            results, _ = me_supervisor.run_checks(
                self.data_dir, self._opts(doc))
        self.assertEqual({r.id: r for r in results}["upstream_platform"].status,
                         "PASS")

    def test_unpinned_doctor_source_parks_needs_input(self):
        # No pin and no manifest: the source is unverified (the agent may
        # have provisioned it), so even a perfect report must NOT pass --
        # the operator must pin the release first. Never silent TOFU.
        doc = self._write_doctor("doc-unpinned", self._ready_report())
        with mock.patch.dict(os.environ, {}, clear=False):
            os.environ.pop(me_supervisor.ENV_UPSTREAM_DOCTOR_SHA, None)
            os.environ.pop(me_supervisor.ENV_UPSTREAM_DOCTOR_MANIFEST, None)
            results, _ = me_supervisor.run_checks(
                self.data_dir, self._opts(doc))
        by_id = {r.id: r for r in results}
        self.assertEqual(by_id["upstream_platform"].status, "NEEDS_INPUT")
        self.assertIn("UNVERIFIED_DOCTOR_SOURCE",
                      by_id["upstream_platform"].evidence)

    def test_legacy_entrypoint_anchor_refused(self):
        # A pre-closure 64hex anchor file is NOT carried over: re-anchor the
        # trusted release explicitly instead of silently trusting it.
        doc = self._write_doctor("doc-legacy", self._ready_report())
        anchor = me_supervisor._doctor_anchor_path(self.data_dir)
        me_supervisor.ensure_private_dir(me_supervisor.supervisor_dir(
            self.data_dir))
        anchor.write_text("0" * 64 + "\n", encoding="utf-8")
        with mock.patch.dict(os.environ, {}, clear=False):
            os.environ.pop(me_supervisor.ENV_UPSTREAM_DOCTOR_SHA, None)
            os.environ.pop(me_supervisor.ENV_UPSTREAM_DOCTOR_MANIFEST, None)
            results, _ = me_supervisor.run_checks(
                self.data_dir, self._opts(doc))
        by_id = {r.id: r for r in results}
        self.assertIn(by_id["upstream_platform"].status, ("FAIL", "NEEDS_INPUT"))
        self.assertIn("anchor",
                      (by_id["upstream_platform"].evidence +
                       by_id["upstream_platform"].next_action).lower())

    def test_version_marker_missing_refused(self):
        rep = self._ready_report()
        del rep["doctor_contract"]
        del rep["checks"]["doctor_contract"]
        doc = self._write_doctor("doc-nomarker", rep)
        with self._pin_for(doc):
            results, _ = me_supervisor.run_checks(
                self.data_dir, self._opts(doc))
        by_id = {r.id: r for r in results}
        self.assertEqual(by_id["upstream_platform"].status, "FAIL")
        self.assertIn("versioned full doctor contract",
                      by_id["upstream_platform"].evidence)

    def test_minimal_forged_ready_refused(self):
        # P0-1 regression: mode+upstream alone (even with a valid marker)
        # must NOT authorize READY.
        rep = {"protocol": me_supervisor.UPSTREAM_DOCTOR_PROTOCOL,
               "doctor_contract": me_supervisor.DOCTOR_CONTRACT_REQUIRED,
               "state": "READY",
               "checks": {"mode": "full",
                          "upstream": {"repo": me_supervisor.UPSTREAM_REPO,
                                       "ref": me_supervisor.UPSTREAM_PIN}}}
        doc = self._write_doctor("doc-minimal", rep)
        with self._pin_for(doc):
            results, _ = me_supervisor.run_checks(
                self.data_dir, self._opts(doc))
        by_id = {r.id: r for r in results}
        self.assertEqual(by_id["upstream_platform"].status, "FAIL")
        self.assertIn("missing required evidence",
                      by_id["upstream_platform"].evidence)

    def test_garbage_intelligence_key_never_passes(self):
        rep = self._ready_report(state="NEEDS_INPUT")
        rep["checks"]["intelligence"] = {
            "apiUrl": None, "gatewayWsUrl": None, "keyPresent": False,
            "selfHosted": False}
        rep["checks"]["needs"] = ["full: CPK_INTELLIGENCE_API_KEY missing"]
        doc = self._write_doctor("doc-nokey", rep)
        with self._pin_for(doc):
            results, _ = me_supervisor.run_checks(
                self.data_dir, self._opts(doc))
        by_id = {r.id: r for r in results}
        self.assertNotEqual(by_id["upstream_platform"].status, "PASS")

    def test_arbitrary_json_keys_never_pass(self):
        doc = self._write_doctor("doc-arbitrary",
                                 {"hook": "ok", "license": "big",
                                  "health": 200, "docker": True})
        with self._pin_for(doc):
            results, _ = me_supervisor.run_checks(
                self.data_dir, self._opts(doc))
        by_id = {r.id: r for r in results}
        self.assertEqual(by_id["upstream_platform"].status, "FAIL")

    def test_no_probe_report_never_ready(self):
        rep = self._ready_report()
        rep["checks"]["probe"] = False
        doc = self._write_doctor("doc-noprobe", rep)
        with self._pin_for(doc):
            results, _ = me_supervisor.run_checks(
                self.data_dir, self._opts(doc))
        by_id = {r.id: r for r in results}
        self.assertEqual(by_id["upstream_platform"].status, "FAIL")
        self.assertIn("probe", by_id["upstream_platform"].evidence)

    def test_nested_probed_false_never_ready(self):
        rep = self._ready_report()
        rep["checks"]["upstreamServer"] = {"url": "http://x", "probed": False}
        doc = self._write_doctor("doc-noprobe2", rep)
        with self._pin_for(doc):
            results, _ = me_supervisor.run_checks(
                self.data_dir, self._opts(doc))
        by_id = {r.id: r for r in results}
        self.assertEqual(by_id["upstream_platform"].status, "FAIL")

    def test_fixture_model_report_never_ready(self):
        rep = self._ready_report()
        rep["checks"]["model"] = {"provider": "fixture"}
        doc = self._write_doctor("doc-fixture", rep)
        with self._pin_for(doc):
            results, _ = me_supervisor.run_checks(
                self.data_dir, self._opts(doc))
        by_id = {r.id: r for r in results}
        self.assertEqual(by_id["upstream_platform"].status, "FAIL")

    def test_docker_false_never_ready(self):
        rep = self._ready_report()
        rep["checks"]["supervisor"] = {"url": "http://127.0.0.1:4500",
                                       "health": {"status": "ok",
                                                  "docker": False},
                                       "list": "ok (1)"}
        doc = self._write_doctor("doc-nodocker", rep)
        with self._pin_for(doc):
            results, _ = me_supervisor.run_checks(
                self.data_dir, self._opts(doc))
        by_id = {r.id: r for r in results}
        self.assertEqual(by_id["upstream_platform"].status, "FAIL")

    def test_supervisor_list_unauth_never_ready(self):
        rep = self._ready_report()
        rep["checks"]["supervisor"] = {"url": "http://127.0.0.1:4500",
                                       "health": {"status": "ok",
                                                  "docker": True},
                                       "list": "401 unauthorized"}
        doc = self._write_doctor("doc-401", rep)
        with self._pin_for(doc):
            results, _ = me_supervisor.run_checks(
                self.data_dir, self._opts(doc))
        by_id = {r.id: r for r in results}
        self.assertEqual(by_id["upstream_platform"].status, "FAIL")

    def test_telemetry_enabled_never_ready(self):
        rep = self._ready_report()
        rep["checks"]["telemetry"] = {"doNotTrack": "0", "product": "1"}
        doc = self._write_doctor("doc-tel", rep)
        with self._pin_for(doc):
            results, _ = me_supervisor.run_checks(
                self.data_dir, self._opts(doc))
        by_id = {r.id: r for r in results}
        self.assertEqual(by_id["upstream_platform"].status, "FAIL")

    def test_postgres_unconfigured_never_ready(self):
        rep = self._ready_report()
        rep["checks"]["postgres"] = {"configured": False, "binding": None}
        doc = self._write_doctor("doc-pg", rep)
        with self._pin_for(doc):
            results, _ = me_supervisor.run_checks(
                self.data_dir, self._opts(doc))
        by_id = {r.id: r for r in results}
        self.assertEqual(by_id["upstream_platform"].status, "FAIL")

    def test_config_gate_not_pass_never_ready(self):
        rep = self._ready_report()
        rep["checks"]["config"] = {"missing": ["DATABASE_URL"],
                                   "gate": "full: FULL profile missing"}
        doc = self._write_doctor("doc-gate", rep)
        with self._pin_for(doc):
            results, _ = me_supervisor.run_checks(
                self.data_dir, self._opts(doc))
        by_id = {r.id: r for r in results}
        self.assertEqual(by_id["upstream_platform"].status, "FAIL")

    # -- Strict doctor schema (OPEN #5): forged/partial READY reports --
    # Each test removes or poisons ONE nested contract field from the
    # complete report; every one must refuse READY (upstream_platform
    # FAIL), per the contract's minimal_forged_READY_rejected_because list.

    def _assert_forged_fails(self, name: str, rep: dict,
                             evidence_part: str) -> None:
        doc = self._write_doctor(name, rep)
        with self._pin_for(doc):
            results, _ = me_supervisor.run_checks(
                self.data_dir, self._opts(doc))
        by_id = {r.id: r for r in results}
        self.assertEqual(by_id["upstream_platform"].status, "FAIL")
        self.assertIn(evidence_part, by_id["upstream_platform"].evidence)

    def test_forged_ready_missing_sourcepin_deployed_fails(self):
        rep = self._ready_report()
        del rep["checks"]["sourcePin"]["deployed"]
        self._assert_forged_fails("doc-nodeployed", rep,
                                  "sourcePin.deployed")

    def test_forged_ready_deployed_patch_not_applied_fails(self):
        rep = self._ready_report()
        rep["checks"]["sourcePin"]["deployed"]["patchApplied"] = False
        self._assert_forged_fails("doc-nopatch", rep, "patchApplied")

    def test_forged_ready_deployed_head_drift_fails(self):
        rep = self._ready_report()
        rep["checks"]["sourcePin"]["deployed"]["head"] = "0" * 40
        self._assert_forged_fails("doc-headdri", rep, "deployed.head")

    def test_forged_ready_missing_nativeauth_fails(self):
        rep = self._ready_report()
        del rep["checks"]["nativeAuth"]
        self._assert_forged_fails("doc-nonauth", rep, "nativeAuth")

    def test_forged_ready_nativeauth_rolegate_open_fails(self):
        # A shared provider answering the fleet to a user assertion is a
        # FAILED stack, never READY.
        rep = self._ready_report()
        rep["checks"]["nativeAuth"]["roleGate"] = "user-allowed"
        self._assert_forged_fails("doc-rolegate", rep, "roleGate")

    def test_forged_ready_missing_entitlement_fails(self):
        rep = self._ready_report()
        del rep["checks"]["intelligence"]["entitlement"]
        self._assert_forged_fails("doc-noentitle", rep, "entitlement")

    def test_forged_ready_entitlement_not_ready_fails(self):
        rep = self._ready_report()
        rep["checks"]["intelligence"]["entitlement"] = "pending"
        self._assert_forged_fails("doc-entpend", rep, "entitlement")

    def test_forged_ready_wrong_sdk_version_fails(self):
        rep = self._ready_report()
        rep["checks"]["intelligence"]["sdkVersion"] = "1.70.1"
        self._assert_forged_fails("doc-sdkver", rep, "sdkVersion")

    def test_forged_ready_missing_model_selected_served_fails(self):
        rep = self._ready_report()
        del rep["checks"]["model"]["selectedServed"]
        self._assert_forged_fails("doc-noserved", rep, "selectedServed")

    def test_forged_ready_model_not_served_fails(self):
        rep = self._ready_report()
        rep["checks"]["model"]["selectedServed"] = False
        self._assert_forged_fails("doc-notserved", rep, "selectedServed")

    def test_forged_ready_postgres_unreachable_fails(self):
        rep = self._ready_report()
        rep["checks"]["postgres"]["reachable"] = False
        del rep["checks"]["postgres"]["live"]
        self._assert_forged_fails("doc-pgdown", rep, "Postgres")

    def test_forged_ready_missing_capabilities_fails(self):
        rep = self._ready_report()
        del rep["checks"]["upstreamServer"]["capabilities"]
        self._assert_forged_fails("doc-nocaps", rep, "capabilities")

    def test_forged_ready_datastore_world_writable_fails(self):
        rep = self._ready_report()
        rep["checks"]["datastore"]["home-data"] = "/opt/me/data (mode 777)"
        self._assert_forged_fails("doc-dsww", rep, "world-writable")

    def test_forged_ready_datastore_bindings_unrecorded_fails(self):
        rep = self._ready_report()
        rep["checks"]["datastore"]["volumes"] = [
            "postgres-data:/var/lib/postgresql/data"]
        self._assert_forged_fails("doc-dsbind", rep, "bindings unrecorded")

    def test_forged_ready_telemetry_unenforced_fails(self):
        rep = self._ready_report()
        del rep["checks"]["telemetry"]["enforced"]
        self._assert_forged_fails("doc-telenf", rep,
                                  "telemetry.enforced")

    def test_wrong_contract_marker_fails(self):
        rep = self._ready_report()
        rep["doctor_contract"] = "upstream-platform-v1/full.0"
        rep["checks"]["doctor_contract"] = "upstream-platform-v1/full.0"
        self._assert_forged_fails("doc-badmarker", rep,
                                  "versioned full doctor contract")

    def test_tampered_doctor_fails_integrity_gate(self):
        doc = self._write_doctor("doc-tamper", self._ready_report())
        files = me_supervisor._doctor_closure_files(Path(doc))
        orig, _, _ = me_supervisor._hash_closure(files)
        assert orig
        with mock.patch.dict(os.environ,
                             {me_supervisor.ENV_UPSTREAM_DOCTOR_SHA: orig}):
            results, _ = me_supervisor.run_checks(
                self.data_dir, self._opts(doc))
        self.assertEqual({r.id: r for r in results}["upstream_platform"].status,
                         "PASS")
        # Tamper after anchor: same path now emits READY from modified bytes.
        Path(doc).write_text("#!/usr/bin/env python3\nimport sys\n"
                             "sys.stdout.write('{\"protocol\": "
                             "\"upstream-platform-v1\", \"state\": \"READY\", "
                             "\"checks\": {\"mode\": \"full\", \"upstream\": "
                             "{\"repo\": \"CopilotKit/OpenBot\", \"ref\": "
                             "\"6bfee780c8e8d05141375ea55ebde33eefb3dbc0\"}}}')\n",
                             encoding="utf-8")
        # Against the ORIGINAL pin the closure mismatch refuses first.
        with mock.patch.dict(os.environ,
                             {me_supervisor.ENV_UPSTREAM_DOCTOR_SHA: orig}):
            results2, _ = me_supervisor.run_checks(
                self.data_dir, self._opts(doc))
        by2 = {r.id: r for r in results2}
        self.assertEqual(by2["upstream_platform"].status, "FAIL")
        self.assertIn("closure", by2["upstream_platform"].evidence)

    def test_pinned_digest_mismatch_refuses(self):
        doc = self._write_doctor("doc-pin", self._ready_report())
        digest = __import__("hashlib").sha256(
            Path(doc).read_bytes()).hexdigest()
        bad = "0" * 64 if not digest.startswith("0" * 64) else "1" * 64
        with mock.patch.dict(os.environ,
                             {me_supervisor.ENV_UPSTREAM_DOCTOR_SHA: bad}):
            results, _ = me_supervisor.run_checks(
                self.data_dir, self._opts(doc))
        by_id = {r.id: r for r in results}
        self.assertEqual(by_id["upstream_platform"].status, "FAIL")

    def test_missing_doctor_parks_needs_input(self):
        results, _ = me_supervisor.run_checks(
            self.data_dir, {"profile": "production", "require_service": False,
                            "opencode_bin": "",
                            "upstream_doctor": str(self.tmp / "absent-doc")})
        by_id = {r.id: r for r in results}
        # Sibling checkout exists in this monorepo, so absence falls back to
        # the trusted sibling -- which is UNPINNED here and must therefore
        # refuse with UNVERIFIED_DOCTOR_SOURCE (NEEDS_INPUT), never PASS from
        # a missing/cached report.
        self.assertEqual(by_id["upstream_platform"].status, "NEEDS_INPUT")
        self.assertIn("UNVERIFIED_DOCTOR_SOURCE",
                      by_id["upstream_platform"].evidence)

    def _write_closure_pair(self, tag: str) -> tuple[str, Path, Path]:
        """Fake cli.mjs + imported dep.mjs module (node-runnable)."""
        root = (self.tmp / f"closure-{tag}").resolve()
        src = root / "src"
        src.mkdir(parents=True)
        dep = src / "dep.mjs"
        dep.write_text("export const TAG = 'v1';\n", encoding="utf-8")
        report = self._ready_report()
        cli = src / "cli.mjs"
        cli.write_text(
            "import { TAG } from './dep.mjs';\n"
            f"const report = {json.dumps(json.dumps(report))};\n"
            "const doc = JSON.parse(report);\n"
            "doc.checks.versions.tag = TAG;\n"
            "console.log(JSON.stringify(doc));\n",
            encoding="utf-8")
        return str(cli), cli, dep

    def test_imported_dependency_tamper_fails_closure(self):
        # P0-2 regression: editing an IMPORTED verifier module must fail the
        # gate even though the entrypoint bytes are unchanged.
        if not shutil.which("node"):
            self.skipTest("node unavailable for closure fixture")
        cli, entry, dep = self._write_closure_pair("dep")
        files = me_supervisor._doctor_closure_files(Path(cli))
        self.assertTrue(any(r == "src/dep.mjs" for r, _ in files),
                        f"closure must include the imported dep: {files}")
        digest, _, _ = me_supervisor._hash_closure(files)
        assert digest
        with mock.patch.dict(os.environ,
                             {me_supervisor.ENV_UPSTREAM_DOCTOR_SHA: digest}):
            results, _ = me_supervisor.run_checks(
                self.data_dir, self._opts(cli))
        self.assertEqual({r.id: r for r in results}["upstream_platform"].status,
                         "PASS")
        self.assertEqual(entry.read_bytes(),
                         (Path(cli)).read_bytes(), "entrypoint untouched")
        dep.write_text("export const TAG = 'evil';\n", encoding="utf-8")
        with mock.patch.dict(os.environ,
                             {me_supervisor.ENV_UPSTREAM_DOCTOR_SHA: digest}):
            results2, _ = me_supervisor.run_checks(
                self.data_dir, self._opts(cli))
        by2 = {r.id: r for r in results2}
        self.assertEqual(by2["upstream_platform"].status, "FAIL")
        self.assertIn("closure", by2["upstream_platform"].evidence)

    def test_release_manifest_match_passes_mismatch_fails(self):
        doc = self._write_doctor("doc-manifest", self._ready_report())
        files = me_supervisor._doctor_closure_files(Path(doc))
        _, _, per = me_supervisor._hash_closure(files)
        manifest = self.tmp / "release-manifest.json"
        manifest.write_text(json.dumps({"files": per}), encoding="utf-8")
        with mock.patch.dict(os.environ,
                             {me_supervisor.ENV_UPSTREAM_DOCTOR_MANIFEST:
                              str(manifest)}):
            # Manifest gate passes with no pin (explicit operator release).
            old = os.environ.pop(me_supervisor.ENV_UPSTREAM_DOCTOR_SHA, None)
            try:
                results, _ = me_supervisor.run_checks(
                    self.data_dir, self._opts(doc))
            finally:
                if old is not None:
                    os.environ[me_supervisor.ENV_UPSTREAM_DOCTOR_SHA] = old
        self.assertEqual({r.id: r for r in results}["upstream_platform"].status,
                         "PASS")
        manifest.write_text(json.dumps(
            {"files": {k: "0" * 64 for k in per}}), encoding="utf-8")
        with mock.patch.dict(os.environ,
                             {me_supervisor.ENV_UPSTREAM_DOCTOR_MANIFEST:
                              str(manifest)}):
            old = os.environ.pop(me_supervisor.ENV_UPSTREAM_DOCTOR_SHA, None)
            try:
                results2, _ = me_supervisor.run_checks(
                    self.data_dir, self._opts(doc))
            finally:
                if old is not None:
                    os.environ[me_supervisor.ENV_UPSTREAM_DOCTOR_SHA] = old
        self.assertEqual({r.id: r for r in results2}["upstream_platform"].status,
                         "FAIL")

    def test_doctor_cwd_contract_module_root(self):
        # Module-root cwd even when invoked from an arbitrary install cwd.
        repo = (self.tmp / "infra").resolve()
        (repo / "src").mkdir(parents=True)
        cli = repo / "src" / "cli.mjs"
        cli.write_text("// fixture\n", encoding="utf-8")
        self.assertEqual(me_supervisor._doctor_cwd(cli), repo)
        standalone = self.tmp / "upstream-doctor"
        standalone.write_text("#!/bin/sh\n", encoding="utf-8")
        self.assertEqual(me_supervisor._doctor_cwd(standalone), self.tmp)

    def test_doctor_invoked_with_module_root_cwd(self):
        # The doctor must resolve its vendor manifest from its own module
        # root, not the caller's cwd: assert the runner gets the module
        # root. Tests run from an arbitrary install cwd.
        doc = self._write_doctor("doc-cwd", self._ready_report())
        seen: dict = {}
        real = me_supervisor._run_doctor_subprocess

        def spy(argv, **kw):
            seen["cwd"] = kw.get("cwd")
            seen["argv"] = argv
            return real(argv, **kw)

        with self._pin_for(doc), \
                mock.patch.object(me_supervisor, "_run_doctor_subprocess",
                                  side_effect=spy):
            me_supervisor.run_checks(self.data_dir, self._opts(doc))
        self.assertEqual(seen.get("cwd"), Path(doc).parent)


class TurnIOCases(unittest.TestCase):
    """I/O review: session latch, holding-pipe deadlock, flood, permissions."""

    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp(prefix="me-io-test-")).resolve()
        self.addCleanup(lambda: shutil.rmtree(self.tmp, ignore_errors=True))
        self.ws = self.tmp / "ws"
        self.ws.mkdir()
        self.dd = self.tmp / "home"
        self.dd.mkdir()

    def _fake_bin(self, name: str, script_body: str) -> str:
        path = self.tmp / name
        path.write_text("#!/usr/bin/env python3\n" + script_body, encoding="utf-8")
        os.chmod(path, 0o755)
        return str(path)

    def test_session_latched_despite_tail_eviction(self):
        # Initial session event followed by >262144B of noise: the bounded
        # EOF tail evicts the session line, but the streaming latch keeps it.
        body = ('import json,sys\n'
                'sys.stdout.write(json.dumps({"sessionID": "ses-latch-1"})+"\\n")\n'
                'sys.stdout.write("x" * 400000 + "\\n")\n'
                'sys.stdout.write(json.dumps({"text": "done"})+"\\n")\n')
        fake = self._fake_bin("fake-latch", body)
        rc, out, serr, sess = me_supervisor.run_opencode_turn(
            binary=fake, workspace=self.ws, prompt="p", session_id="",
            timeout_s=30, max_output=4096, data_dir=self.dd)
        self.assertEqual(rc, 0)
        self.assertEqual(sess, "ses-latch-1")

    def test_exited_leader_holding_pipe_no_deadlock(self):
        # Leader exits immediately; a TERM-ignoring grandchild INHERITS
        # stdout and holds the pipe open. The turn must still finish bounded
        # (residual group killed before close: no close/read deadlock, no
        # orphan). The grandchild redirects only stdin/stderr: fd 1 stays
        # the pipe, so EOF cannot arrive until the group is killed.
        body = ('import os,subprocess,sys,time\n'
                'grand = subprocess.Popen(\n'
                ' ["python3", "-c", "import signal,time;'
                'signal.signal(signal.SIGTERM, signal.SIG_IGN);'
                'time.sleep(60)"],\n'
                ' stdin=subprocess.DEVNULL, stderr=subprocess.DEVNULL,\n'
                ' start_new_session=False)\n'
                'sys.stdout.write("{\\"sessionID\\": \\"ses-hold-1\\"}\\n")\n'
                'sys.stdout.flush()\n')
        fake = self._fake_bin("fake-hold", body)
        t0 = time.time()
        rc, out, serr, sess = me_supervisor.run_opencode_turn(
            binary=fake, workspace=self.ws, prompt="p", session_id="",
            timeout_s=30, max_output=16384, data_dir=self.dd)
        dt = time.time() - t0
        self.assertLess(dt, 25, f"holding-pipe turn took {dt:.1f}s: {serr[-200:]}")
        self.assertEqual(sess, "ses-hold-1")
        # No orphan grandchild keeping our tmp path alive as a live process.
        ps = subprocess.run(["ps", "-eo", "args"], capture_output=True,
                            text=True, timeout=10).stdout
        self.assertNotIn("time.sleep(60)",
                         [ln for ln in ps.splitlines()
                          if "time.sleep(60)" in ln and "ps " not in ln])

    def test_output_flood_bounded_and_terminated(self):
        body = 'import sys\nfor _ in range(200000): sys.stdout.write("y"*500+"\\n")\n'
        fake = self._fake_bin("fake-flood", body)
        rc, out, serr, _ = me_supervisor.run_opencode_turn(
            binary=fake, workspace=self.ws, prompt="p", session_id="",
            timeout_s=60, max_output=16384, data_dir=self.dd)
        total = len(out.encode("utf-8"))
        self.assertLessEqual(total, 16384 + 500)
        self.assertIn("flood cap", serr + out)

    def test_scoped_permission_env_covers_taskpaths(self):
        env = me_supervisor._scoped_permission_env(workspace=self.ws,
                                                   data_dir=self.dd)
        doc = json.loads(env["OPENCODE_PERMISSION"])
        ext = doc["external_directory"]
        self.assertIn(str(self.ws) + "/**", ext)
        self.assertIn(str(self.dd) + "/**", ext)
        # Operator deny wins over our allow (appended last).
        with mock.patch.dict(os.environ, {"OPENCODE_PERMISSION": json.dumps(
                {"external_directory": {str(self.ws) + "/**": "deny"}})}):
            env2 = me_supervisor._scoped_permission_env(workspace=self.ws,
                                                        data_dir=self.dd)
            self.assertEqual(json.loads(env2["OPENCODE_PERMISSION"])
                             ["external_directory"][str(self.ws) + "/**"],
                             "deny")

    def test_permission_events_classified(self):
        ws_file = str(self.ws / "ok.txt")
        evs = me_supervisor.parse_permission_events(
            [json.dumps({"part": {"tool": "read", "state": {
                "status": "error", "input": {"filePath": ws_file},
                "error": "The user rejected permission to use this tool call"}}})],
            ["permission requested: external_directory (/etc/*); auto-rejecting"],
            workspace=self.ws, data_dir=self.dd)
        kinds = {(e["kind"], e["class"]) for e in evs}
        self.assertIn(("permission-denied", "taskpath"), kinds)
        self.assertIn(("permission-requested", "external"), kinds)

    def test_symlink_state_refused(self):
        real = self.tmp / "real-home"
        real.mkdir()
        link = self.tmp / "link-home"
        try:
            link.symlink_to(real, target_is_directory=True)
        except OSError as exc:
            self.skipTest(f"cannot create symlink here: {exc}")
        with self.assertRaises(RuntimeError):
            me_supervisor.ensure_private_dir(link / "supervisor")

    def test_parked_time_excluded_from_active_budget(self):
        state = me_supervisor.new_run_state(
            data_dir=self.dd, workspace=self.ws,
            opts={"workspace": str(self.ws), "profile": "test",
                  "max_attempts": 3, "max_stagnant": 3, "wall_timeout_s": 600,
                  "attempt_timeout_s": 30, "prompt_scope": "test", "model": ""})
        state["active_seconds"] = 10.0
        me_supervisor.ensure_private_dir(me_supervisor.supervisor_dir(self.dd))
        me_supervisor.save_state(self.dd, state)
        loaded = me_supervisor.load_state(self.dd)
        # Simulate overnight park: wall clock jumps but active stays 10 until
        # drive() accrues monotonic time again.
        self.assertAlmostEqual(float(loaded["active_seconds"]), 10.0, delta=1.0)


class DoctorRunnerCases(unittest.TestCase):
    """Bounded doctor subprocess: streaming caps, residual pipes, signals."""

    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp(prefix="me-docrun-test-")).resolve()
        self.addCleanup(lambda: shutil.rmtree(self.tmp, ignore_errors=True))

    def _bin(self, name: str, body: str) -> str:
        path = self.tmp / name
        path.write_text("#!/usr/bin/env python3\n" + body, encoding="utf-8")
        os.chmod(path, 0o755)
        return str(path)

    def test_doctor_flood_bounded_and_terminated(self):
        # Same streaming-cap discipline as agent turns: no
        # communicate()-then-truncate unbounded memory DURING output.
        fake = self._bin("doc-flood",
                         'import sys\nfor _ in range(200000): '
                         'sys.stdout.write("y"*500+"\\n")\n')
        t0 = time.time()
        rc, out, serr = me_supervisor._run_doctor_subprocess(
            [fake], cwd=self.tmp)
        dt = time.time() - t0
        self.assertLess(dt, 30)
        self.assertLessEqual(len(out), me_supervisor.DOCTOR_MAX_BYTES + 1)
        self.assertIn("flood cap", serr)

    def test_doctor_leader_exit_holding_pipe_no_deadlock(self):
        # Leader prints JSON and exits; a TERM-ignoring grandchild inherits
        # stdout and holds the pipe. The runner must finish bounded (residual
        # group killed before close) with the report bytes intact.
        body = ('import json,subprocess,sys\n'
                'sys.stdout.write(json.dumps({"protocol": "upstream-platform-v1",'
                '"state": "NEEDS_INPUT", "checks": {"probe": True}})+"\\n")\n'
                'sys.stdout.flush()\n'
                'grand = subprocess.Popen(\n'
                ' ["python3", "-c", "import signal,time;'
                'signal.signal(signal.SIGTERM, signal.SIG_IGN);'
                'time.sleep(60)"])\n')
        fake = self._bin("doc-hold", body)
        t0 = time.time()
        rc, out, serr = me_supervisor._run_doctor_subprocess(
            [fake], cwd=self.tmp)
        dt = time.time() - t0
        self.assertLess(dt, 25, f"held-pipe doctor took {dt:.1f}s")
        self.assertEqual(rc, 0)
        self.assertIn(b"NEEDS_INPUT", out)
        ps = subprocess.run(["ps", "-eo", "args"], capture_output=True,
                            text=True, timeout=10).stdout
        self.assertNotIn("time.sleep(60)",
                         [ln for ln in ps.splitlines()
                          if "time.sleep(60)" in ln and "ps " not in ln])

    def test_sigterm_during_doctor_reaps_and_persists(self):
        # SIGTERM mid-doctor: the runner terminates the group promptly and
        # the drive loop observes the flag (RUNNING persists, resumable).
        fake = self._bin("doc-slow",
                         'import time,sys; time.sleep(30); '
                         'sys.stdout.write("{}\\n")\n')
        saved = dict(me_supervisor._STOP_REQUESTED)
        timer = threading.Timer(1.0, lambda: me_supervisor._handle_term(
            signal.SIGTERM, None))
        timer.start()
        try:
            t0 = time.time()
            rc, out, serr = me_supervisor._run_doctor_subprocess(
                [fake], cwd=self.tmp, timeout_s=30)
            dt = time.time() - t0
        finally:
            timer.cancel()
            me_supervisor._STOP_REQUESTED.clear()
            me_supervisor._STOP_REQUESTED.update(saved)
        self.assertLess(dt, 20)
        self.assertIn("interrupted", serr)
        ps = subprocess.run(["ps", "-eo", "args"], capture_output=True,
                            text=True, timeout=10).stdout
        self.assertNotIn(str(self.tmp / "doc-slow"),
                         [ln for ln in ps.splitlines()
                          if "doc-slow" in ln and "ps " not in ln])

    def test_deadline_clamp_shares_active_budget(self):
        # A nearly-exhausted shared budget clamps the doctor timeout instead
        # of stacking per-check timeouts past the wall.
        fake = self._bin("doc-slow2", 'import time; time.sleep(30)\n')
        past = time.monotonic() - 1.0  # already-expired budget
        t0 = time.time()
        rc, out, serr = me_supervisor._run_doctor_subprocess(
            [fake], cwd=self.tmp, timeout_s=60, deadline_mono=past)
        dt = time.time() - t0
        self.assertLess(dt, 20)
        self.assertIn("budget", serr)


class BackupCoverageCases(unittest.TestCase):
    """Backup scope: explicit unsupported capability, opt-in requirement."""

    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp(prefix="me-bak-test-")).resolve()
        self.addCleanup(lambda: shutil.rmtree(self.tmp, ignore_errors=True))
        self.port = free_port()
        self.data_dir = make_data_dir(self.tmp, self.port)

    def test_default_operational_excludes_backup_claims(self):
        # Default production: backup_coverage is OPTIONAL stating
        # backup.supported=false -- operational READY must not claim
        # backups, and must not disguise the gap as an operator gate.
        results, cfg = me_supervisor.run_checks(
            self.data_dir, {"profile": "production", "require_service": False,
                            "opencode_bin": ""})
        by_id = {r.id: r for r in results}
        self.assertEqual(by_id["backup_coverage"].status, "OPTIONAL")
        self.assertIn("backup.supported=false",
                      by_id["backup_coverage"].evidence)
        req = me_supervisor.required_ids({"profile": "production"}, cfg)
        self.assertNotIn("backup_coverage", req)

    def test_require_backup_never_passes_without_support(self):
        # Explicit --require-backup product policy: truthfully NOT READY
        # (FAIL with the concrete integration path), never a checkbox PASS --
        # with or without declared volumes (omission hides nothing).
        for volumes in (None, {"postgres-data": {"scope": "postgres-data"},
                               "agent-workspace": {"scope": "agent-workspace"},
                               "agent-profiles": {"scope": "agent-profiles"}}):
            cfg = me_setup.load_config(self.data_dir)
            if volumes is None:
                cfg.pop("volumes", None)
            else:
                cfg["volumes"] = volumes
            me_setup.write_atomic(me_setup.config_path(self.data_dir),
                                  json.dumps(cfg, indent=2, sort_keys=True) + "\n")
            opts = {"profile": "production", "require_service": False,
                    "opencode_bin": "", "require_backup": True}
            results, cfg2 = me_supervisor.run_checks(self.data_dir, opts)
            by_id = {r.id: r for r in results}
            self.assertEqual(by_id["backup_coverage"].status, "FAIL",
                             f"volumes={volumes}")
            self.assertIn("UNSUPPORTED", by_id["backup_coverage"].evidence)
            req = me_supervisor.required_ids(opts, cfg2)
            self.assertIn("backup_coverage", req)
            status, _ = me_supervisor.overall_status(results, opts, cfg2)
            self.assertNotEqual(status, "READY")


class CliAuthGateCases(unittest.TestCase):
    """Fresh-home CLI without model auth parks NEEDS_INPUT (no STALLED burn)."""

    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp(prefix="me-auth-test-")).resolve()
        self.addCleanup(lambda: shutil.rmtree(self.tmp, ignore_errors=True))
        self.port = free_port()
        self.data_dir = make_data_dir(self.tmp, self.port)
        self.ws = self.tmp / "ws"
        self.ws.mkdir()

    def _use_fixture_provider(self) -> None:
        cfg = me_setup.load_config(self.data_dir)
        cfg["models"] = {"provider": "fixture", "name": "fixture-echo",
                         "endpoint": "", "allow_fixture": True,
                         "allow_remote": False, "allow_code_exec": False,
                         "code_sandbox": "", "use_responses_api": False,
                         "capabilities": {}}
        me_setup.write_atomic(me_setup.config_path(self.data_dir),
                              json.dumps(cfg, indent=2, sort_keys=True) + "\n")

    def test_unauthenticated_cli_parks_with_login_instructions(self):
        self._use_fixture_provider()
        fake = self.tmp / "fake-auth"
        fake.write_text(
            "#!/usr/bin/env python3\nimport json,sys\n"
            "if '--version' in sys.argv:\n"
            "    print('fake-opencode 1.0.0'); sys.exit(0)\n"
            "if '--help' in sys.argv:\n"
            "    print('usage: run [--auto]'); sys.exit(0)\n"
            "sys.stderr.write('error: not authenticated. '\n"
            "'Run opencode auth login to connect a provider.\\n')\n"
            "print(json.dumps({'type': 'error', 'sessionID': 'ses-auth-1',"
            "'error': 'not authenticated'}))\n"
            "sys.exit(1)\n", encoding="utf-8")
        os.chmod(fake, 0o755)
        # Force at least one agent turn: verifiers alone would already pass
        # in the TEST profile (that is the point -- the CLI auth gate must
        # fire from the turn itself, not from a verifier).
        me_supervisor.register_check(
            "test_auth_marker", required=True,
            description="test-only: never passes without a real fix",
            handler=lambda dd, cfg, opts: me_supervisor.CheckResult(
                "test_auth_marker", "FAIL",
                evidence="missing (agent must fix)",
                next_action="Create marker."))
        self.addCleanup(lambda: me_supervisor.CHECKS.pop("test_auth_marker",
                                                          None))
        opts = {"workspace": str(self.ws), "require_service": False,
                "profile": "test",
                "allow_install": False, "opencode_bin": str(fake),
                "max_attempts": 5, "max_stagnant": 1,
                "wall_timeout_s": 300, "attempt_timeout_s": 60,
                "prompt_scope": "test", "model": ""}
        state = me_supervisor.new_run_state(
            data_dir=self.data_dir, workspace=self.ws, opts=opts)
        rc = me_supervisor.drive(state, data_dir=self.data_dir, binary=str(fake))
        self.assertEqual(rc, 4)
        self.assertEqual(state["status"], "NEEDS_INPUT")
        self.assertIn("opencode auth login", state["needs_reason"])
        self.assertEqual(state["attempts"], 1, "auth gate must not burn turns")
        self.assertNotEqual(state["status"], "STALLED")

    def test_operator_config_and_denies_preserved(self):
        # The scoped env adds taskpath allows but never overrides explicit
        # operator denies and never touches OPENCODE_CONFIG_CONTENT.
        with mock.patch.dict(os.environ, {
                "OPENCODE_PERMISSION": json.dumps(
                    {"external_directory": {"/etc/**": "deny"}}),
                "OPENCODE_CONFIG_CONTENT": '{"permission": {"bash": "deny"}}'}):
            env = me_supervisor._scoped_permission_env(workspace=self.ws,
                                                       data_dir=self.data_dir)
            doc = json.loads(env["OPENCODE_PERMISSION"])
            self.assertEqual(doc["external_directory"]["/etc/**"], "deny")
            self.assertIn(str(self.ws) + "/**", doc["external_directory"])
            # Child env inherits the operator's inline config untouched.
            child = dict(os.environ)
            child.update(env)
            self.assertEqual(child["OPENCODE_CONFIG_CONTENT"],
                             '{"permission": {"bash": "deny"}}')
            self.assertNotIn("personal", json.dumps(doc).lower())

    def test_agent_prose_about_auth_is_not_a_gate(self):
        self.assertFalse(me_supervisor._is_cli_auth_error(
            "we discussed that you may need to run opencode auth login "
            "someday, all good", "", []))


class OperationalReadinessCases(unittest.TestCase):
    """Operational READY is reachable with full required service evidence."""

    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp(prefix="me-opready-test-")).resolve()
        self.addCleanup(lambda: shutil.rmtree(self.tmp, ignore_errors=True))
        self.port = free_port()
        self.data_dir = make_data_dir(self.tmp, self.port)
        self.ws = self.tmp / "ws"
        self.ws.mkdir()

    def test_operational_ready_reachable_without_backup_claims(self):
        # Production with every required service verified (probes mocked,
        # health server real, fixture full-evidence doctor pinned) reaches
        # READY while backup stays explicitly excluded (supported=false).
        cfg = me_setup.load_config(self.data_dir)
        body = {"status": "ok", "contract": me_setup.CONTRACT_VERSION,
                "installation_id": cfg["installation_id"]}
        srv = None
        try:
            srv = start_health_server(body)
            port = srv.server_address[1]
            cfg["service"]["port"] = port
            me_setup.write_atomic(me_setup.config_path(self.data_dir),
                                  json.dumps(cfg, indent=2, sort_keys=True) + "\n")
            doc = self.tmp / "doc-opready"
            # Full-evidence fixture mirroring the actual live doctor schema
            # (same builder as the integrity cases; no invented shapes).
            rep = DoctorIntegrityCases._ready_report(None)
            doc.write_text("#!/usr/bin/env python3\nimport json,sys\n"
                           f"sys.stdout.write({json.dumps(json.dumps(rep))})\n",
                           encoding="utf-8")
            os.chmod(doc, 0o755)
            files = me_supervisor._doctor_closure_files(doc)
            digest, _, _ = me_supervisor._hash_closure(files)
            opts = {"profile": "production", "require_service": True,
                    "opencode_bin": "", "upstream_doctor": str(doc)}
            # Real loopback /healthz (real HTTP + real SQLite identity);
            # only the model daemon, managed runtime, and doctor are
            # fixtures/mocks (no Ollama/Docker/home service on this Mac).
            with mock.patch.dict(os.environ, {
                    me_supervisor.ENV_UPSTREAM_DOCTOR_SHA: digest or ""}), \
                 mock.patch.object(me_supervisor, "probe_ollama",
                                   return_value=(True, "ollama ok (mock)")), \
                 mock.patch("me_lifecycle.managed_state",
                            return_value=("running", {"pid": 4242})):
                results, cfg2 = me_supervisor.run_checks(self.data_dir, opts)
                by_id = {r.id: r for r in results}
                for cid in ("opencode_cli", "prereqs", "config", "storage",
                            "db_identity", "model_profile", "home_health",
                            "service_runtime", "upstream_platform"):
                    self.assertEqual(by_id[cid].status, "PASS", f"{cid}")
                self.assertEqual(by_id["backup_coverage"].status, "OPTIONAL")
                status, _ = me_supervisor.overall_status(results, opts, cfg2)
                self.assertEqual(status, "READY")
        finally:
            if srv is not None:
                srv.shutdown()

    def test_unmigrated_config_selects_profile_explicitly(self):
        cfg = me_setup.load_config(self.data_dir)
        cfg.pop("upstream", None)
        me_setup.write_atomic(me_setup.config_path(self.data_dir),
                              json.dumps(cfg, indent=2, sort_keys=True) + "\n")
        results, _ = me_supervisor.run_checks(
            self.data_dir, {"profile": "production", "require_service": False,
                            "opencode_bin": ""})
        by_id = {r.id: r for r in results}
        self.assertEqual(by_id["upstream_platform"].status, "NEEDS_INPUT")
        self.assertIn("unselected", (by_id["upstream_platform"].evidence +
                                     by_id["upstream_platform"].needs_reason))


class NativeKeyCases(unittest.TestCase):
    """model_profile verifies the EFFECTIVE native key (bound or gate)."""

    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp(prefix="me-key-test-")).resolve()
        self.addCleanup(lambda: shutil.rmtree(self.tmp, ignore_errors=True))
        self.port = free_port()
        self.data_dir = make_data_dir(self.tmp, self.port)

    def _openai_cfg(self):
        cfg = me_setup.load_config(self.data_dir)
        cfg["models"] = {"provider": "openai", "name": "gpt-x",
                         "endpoint": "https://api.openai.com/v1",
                         "allow_fixture": False, "allow_remote": True,
                         "allow_code_exec": False, "code_sandbox": "",
                         "use_responses_api": False, "capabilities": {}}
        me_setup.write_atomic(me_setup.config_path(self.data_dir),
                              json.dumps(cfg, indent=2, sort_keys=True) + "\n")
        # Setup activates config.json + service.env TOGETHER from the ONE
        # selection (do_setup renders both); rewriting only config.json
        # would leave check_native_model_env comparing against the stale
        # local render. Re-render via the production renderer.
        upstream = cfg.get("upstream") or {}
        env_text = me_setup.render_service_env(
            db_path=self.data_dir / "data" / "home.sqlite",
            host="127.0.0.1", port=self.port, models=cfg["models"],
            coordinator=cfg.get("coordinator"),
            notifications=cfg.get("notifications"),
            upstream_mode=str(upstream.get("mode", "") or "") or None)
        me_setup.write_atomic(self.data_dir / "config" / "service.env",
                              env_text)

    def test_service_env_value_ignores_trailing_comment(self):
        # Regression: the writer appends a NONSECRET comment after the
        # local placeholder key line (`OPENAI_API_KEY='ollama'  # ...`);
        # the supervisor parser must read the shell value, not the tail,
        # or model_profile can never PASS for a default local install.
        parse = me_supervisor._service_env_value
        self.assertEqual(parse("'ollama'  # NONSECRET placeholder"), "ollama")
        self.assertEqual(parse("1  # synthetic tests only"), "1")
        self.assertEqual(parse("'a#b'  # comment"), "a#b")
        self.assertEqual(parse("abc#def"), "abc#def")

    def test_generic_key_satisfies_native_check(self):
        # Generic-only operator key: the probe runs with the BOUND value
        # (what the container receives), not a missing specific name.
        # Explicit "" for the specific name proves the generic path.
        self._openai_cfg()
        seen: dict = {}

        def spy(provider, endpoint, api_key, timeout_s=10):
            seen["key"] = api_key
            return True, "ok (mock)"

        with mock.patch.dict(os.environ, {"ME_RUNTIME_MODEL_API_KEY": "gen-key-1",
                                           "OPENAI_API_KEY": ""}), \
              mock.patch.object(me_supervisor, "probe_remote_model",
                                side_effect=spy):
            results, _ = me_supervisor.run_checks(
                self.data_dir, {"profile": "production",
                                "require_service": False, "opencode_bin": ""})
        self.assertEqual(seen.get("key"), "gen-key-1")
        by_id = {r.id: r for r in results}
        self.assertEqual(by_id["model_profile"].status, "PASS")

    def test_specific_key_wins_over_generic(self):
        self._openai_cfg()
        seen: dict = {}

        def spy(provider, endpoint, api_key, timeout_s=10):
            seen["key"] = api_key
            return True, "ok (mock)"

        with mock.patch.dict(os.environ, {"ME_RUNTIME_MODEL_API_KEY": "gen-key-1",
                                           "OPENAI_API_KEY": "spec-key-2"}), \
             mock.patch.object(me_supervisor, "probe_remote_model",
                               side_effect=spy):
            results, _ = me_supervisor.run_checks(
                self.data_dir, {"profile": "production",
                                "require_service": False, "opencode_bin": ""})
        self.assertEqual(seen.get("key"), "spec-key-2")
        by_id = {r.id: r for r in results}
        self.assertEqual(by_id["model_profile"].status, "PASS")

    def test_missing_both_keys_is_honest_gate(self):
        self._openai_cfg()
        for var in ("OPENAI_API_KEY", "ME_RUNTIME_MODEL_API_KEY"):
            os.environ.pop(var, None)
        with mock.patch.dict(os.environ, {}, clear=False):
            os.environ.pop("OPENAI_API_KEY", None)
            os.environ.pop("ME_RUNTIME_MODEL_API_KEY", None)
            results, _ = me_supervisor.run_checks(
                self.data_dir, {"profile": "production",
                                "require_service": False, "opencode_bin": ""})
        by_id = {r.id: r for r in results}
        self.assertEqual(by_id["model_profile"].status, "NEEDS_INPUT")
        self.assertIn("ME_RUNTIME_MODEL_API_KEY",
                      by_id["model_profile"].needs_reason)


if __name__ == "__main__":
    unittest.main()
