#!/usr/bin/env python3
"""Tests for S7 cloud-coordination activation (setup-infra ownership).

Covers: prepare (authoritative install + local public URL, no network),
activate (bounded STDIN ticket-only POST, exact response validation, atomic
0600 persist, no secret logging), wrong-install short-circuit before fetch,
file gates (mode/symlink/schema), no-JWT auth, redirects/timeouts/unknown
outcome, recovery rotation, service.env + start wiring, pairing-v1
invitations, and a real backend + real home heartbeat round-trip.

All network is synthetic loopback only. Slow integration tests requiring the
sibling backend/home checkouts + Node are skipped with a
transient-dependency note when unavailable (H1/B7 may still be modifying
them); rerun when stable. Nothing here relaxes or skips real failures.

Run: python3 -m unittest discover -s scripts -p 'test_me_coordinator.py' -v
"""

import contextlib
import http.server
import io
import json
import os
import shutil
import socket
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

import me_coordinator
import me_lifecycle
import me_setup

FAKE_NODE = ("/fake/node", "/fake/node (v24.18.0) satisfies >=24.18.0 <25")
FIXTURE_ACCOUNT_TOKEN = "test-token-s7-owner-0000000000000001"
FIXTURE_ACCOUNT_ID = "acct_s7owner"


def setUpModule():
    import collections
    import shutil as _shutil
    usage = collections.namedtuple("usage", ["total", "used", "free"])
    patcher = mock.patch.object(
        _shutil, "disk_usage",
        return_value=usage(total=100 * 1024**3, used=10 * 1024**3, free=90 * 1024**3))
    patcher.start()
    setUpModule._patcher = patcher
    os.environ["ME_HOME_SKIP_BRIDGE_PROBE"] = "1"


def tearDownModule():
    setUpModule._patcher.stop()


def free_port() -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


def free_port_pair() -> tuple[int, int]:
    return free_port(), free_port()


def make_data_dir(testcase) -> Path:
    tmp = Path(tempfile.mkdtemp(prefix="me-coord-test-"))
    testcase.addCleanup(lambda: shutil.rmtree(tmp, ignore_errors=True))
    return tmp / "home"


def run_setup(testcase, data_dir: Path, port: int, **kwargs) -> dict:
    with mock.patch.object(me_setup, "find_node", return_value=FAKE_NODE):
        rc = me_setup.do_setup(data_dir, "127.0.0.1", port, **kwargs)
    testcase.assertEqual(rc, 0)
    return me_setup.load_config(data_dir)


def ensure_test_db(data_dir: Path, cfg: dict) -> str:
    """Simulate 'home started once': create the authoritative SQLite DB.

    Production code mints installation_id on first home open; unit fixtures
    must not rely on the pre-start config reservation. This helper creates a
    real SQLite file at the configured db_path carrying the config's id, so
    prepare/activate exercise the DB-required path without inventing identity.
    """
    import sqlite3 as _sqlite3
    db_path = Path(cfg["service"]["db_path"])
    db_path.parent.mkdir(parents=True, exist_ok=True)
    installation_id = str(cfg.get("installation_id", "") or "")
    if not installation_id:
        raise AssertionError("test setup produced no installation_id")
    with _sqlite3.connect(str(db_path), timeout=5) as conn:
        conn.execute("CREATE TABLE IF NOT EXISTS meta (key TEXT PRIMARY KEY, value TEXT)")
        conn.execute("INSERT OR REPLACE INTO meta VALUES ('installation_id', ?)",
                     (installation_id,))
        conn.commit()
    return installation_id


@contextlib.contextmanager
def patched_stdin(text: str):
    with mock.patch.object(sys, "stdin", io.StringIO(text)):
        yield


@contextlib.contextmanager
def captured():
    out, err = io.StringIO(), io.StringIO()
    with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
        yield out, err


def activate_via_cli(ticket: dict, data_dir: Path, *extra: str) -> tuple[int, str, str]:
    text = json.dumps(ticket)
    with patched_stdin(text), captured() as (out, err):
        rc = me_lifecycle.main(
            ["coordinator", "activate", "--data-dir", str(data_dir),
             "--allow-http-loopback", *extra])
    return rc, out.getvalue(), err.getvalue()


# --- B7 stub backend (synthetic loopback only) --------------------------------

class StubBackend:
    """Minimal B7-shaped activation stub. Records hits + request headers."""

    def __init__(self, testcase, *, installation_id: str,
                 mode: str = "ok", delay_s: float = 0.0):
        self.testcase = testcase
        self.installation_id = installation_id
        self.mode = mode
        self.delay_s = delay_s
        self.hits: list[dict] = []
        self.tickets: dict[str, dict] = {}
        self.counter = 0
        self.server = None
        self.thread = None

    def mint(self, installation_id: str, *, existing_home_id=None) -> dict:
        self.counter += 1
        tid = f"act_stub_{self.counter:04d}"
        secret = f"stub-secret-{self.counter:04d}-{'x' * 40}"
        home_id = existing_home_id or f"home_stub{self.counter:04d}abcd"
        self.tickets[tid] = {"secret": secret,
                             "installationId": installation_id,
                             "mode": "recovery" if existing_home_id else "new",
                             "homeId": home_id, "consumed": False}
        return {"ticketId": tid, "activationSecret": secret,
                "installationId": installation_id,
                "mode": self.tickets[tid]["mode"],
                "homeId": home_id if existing_home_id else None}

    def ticket_json(self, tid: str, backend_url: str) -> dict:
        t = self.tickets[tid]
        doc = {"backend_url": backend_url, "ticketId": tid,
               "activationSecret": t["secret"],
               "installationId": t["installationId"], "mode": t["mode"]}
        if t["mode"] == "recovery":
            doc["homeId"] = t["homeId"]
        return doc

    def start(self) -> str:
        stub = self

        class Handler(http.server.BaseHTTPRequestHandler):
            def log_message(self, *args):
                pass

            def _read_json(self):
                try:
                    length = int(self.headers.get("Content-Length", "0"))
                except ValueError:
                    length = 0
                raw = self.rfile.read(min(length, 64 * 1024)) if length else b""
                try:
                    return json.loads(raw.decode("utf-8")) if raw else {}
                except (json.JSONDecodeError, UnicodeDecodeError):
                    return {}

            def do_POST(self):
                if self.path == "/v1/homes/activation-tickets":
                    # Fixture account auth ONLY to mint (mirrors the owner phone).
                    auth = self.headers.get("Authorization", "")
                    if auth != f"Bearer {FIXTURE_ACCOUNT_TOKEN}":
                        body = json.dumps({"error": "Account authorization required."}).encode()
                        self.send_response(401)
                        self.send_header("Content-Type", "application/json")
                        self.send_header("Content-Length", str(len(body)))
                        self.end_headers()
                        self.wfile.write(body)
                        return
                    req = self._read_json()
                    ticket = stub.mint(req.get("installationId", ""),
                                       existing_home_id=req.get("existingHomeId"))
                    body = json.dumps({**ticket,
                                       "expiresAt": "2099-01-01T00:00:00.000Z"}).encode()
                    self.send_response(201)
                    self.send_header("Content-Type", "application/json")
                    self.send_header("Content-Length", str(len(body)))
                    self.end_headers()
                    self.wfile.write(body)
                    return
                if self.path != "/v1/homes/activate":
                    self.send_error(404)
                    return
                req = self._read_json()
                stub.hits.append({
                    "authorization": self.headers.get("Authorization"),
                    "content_type": self.headers.get("Content-Type"),
                    "body": req,
                })
                if stub.delay_s:
                    time.sleep(stub.delay_s)
                if stub.mode == "drop":
                    try:
                        self.connection.shutdown(socket.SHUT_RDWR)
                    except OSError:
                        pass
                    try:
                        self.connection.close()
                    except OSError:
                        pass
                    return
                if stub.mode == "redirect":
                    self.send_response(302)
                    self.send_header("Location", "https://backend.example.test/v1/homes/activate")
                    self.send_header("Content-Length", "0")
                    self.end_headers()
                    return
                tid = req.get("ticketId", "")
                secret = req.get("activationSecret", req.get("ticketSecret", ""))
                ticket = stub.tickets.get(tid)
                if stub.mode == "bad_shape" or not ticket or ticket["secret"] != secret:
                    if stub.mode == "bad_shape" and ticket and ticket["secret"] == secret:
                        pass  # fall through to malformed 201 below
                    else:
                        body = json.dumps({"error": "Invalid activation ticket."}).encode()
                        self.send_response(403)
                        self.send_header("Content-Type", "application/json")
                        self.send_header("Content-Length", str(len(body)))
                        self.end_headers()
                        self.wfile.write(body)
                        return
                if ticket["consumed"]:
                    body = json.dumps({"error": "expired or used"}).encode()
                    self.send_response(410)
                    self.send_header("Content-Type", "application/json")
                    self.send_header("Content-Length", str(len(body)))
                    self.end_headers()
                    self.wfile.write(body)
                    return
                if req.get("installationId") != ticket["installationId"]:
                    body = json.dumps({"error": "bound to a different installation."}).encode()
                    self.send_response(403)
                    self.send_header("Content-Type", "application/json")
                    self.send_header("Content-Length", str(len(body)))
                    self.end_headers()
                    self.wfile.write(body)
                    return
                if stub.mode == "error500":
                    body = json.dumps({"error": "Internal error."}).encode()
                    self.send_response(500)
                    self.send_header("Content-Type", "application/json")
                    self.send_header("Content-Length", str(len(body)))
                    self.end_headers()
                    self.wfile.write(body)
                    return
                ticket["consumed"] = True
                stub.counter += 1
                token = f"me_home_stubtoken{stub.counter:04d}{'y' * 40}"
                if stub.mode == "bad_shape":
                    reply = {"homeId": ticket["homeId"], "installationId": "WRONG",
                             "homeToken": "bad", "endpointHint": req.get("endpointHint"),
                             "protocolVersion": "bogus", "mode": "new"}
                else:
                    reply = {"homeId": ticket["homeId"],
                             "installationId": ticket["installationId"],
                             "homeToken": token,
                             "endpointHint": req.get("endpointHint"),
                             "protocolVersion": "home-api-v1",
                             "mode": ticket["mode"]}
                body = json.dumps(reply).encode()
                self.send_response(201)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)

        self.server = http.server.ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        self.server.daemon_threads = True
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)
        self.thread.start()
        port = self.server.server_address[1]
        self.testcase.addCleanup(self.close)
        return f"http://127.0.0.1:{port}"

    def close(self):
        try:
            if self.server is not None:
                self.server.shutdown()
                self.server.server_close()
        except OSError:
            pass
        self.server = None


class PrepareTests(unittest.TestCase):
    def setUp(self):
        self.node_patch = mock.patch.object(me_setup, "find_node", return_value=FAKE_NODE)
        self.node_patch.start()
        self.addCleanup(self.node_patch.stop)
        self.data_dir = make_data_dir(self)
        self.port = free_port()
        # Hermetic fixture: test_prepare_uses_tunnel_hostname_when_no_flag
        # configures a tunnel, which fails closed unless the config records
        # the published H1 contract. Pin the probe to the published contract
        # exactly as a sibling layout records it (see test_me_lifecycle.py).
        with mock.patch.object(me_setup, "contract_status",
                               return_value=me_setup.CONTRACT_VERSION):
            self.cfg = run_setup(self, self.data_dir, self.port)
        ensure_test_db(self.data_dir, self.cfg)

    def test_prepare_records_install_and_public_url_no_network(self):
        url = f"http://127.0.0.1:{self.port}"
        with captured():
            rc = me_lifecycle.main(["coordinator", "prepare", "--data-dir",
                                    str(self.data_dir), "--public-url", url,
                                    "--allow-http-loopback"])
        self.assertEqual(rc, 0)
        cfg = me_setup.load_config(self.data_dir)
        self.assertEqual(cfg["coordinator"]["public_home_url"], url)
        self.assertEqual(cfg["installation_id"], self.cfg["installation_id"])
        self.assertTrue(str(cfg["coordinator"]["credentials_file"]).endswith(
            "secrets/backend-home-token.json"))
        # prepare alone does not enable: still zero network by default.
        self.assertFalse(cfg["coordinator"]["enabled"])
        with captured() as (out, _):
            self.assertEqual(me_lifecycle.main(
                ["coordinator", "status", "--data-dir", str(self.data_dir)]), 0)
        self.assertIn("status: disabled", out.getvalue())
        self.assertEqual(me_coordinator.do_check(self.data_dir), 0)

    def test_prepare_rejects_non_loopback_http_without_optin(self):
        with captured():
            rc = me_lifecycle.main(["coordinator", "prepare", "--data-dir",
                                    str(self.data_dir), "--public-url",
                                    "http://example.com/"])
        self.assertEqual(rc, 2)

    def test_prepare_uses_tunnel_hostname_when_no_flag(self):
        with captured():
            rc = me_lifecycle.main(["tunnel", "configure", "--data-dir",
                                    str(self.data_dir), "--hostname",
                                    "home.example.test", "--credential-file",
                                    str(self._cred_file())])
        self.assertEqual(rc, 0)
        with captured():
            rc = me_lifecycle.main(["coordinator", "prepare", "--data-dir",
                                    str(self.data_dir)])
        self.assertEqual(rc, 0)
        cfg = me_setup.load_config(self.data_dir)
        self.assertEqual(cfg["coordinator"]["public_home_url"],
                         "https://home.example.test")

    def _cred_file(self) -> Path:
        cred = self.data_dir / "tunnel-cred.json"
        cred.parent.mkdir(parents=True, exist_ok=True)
        cred.write_text(json.dumps({"TunnelID": "tunnel-uuid-stable-1"}),
                        encoding="utf-8")
        os.chmod(cred, 0o600)
        return cred


class ActivateStubTests(unittest.TestCase):
    def setUp(self):
        self.node_patch = mock.patch.object(me_setup, "find_node", return_value=FAKE_NODE)
        self.node_patch.start()
        self.addCleanup(self.node_patch.stop)
        self.data_dir = make_data_dir(self)
        self.port = free_port()
        self.cfg = run_setup(self, self.data_dir, self.port)
        ensure_test_db(self.data_dir, self.cfg)
        self.stub = StubBackend(self, installation_id=self.cfg["installation_id"])
        self.backend_url = self.stub.start()
        self.public_url = f"http://127.0.0.1:{self.port}"
        with captured():
            rc = me_lifecycle.main(["coordinator", "prepare", "--data-dir",
                                    str(self.data_dir), "--public-url",
                                    self.public_url, "--allow-http-loopback"])
        self.assertEqual(rc, 0)

    def _activate(self, ticket, *extra):
        return activate_via_cli(ticket, self.data_dir, *extra)

    def test_activate_success_exact_schema_redacted(self):
        minted = self.stub.mint(self.cfg["installation_id"])
        ticket = self.stub.ticket_json(minted["ticketId"], self.backend_url)
        secret = ticket["activationSecret"]
        rc, out, err = self._activate(ticket)
        self.assertEqual(rc, 0, msg=err)
        # One request, ticket-only: NO Authorization header ever.
        self.assertEqual(len(self.stub.hits), 1)
        self.assertIsNone(self.stub.hits[0]["authorization"])
        self.assertEqual(self.stub.hits[0]["body"]["protocolVersion"], "home-api-v1")
        self.assertEqual(self.stub.hits[0]["body"]["endpointHint"], self.public_url)
        # Exact H8 file schema: 7 keys incl protocol_version home-api-v1.
        cred_path = Path(me_setup.load_config(self.data_dir)["coordinator"]["credentials_file"])
        self.assertTrue(str(cred_path).endswith("secrets/backend-home-token.json"))
        self.assertEqual(stat.S_IMODE(cred_path.stat().st_mode), 0o600)
        self.assertEqual(stat.S_IMODE(cred_path.parent.stat().st_mode), 0o700)
        self.assertFalse(os.path.islink(cred_path))
        doc = json.loads(cred_path.read_text(encoding="utf-8"))
        self.assertEqual(set(doc.keys()), {"protocol", "backend_url", "home_id",
                                           "installation_id", "home_token",
                                           "endpoint_hint", "protocol_version"})
        self.assertEqual(doc["protocol"], "home-coordinator-v1")
        self.assertEqual(doc["protocol_version"], "home-api-v1")
        self.assertEqual(doc["backend_url"], self.backend_url)
        self.assertEqual(doc["installation_id"], self.cfg["installation_id"])
        self.assertTrue(doc["home_token"].startswith("me_home_"))
        self.assertEqual(doc["endpoint_hint"], self.public_url)
        # Redaction: secret/token never in output; operator reminded to reload.
        self.assertNotIn(secret, out)
        self.assertNotIn(secret, err)
        self.assertNotIn(doc["home_token"], out)
        self.assertNotIn(doc["home_token"], err)
        self.assertIn("service reload required", out + err)
        # Config reference updated (nonsecret) + service.env wired.
        cfg = me_setup.load_config(self.data_dir)
        self.assertTrue(cfg["coordinator"]["enabled"])
        self.assertEqual(cfg["coordinator"]["backend_url"], self.backend_url)
        env_text = (self.data_dir / "config" / "service.env").read_text(encoding="utf-8")
        self.assertIn("HOME_COORDINATOR_CREDENTIALS_FILE=", env_text)
        self.assertIn("HOME_COORDINATOR_ALLOW_HTTP_LOOPBACK=1", env_text)
        self.assertNotIn(secret, env_text)
        self.assertNotIn(doc["home_token"], env_text)
        # No secret VALUE is ever persisted; the shell-only comment documents
        # the operator env var without assigning it.
        self.assertNotIn("HOME_EXPO_ACCESS_TOKEN=", env_text)
        # check passes against the stored file.
        self.assertEqual(me_coordinator.do_check(self.data_dir), 0)

    def test_wrong_installation_never_fetches_not_consumed(self):
        minted = self.stub.mint("some-other-installation")
        ticket = self.stub.ticket_json(minted["ticketId"], self.backend_url)
        rc, _, err = self._activate(ticket)
        self.assertEqual(rc, 1)
        self.assertEqual(len(self.stub.hits), 0)
        self.assertFalse(self.stub.tickets[minted["ticketId"]]["consumed"])
        self.assertIn("wrong_home", err)
        self.assertFalse((self.data_dir / "secrets" / "backend-home-token.json").exists())

    def test_replay_reports_410_no_resurrection(self):
        minted = self.stub.mint(self.cfg["installation_id"])
        ticket = self.stub.ticket_json(minted["ticketId"], self.backend_url)
        rc, _, _ = self._activate(ticket)
        self.assertEqual(rc, 0)
        first = json.loads((self.data_dir / "secrets" / "backend-home-token.json").read_text(
            encoding="utf-8"))["home_token"]
        rc, _, err = self._activate(ticket)
        self.assertEqual(rc, 1)
        self.assertIn("410", err)
        # Old credential preserved; replay never resurrects/overwrites.
        second = json.loads((self.data_dir / "secrets" / "backend-home-token.json").read_text(
            encoding="utf-8"))["home_token"]
        self.assertEqual(first, second)

    def test_bad_reply_shape_rejected(self):
        bad = StubBackend(self, installation_id=self.cfg["installation_id"],
                          mode="bad_shape")
        backend_url = bad.start()
        minted = bad.mint(self.cfg["installation_id"])
        ticket = bad.ticket_json(minted["ticketId"], backend_url)
        rc, _, err = activate_via_cli(ticket, self.data_dir)
        self.assertEqual(rc, 1)
        self.assertFalse((self.data_dir / "secrets" / "backend-home-token.json").exists())
        self.assertIn("installationId", err + " reply ")

    def test_redirect_is_failure(self):
        redir = StubBackend(self, installation_id=self.cfg["installation_id"],
                            mode="redirect")
        backend_url = redir.start()
        minted = redir.mint(self.cfg["installation_id"])
        ticket = redir.ticket_json(minted["ticketId"], backend_url)
        rc, _, err = activate_via_cli(ticket, self.data_dir)
        self.assertEqual(rc, 1)
        self.assertIn("redirect", err.lower())
        self.assertFalse((self.data_dir / "secrets" / "backend-home-token.json").exists())

    def test_timeout_unknown_outcome_no_replay(self):
        slow = StubBackend(self, installation_id=self.cfg["installation_id"],
                           mode="ok", delay_s=3.0)
        backend_url = slow.start()
        minted = slow.mint(self.cfg["installation_id"])
        ticket = slow.ticket_json(minted["ticketId"], backend_url)
        rc, _, err = activate_via_cli(ticket, self.data_dir, "--timeout-ms", "1000")
        self.assertEqual(rc, 1)
        self.assertIn("UNKNOWN", err)
        self.assertIn("FRESH", err)
        self.assertFalse((self.data_dir / "secrets" / "backend-home-token.json").exists())

    def test_drop_unknown_outcome_recovery_rotates(self):
        drop = StubBackend(self, installation_id=self.cfg["installation_id"],
                           mode="drop")
        backend_url = drop.start()
        minted = drop.mint(self.cfg["installation_id"])
        ticket = drop.ticket_json(minted["ticketId"], backend_url)
        rc, _, err = activate_via_cli(ticket, self.data_dir, "--timeout-ms", "2000")
        self.assertEqual(rc, 1)
        self.assertIn("UNKNOWN", err)
        hydrated = drop  # same stub now heals: flip to ok for recovery
        hydrated.mode = "ok"
        # Fresh owner recovery ticket (existingHomeId), minted with the
        # fixture account credential (dev-only mint path).
        import urllib.request
        mint_body = json.dumps({"installationId": self.cfg["installation_id"],
                                "existingHomeId": hydrated.tickets[minted["ticketId"]]["homeId"]}).encode()
        req = urllib.request.Request(
            backend_url + "/v1/homes/activation-tickets", data=mint_body,
            method="POST", headers={"Content-Type": "application/json",
                                    "Authorization": f"Bearer {FIXTURE_ACCOUNT_TOKEN}"})
        with urllib.request.urlopen(req, timeout=5) as resp:
            recovery = json.loads(resp.read().decode("utf-8"))
        recovery_ticket = {**recovery, "backend_url": backend_url}
        rc, _, err2 = activate_via_cli(recovery_ticket, self.data_dir,
                                       "--timeout-ms", "5000")
        self.assertEqual(rc, 0, msg=err2)
        doc = json.loads((self.data_dir / "secrets" / "backend-home-token.json").read_text(
            encoding="utf-8"))
        self.assertEqual(doc["installation_id"], self.cfg["installation_id"])
        self.assertTrue(doc["home_token"].startswith("me_home_"))

    def test_secret_symlink_and_mode_gates(self):
        cred_path = self.data_dir / "secrets" / "backend-home-token.json"
        cred_path.parent.mkdir(parents=True, exist_ok=True)
        real = cred_path.parent / "real.json"
        real.write_text(json.dumps({"protocol": "home-coordinator-v1",
                                    "backend_url": self.backend_url,
                                    "home_id": "home_abc123",
                                    "installation_id": self.cfg["installation_id"],
                                    "home_token": "me_home_" + "z" * 40,
                                    "endpoint_hint": self.public_url,
                                    "protocol_version": "home-api-v1"}),
                        encoding="utf-8")
        os.chmod(real, 0o600)
        try:
            os.symlink(real, cred_path)
        except OSError:
            self.skipTest("symlinks unavailable on this platform")
        _, code = me_coordinator.load_status_record(
            cred_path, expected_installation_id=self.cfg["installation_id"],
            allow_http_loopback=True)
        self.assertEqual(code, "invalid_credentials_file")
        os.unlink(cred_path)
        cred_path.write_text(real.read_text(encoding="utf-8"), encoding="utf-8")
        os.chmod(cred_path, 0o644)
        _, code = me_coordinator.load_status_record(
            cred_path, expected_installation_id=self.cfg["installation_id"],
            allow_http_loopback=True)
        self.assertEqual(code, "invalid_credentials_permissions")

    def test_env_wiring_and_push_secret_never_persisted(self):
        cfg = me_setup.load_config(self.data_dir)
        env = me_lifecycle.build_home_env(cfg)
        # prepare alone: disabled => no coordinator reference wired.
        self.assertNotIn("HOME_COORDINATOR_CREDENTIALS_FILE", env)
        minted = self.stub.mint(self.cfg["installation_id"])
        ticket = self.stub.ticket_json(minted["ticketId"], self.backend_url)
        rc, _, err = self._activate(ticket)
        self.assertEqual(rc, 0, msg=err)
        cfg = me_setup.load_config(self.data_dir)
        with mock.patch.dict(os.environ, {"HOME_EXPO_ACCESS_TOKEN": "token-secret-value",
                                          "ME_RUNTIME_MODEL_API_KEY": "model-secret-value"}):
            env = me_lifecycle.build_home_env(cfg)
            self.assertIn("HOME_COORDINATOR_CREDENTIALS_FILE", env)
            self.assertEqual(env["HOME_EXPO_ACCESS_TOKEN"], "token-secret-value")
            _, unit_env, _ = me_lifecycle.service_command(
                "/fake/node", Path("/fake/infra-server/src/cli.mjs"), cfg)
            self.assertIn("HOME_COORDINATOR_CREDENTIALS_FILE", unit_env)
            self.assertNotIn("HOME_EXPO_ACCESS_TOKEN", unit_env)
            self.assertNotIn("ME_RUNTIME_MODEL_API_KEY", unit_env)
        env_text = (self.data_dir / "config" / "service.env").read_text(encoding="utf-8")
        self.assertNotIn("token-secret-value", env_text)
        self.assertNotIn("model-secret-value", env_text)


class NotificationConfigTests(unittest.TestCase):
    def setUp(self):
        self.node_patch = mock.patch.object(me_setup, "find_node", return_value=FAKE_NODE)
        self.node_patch.start()
        self.addCleanup(self.node_patch.stop)
        self.data_dir = make_data_dir(self)

    def test_notifications_optin_wiring_exact_contract(self):
        port = free_port()
        with mock.patch.object(me_setup, "find_node", return_value=FAKE_NODE):
            rc = me_setup.do_setup(self.data_dir, "127.0.0.1", port,
                                   notifications_enabled=True,
                                   expo_project_id="expo-proj-123")
        self.assertEqual(rc, 0)
        cfg = me_setup.load_config(self.data_dir)
        self.assertTrue(cfg["notifications"]["enabled"])
        self.assertEqual(cfg["notifications"]["expo_project_id"], "expo-proj-123")
        env = me_lifecycle.build_home_env(cfg)
        self.assertEqual(env.get("HOME_NOTIFICATIONS_ENABLED"), "1")
        self.assertEqual(env.get("HOME_EXPO_PROJECT_ID"), "expo-proj-123")
        env_text = (self.data_dir / "config" / "service.env").read_text(encoding="utf-8")
        self.assertIn("HOME_NOTIFICATIONS_ENABLED=1", env_text)
        self.assertIn("HOME_EXPO_PROJECT_ID=expo-proj-123", env_text)
        self.assertNotIn("HOME_EXPO_ACCESS_TOKEN=", env_text)
        with mock.patch.dict(os.environ, {"HOME_EXPO_ACCESS_TOKEN": "sekrit"}):
            env2 = me_lifecycle.build_home_env(cfg)
            self.assertEqual(env2["HOME_EXPO_ACCESS_TOKEN"], "sekrit")

    def test_notifications_default_disabled_zero_network(self):
        port = free_port()
        run_setup(self, self.data_dir, port)
        cfg = me_setup.load_config(self.data_dir)
        self.assertFalse(cfg["notifications"]["enabled"])
        env = me_lifecycle.build_home_env(cfg)
        self.assertNotIn("HOME_NOTIFICATIONS_ENABLED", env)
        self.assertNotIn("HOME_EXPO_PROJECT_ID", env)


def require_node(testcase):
    node, _ = me_setup.find_node(os.environ.get("ME_HOME_NODE") or None)
    if not node:
        testcase.skipTest("transient dependency: no compatible Node (>=24.18.0 <25); rerun when stable")
    return node


_CHECKOUT_DIRS = {"INFRA": "infra-server", "BACKEND": "backend-server"}


def require_checkout(testcase, name, markers):
    checkout = me_setup.resolve_checkout(
        os.environ.get(f"ME_HOME_{name}_CHECKOUT") or None,
        f"ME_HOME_{name}_CHECKOUT", _CHECKOUT_DIRS.get(name, name), markers, name)
    if checkout is None:
        testcase.skipTest(f"transient dependency: {name} checkout unavailable; rerun when stable")
    return checkout


class PairingV1Tests(unittest.TestCase):
    def setUp(self):
        # No fake-node patch here: these tests drive the REAL home CLI, so an
        # explicit real node must flow through resolve_node untouched.
        self.data_dir = make_data_dir(self)
        self.port = free_port()
        self.cfg = run_setup(self, self.data_dir, self.port)

    def test_raw_format_backward_compatible(self):
        node, checkout = None, None
        try:
            node = require_node(self)
            checkout = require_checkout(self, "INFRA", ("src/cli.mjs", "src/server.mjs"))
        except unittest.SkipTest:
            raise
        with captured() as (out, _):
            rc = me_lifecycle.do_bootstrap(self.data_dir, user="alice", node_explicit=node,
                                           infra_explicit=str(checkout))
        self.assertEqual(rc, 0)
        inv = json.loads(out.getvalue())
        self.assertIn("invitation_secret", inv)
        self.assertIn("invitation_id", inv)

    def test_pairing_v1_trusted_local_url(self):
        try:
            node = require_node(self)
            checkout = require_checkout(self, "INFRA", ("src/cli.mjs", "src/server.mjs"))
        except unittest.SkipTest:
            raise
        # Operator sequence: first boot (bootstrap mints DB id), then prepare.
        # Prepare before any DB must fail closed (no reservation binding).
        with captured():
            rc = me_lifecycle.main(["coordinator", "prepare", "--data-dir",
                                    str(self.data_dir), "--public-url",
                                    "https://home.example.test"])
        self.assertNotEqual(rc, 0)
        with captured():
            rc = me_lifecycle.main(["bootstrap", "--data-dir", str(self.data_dir),
                                    "--node", node, "--infra-checkout", str(checkout),
                                    "--user", "alice"])
        self.assertEqual(rc, 0)
        with captured():
            rc = me_lifecycle.main(["coordinator", "prepare", "--data-dir",
                                    str(self.data_dir), "--public-url",
                                    "https://home.example.test"])
        self.assertEqual(rc, 0)
        with captured() as (out, _):
            rc = me_lifecycle.main(["bootstrap", "--data-dir", str(self.data_dir),
                                    "--node", node, "--infra-checkout", str(checkout),
                                    "--user", "alice", "--format", "pairing-v1"])
        self.assertEqual(rc, 0)
        paired = json.loads(out.getvalue())
        self.assertEqual(paired["protocol"], "home-pairing-v1")
        self.assertEqual(paired["home_url"], "https://home.example.test")
        # Authoritative identity: the home database mints installation_id on
        # first open (bootstrap here); setup adopts it on rerun. The pairing
        # doc carries the actual local bootstrap id, never an invention.
        db_id = me_setup.read_db_installation_id(
            Path(self.cfg["service"]["db_path"]))
        self.assertTrue(db_id)
        self.assertEqual(paired["installation_id"], db_id)
        self.assertEqual(paired["user_id"], "alice")
        self.assertTrue(paired["invitation_id"])
        self.assertTrue(paired["invitation_secret"])
        rerun = run_setup(self, self.data_dir, self.port)
        self.assertEqual(rerun["installation_id"], db_id)

    def test_pairing_v1_rejects_missing_url(self):
        try:
            node = require_node(self)
            checkout = require_checkout(self, "INFRA", ("src/cli.mjs", "src/server.mjs"))
        except unittest.SkipTest:
            raise
        with captured():
            rc = me_lifecycle.main(["bootstrap", "--data-dir", str(self.data_dir),
                                    "--node", node, "--infra-checkout", str(checkout),
                                    "--user", "alice", "--format", "pairing-v1"])
        self.assertEqual(rc, 2)


class FreshSetupRequiresDbTests(unittest.TestCase):
    """Fresh setup reservation must NEVER bind a ticket: DB first, then prepare."""

    def setUp(self):
        self.node_patch = mock.patch.object(me_setup, "find_node", return_value=FAKE_NODE)
        self.node_patch.start()
        self.addCleanup(self.node_patch.stop)
        self.data_dir = make_data_dir(self)
        self.port = free_port()
        self.cfg = run_setup(self, self.data_dir, self.port)
        # NOTE: no ensure_test_db here: fresh setup has no DB yet.
        self.stub = StubBackend(self, installation_id=self.cfg["installation_id"])
        self.backend_url = self.stub.start()
        self.public_url = f"http://127.0.0.1:{self.port}"

    def test_prepare_fails_without_db(self):
        with captured() as (out, err):
            rc = me_lifecycle.main(["coordinator", "prepare", "--data-dir",
                                    str(self.data_dir), "--public-url",
                                    self.public_url, "--allow-http-loopback"])
        self.assertEqual(rc, 2)
        self.assertIn("no authoritative", (out.getvalue() + err.getvalue()).lower())

    def test_activate_fails_before_network_without_db_ticket_not_consumed(self):
        minted = self.stub.mint(self.cfg["installation_id"])
        ticket = self.stub.ticket_json(minted["ticketId"], self.backend_url)
        # Prepare also fails, so endpoint comes from explicit public-url via
        # prepare? No: activate resolves public URL from config/tunnel/env.
        # Seed the public URL via env so activate reaches the DB gate (not
        # the URL gate), proving the DB gate fires before any POST.
        with mock.patch.dict(os.environ, {"ME_HOME_PUBLIC_URL": self.public_url}):
            rc, out, err = activate_via_cli(ticket, self.data_dir)
        self.assertEqual(rc, 2)
        self.assertEqual(len(self.stub.hits), 0)
        self.assertFalse(self.stub.tickets[minted["ticketId"]]["consumed"])
        self.assertIn("no authoritative", (out + err).lower())

    def test_db_unreadable_fails_closed(self):
        db_path = Path(self.cfg["service"]["db_path"])
        db_path.parent.mkdir(parents=True, exist_ok=True)
        db_path.write_text("not-a-sqlite-db", encoding="utf-8")
        with captured() as (out, err):
            rc = me_lifecycle.main(["coordinator", "prepare", "--data-dir",
                                    str(self.data_dir), "--public-url",
                                    self.public_url, "--allow-http-loopback"])
        self.assertEqual(rc, 2)
        self.assertIn("no authoritative", (out.getvalue() + err.getvalue()).lower())

    def test_status_never_reports_reservation_verified(self):
        # Fresh reservation + no DB: status disabled, never verified.
        with captured() as (out, _):
            rc = me_lifecycle.main(["coordinator", "status", "--data-dir",
                                    str(self.data_dir)])
        self.assertEqual(rc, 0)
        self.assertIn("status: disabled", out.getvalue())
        self.assertIn("installation_verified: false", out.getvalue())


class TrickleDeadlineTests(unittest.TestCase):
    """Adversarial 1-byte trickles must hit the HARD 1s whole-request budget.

    Servers use raw sockets ( http.server would buffer ), send one byte per
    ~0.1s for >3s, and self-stop via daemon threads + stop events so no test
    cleanup hangs. Proves parent kill/reap bounds DNS/connect/headers/body
    including the header-trickle case the old per-socket timeout missed.
    """

    def setUp(self):
        self.node_patch = mock.patch.object(me_setup, "find_node", return_value=FAKE_NODE)
        self.node_patch.start()
        self.addCleanup(self.node_patch.stop)
        self.data_dir = make_data_dir(self)
        self.port = free_port()
        self.cfg = run_setup(self, self.data_dir, self.port)
        ensure_test_db(self.data_dir, self.cfg)
        self.public_url = f"http://127.0.0.1:{self.port}"
        with captured():
            rc = me_lifecycle.main(["coordinator", "prepare", "--data-dir",
                                    str(self.data_dir), "--public-url",
                                    self.public_url, "--allow-http-loopback"])
        self.assertEqual(rc, 0)
        self._servers: list = []
        self.addCleanup(self._close_all)

    def _close_all(self):
        for srv, stop_ev, thr in self._servers:
            try:
                stop_ev.set()
            except OSError:
                pass
            try:
                srv.close()
            except OSError:
                pass
        for _, _, thr in self._servers:
            thr.join(timeout=5)

    def _start_trickle(self, *, mode: str):
        """mode: 'body201' | 'body400' | 'headers'."""
        stop_ev = threading.Event()
        srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        srv.bind(("127.0.0.1", 0))
        srv.listen(5)
        srv.settimeout(0.5)
        port = srv.getsockname()[1]

        def _serve():
            deadline = time.time() + 8
            while not stop_ev.is_set() and time.time() < deadline:
                try:
                    conn, _ = srv.accept()
                except socket.timeout:
                    continue
                except OSError:
                    return
                try:
                    conn.settimeout(2)
                    # Read request headers (bounded).
                    buf = b""
                    while b"\r\n\r\n" not in buf and len(buf) < 16384:
                        try:
                            chunk = conn.recv(4096)
                        except socket.timeout:
                            break
                        if not chunk:
                            break
                        buf += chunk
                    if mode == "headers":
                        try:
                            conn.sendall(b"HTTP/1.1 201 Created\r\nContent-Type: application/json\r\n")
                            for i in range(35):
                                if stop_ev.is_set():
                                    break
                                conn.sendall(b"X-Trickle: %d\r\n" % i)
                                time.sleep(0.1)
                        except OSError:
                            pass
                    elif mode == "body400":
                        try:
                            conn.sendall(b"HTTP/1.1 400 Bad Request\r\nContent-Type: application/json\r\n"
                                        b"Content-Length: 5000\r\nConnection: close\r\n\r\n")
                            for _ in range(35):
                                if stop_ev.is_set():
                                    break
                                try:
                                    conn.sendall(b"x")
                                except OSError:
                                    break
                                time.sleep(0.1)
                        except OSError:
                            pass
                    else:  # body201
                        try:
                            conn.sendall(b"HTTP/1.1 201 Created\r\nContent-Type: application/json\r\n"
                                        b"Content-Length: 5000\r\nConnection: close\r\n\r\n")
                            for _ in range(35):
                                if stop_ev.is_set():
                                    break
                                try:
                                    conn.sendall(b"y")
                                except OSError:
                                    break
                                time.sleep(0.1)
                        except OSError:
                            pass
                finally:
                    try:
                        conn.shutdown(socket.SHUT_RDWR)
                    except OSError:
                        pass
                    try:
                        conn.close()
                    except OSError:
                        pass

        thr = threading.Thread(target=_serve, daemon=True)
        thr.start()
        self._servers.append((srv, stop_ev, thr))
        return f"http://127.0.0.1:{port}"

    def _mint_ticket(self, backend_url: str) -> dict:
        return {"backend_url": backend_url, "ticketId": "act_trickle_0001",
                "activationSecret": "stub-secret-trickle-xxxx",
                "installationId": self.cfg["installation_id"]}

    def _assert_bounded_unknown(self, rc: int, out: str, err: str, elapsed: float):
        self.assertEqual(rc, 1)
        combined = out + err
        self.assertIn("UNKNOWN", combined)
        self.assertIn("FRESH", combined)
        # 1s budget + child spawn/kill slack: hard bound well under 3.5s.
        self.assertLess(elapsed, 3.5, msg=f"deadline not hard-bounded: {elapsed:.2f}s")
        # No secret echo: generic codes only.
        self.assertNotIn("stub-secret-trickle", combined)

    def test_body_trickle_201_bounded(self):
        backend_url = self._start_trickle(mode="body201")
        ticket = self._mint_ticket(backend_url)
        t0 = time.monotonic()
        rc, out, err = activate_via_cli(ticket, self.data_dir, "--timeout-ms", "1000")
        elapsed = time.monotonic() - t0
        self._assert_bounded_unknown(rc, out, err, elapsed)

    def test_body_trickle_400_bounded_no_echo(self):
        backend_url = self._start_trickle(mode="body400")
        ticket = self._mint_ticket(backend_url)
        t0 = time.monotonic()
        rc, out, err = activate_via_cli(ticket, self.data_dir, "--timeout-ms", "1000")
        elapsed = time.monotonic() - t0
        self._assert_bounded_unknown(rc, out, err, elapsed)

    def test_header_trickle_bounded(self):
        backend_url = self._start_trickle(mode="headers")
        ticket = self._mint_ticket(backend_url)
        t0 = time.monotonic()
        rc, out, err = activate_via_cli(ticket, self.data_dir, "--timeout-ms", "1000")
        elapsed = time.monotonic() - t0
        self._assert_bounded_unknown(rc, out, err, elapsed)

    def test_no_orphan_helper_after_timeout(self):
        import subprocess as _sp
        backend_url = self._start_trickle(mode="body201")
        ticket = self._mint_ticket(backend_url)
        activate_via_cli(ticket, self.data_dir, "--timeout-ms", "1000")
        time.sleep(0.5)
        try:
            ps = _sp.run(["pgrep", "-f", "transport-helper"], capture_output=True,
                         text=True, timeout=5)
            self.assertEqual(ps.stdout.strip(), "",
                             msg=f"orphan transport helper: {ps.stdout.strip()}")
        except FileNotFoundError:
            pass


class RedactionAndCapTests(unittest.TestCase):
    """Backend bodies never echo: sentinel secrets stay out of stdout/stderr."""

    def setUp(self):
        self.node_patch = mock.patch.object(me_setup, "find_node", return_value=FAKE_NODE)
        self.node_patch.start()
        self.addCleanup(self.node_patch.stop)
        self.data_dir = make_data_dir(self)
        self.port = free_port()
        self.cfg = run_setup(self, self.data_dir, self.port)
        ensure_test_db(self.data_dir, self.cfg)
        self.public_url = f"http://127.0.0.1:{self.port}"
        with captured():
            rc = me_lifecycle.main(["coordinator", "prepare", "--data-dir",
                                    str(self.data_dir), "--public-url",
                                    self.public_url, "--allow-http-loopback"])
        self.assertEqual(rc, 0)

    def _serve_raw(self, status_line: bytes, body: bytes):
        stop_ev = threading.Event()
        srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        srv.bind(("127.0.0.1", 0))
        srv.listen(5)
        srv.settimeout(0.5)
        port = srv.getsockname()[1]

        def _serve():
            deadline = time.time() + 8
            while not stop_ev.is_set() and time.time() < deadline:
                try:
                    conn, _ = srv.accept()
                except socket.timeout:
                    continue
                except OSError:
                    return
                try:
                    conn.settimeout(2)
                    buf = b""
                    while b"\r\n\r\n" not in buf and len(buf) < 16384:
                        chunk = conn.recv(4096)
                        if not chunk:
                            break
                        buf += chunk
                    conn.sendall(status_line + b"Content-Type: application/json\r\n"
                                 + b"Content-Length: " + str(len(body)).encode() + b"\r\n"
                                 + b"Connection: close\r\n\r\n" + body)
                    # Serve exactly one request per test.
                    break
                except OSError:
                    pass
                finally:
                    try:
                        conn.close()
                    except OSError:
                        pass
            try:
                srv.close()
            except OSError:
                pass

        thr = threading.Thread(target=_serve, daemon=True)
        thr.start()
        self.addCleanup(stop_ev.set)
        self.addCleanup(lambda: thr.join(timeout=5))
        return f"http://127.0.0.1:{port}"

    def test_malformed_201_with_secret_sentinel_never_echoed(self):
        sentinel_secret = "SENTINEL_ACTIVATION_SECRET_ABC123xyz789"
        sentinel_token = "me_home_" + "S" * 40
        body = json.dumps({"homeId": "home_badshape1",
                           "installationId": "WRONG",
                           "homeToken": sentinel_token,
                           "endpointHint": self.public_url,
                           "protocolVersion": "bogus",
                           "mode": "new",
                           "leak": sentinel_secret}).encode()
        backend_url = self._serve_raw(b"HTTP/1.1 201 Created\r\n", body)
        ticket = {"backend_url": backend_url, "ticketId": "act_sentinel_1",
                  "activationSecret": sentinel_secret,
                  "installationId": self.cfg["installation_id"]}
        rc, out, err = activate_via_cli(ticket, self.data_dir)
        self.assertEqual(rc, 1)
        combined = out + err
        self.assertNotIn(sentinel_secret, combined)
        self.assertNotIn(sentinel_token, combined)
        self.assertFalse((self.data_dir / "secrets" / "backend-home-token.json").exists())

    def test_error_body_with_secret_sentinel_never_echoed(self):
        sentinel = "SENTINEL_ERROR_BODY_SECRET_ZZ99"
        body = json.dumps({"error": f"rejected {sentinel} details"}).encode()
        backend_url = self._serve_raw(b"HTTP/1.1 403 Forbidden\r\n", body)
        ticket = {"backend_url": backend_url, "ticketId": "act_sentinel_2",
                  "activationSecret": "stub-secret-redact-2",
                  "installationId": self.cfg["installation_id"]}
        rc, out, err = activate_via_cli(ticket, self.data_dir)
        self.assertEqual(rc, 1)
        self.assertIn("403", out + err)
        self.assertNotIn(sentinel, out + err)

    def test_oversize_201_and_400_uniformly_refused(self):
        big = b"z" * (me_coordinator.RESPONSE_MAX_BYTES + 1024)
        for status in (b"HTTP/1.1 201 Created\r\n", b"HTTP/1.1 400 Bad Request\r\n"):
            backend_url = self._serve_raw(status, big)
            ticket = {"backend_url": backend_url, "ticketId": "act_big_1",
                      "activationSecret": "stub-secret-big-1",
                      "installationId": self.cfg["installation_id"]}
            rc, out, err = activate_via_cli(ticket, self.data_dir)
            self.assertEqual(rc, 1, msg=f"status={status}")
            self.assertNotIn("zzzz", out + err)

    def test_proxy_env_ignored_direct_loopback_still_works(self):
        minted_stub = StubBackend(self, installation_id=self.cfg["installation_id"])
        backend_url = minted_stub.start()
        minted = minted_stub.mint(self.cfg["installation_id"])
        ticket = minted_stub.ticket_json(minted["ticketId"], backend_url)
        with mock.patch.dict(os.environ, {"HTTP_PROXY": "http://127.0.0.1:9",
                                          "HTTPS_PROXY": "http://127.0.0.1:9",
                                          "http_proxy": "http://127.0.0.1:9",
                                          "https_proxy": "http://127.0.0.1:9"}):
            rc, _, err = activate_via_cli(ticket, self.data_dir)
        self.assertEqual(rc, 0, msg=err)
        self.assertEqual(len(minted_stub.hits), 1)


BACKEND_HARNESS = r"""
import { createServer } from "node:http";
import { createBackend } from "__BACKEND_SRC__";
const dataDir = process.argv[2];
const token = process.argv[3];
const accountId = process.argv[4];
const { handler } = createBackend({
  host: "127.0.0.1", port: 0, dataDir,
  devAccounts: new Map([[token, accountId]]),
});
const server = createServer(handler);
server.listen(0, "127.0.0.1", () => {
  console.log(JSON.stringify({ base: `http://127.0.0.1:${server.address().port}` }));
});
"""


class RealBackendHomeTests(unittest.TestCase):
    """Actual S7 round-trip: real backend (B7) + setup redeem + real home H8
    heartbeat + backend discovery online. Synthetic loopback only; the dev
    fixture token mints the test ticket and nothing else."""

    def test_real_backend_redeem_and_home_heartbeat(self):
        try:
            node = require_node(self)
            backend_checkout = require_checkout(
                self, "BACKEND", ("src/server.mjs", "package.json"))
            infra_checkout = require_checkout(
                self, "INFRA", ("src/cli.mjs", "src/server.mjs"))
        except unittest.SkipTest:
            raise
        backend_src = backend_checkout / "src" / "server.mjs"
        if not (backend_checkout / "node_modules").is_dir():
            self.skipTest("transient dependency: backend node_modules not installed; rerun when stable")
        tmp = Path(tempfile.mkdtemp(prefix="me-s7-e2e-"))
        self.addCleanup(lambda: shutil.rmtree(tmp, ignore_errors=True))
        backend_data = tmp / "backend-data"
        backend_data.mkdir()
        harness = tmp / "backend-harness.mjs"
        harness.write_text(BACKEND_HARNESS.replace("__BACKEND_SRC__", str(backend_src)),
                           encoding="utf-8")
        proc = subprocess.Popen(
            [node, str(harness), str(backend_data), FIXTURE_ACCOUNT_TOKEN, FIXTURE_ACCOUNT_ID],
            stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)

        def _cleanup_backend():
            try:
                proc.kill()
                proc.wait(timeout=10)
            except OSError:
                pass
            for stream in (proc.stdout, proc.stderr):
                try:
                    if stream is not None:
                        stream.close()
                except OSError:
                    pass
        self.addCleanup(_cleanup_backend)
        try:
            line = proc.stdout.readline()
        except OSError:
            self.fail("backend harness produced no output")
        base = json.loads(line)["base"]
        self.assertTrue(base.startswith("http://127.0.0.1:"))

        data_dir = make_data_dir(self)
        home_port = free_port()
        with mock.patch.object(me_setup, "find_node", return_value=(node, "real")):
            rc = me_setup.do_setup(data_dir, "127.0.0.1", home_port)
        self.assertEqual(rc, 0)
        # First start lets the home database mint its authoritative
        # installation_id (config adopts it); activation must bind that id,
        # never the pre-start reservation. Stop before mutating config.
        with captured():
            self.assertEqual(me_lifecycle.main(
                ["start", "--data-dir", str(data_dir),
                 "--infra-checkout", str(infra_checkout), "--node", node]), 0)
        try:
            self.assertEqual(me_lifecycle.main(
                ["stop", "--data-dir", str(data_dir)]), 0)
        finally:
            pass
        cfg = me_setup.load_config(data_dir)
        installation_id = cfg["installation_id"]
        self.assertEqual(cfg.get("installation_source"), "home-database")
        public_url = f"http://127.0.0.1:{home_port}"
        with captured():
            self.assertEqual(me_lifecycle.main(
                ["coordinator", "prepare", "--data-dir", str(data_dir),
                 "--public-url", public_url, "--allow-http-loopback"]), 0)

        # Fixture credential ONLY to mint the test ticket (owner phone role).
        import urllib.request
        mint_body = json.dumps({"installationId": installation_id,
                                "displayName": "S7 e2e home"}).encode()
        req = urllib.request.Request(
            base + "/v1/homes/activation-tickets", data=mint_body, method="POST",
            headers={"Content-Type": "application/json",
                     "Authorization": f"Bearer {FIXTURE_ACCOUNT_TOKEN}"})
        with urllib.request.urlopen(req, timeout=10) as resp:
            self.assertEqual(resp.status, 201)
            ticket = json.loads(resp.read().decode("utf-8"))
        self.assertEqual(ticket["mode"], "new")
        self.assertNotIn("homeToken", ticket)
        activation = {**ticket, "backend_url": base}
        with patched_stdin(json.dumps(activation)), captured() as (out, err):
            rc = me_lifecycle.main(["coordinator", "activate", "--data-dir",
                                    str(data_dir), "--allow-http-loopback"])
        self.assertEqual(rc, 0, msg=err.getvalue())
        self.assertNotIn(ticket["activationSecret"], out.getvalue() + err.getvalue())
        doc = json.loads((data_dir / "secrets" / "backend-home-token.json").read_text(
            encoding="utf-8"))
        self.assertEqual(doc["installation_id"], installation_id)
        self.assertTrue(doc["home_token"].startswith("me_home_"))
        home_id = doc["home_id"]

        # Real home with the wired coordinator file: H8 heartbeats automatically.
        with captured():
            rc = me_lifecycle.main(["start", "--data-dir", str(data_dir),
                                    "--infra-checkout", str(infra_checkout),
                                    "--node", node])
        self.assertEqual(rc, 0)
        self.addCleanup(lambda: me_lifecycle.main(
            ["stop", "--data-dir", str(data_dir)]))
        deadline = time.time() + 45
        online = False
        last = None
        while time.time() < deadline:
            try:
                req = urllib.request.Request(
                    f"{base}/v1/homes/{home_id}/status",
                    headers={"Authorization": f"Bearer {FIXTURE_ACCOUNT_TOKEN}"})
                with urllib.request.urlopen(req, timeout=5) as resp:
                    last = json.loads(resp.read().decode("utf-8"))
                if last.get("online") is True:
                    online = True
                    break
            except OSError:
                pass
            time.sleep(1.5)
        self.assertTrue(online, msg=f"home never heartbeated online: {last}")
        # Coordinator status stays redacted over the local API as well.
        with captured() as (out2, _):
            self.assertEqual(me_coordinator.do_status(data_dir), 0)
        self.assertNotIn(doc["home_token"], out2.getvalue())


if __name__ == "__main__":
    unittest.main()
