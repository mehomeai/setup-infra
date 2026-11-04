#!/usr/bin/env python3
"""Tests for the rerunnable dev setup (scripts/me_setup.py).

Run: python3 -m unittest discover -s scripts -p 'test_*.py' -v
"""

import json
import os
import socket
import stat
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

sys.path.insert(0, str(Path(__file__).resolve().parent))

import me_setup

FAKE_NODE = ("/fake/node", "/fake/node (v24.18.0) satisfies >=24.18.0 <25")


def setUpModule():
    """Isolate unit tests from host disk pressure (the 1 GiB guard stays live)."""
    import collections
    import shutil as _shutil
    usage = collections.namedtuple("usage", ["total", "used", "free"])
    patcher = mock.patch.object(
        _shutil, "disk_usage",
        return_value=usage(total=100 * 1024**3, used=10 * 1024**3, free=90 * 1024**3))
    patcher.start()
    setUpModule._patcher = patcher
    # Skip the H2 bridge subprocess probe: unit tests must stay stdlib-only and
    # fast, especially under the coordinator's disk/network limits.
    os.environ["ME_HOME_SKIP_BRIDGE_PROBE"] = "1"


def tearDownModule():
    setUpModule._patcher.stop()


def free_port() -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


def run_setup(data_dir: Path, port: int | None = None, host: str = "127.0.0.1") -> int:
    port = port if port is not None else free_port()
    with mock.patch.object(me_setup, "find_node", return_value=FAKE_NODE):
        return me_setup.do_setup(data_dir, host, port)


def require_h1_contract(testcase) -> None:
    """Skip when the sibling H1 contract checkout is unavailable.

    Mirrors require_h1() in test_me_lifecycle.py: these cases assert on the
    published home-api-v1 contract that setup records, which only happens
    when ../infra-server is checked out next to this repo. A standalone
    checkout records the "pending-h1" marker instead, so skip with a
    transient-dependency note rather than failing on the marker.
    """
    sibling = me_setup.repo_root().parent / me_setup.CONTRACT_REL_PATH
    if not sibling.is_file():
        testcase.skipTest(
            "transient dependency: infra-server sibling checkout unavailable "
            "(../infra-server/contracts/home-api-v1.md missing); rerun when stable")


class SetupHappyPath(unittest.TestCase):
    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp(prefix="me-setup-test-"))
        self.addCleanup(lambda: __import__("shutil").rmtree(self.tmp, ignore_errors=True))
        self.data_dir = self.tmp / "home"
        self.node_patch = mock.patch.object(me_setup, "find_node", return_value=FAKE_NODE)
        self.node_patch.start()
        self.addCleanup(self.node_patch.stop)

    def test_repeat_setup_stable_installation_id(self):
        port = free_port()
        self.assertEqual(me_setup.do_setup(self.data_dir, "127.0.0.1", port), 0)
        cfg1 = me_setup.load_config(self.data_dir)
        self.assertEqual(me_setup.do_setup(self.data_dir, "127.0.0.1", port), 0)
        cfg2 = me_setup.load_config(self.data_dir)
        self.assertEqual(cfg1["installation_id"], cfg2["installation_id"])
        self.assertEqual(cfg1["created_at"], cfg2["created_at"])
        self.assertEqual(me_setup.do_check(self.data_dir), 0)

    def test_default_port_matches_h1_contract(self):
        args = me_setup.build_parser().parse_args(["setup"])
        self.assertEqual(args.port, 7070)
        self.assertEqual(me_setup.DEFAULT_PORT, 7070)

    def test_home_api_section_tracks_h1_contract(self):
        require_h1_contract(self)
        self.assertEqual(run_setup(self.data_dir), 0)
        cfg = me_setup.load_config(self.data_dir)
        home_api = cfg["home_api"]
        self.assertEqual(home_api["contract"],
                         "infra-server/contracts/home-api-v1.md")
        self.assertEqual(home_api["contract_status"], "home-api-v1")
        for path in ("/healthz", "/readyz", "/v1/pair"):
            self.assertIn(path, home_api["anonymous_paths"])
        self.assertEqual(home_api["auth"]["token_prefix"], "ht1_")
        self.assertTrue(cfg["service"]["db_path"].endswith("data/home.sqlite"))
        self.assertIn("--db=", home_api["launch"]["start"])
        self.assertIn("--port=", home_api["launch"]["start"])

    def test_household_data_preserved_across_reruns(self):
        port = free_port()
        self.assertEqual(me_setup.do_setup(self.data_dir, "127.0.0.1", port), 0)
        household_file = self.data_dir / "data" / "household" / "conversations.json"
        household_file.write_text('{"alice": ["hi"]}', encoding="utf-8")
        pairing_file = self.data_dir / "data" / "household" / "pairing" / "device-a.json"
        pairing_file.write_text('{"device": "a"}', encoding="utf-8")
        # Rerun with a changed port (exercises the backup path too).
        self.assertEqual(me_setup.do_setup(self.data_dir, "127.0.0.1", free_port()), 0)
        self.assertEqual(household_file.read_text(encoding="utf-8"), '{"alice": ["hi"]}')
        self.assertEqual(pairing_file.read_text(encoding="utf-8"), '{"device": "a"}')
        backups = list((self.data_dir / "backups").glob("config-*.json"))
        self.assertTrue(backups, "expected a config backup after the port change")

    def test_config_has_no_secret_values_and_secrets_locked_down(self):
        require_h1_contract(self)
        self.assertEqual(run_setup(self.data_dir), 0)
        text = (self.data_dir / "config" / "config.json").read_text(encoding="utf-8")
        for banned in ("connector_credential\" :", "admin_credential", "pairing_secret",
                       "private_key", "trycloudflare"):
            self.assertNotIn(banned, text)
        mode = stat.S_IMODE((self.data_dir / "secrets").stat().st_mode)
        self.assertEqual(mode, 0o700)
        cfg = json.loads(text)
        self.assertEqual(cfg["schema_version"], me_setup.SCHEMA_VERSION)
        self.assertEqual(cfg["tunnel"]["mode"], "disabled")
        self.assertEqual(cfg["contract_status"] if "contract_status" in cfg
                         else cfg["home_api"]["contract_status"], "home-api-v1")


class UpstreamModeProvisioning(unittest.TestCase):
    """P0-6: full default, sticky explicit choice, native env activation."""

    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp(prefix="me-mode-test-"))
        self.addCleanup(lambda: __import__("shutil").rmtree(self.tmp, ignore_errors=True))
        self.data_dir = self.tmp / "home"
        self.node_patch = mock.patch.object(me_setup, "find_node", return_value=FAKE_NODE)
        self.node_patch.start()
        self.addCleanup(self.node_patch.stop)

    def test_fresh_install_defaults_full(self):
        self.assertEqual(me_setup.do_setup(self.data_dir, "127.0.0.1",
                                           free_port()), 0)
        cfg = me_setup.load_config(self.data_dir)
        self.assertEqual(cfg["upstream"]["mode"], "full")
        svc = (self.data_dir / "config" / "service.env").read_text(encoding="utf-8")
        self.assertIn("ME_UPSTREAM_MODE=full", svc)
        # Local default maps to the supported native route (B spec: openai +
        # container base URL; BOT_PROVIDER=ollama is rejected by the harness).
        # The SDK requires a non-empty key even for Ollama: the documented
        # NONSECRET placeholder constant, never a credential.
        self.assertIn("BOT_PROVIDER=openai", svc)
        self.assertIn("OPENAI_BASE_URL=http://host.docker.internal:11434/v1", svc)
        self.assertIn("OPENAI_API_KEY=ollama", svc)
        self.assertIn("BOT_MODEL=llama3.1", svc)

    def test_explicit_core_sticky_on_reruns(self):
        port = free_port()
        self.assertEqual(me_setup.do_setup(self.data_dir, "127.0.0.1", port,
                                           upstream_mode="core"), 0)
        self.assertEqual(me_setup.load_config(self.data_dir)["upstream"]["mode"],
                         "core")
        # Rerun WITHOUT the flag preserves the explicit choice (never
        # silently overwritten back to full).
        self.assertEqual(me_setup.do_setup(self.data_dir, "127.0.0.1", port), 0)
        cfg = me_setup.load_config(self.data_dir)
        self.assertEqual(cfg["upstream"]["mode"], "core")
        svc = (self.data_dir / "config" / "service.env").read_text(encoding="utf-8")
        self.assertIn("ME_UPSTREAM_MODE=core", svc)
        # Core is the computer-plane dev/partial profile, not the original
        # Me runtime: labels must say so.
        self.assertIn("computer-plane", cfg["upstream"]["note"])
        self.assertNotIn("legacy", cfg["upstream"]["note"].lower())

    def test_explicit_flag_overrides_previous(self):
        port = free_port()
        self.assertEqual(me_setup.do_setup(self.data_dir, "127.0.0.1", port), 0)
        self.assertEqual(me_setup.do_setup(self.data_dir, "127.0.0.1", port,
                                           upstream_mode="core"), 0)
        self.assertEqual(me_setup.load_config(self.data_dir)["upstream"]["mode"],
                         "core")

    def test_absent_legacy_config_preserved(self):
        port = free_port()
        self.assertEqual(me_setup.do_setup(self.data_dir, "127.0.0.1", port), 0)
        cfg = me_setup.load_config(self.data_dir)
        del cfg["upstream"]
        me_setup.write_atomic(me_setup.config_path(self.data_dir),
                              json.dumps(cfg, indent=2, sort_keys=True) + "\n")
        # Rerun without a flag must NOT silently inject a mode.
        self.assertEqual(me_setup.do_setup(self.data_dir, "127.0.0.1", port), 0)
        cfg2 = me_setup.load_config(self.data_dir)
        self.assertNotIn("upstream", cfg2)
        svc = (self.data_dir / "config" / "service.env").read_text(encoding="utf-8")
        self.assertNotIn("ME_UPSTREAM_MODE=", svc)

    def test_native_harness_env_mapping(self):
        local = me_setup.native_harness_env(
            {"provider": "local", "name": "qwen3", "endpoint": "http://h:11434"})
        # Non-loopback operator URL preserved as-is (private container).
        self.assertEqual(local, {"BOT_PROVIDER": "openai", "BOT_MODEL": "qwen3",
                                 "OPENAI_BASE_URL": "http://h:11434/v1",
                                 "OPENAI_API_KEY": "ollama"})
        loopback = me_setup.native_harness_env(
            {"provider": "local", "name": "llama3.1",
             "endpoint": "http://127.0.0.1:11434"})
        # Loopback (host-legacy probe address) translated to the
        # container-reachable default; NONSECRET placeholder, not a key.
        self.assertEqual(loopback["OPENAI_BASE_URL"],
                         "http://host.docker.internal:11434/v1")
        self.assertEqual(loopback["OPENAI_API_KEY"], "ollama")
        self.assertEqual(loopback["OPENAI_API_KEY"],
                         me_setup.NATIVE_LOCAL_API_KEY_PLACEHOLDER)
        custom_port = me_setup.native_harness_env(
            {"provider": "local", "name": "m",
             "endpoint": "http://localhost:11435"})
        self.assertEqual(custom_port["OPENAI_BASE_URL"],
                         "http://host.docker.internal:11435/v1")
        remote = me_setup.native_harness_env(
            {"provider": "anthropic", "name": "claude-x",
             "endpoint": "https://api.anthropic.com"})
        self.assertEqual(remote, {"BOT_PROVIDER": "anthropic",
                                  "BOT_MODEL": "claude-x",
                                  "OPENAI_BASE_URL": "https://api.anthropic.com"})
        # Remote without endpoint: no base URL invented.
        self.assertEqual(me_setup.native_harness_env(
            {"provider": "openai", "name": "gpt-x"}),
            {"BOT_PROVIDER": "openai", "BOT_MODEL": "gpt-x"})
        self.assertEqual(me_setup.native_harness_env({"provider": "fixture"}),
                         {})
        with self.assertRaises(me_setup.SetupError):
            me_setup.native_harness_env({"provider": "ollama"})
        with self.assertRaises(me_setup.SetupError):
            me_setup.native_harness_env({"provider": "local",
                                         "endpoint": "not-a-url"})

    def test_container_url_preserved_not_claimed_reachable(self):
        # Explicit private-container URL preserved byte-for-byte (no
        # translation, no reachability claim from host tags).
        out = me_setup.native_harness_env(
            {"provider": "local", "name": "m",
             "endpoint": "http://ollama-computer:11434"})
        self.assertEqual(out["OPENAI_BASE_URL"], "http://ollama-computer:11434/v1")
        already = me_setup.native_harness_env(
            {"provider": "local", "name": "m",
             "endpoint": "http://host.docker.internal:11434/v1"})
        self.assertEqual(already["OPENAI_BASE_URL"],
                         "http://host.docker.internal:11434/v1")

    def test_service_env_placeholder_marked_nonsecret(self):
        port = free_port()
        self.assertEqual(me_setup.do_setup(self.data_dir, "127.0.0.1", port), 0)
        svc = (self.data_dir / "config" / "service.env").read_text(encoding="utf-8")
        self.assertIn("NONSECRET", svc)
        self.assertIn("harness-namespace probe", svc)

    def test_home_env_activates_mode_and_native_model(self):
        import me_lifecycle
        port = free_port()
        self.assertEqual(me_setup.do_setup(self.data_dir, "127.0.0.1", port), 0)
        cfg = me_setup.load_config(self.data_dir)
        env = me_lifecycle.build_home_env(cfg)
        self.assertEqual(env["ME_UPSTREAM_MODE"], "full")
        self.assertEqual(env["BOT_PROVIDER"], "openai")
        # Container-reachable default (translated from loopback); the
        # NONSECRET placeholder, never a real key.
        self.assertEqual(env["OPENAI_BASE_URL"], "http://host.docker.internal:11434/v1")
        self.assertEqual(env["OPENAI_API_KEY"], "ollama")
        # Old tasks/data preserved across a mode switch (explicit read/resume,
        # no silent new legacy, no deletion).
        task = self.data_dir / "data" / "household" / "keep.json"
        task.write_text('{"t": 1}', encoding="utf-8")
        self.assertEqual(me_setup.do_setup(self.data_dir, "127.0.0.1", port,
                                           upstream_mode="core"), 0)
        self.assertEqual(task.read_text(encoding="utf-8"), '{"t": 1}')


class UnsafePaths(unittest.TestCase):
    def test_rejected_destinations(self):
        with tempfile.NamedTemporaryFile(delete=False) as f:
            file_path = f.name
        self.addCleanup(lambda: os.unlink(file_path))
        bad = ["", "   ", "/", "/etc", "/etc/me-home", "/usr/local/me",
               "/bin/me", "/System/x", "/Library/x", str(Path.home()),
               "/tmp", file_path, "\0/bad",
               str(me_setup.repo_root() / "data")]
        for raw in bad:
            with self.subTest(raw=raw):
                with self.assertRaises(me_setup.SetupError):
                    me_setup.resolve_data_dir(raw)

    def test_relative_resolves_inside_cwd(self):
        with tempfile.TemporaryDirectory() as tmp:
            cwd = os.getcwd()
            os.chdir(tmp)
            try:
                resolved = me_setup.resolve_data_dir("rel-home")
                self.assertTrue(resolved.is_absolute())
            finally:
                os.chdir(cwd)


class ConfigFailures(unittest.TestCase):
    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp(prefix="me-setup-cfg-"))
        self.addCleanup(lambda: __import__("shutil").rmtree(self.tmp, ignore_errors=True))
        self.data_dir = self.tmp / "home"
        (self.data_dir / "config").mkdir(parents=True)
        self.cfg_file = self.data_dir / "config" / "config.json"

    def _write(self, obj) -> None:
        self.cfg_file.write_text(obj if isinstance(obj, str) else json.dumps(obj),
                                 encoding="utf-8")

    def test_invalid_json_fails_loudly(self):
        self._write("{not json")
        with self.assertRaises(me_setup.SetupError):
            me_setup.load_config(self.data_dir)

    def test_future_schema_version_refuses_to_overwrite(self):
        self._write({"schema_version": 999, "installation_id": "x",
                     "service": {}, "tunnel": {}})
        with self.assertRaises(me_setup.SetupError) as ctx:
            me_setup.load_config(self.data_dir)
        self.assertIn("schema_version", str(ctx.exception))

    def test_missing_keys_fail_loudly(self):
        self._write({"schema_version": 1})
        with self.assertRaises(me_setup.SetupError):
            me_setup.load_config(self.data_dir)

    def test_embedded_secret_in_config_rejected(self):
        self._write({"schema_version": 1, "installation_id": "x",
                     "service": {"host": "127.0.0.1", "port": 1},
                     "tunnel": {}, "note": "tunnel_connector_credential: abc"})
        with self.assertRaises(me_setup.SetupError):
            me_setup.load_config(self.data_dir)

    def test_check_fails_without_setup(self):
        empty = self.tmp / "nothing"
        empty.mkdir()
        self.assertNotEqual(me_setup.do_check(empty), 0)


class Guardrails(unittest.TestCase):
    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp(prefix="me-setup-guard-"))
        self.addCleanup(lambda: __import__("shutil").rmtree(self.tmp, ignore_errors=True))
        self.node_patch = mock.patch.object(me_setup, "find_node", return_value=FAKE_NODE)
        self.node_patch.start()
        self.addCleanup(self.node_patch.stop)

    def test_non_loopback_host_rejected(self):
        dest = self.tmp / "a"
        self.assertEqual(me_setup.do_setup(dest, "0.0.0.0", free_port()), 3)
        self.assertFalse((dest / "config" / "config.json").exists(),
                         "failed setup must not write config")

    def test_privileged_and_wild_ports_rejected(self):
        for port in (80, 0, 70000):
            with self.subTest(port=port):
                dest = self.tmp / f"p{port}"
                self.assertEqual(me_setup.do_setup(dest, "127.0.0.1", port), 3)

    def test_redaction(self):
        self.assertNotIn("abc123", me_setup.redact("token: abc123"))
        self.assertNotIn("s3cret", me_setup.redact("pairing_secret=s3cret"))
        self.assertIn("8787", me_setup.redact("port 8787 ok"))


class AdoptServiceId(unittest.TestCase):
    """Adopting the live H1 installation_id, against a stub /healthz server."""

    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp(prefix="me-setup-adopt-"))
        self.addCleanup(lambda: __import__("shutil").rmtree(self.tmp, ignore_errors=True))
        self.data_dir = self.tmp / "home"
        self.node_patch = mock.patch.object(me_setup, "find_node", return_value=FAKE_NODE)
        self.node_patch.start()
        self.addCleanup(self.node_patch.stop)
        self._servers = []
        self.addCleanup(self._stop_servers)

    def _stop_servers(self):
        for srv in self._servers:
            srv.shutdown()
            srv.server_close()

    def _serve_healthz(self, payload: dict) -> int:
        import http.server
        import threading

        body = json.dumps(payload).encode()

        class Handler(http.server.BaseHTTPRequestHandler):
            def do_GET(self):
                if self.path == "/healthz":
                    self.send_response(200)
                    self.send_header("Content-Type", "application/json")
                    self.send_header("Content-Length", str(len(body)))
                    self.end_headers()
                    self.wfile.write(body)
                else:
                    self.send_error(404)

            def log_message(self, *args):
                pass

        srv = http.server.HTTPServer(("127.0.0.1", 0), Handler)
        threading.Thread(target=srv.serve_forever, daemon=True).start()
        self._servers.append(srv)
        return srv.server_address[1]

    def test_adopt_live_id_with_backup(self):
        port = self._serve_healthz({"status": "ok", "installation_id": "live-id-1",
                                    "contract": "home-api-v1"})
        self.assertEqual(me_setup.do_setup(self.data_dir, "127.0.0.1", port), 0)
        before = me_setup.load_config(self.data_dir)["installation_id"]
        self.assertNotEqual(before, "live-id-1")
        self.assertEqual(me_setup.adopt_live_service_id(self.data_dir, "127.0.0.1", port), 0)
        cfg = me_setup.load_config(self.data_dir)
        self.assertEqual(cfg["installation_id"], "live-id-1")
        self.assertTrue(list((self.data_dir / "backups").glob("config-*.json")))
        # Idempotent second adopt.
        self.assertEqual(me_setup.adopt_live_service_id(self.data_dir, "127.0.0.1", port), 0)

    def test_adopt_rejects_wrong_contract(self):
        port = self._serve_healthz({"status": "ok", "installation_id": "live-id-2",
                                    "contract": "something-else"})
        self.assertEqual(me_setup.do_setup(self.data_dir, "127.0.0.1", port), 0)
        before = me_setup.load_config(self.data_dir)["installation_id"]
        self.assertNotEqual(me_setup.adopt_live_service_id(self.data_dir, "127.0.0.1", port), 0)
        self.assertEqual(me_setup.load_config(self.data_dir)["installation_id"], before)

    def test_adopt_fails_when_nothing_listening(self):
        port = free_port()
        self.assertEqual(me_setup.do_setup(self.data_dir, "127.0.0.1", port), 0)
        before = me_setup.load_config(self.data_dir)["installation_id"]
        self.assertNotEqual(me_setup.adopt_live_service_id(self.data_dir, "127.0.0.1", port), 0)
        self.assertEqual(me_setup.load_config(self.data_dir)["installation_id"], before)


if __name__ == "__main__":
    unittest.main()
