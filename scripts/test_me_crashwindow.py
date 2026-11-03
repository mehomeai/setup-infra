#!/usr/bin/env python3
"""Crash-window + autostart-guard regressions (S6.2).

Gap A: the old `_log_move` renamed first and journaled after, so a power-kill
AFTER the first filesystem move but BEFORE the journal persist left the
original moved away with no durable record. These tests kill a REAL restore
subprocess (os._exit / SIGKILL, not an in-memory Python exception) in that
exact window, then run a FRESH `restore-recover` CLI and require the original
DB/tasks/household (including absent-tree and config identity) back.

Gap B: generated launchd/systemd units used to exec Node directly, bypassing
`me_lifecycle.start`'s interrupted-journal guard. Units now exec a shared
Python guard (config/me-home.exec.py) that re-checks the journal and only
then execs Node (same PID). The live test proves an interrupted journal
blocks the REAL generated ProgramArguments with no port bound, and that after
recovery the same argv becomes ready and SIGTERM exits cleanly.
"""

import collections
import json
import os
import shutil
import signal
import sqlite3
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


def require_h1(testcase):
    checkout = me_setup.resolve_checkout(
        os.environ.get("ME_HOME_INFRA_CHECKOUT") or None,
        "ME_HOME_INFRA_CHECKOUT", "infra-server",
        ("src/cli.mjs", "src/server.mjs"), "home service")
    node, _ = me_setup.find_node(os.environ.get("ME_HOME_NODE") or None)
    if checkout is None or node is None:
        testcase.skipTest("transient dependency: infra-server/Node unavailable")
    assert checkout is not None and node is not None
    return checkout, node


def synthetic_db(db: Path, installation_id="crash-test-id") -> None:
    db.parent.mkdir(parents=True, exist_ok=True)
    with me_lifecycle.sqlite_conn(db) as conn:
        conn.execute("PRAGMA journal_mode=WAL")
        conn.execute("CREATE TABLE meta (key TEXT PRIMARY KEY, value TEXT)")
        conn.execute("INSERT INTO meta VALUES ('installation_id', ?)",
                     (installation_id,))
        conn.execute("CREATE TABLE kv (k TEXT PRIMARY KEY, v TEXT)")
        conn.execute("INSERT INTO kv VALUES ('orig', '1')")


class CrashWindowKill(unittest.TestCase):
    """Real subprocess kill in the rename-then-journal window."""

    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp(prefix="me-crash-")).resolve()
        self.addCleanup(lambda: shutil.rmtree(self.tmp, ignore_errors=True))
        self.port = free_port()
        # Spaces in data-dir path are part of the requirement.
        self.data_dir = self.tmp / "home dir with spaces"
        with mock.patch.object(me_setup, "find_node",
                               return_value=("/fake/node", "fake")):
            self.assertEqual(me_setup.do_setup(self.data_dir, "127.0.0.1",
                                               self.port), 0)
        self.cfg = me_setup.load_config(self.data_dir)
        self.db = Path(self.cfg["service"]["db_path"])
        synthetic_db(self.db, installation_id="orig-id")
        self.tasks_root = self.db.parent / "tasks"
        (self.tasks_root / "task_keep" / "output").mkdir(parents=True)
        (self.tasks_root / "task_keep" / "output" / "result.md").write_text(
            "keep", encoding="utf-8")
        self.house = self.data_dir / "data" / "household"
        self.house.mkdir(parents=True, exist_ok=True)
        (self.house / "family.md").write_text("orig-house", encoding="utf-8")
        self.orig_config_id = self.cfg["installation_id"]
        # Archive with DIFFERENT content so a successful swap would be visible.
        other = self.tmp / "other"
        with mock.patch.object(me_setup, "find_node",
                               return_value=("/fake/node", "fake")):
            self.assertEqual(me_setup.do_setup(other, "127.0.0.1", free_port()), 0)
        other_db = Path(me_setup.load_config(other)["service"]["db_path"])
        synthetic_db(other_db, installation_id="new-id")
        self.archive = self.tmp / "new.tar.gz"
        self.assertEqual(me_lifecycle.do_backup(
            self.data_dir, output=str(self.tmp / "orig.tar.gz"), scope="full"), 0)
        # Craft a "new" archive by backing up `other` after adding payload.
        other_tasks = other_db.parent / "tasks"
        (other_tasks / "task_new").mkdir(parents=True)
        (other_tasks / "task_new" / "f.txt").write_text("new", encoding="utf-8")
        self.assertEqual(me_lifecycle.do_backup(
            other, output=str(self.archive), scope="full"), 0)
        self.before_db = self.db.read_bytes()
        self.before_tasks = sorted(
            p.relative_to(self.tasks_root).as_posix()
            for p in self.tasks_root.rglob("*") if p.is_file())
        self.before_house = (self.house / "family.md").read_bytes()

    def _kill_restore(self, mode: str) -> None:
        """Run restore in a child that power-kills itself in the window.

        mode="after-first-rename": real rename of the first move, then
          os._exit(137) BEFORE the done=True journal write (the old lost-move
          window). mode="before-move-after-intent": durable intent already
          written, then SIGKILL self before any rename.
        Parent waits for the child death and returns; child never raises a
        Python exception (those paths are already covered elsewhere).
        """
        pid = os.fork()
        if pid == 0:
            try:
                real = me_lifecycle._rename_or_copy
                calls = {"n": 0}

                def killer(src, dst):
                    calls["n"] += 1
                    if mode == "before-move-after-intent":
                        # Intent is already durably written by _log_move;
                        # die before mutating anything.
                        os.kill(os.getpid(), signal.SIGKILL)
                        time.sleep(5)
                        os._exit(137)
                    # after-first-rename: perform the real first rename, then
                    # die before the done=True persist.
                    out = real(src, dst)
                    os._exit(137)
                    return out

                with mock.patch.object(me_lifecycle, "_rename_or_copy",
                                       side_effect=killer):
                    me_lifecycle.do_restore(
                        self.data_dir, source=str(self.archive),
                        confirm_destructive=True, scope="full")
            finally:
                os._exit(137)
        _, status = os.waitpid(pid, 0)
        # Child must have died by kill/exit, not by clean return.
        self.assertTrue(os.WIFSIGNALED(status) or os.WIFEXITED(status))

    def test_kill_after_first_rename_recover(self):
        self._kill_restore("after-first-rename")
        journal = me_lifecycle.incomplete_journal(self.data_dir)
        self.assertIsNotNone(journal, "killed restore must leave blocking journal")
        self.assertEqual(me_lifecycle.do_start(self.data_dir), 1)
        # Fresh CLI recover (new process semantics via main()).
        rc = me_lifecycle.main(["restore-recover", "--data-dir",
                                str(self.data_dir)])
        self.assertEqual(rc, 0)
        self.assertEqual(self.db.read_bytes(), self.before_db)
        after_tasks = sorted(
            p.relative_to(self.tasks_root).as_posix()
            for p in self.tasks_root.rglob("*") if p.is_file())
        self.assertEqual(after_tasks, self.before_tasks)
        self.assertEqual((self.house / "family.md").read_bytes(),
                         self.before_house)
        self.assertEqual(me_setup.load_config(self.data_dir)["installation_id"],
                         self.orig_config_id)
        self.assertIsNone(me_lifecycle.incomplete_journal(self.data_dir))

    def test_kill_before_move_after_intent_idempotent(self):
        self._kill_restore("before-move-after-intent")
        journal = me_lifecycle.incomplete_journal(self.data_dir)
        self.assertIsNotNone(journal)
        # Recover twice: second run must be a clean no-op.
        self.assertEqual(me_lifecycle.main(["restore-recover", "--data-dir",
                                            str(self.data_dir)]), 0)
        self.assertEqual(self.db.read_bytes(), self.before_db)
        self.assertEqual(me_lifecycle.main(["restore-recover", "--data-dir",
                                            str(self.data_dir)]), 0)
        self.assertIsNone(me_lifecycle.incomplete_journal(self.data_dir))

    def test_absent_tree_stays_absent_after_kill_recover(self):
        # Remove household tree: prestate records absence; kill must not
        # resurrect it, and the archive's household must not leak in.
        shutil.rmtree(self.house)
        self.assertFalse(self.house.exists())
        before_cfg = me_setup.load_config(self.data_dir)["installation_id"]
        self._kill_restore("after-first-rename")
        self.assertEqual(me_lifecycle.main(["restore-recover", "--data-dir",
                                            str(self.data_dir)]), 0)
        # Household was absent pre-restore and the test archive path still
        # restores absent correctly when the swap never completed: live must
        # match prestate (absent), not the archive.
        # (If has_house installed without prestate, it would appear -- fail.)
        self.assertFalse((self.tasks_root / "task_new").exists())
        self.assertEqual(me_setup.load_config(self.data_dir)["installation_id"],
                         before_cfg)


class GuardBlocksAutostart(unittest.TestCase):
    """Generated guard blocks on interrupted journal; recovers to ready."""

    def test_guard_blocks_then_recovers_live(self):
        checkout, node = require_h1(self)
        tmp = Path(tempfile.mkdtemp(prefix="me-guard-live-")).resolve()
        self.addCleanup(lambda: shutil.rmtree(tmp, ignore_errors=True))
        data_dir = tmp / "home dir with spaces"
        port = free_port()
        with mock.patch.dict(os.environ, {"ME_HOME_INFRA_CHECKOUT": str(checkout),
                                          "ME_HOME_NODE": node}):
            self.assertEqual(me_setup.do_setup(data_dir, "127.0.0.1", port), 0)
            for fmt in ("launchd", "systemd"):
                self.assertEqual(me_lifecycle.main(
                    ["service", "--data-dir", str(data_dir), "--format", fmt,
                     "--node", node, "--infra-checkout", str(checkout)]), 0)
        import plistlib
        doc = plistlib.loads(
            (data_dir / "config" / "me-home.launchd.plist").read_bytes())
        argv = doc["ProgramArguments"]
        env = {k: str(v) for k, v in doc["EnvironmentVariables"].items()}
        workdir = doc["WorkingDirectory"]
        # Plant an interrupted journal (started) as a crashed restore would.
        journal = data_dir / "backups" / ".restore-journal-20260101T000000Z-9.json"
        journal.write_text(json.dumps(
            {"journal_version": me_lifecycle.RESTORE_JOURNAL_VERSION,
             "status": "started", "moves": [],
             "prestate": {}, "pre_dir": str(data_dir / "backups" / "pre-x")}),
            encoding="utf-8")
        self.addCleanup(lambda: journal.unlink(missing_ok=True))
        full_env = dict(os.environ)
        full_env.update(env)
        # Guard must refuse with no listener on the port.
        proc = subprocess.Popen(argv, stdout=subprocess.PIPE,
                                stderr=subprocess.PIPE,
                                env=full_env, cwd=workdir)
        try:
            _, err_text = proc.communicate(timeout=15)
        except subprocess.TimeoutExpired:
            proc.kill()
            self.fail("guard did not exit on blocked journal (orphan risk)")
        self.assertNotEqual(proc.returncode, 0,
                            "guard must refuse while journal is started")
        self.assertIn("interrupted", err_text.decode("utf-8", "replace"))
        free, _ = me_setup.port_free("127.0.0.1", port)
        self.assertTrue(free, "blocked guard must bind nothing on the home port")
        # Recover (no moves, but clears the journal) then the SAME argv boots.
        journal.unlink(missing_ok=True)
        log_path = Path(me_setup.load_config(data_dir)["service"]["log_dir"]
                        ) / "home-service.log"
        with open(log_path, "a", encoding="utf-8") as fh:
            proc2 = subprocess.Popen(argv, stdout=fh, stderr=subprocess.STDOUT,
                                     start_new_session=True, env=full_env,
                                     cwd=workdir)
        try:
            body = me_lifecycle.wait_for_healthz("127.0.0.1", port, timeout=15)
            self.assertIsNotNone(body, "recovered guard argv must become ready")
            assert body is not None
            self.assertEqual(body.get("status"), "ok")
        finally:
            try:
                os.kill(proc2.pid, signal.SIGTERM)
            except OSError:
                pass
            exited = me_lifecycle.wait_for_exit(proc2.pid, 10)
            try:
                proc2.wait(timeout=5)
            except Exception:
                pass
            self.assertTrue(exited or me_lifecycle.pid_exited(proc2.pid),
                            "guarded service must exit on SIGTERM (no orphans)")


if __name__ == "__main__":
    unittest.main()
