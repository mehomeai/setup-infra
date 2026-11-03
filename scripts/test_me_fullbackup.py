#!/usr/bin/env python3
"""Tests for S6 full household backup/restore (scripts/me_lifecycle.py).

scope=db: legacy online-safe SQLite snapshot only (works while running).
scope=full: stopped-service .tar.gz archive of SQLite (backup API) +
  per-task workspaces (incl. .me_runtime checkpoints) + household files +
  manifest.json. Setup-owned config/logs/secrets/operator-env/tunnel
  credentials are never read in; workspace files ARE private household data
  (local-only archive, never uploaded; no scanning/redaction claimed).

Full restore validates in two streaming passes (header-only preflight with
honest unpacked free-space estimate, then bounded 64 KiB-chunk extraction),
rebases pending.json workspace bindings cross-path, enforces strict
checkpoint SQLite integrity, swaps by rename under a persisted 0600 journal
with rollback that reports its own failures (restore-recover replays an
interrupted journal; start refuses while one is open), and scrubs restored
sessions/devices/invitations so a rolled-back backup cannot revive a revoked
phone (fresh pairing required; identity + household/task data preserved).

Run: python3 -m unittest discover -s scripts -p 'test_me_fullbackup.py' -v
"""

import contextlib
import io
import json
import os
import shutil
import sqlite3
import stat
import subprocess
import tarfile
import tempfile
import time
import unittest
from pathlib import Path
from unittest import mock

sys_path = str(Path(__file__).resolve().parent)
import sys

sys.path.insert(0, sys_path)

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


def setup_home(testcase, tmp: Path, name: str, port: int) -> Path:
    data_dir = tmp / name
    with mock.patch.object(me_setup, "find_node",
                           return_value=("/fake/node", "fake")):
        testcase.assertEqual(me_setup.do_setup(data_dir, "127.0.0.1", port), 0)
    return data_dir


def synthetic_db(db: Path, installation_id: str = "full-test-id-1") -> None:
    """Minimal home-shaped database: meta mirrors H1's authority row."""
    db.parent.mkdir(parents=True, exist_ok=True)
    with me_lifecycle.sqlite_conn(db) as conn:
        conn.execute("PRAGMA journal_mode=WAL")
        conn.execute("CREATE TABLE meta (key TEXT PRIMARY KEY, value TEXT)")
        conn.execute("INSERT INTO meta VALUES ('installation_id', ?)",
                     (installation_id,))
        conn.execute("CREATE TABLE kv (k TEXT PRIMARY KEY, v TEXT)")
        conn.execute("INSERT INTO kv VALUES ('a', '1')")


class FullBackupUnit(unittest.TestCase):
    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp(prefix="me-full-")).resolve()
        self.addCleanup(lambda: shutil.rmtree(self.tmp, ignore_errors=True))
        self.port = free_port()
        self.data_dir = setup_home(self, self.tmp, "home", self.port)
        self.cfg = me_setup.load_config(self.data_dir)
        self.db = Path(self.cfg["service"]["db_path"])
        synthetic_db(self.db)
        self.tasks_root = self.db.parent / "tasks"
        ws = self.tasks_root / "task_1"
        (ws / "input").mkdir(parents=True)
        (ws / "output").mkdir(parents=True)
        (ws / "input" / "notes.md").write_text("task input", encoding="utf-8")
        (ws / "output" / "result.md").write_text("task output", encoding="utf-8")
        ck = ws / ".me_runtime"
        ck.mkdir(parents=True)
        with sqlite3.connect(str(ck / "graph.db")) as c:
            c.execute("CREATE TABLE t (x TEXT)")
            c.execute("INSERT INTO t VALUES ('ckpt')")
            c.commit()
        # Realistic R2 pending record: absolute workspace binding, run/user/
        # conversation identity (restore rebases workspace cross-path).
        (ck / "pending.json").write_text(json.dumps(
            {"request": "need input", "run_id": "task_1", "user_id": "alice",
             "conversation_id": "conv_1",
             "workspace": str(self.tasks_root / "task_1"),
             "kind": "waiting_input", "id": "q1", "prompt": "more input needed"}),
            encoding="utf-8")
        house = self.data_dir / "data" / "household"
        (house / "family.md").write_text("household notes", encoding="utf-8")
        # Secret-shaped material that must never enter an archive.
        (self.data_dir / "secrets" / "tunnel-cred.json").write_text(
            '{"TunnelSecret": "connector-secret-abc"}', encoding="utf-8")
        (self.data_dir / "logs" / "home-service.log").write_text("log line")

    def archive_names(self, archive: Path) -> list:
        with tarfile.open(archive, "r:gz") as tar:
            return tar.getnames()

    def test_full_roundtrip_into_fresh_home(self):
        dest = self.tmp / "full.tar.gz"
        self.assertEqual(
            me_lifecycle.do_backup(self.data_dir, output=str(dest), scope="full"), 0)
        self.assertTrue(dest.is_file())
        self.assertEqual(stat.S_IMODE(dest.stat().st_mode), 0o600)
        names = self.archive_names(dest)
        self.assertIn("manifest.json", names)
        self.assertIn("database/home.sqlite", names)
        self.assertTrue(any(n.startswith("tasks/task_1/") for n in names))
        self.assertTrue(any(n.startswith("household/") for n in names))
        self.assertFalse(any("secret" in n.lower() or "config" in n.lower()
                             or n.startswith("logs/") or n.startswith("run/")
                             or n.startswith("backups/") or n.startswith("tmp/")
                             for n in names))
        with tarfile.open(dest, "r:gz") as tar:
            manifest = json.loads(tar.extractfile("manifest.json").read().decode())
            payload = b"".join(
                tar.extractfile(n).read()
                for n in names if n != "manifest.json" and tar.getmember(n).isfile())
        self.assertEqual(manifest["format_version"], me_lifecycle.FULL_FORMAT_VERSION)
        self.assertEqual(manifest["scope"], "full")
        self.assertEqual(manifest["installation_id"], "full-test-id-1")
        self.assertNotIn("connector-secret-abc", payload.decode("utf-8", "replace"))
        # Restore into a second managed home (layout portability: source paths
        # differ, spaces in data-dir path covered).
        other = setup_home(self, self.tmp, "home 2", free_port())
        other_db = Path(me_setup.load_config(other)["service"]["db_path"])
        self.assertEqual(
            me_lifecycle.do_restore(other, source=str(dest),
                                    confirm_destructive=True, scope="full"), 0)
        ok, _ = me_lifecycle.sqlite_verify(other_db)
        self.assertTrue(ok)
        with me_lifecycle.sqlite_conn(other_db, read_only=True) as conn:
            row = conn.execute("SELECT v FROM kv WHERE k='a'").fetchone()
            self.assertIsNotNone(row)
        self.assertEqual(
            (other_db.parent / "tasks" / "task_1" / "output" / "result.md").read_text(
                encoding="utf-8"), "task output")
        self.assertEqual(
            (other / "data" / "household" / "family.md").read_text(encoding="utf-8"),
            "household notes")
        got, _ = me_lifecycle.checkpoint_sqlite_ok(
            other_db.parent / "tasks" / "task_1" / ".me_runtime" / "graph.db",
            strict=True)
        self.assertTrue(got)
        # Cross-path restore rebased ONLY the workspace binding; run/user/
        # conversation identity is preserved byte-identical.
        rebased = json.loads(
            (other_db.parent / "tasks" / "task_1" / ".me_runtime"
             / "pending.json").read_text(encoding="utf-8"))
        self.assertEqual(rebased["workspace"],
                         str(other_db.parent / "tasks" / "task_1"))
        self.assertEqual(
            {k: rebased[k] for k in ("run_id", "user_id", "conversation_id")},
            {"run_id": "task_1", "user_id": "alice",
             "conversation_id": "conv_1"})
        cfg = me_setup.load_config(other)
        self.assertEqual(cfg["installation_id"], "full-test-id-1")
        self.assertTrue(list((other / "backups").glob("pre-restore-full-*")))
        self.assertIsNone(me_lifecycle.incomplete_journal(other),
                          "successful restore leaves no blocking journal")

    def test_full_backup_refuses_while_running_or_stale(self):
        dest = self.tmp / "full.tar.gz"
        with mock.patch.object(me_lifecycle, "managed_state",
                               return_value=("running", {"pid": 1234})):
            self.assertEqual(
                me_lifecycle.do_backup(self.data_dir, output=str(dest), scope="full"), 1)
        self.assertFalse(dest.exists(), "refused backup must write nothing")
        proc = subprocess.Popen(["sleep", "60"])
        self.addCleanup(lambda: (proc.kill(), proc.wait()))
        pf = self.data_dir / "run" / "home-service.pid"
        pf.parent.mkdir(parents=True, exist_ok=True)
        pf.write_text(json.dumps({"pid": proc.pid, "exe": "sleep",
                                  "argv": ["sleep", "60"], "db": str(self.db),
                                  "host": "127.0.0.1", "port": self.port}),
                      encoding="utf-8")
        # Stale pidfile (foreign process, unverified): full snapshot refuses.
        self.assertEqual(
            me_lifecycle.do_backup(self.data_dir, output=str(dest), scope="full"), 1)
        self.assertFalse(dest.exists())
        self.assertIsNone(proc.poll(), "refusal must not touch foreign processes")
        self.assertTrue(self.db.is_file(), "original data untouched by refusal")

    def test_db_scope_stays_online_and_labelled(self):
        """Legacy scope=db keeps working (even while busy) and says its scope."""
        dest = self.tmp / "db.sqlite"
        with mock.patch.object(me_lifecycle, "managed_state",
                               return_value=("running", {"pid": 1234})):
            with mock.patch("sys.stdout", new=io.StringIO()) as buf:
                rc = me_lifecycle.do_backup(self.data_dir, output=str(dest),
                                            scope="db")
        self.assertEqual(rc, 0)
        self.assertIn("scope=db", buf.getvalue())

    def test_full_backup_refuses_symlink_and_keeps_original(self):
        link = self.tasks_root / "task_1" / "evil-link"
        try:
            link.symlink_to("/etc/passwd")
        except OSError as exc:
            self.skipTest(f"cannot create symlink here: {exc}")
        dest = self.tmp / "full.tar.gz"
        self.assertEqual(
            me_lifecycle.do_backup(self.data_dir, output=str(dest), scope="full"), 1)
        self.assertFalse(dest.exists())
        self.assertTrue((self.tasks_root / "task_1" / "output" / "result.md").is_file())

    def test_full_restore_requires_confirm(self):
        dest = self.tmp / "full.tar.gz"
        self.assertEqual(
            me_lifecycle.do_backup(self.data_dir, output=str(dest), scope="full"), 0)
        before = self.db.read_bytes()
        self.assertEqual(
            me_lifecycle.do_restore(self.data_dir, source=str(dest),
                                    confirm_destructive=False, scope="full"), 2)
        self.assertEqual(self.db.read_bytes(), before, "no mutation without confirm")

    def _craft_archive(self, dest: Path, files: dict, manifest_patch=None,
                       manifest_override=None) -> None:
        staging = self.tmp / "craft"
        if staging.exists():
            shutil.rmtree(staging)
        (staging / "database").mkdir(parents=True)
        (staging / "tasks").mkdir(parents=True)
        (staging / "household").mkdir(parents=True)
        shutil.copy2(self.db, staging / "database" / "home.sqlite")
        items = []
        for arc, data in files.items():
            full = staging / arc
            full.parent.mkdir(parents=True, exist_ok=True)
            full.write_bytes(data)
            if arc != "manifest.json":
                import hashlib
                items.append({"path": arc,
                              "sha256": hashlib.sha256(data).hexdigest(),
                              "size": len(data)})
        manifest = {"format_version": me_lifecycle.FULL_FORMAT_VERSION,
                    "scope": "full", "created_at": "2026-01-01T00:00:00+00:00",
                    "installation_id": "full-test-id-1",
                    "source": {}, "database": {
                        "path": "database/home.sqlite",
                        "sha256": me_lifecycle.sha256_file(staging / "database" / "home.sqlite"),
                        "size": (staging / "database" / "home.sqlite").stat().st_size},
                    "tasks": [i for i in items if i["path"].startswith("tasks/")],
                    "household": [i for i in items if i["path"].startswith("household/")],
                    "counts": {}, "total_bytes": 0, "excludes": [], "note": "craft"}
        if manifest_patch:
            manifest_patch(manifest)
        if manifest_override is not None:
            manifest = manifest_override
        (staging / "manifest.json").write_text(json.dumps(manifest),
                                               encoding="utf-8")
        with tarfile.open(dest, "w:gz", format=tarfile.PAX_FORMAT) as tar:
            tar.add(str(staging / "manifest.json"), arcname="manifest.json")
            tar.add(str(staging / "database" / "home.sqlite"),
                    arcname="database/home.sqlite")
            for arc in files:
                if arc == "manifest.json":
                    continue
                tar.add(str(staging / arc), arcname=arc)

    def test_full_restore_rejects_traversal_symlink_duplicate(self):
        before_db = self.db.read_bytes()
        before_tasks = sorted(p.relative_to(self.tasks_root).as_posix()
                              for p in self.tasks_root.rglob("*") if p.is_file())
        # Traversal entry.
        bad = self.tmp / "bad-traversal.tar.gz"
        self._craft_archive(bad, {"tasks/ok.txt": b"ok"})
        with tarfile.open(bad, "a:gz") if False else contextlib.nullcontext():
            pass
        import io as _io
        with tarfile.open(bad, "r:gz") as tar:
            members = list(tar.getmembers())
        with tarfile.open(bad, "w:gz") as tar:
            for m in members:
                f = tarfile.TarInfo("../evil.txt")
                f.size = 3
                tar.addfile(f, _io.BytesIO(b"evil"))
                break
        self.assertEqual(
            me_lifecycle.do_restore(self.data_dir, source=str(bad),
                                    confirm_destructive=True, scope="full"), 1)
        # Symlink entry.
        bad2 = self.tmp / "bad-symlink.tar.gz"
        self._craft_archive(bad2, {"tasks/ok.txt": b"ok"})
        with tarfile.open(bad2, "r:gz") as tar:
            members = list(tar.getmembers())
            blobs = {m.name: tar.extractfile(m).read() for m in members if m.isfile()}
        with tarfile.open(bad2, "w:gz") as tar:
            for m in members:
                if m.name == "manifest.json":
                    continue
                m2 = tarfile.TarInfo(m.name)
                m2.size = len(blobs[m.name])
                tar.addfile(m2, _io.BytesIO(blobs[m.name]))
            link = tarfile.TarInfo("tasks/link")
            link.type = tarfile.SYMTYPE
            link.linkname = "/etc/passwd"
            tar.addfile(link)
            man = json.loads(blobs["manifest.json"].decode())
            import hashlib as _hl
            link_bytes = b""
            man["tasks"].append({"path": "tasks/link",
                                 "sha256": _hl.sha256(link_bytes).hexdigest(),
                                 "size": 0})
            raw = json.dumps(man).encode()
            m2 = tarfile.TarInfo("manifest.json")
            m2.size = len(raw)
            tar.addfile(m2, _io.BytesIO(raw))
        self.assertEqual(
            me_lifecycle.do_restore(self.data_dir, source=str(bad2),
                                    confirm_destructive=True, scope="full"), 1)
        # Duplicate entry.
        bad3 = self.tmp / "bad-dup.tar.gz"
        self._craft_archive(bad3, {"tasks/ok.txt": b"ok"})
        with tarfile.open(bad3, "r:gz") as tar:
            members = list(tar.getmembers())
            blobs = {m.name: tar.extractfile(m).read() for m in members if m.isfile()}
        with tarfile.open(bad3, "w:gz", format=tarfile.PAX_FORMAT) as tar:
            for m in members:
                if not m.isfile():
                    continue
                m2 = tarfile.TarInfo(m.name)
                m2.size = len(blobs[m.name])
                tar.addfile(m2, _io.BytesIO(blobs[m.name]))
            dup = tarfile.TarInfo("tasks/ok.txt")
            dup.size = 2
            tar.addfile(dup, _io.BytesIO(b"ok"))
        self.assertEqual(
            me_lifecycle.do_restore(self.data_dir, source=str(bad3),
                                    confirm_destructive=True, scope="full"), 1)
        self.assertEqual(self.db.read_bytes(), before_db, "failed restore untouched")
        after_tasks = sorted(p.relative_to(self.tasks_root).as_posix()
                             for p in self.tasks_root.rglob("*") if p.is_file())
        self.assertEqual(after_tasks, before_tasks)

    def test_full_restore_rejects_bad_manifest_and_hash(self):
        before = self.db.read_bytes()
        bad = self.tmp / "bad-manifest.tar.gz"
        self._craft_archive(bad, {"tasks/ok.txt": b"ok"},
                            manifest_patch=lambda m: m.update({"format_version": "nope"}))
        self.assertEqual(
            me_lifecycle.do_restore(self.data_dir, source=str(bad),
                                    confirm_destructive=True, scope="full"), 1)
        bad2 = self.tmp / "bad-hash.tar.gz"

        def _break(m):
            m["tasks"][0]["sha256"] = "0" * 64
        self._craft_archive(bad2, {"tasks/ok.txt": b"ok"}, manifest_patch=_break)
        self.assertEqual(
            me_lifecycle.do_restore(self.data_dir, source=str(bad2),
                                    confirm_destructive=True, scope="full"), 1)
        self.assertEqual(self.db.read_bytes(), before)

    def test_streaming_rejects_oversize_name_and_bomb(self):
        before_db = self.db.read_bytes()
        # Oversize member name (longname/PAX bomb vector) refused pre-payload.
        bad = self.tmp / "bad-longname.tar.gz"
        self._craft_archive(bad, {"tasks/ok.txt": b"ok"})
        import io as _io
        with tarfile.open(bad, "r:gz") as tar:
            members = list(tar.getmembers())
            blobs = {m.name: tar.extractfile(m).read()
                     for m in members if m.isfile()}
        with tarfile.open(bad, "w:gz") as tar:
            for m in members:
                if not m.isfile() or m.name != "manifest.json":
                    continue
                m2 = tarfile.TarInfo(m.name)
                m2.size = len(blobs[m.name])
                tar.addfile(m2, _io.BytesIO(blobs[m.name]))
            longname = "tasks/" + "x" * 2000 + ".txt"
            big = tarfile.TarInfo(longname)
            big.size = 2
            tar.addfile(big, _io.BytesIO(b"ok"))
        self.assertEqual(
            me_lifecycle.do_restore(self.data_dir, source=str(bad),
                                    confirm_destructive=True, scope="full"), 1)
        # Decompression bomb refused in the write-free preflight with
        # injected caps: 3 MiB of zeros compresses to ~3 KiB on disk.
        bomb = self.tmp / "bomb.tar.gz"
        self._craft_archive(bomb, {"tasks/big.bin": b"\0" * (3 * 1024**2)})
        self.assertLess(bomb.stat().st_size, 64 * 1024)
        with mock.patch.dict(os.environ, {"ME_HOME_FULL_MAX_TOTAL_BYTES": "1048576"}):
            self.assertEqual(
                me_lifecycle.do_restore(self.data_dir, source=str(bomb),
                                        confirm_destructive=True, scope="full"), 1)
        # Garbage bytes with an archive suffix are not a valid archive.
        garbage = self.tmp / "garbage.tar.gz"
        garbage.write_bytes(b"not a gzip stream")
        self.assertEqual(
            me_lifecycle.do_restore(self.data_dir, source=str(garbage),
                                    confirm_destructive=True, scope="full"), 1)
        self.assertEqual(self.db.read_bytes(), before_db)
        leftovers = [p for p in (self.data_dir / "tmp").iterdir()
                     if p.name.startswith(".full-restore-")]
        self.assertEqual(leftovers, [], "refused restores stage nothing")

    def test_free_space_and_huge_manifest_refusals(self):
        dest = self.tmp / "full.tar.gz"
        self.assertEqual(
            me_lifecycle.do_backup(self.data_dir, output=str(dest), scope="full"), 0)
        before = self.db.read_bytes()
        import collections as _c
        tiny = _c.namedtuple("usage", ["total", "used", "free"])(
            10 * 1024**3, 10 * 1024**3 - 1024, 1024)
        with mock.patch.object(shutil, "disk_usage", return_value=tiny):
            self.assertEqual(
                me_lifecycle.do_restore(self.data_dir, source=str(dest),
                                        confirm_destructive=True, scope="full"), 1)
        self.assertEqual(self.db.read_bytes(), before)
        # Manifest over its cap is refused before parsing (injected limit).
        with mock.patch.dict(os.environ, {"ME_HOME_FULL_MAX_MANIFEST_BYTES": "100"}):
            self.assertEqual(
                me_lifecycle.do_restore(self.data_dir, source=str(dest),
                                        confirm_destructive=True, scope="full"), 1)
        self.assertEqual(self.db.read_bytes(), before)

    def test_strict_checkpoint_rejects_garbage_graph_db(self):
        before = self.db.read_bytes()
        # Garbage graph.db with a MATCHING manifest hash: the archive is
        # intact, the checkpoint is corrupt -- still refused.
        bad = self.tmp / "bad-checkpoint.tar.gz"
        self._craft_archive(
            bad, {"tasks/task_x/.me_runtime/graph.db": b"definitely not sqlite"})
        self.assertEqual(
            me_lifecycle.do_restore(self.data_dir, source=str(bad),
                                    confirm_destructive=True, scope="full"), 1)
        self.assertEqual(self.db.read_bytes(), before)
        # A garbage non-checkpoint .db is ordinary payload and restores.
        ok_archive = self.tmp / "ok-nondb.tar.gz"
        self._craft_archive(ok_archive, {"household/cache.db": b"opaque bytes"})
        self.assertEqual(
            me_lifecycle.do_restore(self.data_dir, source=str(ok_archive),
                                    confirm_destructive=True, scope="full"), 0)

    def _pending_record(self, tid, workspace, run_id=None):
        return {"request": "q", "run_id": run_id or tid, "user_id": "alice",
                "conversation_id": "conv_1", "workspace": workspace,
                "kind": "waiting_input", "id": "q1", "prompt": "p"}

    def test_pending_binding_mismatch_rejected(self):
        before = self.db.read_bytes()
        src_root = "/old/home/data/tasks"
        # Foreign workspace binding (not under the manifest tasks root).
        bad = self.tmp / "bad-binding.tar.gz"
        self._craft_archive(
            bad, {"tasks/task_9/.me_runtime/pending.json": json.dumps(
                self._pending_record("task_9", "/elsewhere/tasks/task_9")).encode()},
            manifest_patch=lambda m: m.update(
                {"source": {"tasks_root": src_root}}))
        self.assertEqual(
            me_lifecycle.do_restore(self.data_dir, source=str(bad),
                                    confirm_destructive=True, scope="full"), 1)
        # run_id not matching the workspace directory.
        bad2 = self.tmp / "bad-runid.tar.gz"
        self._craft_archive(
            bad2, {"tasks/task_9/.me_runtime/pending.json": json.dumps(
                self._pending_record("task_9", f"{src_root}/task_9",
                                     run_id="task_other")).encode()},
            manifest_patch=lambda m: m.update(
                {"source": {"tasks_root": src_root}}))
        self.assertEqual(
            me_lifecycle.do_restore(self.data_dir, source=str(bad2),
                                    confirm_destructive=True, scope="full"), 1)
        # Pending without a verifiable source root is unverifiable.
        bad3 = self.tmp / "bad-nosource.tar.gz"
        self._craft_archive(
            bad3, {"tasks/task_9/.me_runtime/pending.json": json.dumps(
                self._pending_record("task_9", f"{src_root}/task_9")).encode()})
        self.assertEqual(
            me_lifecycle.do_restore(self.data_dir, source=str(bad3),
                                    confirm_destructive=True, scope="full"), 1)
        self.assertEqual(self.db.read_bytes(), before, "validation rejects cleanly")

    def test_valid_cross_binding_rebases_workspace_only(self):
        src_root = "/old/home/data/tasks"
        arc = self.tmp / "cross.tar.gz"
        record = self._pending_record("task_9", f"{src_root}/task_9")
        self._craft_archive(
            arc, {"tasks/task_9/.me_runtime/pending.json":
                  json.dumps(record).encode()},
            manifest_patch=lambda m: m.update(
                {"source": {"tasks_root": src_root}}))
        self.assertEqual(
            me_lifecycle.do_restore(self.data_dir, source=str(arc),
                                    confirm_destructive=True, scope="full"), 0)
        got = json.loads(
            (self.tasks_root / "task_9" / ".me_runtime" / "pending.json"
             ).read_text(encoding="utf-8"))
        self.assertEqual(got["workspace"], str(self.tasks_root / "task_9"))
        for field in ("run_id", "user_id", "conversation_id", "kind", "id"):
            self.assertEqual(got[field], record[field])

    def test_swap_failure_recovers_original(self):
        before_db = self.db.read_bytes()
        before_tasks = sorted(p.relative_to(self.tasks_root).as_posix()
                              for p in self.tasks_root.rglob("*") if p.is_file())
        dest = self.tmp / "full.tar.gz"
        self.assertEqual(
            me_lifecycle.do_backup(self.data_dir, output=str(dest), scope="full"), 0)
        real = me_lifecycle._rename_or_copy

        def flaky(src, dst):
            if "ready" in str(src) and str(dst) == str(self.db):
                raise OSError("injected install failure")
            return real(src, dst)

        with mock.patch.object(me_lifecycle, "_rename_or_copy",
                               side_effect=flaky):
            self.assertEqual(
                me_lifecycle.do_restore(self.data_dir, source=str(dest),
                                        confirm_destructive=True, scope="full"), 1)
        self.assertEqual(self.db.read_bytes(), before_db)
        after_tasks = sorted(p.relative_to(self.tasks_root).as_posix()
                             for p in self.tasks_root.rglob("*") if p.is_file())
        self.assertEqual(after_tasks, before_tasks)
        journals = me_lifecycle.restore_journals(self.data_dir)
        self.assertTrue(journals)
        journal = json.loads(journals[-1].read_text(encoding="utf-8"))
        self.assertEqual(journal["status"], "rolled-back")
        self.assertIsNone(me_lifecycle.incomplete_journal(self.data_dir))

    def test_config_failure_with_absent_tree_recovers_absence(self):
        other = self.tmp / "fresh home"
        with mock.patch.object(me_setup, "find_node",
                               return_value=("/fake/node", "fake")):
            self.assertEqual(me_setup.do_setup(other, "127.0.0.1", free_port(),
                                               min_disk_mib=32), 0)
        other_cfg = me_setup.load_config(other)
        other_db = Path(other_cfg["service"]["db_path"])
        synthetic_db(other_db, installation_id="other-id")
        before_id = me_setup.load_config(other)["installation_id"]
        self.assertFalse((other_db.parent / "tasks").exists())
        before_db = other_db.read_bytes()
        dest = self.tmp / "full.tar.gz"
        self.assertEqual(
            me_lifecycle.do_backup(self.data_dir, output=str(dest), scope="full"), 0)
        real_write = me_setup.write_atomic

        def flaky_write(path, text, mode=0o644):
            if str(path).endswith("config.json"):
                raise OSError("injected config failure")
            return real_write(path, text, mode=mode)

        with mock.patch.object(me_setup, "write_atomic", side_effect=flaky_write):
            self.assertEqual(
                me_lifecycle.do_restore(other, source=str(dest),
                                        confirm_destructive=True, scope="full"), 1)
        # Original recovered AND the absent tree stays absent (no leftovers).
        self.assertEqual(other_db.read_bytes(), before_db)
        self.assertFalse((other_db.parent / "tasks").exists(),
                         "failed restore must not leave a new tree behind")
        self.assertEqual(me_setup.load_config(other)["installation_id"], before_id)
        journals = me_lifecycle.restore_journals(other)
        self.assertTrue(journals)
        self.assertEqual(
            json.loads(journals[-1].read_text(encoding="utf-8"))["status"],
            "rolled-back")

    def test_rollback_failure_retains_journal_and_recover(self):
        before_db = self.db.read_bytes()
        dest = self.tmp / "full.tar.gz"
        self.assertEqual(
            me_lifecycle.do_backup(self.data_dir, output=str(dest), scope="full"), 0)
        real = me_lifecycle._rename_or_copy

        def flaky2(src, dst):
            s, d = str(src), str(dst)
            if "ready" in s and d == str(self.db):
                raise OSError("injected install failure")
            if "pre-restore-full" in s and d == str(self.tasks_root):
                raise OSError("injected rollback failure")
            return real(src, dst)

        with mock.patch.object(me_lifecycle, "_rename_or_copy",
                               side_effect=flaky2):
            rc = me_lifecycle.do_restore(
                self.data_dir, source=str(dest),
                confirm_destructive=True, scope="full")
        self.assertEqual(rc, 1)
        journal_path = me_lifecycle.incomplete_journal(self.data_dir)
        self.assertIsNotNone(journal_path, "incomplete rollback must block start")
        self.assertEqual(me_lifecycle.do_start(self.data_dir), 1)
        # Recover for real: remaining renames replay, prestate verified.
        self.assertEqual(me_lifecycle.do_restore_recover(self.data_dir), 0)
        self.assertEqual(self.db.read_bytes(), before_db)
        self.assertTrue((self.tasks_root / "task_1" / "output" / "result.md").is_file())
        self.assertIsNone(me_lifecycle.incomplete_journal(self.data_dir))

    def test_recover_with_no_journal_and_completed_journal(self):
        self.assertEqual(me_lifecycle.do_restore_recover(self.data_dir), 0)
        journal_path = (self.data_dir / "backups"
                        / ".restore-journal-20260101T000000Z-1.json")
        journal_path.write_text(json.dumps(
            {"journal_version": me_lifecycle.RESTORE_JOURNAL_VERSION,
             "status": "completed"}), encoding="utf-8")
        self.assertEqual(me_lifecycle.do_restore_recover(self.data_dir), 0)
        self.assertFalse(journal_path.exists(), "completed journal cleared")

    def test_start_refuses_with_interrupted_journal(self):
        journal_path = (self.data_dir / "backups"
                        / ".restore-journal-20260101T000000Z-1.json")
        journal_path.write_text(json.dumps(
            {"journal_version": me_lifecycle.RESTORE_JOURNAL_VERSION,
             "status": "started", "moves": [], "prestate": {},
             "pre_dir": str(self.data_dir / "backups" / "pre-x")}),
            encoding="utf-8")
        self.addCleanup(lambda: journal_path.unlink(missing_ok=True))
        self.assertIsNotNone(me_lifecycle.incomplete_journal(self.data_dir))
        self.assertEqual(me_lifecycle.do_start(self.data_dir), 1)

    def test_full_restore_scrubs_auth_preserves_identity(self):
        with me_lifecycle.sqlite_conn(self.db) as conn:
            conn.execute("CREATE TABLE users (id TEXT PRIMARY KEY, display_name TEXT, "
                         "created_at INTEGER)")
            conn.execute("INSERT INTO users VALUES ('alice', 'Alice', 1)")
            conn.execute("INSERT INTO users VALUES ('bob', 'Bob', 2)")
            conn.execute("CREATE TABLE devices (id TEXT PRIMARY KEY, user_id TEXT, "
                         "secret_hash BLOB, revoked_at INTEGER)")
            conn.execute("INSERT INTO devices VALUES ('dev1', 'alice', x'00', NULL)")
            conn.execute("CREATE TABLE sessions (token_hash BLOB PRIMARY KEY, "
                         "device_id TEXT, user_id TEXT, revoked_at INTEGER)")
            conn.execute("INSERT INTO sessions VALUES (x'01', 'dev1', 'alice', NULL)")
            conn.execute("CREATE TABLE invitations (id TEXT PRIMARY KEY, user_id TEXT, "
                         "consumed_at INTEGER)")
            conn.execute("INSERT INTO invitations VALUES ('inv1', 'bob', NULL)")
            conn.execute("CREATE TABLE conversations (id TEXT PRIMARY KEY, "
                         "owner_id TEXT, title TEXT)")
            conn.execute("INSERT INTO conversations VALUES ('conv1', 'alice', 't')")
            conn.execute("CREATE TABLE messages (id TEXT PRIMARY KEY, "
                         "conversation_id TEXT, body TEXT)")
            conn.execute("INSERT INTO messages VALUES ('m1', 'conv1', 'hello')")
        dest = self.tmp / "full.tar.gz"
        self.assertEqual(
            me_lifecycle.do_backup(self.data_dir, output=str(dest), scope="full"), 0)
        other = setup_home(self, self.tmp, "other home", free_port())
        other_db = Path(me_setup.load_config(other)["service"]["db_path"])
        synthetic_db(other_db, installation_id="other-id")
        self.assertEqual(
            me_lifecycle.do_restore(other, source=str(dest),
                                    confirm_destructive=True, scope="full"), 0)
        with me_lifecycle.sqlite_conn(other_db, read_only=True) as conn:
            dev = conn.execute("SELECT revoked_at FROM devices WHERE id='dev1'").fetchone()
            sess = conn.execute("SELECT revoked_at FROM sessions").fetchone()
            inv = conn.execute(
                "SELECT consumed_at FROM invitations WHERE id='inv1'").fetchone()
            users = sorted(r[0] for r in conn.execute("SELECT id FROM users").fetchall())
            msgs = conn.execute("SELECT body FROM messages WHERE id='m1'").fetchone()
            inst = conn.execute(
                "SELECT value FROM meta WHERE key='installation_id'").fetchone()
        self.assertIsNotNone(dev[0], "restored device must be revoked")
        self.assertIsNotNone(sess[0], "restored session must be revoked")
        self.assertIsNotNone(inv[0], "restored invitation must be consumed")
        self.assertEqual(users, ["alice", "bob"], "identity/users preserved")
        self.assertEqual(msgs[0], "hello", "household data preserved")
        self.assertEqual(inst[0], "full-test-id-1")
        cfg = me_setup.load_config(other)
        self.assertEqual(cfg["installation_id"], "full-test-id-1",
                         "restored home identity adopted, never an input ID")

    def test_scope_mismatch_refused(self):
        db_snap = self.tmp / "snap.sqlite"
        self.assertEqual(
            me_lifecycle.do_backup(self.data_dir, output=str(db_snap), scope="db"), 0)
        full = self.tmp / "full.tar.gz"
        self.assertEqual(
            me_lifecycle.do_backup(self.data_dir, output=str(full), scope="full"), 0)
        self.assertEqual(
            me_lifecycle.do_restore(self.data_dir, source=str(full),
                                    confirm_destructive=True, scope="db"), 2)
        self.assertEqual(
            me_lifecycle.do_restore(self.data_dir, source=str(db_snap),
                                    confirm_destructive=True, scope="full"), 2)


class FullBackupLive(unittest.TestCase):
    """Real home + fixture bridge: waiting_input checkpoint backup in home A,
    restore into a DIFFERENT home B, fresh pairing, answer -> completion.
    Skips when H1/H2 are mid-migration."""

    def setUp(self):
        checkout, node = require_h1(self)
        self.checkout, self.node = checkout, node
        framework = me_setup.resolve_checkout(
            os.environ.get("ME_HOME_FRAMEWORK_CHECKOUT") or None,
            "ME_HOME_FRAMEWORK_CHECKOUT", "agentic-framework",
            ("docs/runtime-bridge-v1.md",), "agent framework")
        if framework is None:
            self.skipTest("transient dependency: agentic-framework checkout missing")
        self.framework = framework
        self.tmp = Path(tempfile.mkdtemp(prefix="me-full-live-")).resolve()
        self.addCleanup(lambda: shutil.rmtree(self.tmp, ignore_errors=True))
        self.data_dir = self.tmp / "home A"
        self.port = free_port()
        # Home B: different path (with spaces) and port -- the cross-path case
        # that proves pending.json workspace rebasing works.
        self.data_dir_b = self.tmp / "home B with spaces"
        self.port_b = free_port()
        self.addCleanup(self._ensure_stopped)

    def _ensure_stopped(self):
        for dd in (getattr(self, "data_dir", None),
                   getattr(self, "data_dir_b", None)):
            if dd is None:
                continue
            try:
                me_lifecycle.do_stop(dd, force=True)
            except Exception:
                pass

    def _api(self, method, path, body=None, token=None, port=None):
        import urllib.request
        import urllib.error

        data = json.dumps(body).encode() if body is not None else None
        headers = {"Content-Type": "application/json"}
        if token:
            headers["Authorization"] = f"Bearer {token}"
        req = urllib.request.Request(
            f"http://127.0.0.1:{port if port is not None else self.port}{path}",
            data=data, headers=headers, method=method)
        try:
            with urllib.request.urlopen(req, timeout=10) as r:
                raw = r.read().decode()
                return r.status, json.loads(raw) if raw else {}
        except urllib.error.HTTPError as e:
            return e.code, json.loads(e.read().decode())

    def _pair(self, user, data_dir=None, port=None):
        dd = data_dir if data_dir is not None else self.data_dir
        buf = io.StringIO()
        with contextlib.redirect_stdout(buf):
            rc = me_lifecycle.main(["bootstrap", "--data-dir", str(dd),
                                    "--user", user])
        self.assertEqual(rc, 0)
        inv = json.loads(buf.getvalue())
        s, paired = self._api("POST", "/v1/pair",
                              {"invitation_id": inv["invitation_id"],
                               "invitation_secret": inv["invitation_secret"],
                               "device_label": "live",
                               "installation_id": inv["installation_id"]},
                              port=port)
        self.assertEqual(s, 201, paired)
        s, sess = self._api("POST", "/v1/sessions",
                            {"device_id": paired["device_id"],
                             "device_secret": paired["device_secret"]},
                            port=port)
        self.assertEqual(s, 201, sess)
        return sess["token"]

    def _wait_task(self, token, task_id, wants, timeout=120):
        for _ in range(timeout):
            s, cur = self._api("GET", f"/v1/tasks/{task_id}", token=token)
            self.assertEqual(s, 200, cur)
            if cur.get("status") in wants:
                return cur
            time.sleep(1)
        self.fail(f"task {task_id} never reached {wants}")

    def _wait_task_b(self, token, task_id, wants, timeout=120):
        for _ in range(timeout):
            s, cur = self._api("GET", f"/v1/tasks/{task_id}", token=token,
                               port=self.port_b)
            self.assertEqual(s, 200, cur)
            if cur.get("status") in wants:
                return cur
            time.sleep(1)
        self.fail(f"task {task_id} never reached {wants}")

    def test_waiting_input_backup_restore_resume(self):
        env = {"ME_HOME_INFRA_CHECKOUT": str(self.checkout),
               "ME_HOME_NODE": self.node,
               "ME_HOME_FRAMEWORK_CHECKOUT": str(self.framework)}
        with mock.patch.dict(os.environ, env):
            with mock.patch.dict(os.environ):
                os.environ.pop("ME_HOME_SKIP_BRIDGE_PROBE", None)
                rc = me_setup.do_setup(
                    self.data_dir, "127.0.0.1", self.port,
                    model_provider="fixture", allow_fixture_model=True)
            self.assertEqual(rc, 0)
            bridge = me_setup.load_config(self.data_dir)["runtime_bridge"]
            if bridge.get("status") != "importable":
                self.skipTest(f"transient dependency: {bridge.get('detail')}")
            self.assertEqual(me_lifecycle.do_start(self.data_dir), 0)
            alice_tok = self._pair("alice")
            bob_tok = self._pair("bob")
            s, conv = self._api("POST", "/v1/conversations", {"title": "live"},
                                token=alice_tok)
            self.assertEqual(s, 201, conv)
            conv_id = conv["id"]
            s, msg = self._api("POST", f"/v1/conversations/{conv_id}/messages",
                               {"body": "remember the blue marble"}, token=alice_tok)
            self.assertEqual(s, 201, msg)
            s, bconv = self._api("POST", "/v1/conversations", {"title": "bob"},
                                 token=bob_tok)
            self.assertEqual(s, 201, bconv)
            s, bmsg = self._api(
                "POST", f"/v1/conversations/{bconv['id']}/messages",
                {"body": "bob household note"}, token=bob_tok)
            self.assertEqual(s, 201, bmsg)
            s, done_task = self._api(
                "POST", f"/v1/conversations/{conv_id}/tasks",
                {"title": "quick", "request": "say hello"}, token=alice_tok)
            self.assertEqual(s, 201, done_task)
            done = self._wait_task(alice_tok, done_task["id"], {"succeeded"})
            self.assertTrue(done.get("artifact_ids"), done)
            s, task = self._api(
                "POST", f"/v1/conversations/{conv_id}/tasks",
                {"title": "needs input", "request": "ASK: what color?"},
                token=alice_tok)
            self.assertEqual(s, 201, task)
            waiting = self._wait_task(alice_tok, task["id"], {"waiting_input"})
            self.assertTrue(waiting.get("questions"), waiting)
            qid = waiting["questions"][0]["id"]
            # Runtime checkpoint files exist for the waiting run, with the
            # absolute home-A workspace binding the bridge will enforce.
            cfg = me_setup.load_config(self.data_dir)
            tasks_root = Path(cfg["service"]["db_path"]).parent / "tasks"
            ws = tasks_root / task["id"]
            self.assertTrue((ws / ".me_runtime" / "graph.db").is_file())
            pending_a = json.loads(
                (ws / ".me_runtime" / "pending.json").read_text(encoding="utf-8"))
            self.assertEqual(pending_a["workspace"], str(ws))
            self.assertEqual(pending_a["run_id"], task["id"])
            done_ws = tasks_root / done_task["id"]
            self.assertTrue((done_ws / "output" / "result.md").is_file())
            old_token = alice_tok
            self.assertEqual(me_lifecycle.do_stop(self.data_dir, force=True), 0)
            archive = self.tmp / "household-full.tar.gz"
            with mock.patch.dict(os.environ, env):
                self.assertEqual(
                    me_lifecycle.do_backup(self.data_dir, output=str(archive),
                                           scope="full"), 0)
            self.assertEqual(stat.S_IMODE(archive.stat().st_mode), 0o600)
            # Restore into a DIFFERENT managed home B (path + port differ).
            # Installation identity is adopted from the archive (explicit via
            # --confirm-destructive); B becomes this household's home: point
            # any backend endpoint registration at B's host/port afterwards.
            with mock.patch.dict(os.environ, env):
                os.environ.pop("ME_HOME_SKIP_BRIDGE_PROBE", None)
                rc = me_setup.do_setup(
                    self.data_dir_b, "127.0.0.1", self.port_b,
                    model_provider="fixture", allow_fixture_model=True,
                    min_disk_mib=32)
            self.assertEqual(rc, 0)
            with mock.patch.dict(os.environ, env):
                self.assertEqual(
                    me_lifecycle.do_restore(self.data_dir_b, source=str(archive),
                                            confirm_destructive=True,
                                            scope="full"), 0)
            cfg_b = me_setup.load_config(self.data_dir_b)
            ws_b = Path(cfg_b["service"]["db_path"]).parent / "tasks" / task["id"]
            self.assertTrue((ws_b / ".me_runtime" / "graph.db").is_file())
            # The absolute binding was rebased to B; run/user/conversation
            # identity is preserved, so the bridge accepts the resume.
            pending_b = json.loads(
                (ws_b / ".me_runtime" / "pending.json").read_text(encoding="utf-8"))
            self.assertEqual(pending_b["workspace"], str(ws_b))
            for field in ("run_id", "user_id", "conversation_id"):
                self.assertEqual(pending_b[field], pending_a[field])
            done_ws_b = Path(cfg_b["service"]["db_path"]).parent / "tasks" \
                / done_task["id"]
            self.assertTrue((done_ws_b / "output" / "result.md").is_file())
            with me_lifecycle.sqlite_conn(
                    Path(cfg_b["service"]["db_path"]), read_only=True) as conn:
                bodies = [r[0] for r in conn.execute(
                    "SELECT body FROM messages WHERE conversation_id=?",
                    (conv_id,)).fetchall()]
            self.assertIn("remember the blue marble", bodies)
            self.assertEqual(cfg_b["installation_id"], cfg["installation_id"])
            # Old sessions are dead after the scrub: fresh pairing required.
            self.assertEqual(me_lifecycle.do_start(self.data_dir_b), 0)
            try:
                s, _ = self._api("GET", "/v1/conversations", token=old_token,
                                 port=self.port_b)
                self.assertEqual(s, 401, "restored old session must be revoked")
                fresh_tok = self._pair("alice", data_dir=self.data_dir_b,
                                       port=self.port_b)
                s, cur = self._api("GET", f"/v1/tasks/{task['id']}",
                                   token=fresh_tok, port=self.port_b)
                self.assertEqual(s, 200, cur)
                self.assertEqual(cur.get("status"), "waiting_input", cur)
                s, answered = self._api(
                    "POST", f"/v1/tasks/{task['id']}/inputs",
                    {"inputs": [{"id": qid, "answer": "blue"}]},
                    token=fresh_tok, port=self.port_b)
                self.assertEqual(s, 200, answered)
                resumed = self._wait_task_b(fresh_tok, task["id"],
                                            {"succeeded", "failed"})
                self.assertEqual(resumed.get("status"), "succeeded", resumed)
                self.assertIn("blue", resumed.get("output", ""), resumed)
                # Bob's household data survived; his old session is revoked too.
                s, _ = self._api("GET", "/v1/conversations", token=bob_tok,
                                 port=self.port_b)
                self.assertEqual(s, 401)
                bob_fresh = self._pair("bob", data_dir=self.data_dir_b,
                                       port=self.port_b)
                s, convs = self._api("GET", "/v1/conversations",
                                     token=bob_fresh, port=self.port_b)
                self.assertEqual(s, 200, convs)
                self.assertTrue(any(c["id"] == bconv["id"]
                                    for c in convs["conversations"]), convs)
            finally:
                self.assertEqual(
                    me_lifecycle.do_stop(self.data_dir_b, force=True), 0)


if __name__ == "__main__":
    unittest.main()
