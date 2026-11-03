#!/usr/bin/env python3
"""Autonomous OpenCode installer/supervisor (setup-infra task C).

PRIMARY integration checklist: FULL upstream OpenBot platform + licensed
self-hosted Intelligence (user steering: "Allow licensed, self-hosted
CopilotKit Intelligence"). All household conversations/memory stay on
HOME-OWNED self-hosted Intelligence; no managed-cloud default.

Parent/supervisor is the SOLE authority for completion. The OpenCode agent
never selects completion criteria: every turn is followed by STATIC trusted
verifiers (this file, executed in the parent process) that check real
prerequisites / config / storage / authoritative DB identity / live home
health / managed service runtime / exact model profile (probed, never
flags-only) / upstream platform (native API + source pin + licensed
Intelligence + owner token) / backup coverage. Conversational "done" or CLI
exit 0 NEVER counts unless the profile's required checks ALL PASS with real
evidence.

Profiles (explicit, never agent-chosen):
- production (default): full platform bar. Terminal state READY only when
  every required check passes with evidence.
- configure: config-only runs. Terminal state CONFIGURED (explicitly NOT
  complete, never claims READY).
- test: named TEST profile only; fixture providers may complete here with a
  clearly-TEST status (TEST_READY), never production READY.

Usage:
    python3 scripts/me_supervisor.py start   --data-dir DIR --workspace DIR [options]
    python3 scripts/me_supervisor.py status  --data-dir DIR
    python3 scripts/me_supervisor.py resume  --data-dir DIR [options]
    python3 scripts/me_supervisor.py recheck --data-dir DIR [--profile P]
    python3 scripts/me_supervisor.py install-check [--opencode-bin PATH] [--allow-install]

State: <data-dir>/supervisor/run.json (0600, dir 0700, atomic, versioned).
Lock:  <data-dir>/supervisor/lock (fcntl exclusive, crash-safe; stale fenced).

Exit codes: 0 ok (READY/CONFIGURED/TEST_READY), 1 operation/state
(FAILED/STALLED), 2 usage/validation (incl. concurrent-run refusal),
3 prerequisite/install refusal, 4 NEEDS_INPUT (genuine external
credential/license/hardware/user-approval gate -- parked, never
fake-completed).
"""

from __future__ import annotations

import argparse
import fcntl
import hashlib
import json
import os
import platform
import re
import shutil
import signal
import subprocess
import sys
import tempfile
import threading
import time
import urllib.error
import urllib.parse
import urllib.request
import uuid
from dataclasses import dataclass
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

import me_setup

SCHEMA_VERSION = 1
SUPERVISOR_DIRNAME = "supervisor"
STATE_FILENAME = "run.json"
LOCK_FILENAME = "lock"

DEFAULT_MAX_ATTEMPTS = 8
DEFAULT_ATTEMPT_TIMEOUT_S = 300
DEFAULT_WALL_TIMEOUT_S = 1800
DEFAULT_MAX_STAGNANT = 3
DEFAULT_MAX_OUTPUT_BYTES = 256 * 1024
DEFAULT_MAX_EVENTS = 200
DEFAULT_PER_LINE_CAP = 4096
DEFAULT_KEPT_LINES = 200
KILL_GRACE_S = 5

# Official primary install surface (verified 2026-11-03 against the live
# installer + docs; upstream moved sst/opencode -> anomalyco/opencode):
# docs https://opencode.ai/docs (CLI page documents `run --format json`,
# `-s/--session`, `--auto`, `--agent`, `-m/--model`, `--dir`).
# Primary installer https://opencode.ai/install (307 -> the versioned script
# below). The v1 install script supports `--version X` / `$VERSION`, refuses
# >=2.x, installs user-local to ~/.opencode/bin (no sudo), and resolves
# release assets from the official releases page.
OFFICIAL_INSTALL_URL = "https://opencode.ai/install"
OFFICIAL_INSTALL_HOSTS = ("opencode.ai", "www.opencode.ai",
                          "raw.githubusercontent.com")
OFFICIAL_RELEASES_URL = "https://github.com/anomalyco/opencode/releases"
INSTALL_SCRIPT_MAX_BYTES = 1 * 1024 * 1024
INSTALL_WHOLE_TIMEOUT_S = 60
INSTALL_MAX_REDIRECTS = 3
SUPPORTED_SYSTEMS = ("darwin", "linux")
SUPPORTED_ARCHES = ("arm64", "aarch64", "x86_64", "amd64")

PROFILES = ("production", "configure", "test")
MODES = ("dev", "provision")
TERMINAL_OK = ("READY", "CONFIGURED", "TEST_READY")
STATUSES = ("RUNNING", "READY", "CONFIGURED", "TEST_READY",
            "NEEDS_INPUT", "STALLED", "FAILED")

# Operator-owned inputs (env/file only; NEVER read user auth secrets such as
# ~/.config/opencode/auth.json, keychains, or personal keys -- this file never
# references those paths, and provider keys stay in the operator shell).
ENV_OPENAI_KEY = "OPENAI_API_KEY"
ENV_ANTHROPIC_KEY = "ANTHROPIC_API_KEY"
ENV_GENERIC_MODEL_KEY = "ME_RUNTIME_MODEL_API_KEY"
ENV_INTELLIGENCE_URL = "ME_INTELLIGENCE_URL"
ENV_INTELLIGENCE_LICENSE_FILE = "ME_INTELLIGENCE_LICENSE_FILE"
ENV_UPSTREAM_CONTRACT = "ME_UPSTREAM_CONTRACT"
ENV_UPSTREAM_DOCTOR = "ME_UPSTREAM_DOCTOR"
ENV_UPSTREAM_DOCTOR_SHA = "ME_UPSTREAM_DOCTOR_SHA256"
ENV_UPSTREAM_DOCTOR_MANIFEST = "ME_UPSTREAM_DOCTOR_MANIFEST"
ENV_UPSTREAM_APPROVED_PATCHES = "ME_UPSTREAM_APPROVED_PATCHES"
ENV_REQUIRE_BACKUP = "ME_REQUIRE_BACKUP"
LICENSE_FILE_MAX_BYTES = 16 * 1024
PROBE_WHOLE_TIMEOUT_S = 10
PROBE_MAX_BYTES = 64 * 1024

# Trusted upstream-doctor contract (A-owned infra-server, C invokes).
# Protocol: upstream-platform-v1 (src/upstream-doctor.mjs via
# `node --experimental-transform-types src/cli.mjs upstream-doctor` with
# probing ENABLED). A cached/operator-written JSON report can NEVER
# authorize READY -- only a live subprocess invocation with strict schema.
UPSTREAM_DOCTOR_PROTOCOL = "upstream-platform-v1"
UPSTREAM_PIN = "6bfee780c8e8d05141375ea55ebde33eefb3dbc0"
UPSTREAM_REPO = "CopilotKit/OpenBot"
DOCTOR_TIMEOUT_S = 60
DOCTOR_MAX_BYTES = 64 * 1024
DOCTOR_ANCHOR_FILENAME = "doctor.sha256"
# Versioned full-evidence contract C requires (fail-closed until present).
# Published early in results/setup-wire-contract.json `doctor` section so A
# can implement it in results/setup-doctor-contract.json: the live doctor
# report must carry this marker (top-level or checks.doctor_contract) AND
# every name in DOCTOR_REQUIRED_EVIDENCE with verified values, or READY is
# refused. No guessed endpoints; no fake checks.
DOCTOR_CONTRACT_REQUIRED = "upstream-platform-v1/full.1"
# Required READY evidence names (dotted paths into the live report). Missing,
# unknown-sentinel, or probe:false on ANY of these refuses READY.
DOCTOR_REQUIRED_EVIDENCE = (
    "checks.mode",
    "checks.upstream",
    "checks.sourcePin",
    "checks.config",
    "checks.supervisor",
    "checks.perUserBoundary",
    "checks.versions",
    "checks.license",
    "checks.upstreamServer",
    "checks.postgres",
    "checks.intelligence",
    "checks.model",
    "checks.telemetry",
    "checks.datastore",
    "checks.probe",
)
# Module-closure anchoring bounds (P0-2): the entrypoint hash alone is NOT
# trust (imported modules are mutable). The closure = every *.mjs under the
# doctor module root + the vendor upstream manifest (+ approved patches when
# declared). Bounded counts/sizes; symlinks refused.
DOCTOR_CLOSURE_MAX_FILES = 100
DOCTOR_CLOSURE_MAX_FILE_BYTES = 2 * 1024 * 1024
DOCTOR_CLOSURE_MAX_TOTAL_BYTES = 16 * 1024 * 1024

# Test seam for the installer executor (tests set a fake; production path
# below never runs in unit tests). Also honored: dry_run short-circuits
# before any network.
_INSTALL_RUNNER = None

# ---------------------------------------------------------------------------
# redaction / logging (never persist secrets or raw prompts with secrets)


def redact(text: str) -> str:
    redacted = me_setup.redact(text or "")
    # Extra: home_token shape + activation secrets + bearer-ish long secrets.
    redacted = re.sub(r"(me_home_[A-Za-z0-9_\-]{8,})",
                      r"***redacted***", redacted)
    redacted = re.sub(r"(?i)(activationSecret\s*[:=]\s*)([^\s,;\"']+)",
                      r"\1***redacted***", redacted)
    redacted = re.sub(r"(?i)((?:license[_-]?key|api[_-]?key)\s*[:=]\s*)"
                      r"([^\s,;\"']+)",
                      r"\1***redacted***", redacted)
    return redacted


def log(msg: str) -> None:
    print(redact(msg), flush=True)


def err(msg: str) -> None:
    print(redact(msg), file=sys.stderr, flush=True)


# ---------------------------------------------------------------------------
# interruption (SIGINT/SIGTERM set a stop flag; the loop persists RUNNING and
# returns 130/143 WITHOUT launching a new turn -- the handler never waits)


_STOP_REQUESTED: dict = {"signo": None}
_child_proc: subprocess.Popen | None = None
_doctor_proc: subprocess.Popen | None = None


def _handle_term(signum, frame):
    _STOP_REQUESTED["signo"] = signum
    # Reap-owned procs only: the agent child and the doctor child (both in
    # their own process groups). The handler never waits; loops observe the
    # flag, terminate groups, persist state, and return.
    for attr in ("_child_proc", "_doctor_proc"):
        proc = globals().get(attr)
        if proc is not None and proc.poll() is None:
            try:
                os.killpg(os.getpgid(proc.pid), signal.SIGTERM)
            except (OSError, ProcessLookupError):
                pass


def stop_code() -> int:
    signo = _STOP_REQUESTED.get("signo")
    if signo in (signal.SIGINT, 2):
        return 130
    return 143


# ---------------------------------------------------------------------------
# OpenCode discovery (default installed CLI; never XDG-override, never modify
# an existing DEV CLI). Order: explicit > OPENCODE_BIN env > PATH >
# ~/.opencode/bin/opencode.


def discover_opencode(explicit: str | None = None) -> str | None:
    candidates: list[str] = []
    if explicit:
        candidates.append(explicit)
    env = os.environ.get("OPENCODE_BIN", "").strip()
    if env:
        candidates.append(env)
    which = shutil.which("opencode")
    if which:
        candidates.append(which)
    home_bin = Path.home() / ".opencode" / "bin" / "opencode"
    candidates.append(str(home_bin))
    for cand in candidates:
        if cand and Path(cand).is_file() and os.access(cand, os.X_OK):
            return cand
    return None


def opencode_version(binary: str) -> str:
    try:
        out = subprocess.check_output(
            [binary, "--version"], stderr=subprocess.STDOUT,
            timeout=15, text=True)
        return out.strip()[:64]
    except (OSError, subprocess.SubprocessError) as exc:
        return f"unavailable: {exc}"


_AUTO_SUPPORT: dict[str, bool] = {}


def supports_auto(binary: str) -> bool:
    """Feature-detect `run --auto` on the installed CLI (cached, bounded)."""
    if binary in _AUTO_SUPPORT:
        return _AUTO_SUPPORT[binary]
    try:
        out = subprocess.check_output(
            [binary, "run", "--help"], stderr=subprocess.STDOUT,
            timeout=10, text=True)
        ok = "--auto" in out
    except (OSError, subprocess.SubprocessError):
        ok = False
    _AUTO_SUPPORT[binary] = ok
    return ok


# ---------------------------------------------------------------------------
# Official installer (missing-binary path only; never modifies existing)

class _NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        raise urllib.error.HTTPError(
            newurl, code, "redirect refused (supervisor follows manually)",
            headers, fp)


def _fetch_installer_script() -> tuple[bytes, str]:
    """Download the official installer with bounded redirects/size/time.

    Returns (script_bytes, final_url). Only https hosts in
    OFFICIAL_INSTALL_HOSTS are followed (max INSTALL_MAX_REDIRECTS).
    Raises RuntimeError on any violation.
    """
    opener = urllib.request.build_opener(
        _NoRedirect, urllib.request.ProxyHandler({}))
    url = OFFICIAL_INSTALL_URL
    final = url
    for _ in range(INSTALL_MAX_REDIRECTS + 1):
        parts = urllib.parse.urlsplit(url)
        if parts.scheme != "https" or parts.hostname not in OFFICIAL_INSTALL_HOSTS:
            raise RuntimeError(
                f"installer URL outside trusted hosts: {url} "
                f"(trusted: {list(OFFICIAL_INSTALL_HOSTS)})")
        req = urllib.request.Request(
            url, headers={"User-Agent": "me-supervisor/1"})
        try:
            with opener.open(req, timeout=INSTALL_WHOLE_TIMEOUT_S) as resp:
                if getattr(resp, "status", 200) != 200:
                    raise RuntimeError(
                        f"installer download status {resp.status}")
                final = resp.geturl() or url
                parts_f = urllib.parse.urlsplit(final)
                if parts_f.scheme != "https" or \
                        parts_f.hostname not in OFFICIAL_INSTALL_HOSTS:
                    raise RuntimeError(
                        f"installer landed outside trusted hosts: {final}")
                data = resp.read(INSTALL_SCRIPT_MAX_BYTES + 1)
        except urllib.error.HTTPError as exc:
            raise RuntimeError(f"installer download refused: {exc}")
        except (urllib.error.URLError, TimeoutError, OSError) as exc:
            raise RuntimeError(f"installer download failed: {exc}")
        if len(data) > INSTALL_SCRIPT_MAX_BYTES:
            raise RuntimeError("installer script exceeds size bound; refusing")
        return data, final
    raise RuntimeError("installer redirect chain too long; refusing")


def _default_install_impl(*, version: str) -> tuple[bool, str]:
    script, final_url = _fetch_installer_script()
    if len(script) < 200 or b"opencode" not in script.lower():
        raise RuntimeError("installer script failed sanity check; refusing")
    digest = hashlib.sha256(script).hexdigest()
    pinned = os.environ.get("OPENCODE_INSTALLER_SHA256", "").strip().lower()
    if pinned:
        if not re.fullmatch(r"[0-9a-f]{64}", pinned):
            raise RuntimeError("OPENCODE_INSTALLER_SHA256 malformed; refusing")
        if digest != pinned:
            raise RuntimeError(
                "installer script digest does NOT match pinned "
                "OPENCODE_INSTALLER_SHA256; refusing (recorded "
                f"{digest[:16]}...)")
        digest_note = f"digest verified against pinned {pinned[:16]}..."
    else:
        digest_note = (f"digest recorded {digest} (no pinned "
                       "OPENCODE_INSTALLER_SHA256; not verified against "
                       f"releases -- see {OFFICIAL_RELEASES_URL})")
    argv = ["bash", "-s", "--", "--no-modify-path"]
    if version:
        argv += ["--version", version]
    try:
        proc = subprocess.run(
            argv, input=script, stdout=subprocess.PIPE,
            stderr=subprocess.PIPE, timeout=300)
    except (OSError, subprocess.SubprocessError) as exc:
        raise RuntimeError(f"installer execution failed: {exc}")
    if proc.returncode != 0:
        tail = proc.stderr.decode("utf-8", "replace")[-500:]
        raise RuntimeError(f"installer exited {proc.returncode}: "
                           f"{redact(tail)}")
    found = discover_opencode()
    if not found:
        raise RuntimeError("installer finished but no opencode binary found "
                           "(checked PATH and ~/.opencode/bin/opencode)")
    return True, (f"installed via official {final_url} "
                  f"(version={version or 'latest-v1'}; {digest_note}) "
                  f"-> {found} ({opencode_version(found)})")


def install_opencode(target_dir: Path | None = None, *,
                     allow_install: bool = False,
                     pinned_version: str = "",
                     dry_run: bool = False) -> tuple[bool, str]:
    """Install OpenCode ONLY when the binary is missing.

    Never installs/downgrades/modifies an existing DEV CLI. Validates
    platform/arch loudly (no silent unsupported OS). Pinned version via
    pinned_version / OPENCODE_VERSION / OPENCODE_PIN_VERSION (passed as the
    install script's documented --version flag -- the optional pin is REAL,
    not a fake claim). Script digest is recorded, and enforced when the
    operator pins OPENCODE_INSTALLER_SHA256.
    """
    found = discover_opencode()
    if found:
        return False, (f"already installed at {found} "
                       f"({opencode_version(found)}); refusing to modify")
    if not allow_install and not dry_run:
        raise RuntimeError(
            "opencode binary missing; install requires operator consent "
            f"(user-invoked `start`, or explicit --allow-install). Official "
            f"primary installer: {OFFICIAL_INSTALL_URL} "
            f"(releases/checksums: {OFFICIAL_RELEASES_URL})")
    system = platform.system()
    machine = platform.machine()
    if system not in SUPPORTED_SYSTEMS:
        raise RuntimeError(
            f"unsupported OS {system}: refusing silent install "
            f"(supports {list(SUPPORTED_SYSTEMS)}; see {OFFICIAL_RELEASES_URL})")
    if machine.lower() not in SUPPORTED_ARCHES:
        raise RuntimeError(
            f"unsupported arch {machine}: refusing silent install "
            f"(see {OFFICIAL_RELEASES_URL})")
    version = (pinned_version or os.environ.get("OPENCODE_VERSION", "")
               or os.environ.get("OPENCODE_PIN_VERSION", "")).strip()
    version = version.lstrip("v")
    if version and not re.fullmatch(r"\d+\.\d+\.\d+", version):
        raise RuntimeError(f"pinned version {version!r} is not X.Y.Z; refusing")
    if version and version.split(".")[0] != "1":
        raise RuntimeError(
            f"pinned version {version!r} is not on the v1 installer track "
            "(this supervisor manages OpenCode 1; refusing to guess)")
    detail = (f"official installer {OFFICIAL_INSTALL_URL} "
              f"(system={system} arch={machine} "
              f"version={version or 'latest-v1'}; "
              f"checksums: {OFFICIAL_RELEASES_URL})")
    if dry_run:
        return False, f"dry-run: would install via {detail}"
    if _INSTALL_RUNNER is not None:
        return _INSTALL_RUNNER(version=version)
    return _default_install_impl(version=version)


# ---------------------------------------------------------------------------
# No-ambient-proxy bounded JSON probes (model daemon / upstream native APIs)


def _no_proxy_no_redirect_opener():
    return urllib.request.build_opener(
        _NoRedirect, urllib.request.ProxyHandler({}))


def fetch_json(url: str, *, headers: dict | None = None,
               timeout_s: int = PROBE_WHOLE_TIMEOUT_S) -> dict:
    """Bounded GET returning parsed JSON. No proxy, no redirects, capped body.

    Redirects are refused (never forward Authorization/keys), so a 3xx from
    an API endpoint surfaces as a probe failure, not a silent follow.
    """
    parts = urllib.parse.urlsplit(url)
    if parts.scheme not in ("http", "https") or not parts.hostname:
        raise ValueError(f"bad probe URL: {url[:80]}")
    req = urllib.request.Request(url, headers=headers or {},
                                 method="GET")
    opener = _no_proxy_no_redirect_opener()
    try:
        with opener.open(req, timeout=timeout_s) as resp:
            if getattr(resp, "status", 200) != 200:
                raise RuntimeError(f"probe status {resp.status}")
            raw = resp.read(PROBE_MAX_BYTES + 1)
    except urllib.error.HTTPError as exc:
        try:
            exc.close()
        except OSError:
            pass
        raise RuntimeError(f"probe HTTP {exc.code}")
    except (urllib.error.URLError, TimeoutError, OSError,
            ValueError) as exc:
        raise RuntimeError(f"probe transport failed: {exc}")
    if len(raw) > PROBE_MAX_BYTES:
        raise RuntimeError("probe body exceeds cap")
    try:
        doc = json.loads(raw.decode("utf-8"))
    except (UnicodeDecodeError, ValueError) as exc:
        raise RuntimeError(f"probe body is not JSON: {exc}")
    if not isinstance(doc, dict):
        raise RuntimeError("probe body is not a JSON object")
    return doc


def _clamp_timeout(opts: dict, default_s: float) -> float:
    """Clamp one network/probe timeout to the SHARED remaining ACTIVE budget.

    Full run_checks fans out to several bounded probes; without clamping,
    per-check timeouts stack past the wall budget (8s*N overshoot). Drive
    sets opts["_deadline_mono"]; status/recheck leave it unset (defaults).
    Minimum 1s so a nearly-exhausted budget still fails fast, never hangs.
    """
    try:
        deadline = opts.get("_deadline_mono")
        if deadline is None:
            return max(1.0, float(default_s))
        return max(1.0, min(float(default_s), float(deadline) - time.monotonic()))
    except (TypeError, ValueError):
        return max(1.0, float(default_s))


def probe_ollama(endpoint: str, timeout_s: float = PROBE_WHOLE_TIMEOUT_S
                 ) -> tuple[bool, str]:
    """Local engine probe: GET {endpoint}/api/tags must answer 200 + models."""
    base = (endpoint or "").rstrip("/")
    if not base:
        return False, "no local endpoint configured"
    try:
        doc = fetch_json(base + "/api/tags", timeout_s=int(timeout_s))
    except (RuntimeError, ValueError) as exc:
        return False, f"ollama unreachable at {base}: {exc}"
    if not isinstance(doc.get("models"), list):
        return False, f"ollama at {base} answered without models list"
    return True, f"ollama ok at {base} ({len(doc['models'])} models)"


def probe_remote_model(provider: str, endpoint: str, api_key: str,
                       timeout_s: float = PROBE_WHOLE_TIMEOUT_S
                       ) -> tuple[bool, str]:
    """Remote engine probe against the EXACT configured endpoint + key."""
    base = (endpoint or "").rstrip("/")
    if provider == "openai":
        url = base + "/v1/models"
        headers = {"Authorization": "Bearer " + api_key,
                   "Accept": "application/json"}
    elif provider == "anthropic":
        url = base + "/v1/models"
        headers = {"x-api-key": api_key,
                   "anthropic-version": "2023-06-01",
                   "Accept": "application/json"}
    else:
        return False, f"unknown remote provider {provider!r}"
    try:
        doc = fetch_json(url, headers=headers, timeout_s=int(timeout_s))
    except (RuntimeError, ValueError) as exc:
        return False, f"{provider} probe failed at {base}: {exc}"
    if not isinstance(doc.get("data"), list):
        return False, f"{provider} at {base} answered without data list"
    return True, f"{provider} ok at {base} ({len(doc['data'])} models)"


def probe_docker(timeout_s: float = 15) -> tuple[bool, str]:
    """Real hardware check: docker daemon reachable. Parked, never stubbed."""
    daemon = shutil.which("docker")
    if not daemon:
        return False, "docker binary not found"
    try:
        out = subprocess.check_output(
            [daemon, "info", "--format", "{{.ServerVersion}}"],
            stderr=subprocess.STDOUT, timeout=max(1.0, float(timeout_s)),
            text=True)
    except (OSError, subprocess.SubprocessError) as exc:
        return False, f"docker daemon unreachable: {exc}"
    ver = out.strip().splitlines()
    return True, f"docker ok (server {ver[0][:32] if ver else 'unknown'})"


def probe_intelligence(url: str, timeout_s: float = PROBE_WHOLE_TIMEOUT_S
                       ) -> tuple[bool, str]:
    """Licensed self-hosted Intelligence deployment probe (bounded /healthz)."""
    base = (url or "").rstrip("/")
    if not base:
        return False, "no intelligence URL configured"
    try:
        doc = fetch_json(base + "/healthz", timeout_s=int(timeout_s))
    except (RuntimeError, ValueError) as exc:
        return False, f"intelligence unreachable at {base}: {exc}"
    if doc.get("status") != "ok":
        return False, f"intelligence at {base} status != ok"
    keys = sorted(k for k in doc.keys())[:8]
    return True, f"intelligence ok at {base} (keys: {','.join(keys)})"


# ---------------------------------------------------------------------------
# STATIC trusted checks (parent process only; the agent can never add/waive).
# Each handler returns CheckResult. Only code in this file (register_check at
# import time) extends the registry -- never LLM output.

@dataclass
class CheckResult:
    id: str
    status: str  # PASS | FAIL | NEEDS_INPUT | OPTIONAL
    evidence: str = ""
    next_action: str = ""
    needs_reason: str = ""

    def ok_required(self) -> bool:
        return self.status == "PASS"


CHECKS: dict[str, dict] = {}


def register_check(check_id: str, *, required: bool, description: str = "",
                   handler=None):
    def _add(fn):
        CHECKS[check_id] = {"handler": fn, "required": required,
                            "description": description}
        return fn
    if handler is not None:
        return _add(handler)
    return _add


def _profile(opts: dict) -> str:
    p = str(opts.get("profile", "production") or "production")
    return p if p in PROFILES else "production"


def _service_required(opts: dict) -> bool:
    return _profile(opts) == "production" or bool(opts.get("require_service"))


def _http_loopback_ok(opts: dict) -> bool:
    return bool(opts.get("test_allow_http_loopback"))


@register_check("opencode_cli", required=True,
                description="OpenCode CLI binary present and --version works")
def check_opencode_cli(data_dir: Path, cfg: dict | None, opts: dict) -> CheckResult:
    explicit = opts.get("opencode_bin") or ""
    found = discover_opencode(explicit or None)
    if not found:
        if opts.get("allow_install"):
            return CheckResult("opencode_cli", "FAIL",
                               evidence="opencode binary missing",
                               next_action="Install OpenCode via the official primary "
                               f"installer {OFFICIAL_INSTALL_URL} "
                               f"(checksums {OFFICIAL_RELEASES_URL}), then re-run "
                               "`opencode --version`.")
        return CheckResult("opencode_cli", "NEEDS_INPUT",
                           evidence="opencode binary missing on target",
                           needs_reason="opencode-not-installed: operator consent "
                           "required to run the official installer "
                           f"({OFFICIAL_INSTALL_URL}); user-invoked `start` "
                           "installs it by default (opt out with --no-install), "
                           "or install manually and retry")
    ver = opencode_version(found)
    if ver.startswith("unavailable"):
        return CheckResult("opencode_cli", "FAIL",
                           evidence=f"{found}: {ver}",
                           next_action=f"Repair the OpenCode install so `{found} "
                           "--version` exits 0 (reinstall via "
                           f"{OFFICIAL_INSTALL_URL} only with operator consent).")
    return CheckResult("opencode_cli", "PASS",
                       evidence=f"{found} {ver}")


@register_check("prereqs", required=True,
                description="setup-infra prerequisites (os/node/python/loopback/disk)")
def check_prereqs(data_dir: Path, cfg: dict | None, opts: dict) -> CheckResult:
    host = "127.0.0.1"
    port = me_setup.DEFAULT_PORT
    if cfg:
        try:
            host = str(cfg["service"]["host"])
            port = int(cfg["service"]["port"])
        except (KeyError, ValueError, TypeError):
            pass
    try:
        results = me_setup.check_prerequisites(data_dir, host, port)
    except Exception as exc:
        return CheckResult("prereqs", "FAIL", evidence=f"probe error: {exc}",
                           next_action="Fix the Python environment so prerequisites "
                           "can be probed, then re-run recheck.")
    bad = [f"{n}: {d}" for n, ok, d in results
           if not ok and n in ("os", "non-root", "node24", "python",
                               "port-range", "loopback-host", "disk")]
    if bad:
        return CheckResult("prereqs", "FAIL",
                           evidence="; ".join(bad)[:800],
                           next_action="Fix prerequisites: install Node "
                           ">=24.18.0 <25, free disk to >=1 GiB, use a "
                           "loopback host and unprivileged port, then re-run "
                           "`python3 scripts/me_setup.py setup --data-dir DIR`.")
    return CheckResult("prereqs", "PASS",
                       evidence="; ".join(f"{n}=ok" for n, ok, _ in results if ok)[:500])


@register_check("config", required=True,
                description="generated config valid, no embedded secrets")
def check_config(data_dir: Path, cfg: dict | None, opts: dict) -> CheckResult:
    try:
        loaded = me_setup.load_config(data_dir)
    except me_setup.SetupError as exc:
        return CheckResult("config", "FAIL", evidence=str(exc)[:500],
                           next_action="Run `python3 scripts/me_setup.py setup "
                           "--data-dir DIR` (rerunnable; preserves household data) "
                           "to generate a valid config.json + service.env.")
    return CheckResult("config", "PASS",
                       evidence=f"schema v{loaded.get('schema_version')} "
                       f"installation_id={loaded.get('installation_id')}")


@register_check("storage", required=True,
                description="layout dirs exist, secrets 0700, no secret leakage")
def check_storage(data_dir: Path, cfg: dict | None, opts: dict) -> CheckResult:
    missing = []
    for sub in me_setup.SERVICE_SUBDIRS:
        p = data_dir / sub
        if not p.is_dir():
            missing.append(sub)
    if missing:
        return CheckResult("storage", "FAIL",
                           evidence=f"missing dirs: {','.join(missing)}",
                           next_action="Run `python3 scripts/me_setup.py setup "
                           "--data-dir DIR` to create the layout (it never deletes "
                           "household data).")
    secrets = data_dir / "secrets"
    try:
        import stat as _stat
        mode = _stat.S_IMODE(os.stat(secrets).st_mode)
        if mode != 0o700:
            return CheckResult("storage", "FAIL",
                               evidence=f"secrets mode {oct(mode)} != 0o700",
                               next_action="Run `chmod 0700 <data-dir>/secrets` "
                               "or re-run setup (it restricts the dir every run).")
    except OSError as exc:
        return CheckResult("storage", "FAIL", evidence=f"secrets stat: {exc}",
                           next_action="Recreate <data-dir>/secrets via setup.")
    return CheckResult("storage", "PASS",
                       evidence="layout present, secrets 0700")


@register_check("db_identity", required=True,
                description="authoritative installation_id: home SQLite DB mints it")
def check_db_identity(data_dir: Path, cfg: dict | None, opts: dict) -> CheckResult:
    if cfg is None:
        return CheckResult("db_identity", "FAIL", evidence="no config loaded",
                           next_action="Run setup first, then start the home once.")
    try:
        db_path = Path(str(cfg["service"]["db_path"]))
    except (KeyError, TypeError):
        return CheckResult("db_identity", "FAIL", evidence="config has no service.db_path",
                           next_action="Re-run setup to regenerate config.")
    db_id = me_setup.read_db_installation_id(db_path)
    if not db_id:
        return CheckResult("db_identity", "FAIL",
                           evidence=f"no installation_id in {db_path} (home never opened it)",
                           next_action="Start the loopback home once "
                           "(`python3 scripts/me_lifecycle.py start --data-dir DIR`, "
                           "then `stop`) so SQLite mints the REAL installation_id, "
                           "or run `bootstrap`; then re-run recheck. Do NOT invent an id.")
    if db_id != cfg.get("installation_id"):
        return CheckResult("db_identity", "FAIL",
                           evidence="config installation_id differs from the "
                           "authoritative home-database id",
                           next_action="Run `python3 scripts/me_setup.py setup "
                           "--data-dir DIR` (auto-adopts the DB id with backup) or "
                           "`setup --adopt-service-id` after verifying the live service.")
    return CheckResult("db_identity", "PASS",
                       evidence=f"installation_id={db_id} (home-database)")


@register_check("model_profile", required=True,
                description="exact configured model/API profile, REALLY probed")
def check_model_profile(data_dir: Path, cfg: dict | None, opts: dict) -> CheckResult:
    if cfg is None:
        return CheckResult("model_profile", "FAIL", evidence="no config loaded",
                           next_action="Run setup first.")
    models = cfg.get("models") or {}
    provider = str(models.get("provider", "local"))
    profile = _profile(opts)
    if provider not in ("local", "fixture", "openai", "anthropic"):
        return CheckResult("model_profile", "FAIL",
                           evidence=f"unknown provider {provider!r}",
                           next_action="Re-run setup with --model-provider "
                           "local|fixture|openai|anthropic.")
    if provider == "fixture":
        if profile == "test":
            return CheckResult("model_profile", "PASS",
                               evidence="TEST PROFILE ONLY: provider=fixture "
                               "(synthetic; NEVER household data; NEVER "
                               "production READY)")
        return CheckResult("model_profile", "FAIL",
                           evidence="provider=fixture completes ONLY the named "
                           "TEST profile (use --profile test); never production",
                           next_action="Re-run setup with a real provider "
                           "(local default, or --allow-remote-model for "
                           "openai/anthropic), or use `--profile test` for "
                           "synthetic runs.")
    if provider == "local":
        endpoint = str(models.get("endpoint", "") or "").strip()
        if not endpoint:
            endpoint = "http://127.0.0.1:11434"
        if not endpoint.startswith(("http://", "https://")):
            return CheckResult("model_profile", "FAIL",
                               evidence=f"local endpoint malformed: {endpoint!r}",
                               next_action="Re-run setup with the ChatOllama base URL "
                               "(default http://127.0.0.1:11434, no /v1).")
        ok, detail = probe_ollama(endpoint,
                              timeout_s=_clamp_timeout(opts, PROBE_WHOLE_TIMEOUT_S))
        if not ok:
            return CheckResult("model_profile", "FAIL", evidence=detail,
                               next_action="Start the local model daemon "
                               f"(Ollama) at {endpoint}, or re-run setup with "
                               "the correct --model-endpoint.")
        native = check_native_model_env(data_dir, cfg, models)
        if native is not None:
            return native
        return CheckResult("model_profile", "PASS",
                           evidence=f"selected engine probed: {detail}")
    # openai / anthropic: operator key required (env only, never files, never
    # baked); key presence alone is NOT readiness -- the exact endpoint is
    # probed with it.
    if not models.get("allow_remote"):
        return CheckResult("model_profile", "FAIL",
                           evidence=f"provider={provider} without allow_remote opt-in",
                           next_action="Re-run setup with --allow-remote-model "
                           "(key stays in operator shell, never stored).")
    endpoint = str(models.get("endpoint", "") or "").strip()
    if not endpoint.startswith("https://"):
        if endpoint.startswith("http://") and _http_loopback_ok(opts):
            pass  # explicit test-only loopback fixture
        else:
            return CheckResult("model_profile", "FAIL",
                               evidence=f"{provider} endpoint must be https:// "
                               f"(got {endpoint!r})",
                               next_action="Re-run setup with --model-endpoint "
                               "https://... (operator value).")
    key_env = ENV_OPENAI_KEY if provider == "openai" else ENV_ANTHROPIC_KEY
    # Effective NATIVE key: what the container actually receives. The
    # provider-specific shell value wins; else the generic operator key
    # (bound to the provider key at trusted launch, never persisted).
    # Verifying only one name while the container runs on the other would
    # check a key nothing uses.
    api_key = (os.environ.get(key_env, "").strip()
               or os.environ.get(ENV_GENERIC_MODEL_KEY, "").strip())
    if not api_key:
        return CheckResult("model_profile", "NEEDS_INPUT",
                           evidence=f"{provider} selected but no native key "
                           f"in the operator shell ({key_env} or generic "
                           f"{ENV_GENERIC_MODEL_KEY})",
                           needs_reason=f"provider credential: {provider} native key "
                           f"is an operator-provided secret ({key_env} or generic "
                           f"{ENV_GENERIC_MODEL_KEY}, bound at trusted launch, "
                           "never baked, never user auth stores); configure "
                           "it in the operator shell/env file (never chat, never "
                           "baked, never user auth stores)",
                           next_action=f"Export {key_env} (or generic "
                           f"{ENV_GENERIC_MODEL_KEY}) in the operator shell "
                           "and resume.")
    ok, detail = probe_remote_model(provider, endpoint, api_key,
                                   timeout_s=_clamp_timeout(
                                       opts, PROBE_WHOLE_TIMEOUT_S))
    if not ok:
        return CheckResult("model_profile", "FAIL", evidence=detail,
                           next_action="Fix the remote endpoint/key, then resume. "
                           "No key material was logged or stored.")
    native = check_native_model_env(data_dir, cfg, models)
    if native is not None:
        return native
    return CheckResult("model_profile", "PASS",
                       evidence=f"selected engine probed: {detail}")


def check_native_model_env(data_dir: Path, cfg: dict | None,
                           models: dict) -> CheckResult | None:
    """ONE selected full-model config must reach the native harness env.

    The native harness (B runtime-wire-contract) runs on BOT_PROVIDER /
    BOT_MODEL / OPENAI_BASE_URL -- NOT on a legacy local-only probe. Setup
    materializes that mapping into config/service.env (non-secret routing
    only; keys stay in the operator shell). Verifying the legacy Ollama
    endpoint while the harness actually defaults to remote GPT would check
    the wrong stack, so in FULL mode service.env MUST carry the matching
    native vars, or the check FAILs with re-run instructions. Returns None
    when consistent (caller then PASSes), a FAIL CheckResult otherwise.
    Fixture/test selections skip (synthetic only, no native mapping).
    """
    try:
        mode = str(((cfg.get("upstream") or {}).get("mode", "")) or "")
    except (AttributeError, TypeError):
        mode = ""
    if not mode or mode.strip().lower() != "full":
        return None  # core/unmigrated: native bar not required here
    provider = str(models.get("provider", "local"))
    if provider == "fixture":
        return None
    try:
        expected = me_setup.native_harness_env(models)
    except me_setup.SetupError as exc:
        return CheckResult("model_profile", "FAIL",
                           evidence=f"native model mapping: {exc}"[:300],
                           next_action="Re-run setup with a supported model "
                           "selection (local Ollama default, or explicit "
                           "openai/anthropic with --allow-remote-model).")
    if not expected:
        return None
    try:
        env_text = (data_dir / "config" / "service.env").read_text(
            encoding="utf-8")
    except OSError as exc:
        return CheckResult("model_profile", "FAIL",
                           evidence=f"service.env unreadable: {exc}"[:200],
                           next_action="Re-run setup so service.env activates "
                           "the selected FULL model for the home process.")
    have: dict[str, str] = {}
    for line in env_text.splitlines():
        line = line.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        k, _, v = line.partition("=")
        have[k.strip()] = v.strip().strip("'\"")
    missing = [f"{k}={v}" for k, v in expected.items() if have.get(k) != v]
    if missing:
        return CheckResult("model_profile", "FAIL",
                           evidence="service.env native model mismatch: "
                           f"{'; '.join(missing)[:300]} (home process would "
                           "run a different stack than verified)",
                           next_action="Re-run setup (it rewrites service.env "
                           "with the ONE selected model mapping: BOT_PROVIDER/"
                           "BOT_MODEL/OPENAI_BASE_URL), then restart the home "
                           "service and recheck.")
    return None


@register_check("upstream_stack", required=False,
                description="OPTIONAL legacy remote-profile note (informational only)")
def check_upstream_stack(data_dir: Path, cfg: dict | None, opts: dict) -> CheckResult:
    # Informational only. A remote provider opt-in NEVER marks any stack
    # ready; the real bar is the upstream_platform check below.
    if cfg is None:
        return CheckResult("upstream_stack", "OPTIONAL",
                           evidence="no config; upstream not evaluated")
    models = cfg.get("models") or {}
    provider = str(models.get("provider", ""))
    if provider == "fixture":
        return CheckResult("upstream_stack", "OPTIONAL",
                           evidence="fixture provider is synthetic-only; full "
                           "upstream stack NOT ready (honest, not skipped-as-pass)")
    return CheckResult("upstream_stack", "OPTIONAL",
                       evidence="legacy provider flag is not readiness evidence; "
                       "see upstream_platform for the real platform bar")


def _upstream_contract_path(data_dir: Path, cfg: dict | None,
                            opts: dict) -> Path | None:
    cands: list[str] = []
    if opts.get("upstream_contract"):
        cands.append(str(opts["upstream_contract"]))
    env = os.environ.get(ENV_UPSTREAM_CONTRACT, "").strip()
    if env:
        cands.append(env)
    if cfg:
        try:
            c = str(((cfg.get("upstream") or {}).get("contract_file", "")) or "")
            if c:
                cands.append(c)
        except (AttributeError, TypeError):
            pass
    cands.append(str(Path(data_dir) / "config" / "upstream-contract.json"))
    for cand in cands:
        p = Path(os.path.expanduser(cand))
        if p.is_file():
            return p
    return None


def _doctor_anchor_path(data_dir: Path) -> Path:
    return supervisor_dir(data_dir) / DOCTOR_ANCHOR_FILENAME


def _resolve_doctor_bin(data_dir: Path, cfg: dict | None,
                        opts: dict) -> Path | None:
    """Trusted doctor entrypoint (live subprocess only, never a report)."""
    cands: list[str] = []
    if opts.get("upstream_doctor"):
        cands.append(str(opts["upstream_doctor"]))
    env = os.environ.get(ENV_UPSTREAM_DOCTOR, "").strip()
    if env:
        cands.append(env)
    if cfg:
        try:
            d = str(((cfg.get("upstream") or {}).get("doctor_bin", "")) or "")
            if d:
                cands.append(d)
        except (AttributeError, TypeError):
            pass
    cands.append(str(data_dir / "upstream" / "bin" / "upstream-doctor"))
    # Monorepo dev fallback: sibling infra-server checkout (anchored, never
    # trusted by path alone).
    try:
        sib = (Path(__file__).resolve().parent.parent.parent
               / "infra-server" / "src" / "cli.mjs")
        cands.append(str(sib))
    except OSError:
        pass
    for cand in cands:
        if not cand:
            continue
        p = Path(os.path.expanduser(cand))
        try:
            if p.is_symlink() or not p.is_file():
                continue
        except OSError:
            continue
        return p
    return None


def _doctor_cwd(doctor: Path) -> Path:
    """Cwd contract for the trusted doctor subprocess.

    The A doctor resolves its vendor manifest (vendor/openbot/upstream.json)
    relative to its own module root. Invoking sibling cli.mjs from a setup
    data dir would fail the pin read, so run it with cwd = its repo root
    (src/cli.mjs -> parent.parent). Standalone doctor bins run with cwd =
    the home data dir. Tests invoke from arbitrary install cwds to prove the
    contract (no process.cwd() dependence on the caller).
    """
    if doctor.name == "cli.mjs":
        root = doctor.parent.parent
        try:
            if root.is_dir() and not os.path.islink(root):
                return root
        except OSError:
            pass
    return doctor.parent


def _doctor_closure_files(doctor: Path) -> list[tuple[str, Path]]:
    """Trusted module closure: entrypoint PLUS every imported module file.

    Hashing cli.mjs alone is NOT trust: upstream-doctor/config/computer are
    imported and mutable, so editing an imported verifier to emit READY would
    leave the entrypoint hash unchanged. The closure covers every *.mjs
    under the doctor module root (src/) + the vendor upstream manifest (+
    operator-declared approved patches). Bounded counts/sizes; symlinks
    refused anywhere in the closure.
    """
    if doctor.name == "cli.mjs":
        root = doctor.parent  # <repo>/src
        try:
            if not root.is_dir() or os.path.islink(root):
                return [("cli.mjs", doctor)]
        except OSError:
            return [("cli.mjs", doctor)]
        try:
            members = sorted(root.glob("*.mjs"))
        except OSError:
            return [("cli.mjs", doctor)]
        files: list[tuple[str, Path]] = []
        for m in members[:DOCTOR_CLOSURE_MAX_FILES + 1]:
            files.append((f"src/{m.name}", m))
        vendor = root.parent / "vendor" / "openbot" / "upstream.json"
        try:
            if vendor.is_file() and not os.path.islink(vendor):
                files.append(("vendor/openbot/upstream.json", vendor))
        except OSError:
            pass
        return files
    return [(doctor.name, doctor)]


def _hash_closure(files: list[tuple[str, Path]]
                  ) -> tuple[str | None, str, dict[str, str]]:
    """Hash the closure (bounded). Returns (digest, detail, file_digests)."""
    if len(files) > DOCTOR_CLOSURE_MAX_FILES + 1:
        return None, (f"doctor closure has {len(files)} files "
                      f"(>{DOCTOR_CLOSURE_MAX_FILES}); refusing"), {}
    total = 0
    per: dict[str, str] = {}
    try:
        for rel, p in files:
            if os.path.islink(p):
                return None, f"refusing symlinked closure file: {rel}", {}
            try:
                raw = p.read_bytes()
            except OSError as exc:
                return None, f"closure file unreadable {rel}: {exc}", {}
            if len(raw) > DOCTOR_CLOSURE_MAX_FILE_BYTES:
                return None, (f"closure file {rel} exceeds "
                               f"{DOCTOR_CLOSURE_MAX_FILE_BYTES}B; refusing"), {}
            total += len(raw)
            if total > DOCTOR_CLOSURE_MAX_TOTAL_BYTES:
                return None, ("doctor closure exceeds "
                               f"{DOCTOR_CLOSURE_MAX_TOTAL_BYTES}B; refusing"), {}
            per[rel] = hashlib.sha256(raw).hexdigest()
        patches = _approved_patches_digest()
        if patches is None:
            return None, "approved-patches dir unreadable; refusing", {}
        canonical = json.dumps({"files": per, "patches": patches},
                               sort_keys=True).encode("utf-8")
        return hashlib.sha256(canonical).hexdigest(), "", per
    except OSError as exc:
        return None, f"closure hash failed: {exc}", {}


def _approved_patches_digest() -> dict[str, str] | None:
    """Operator-declared approved patches (A-published) folded into closure."""
    d = os.environ.get(ENV_UPSTREAM_APPROVED_PATCHES, "").strip()
    if not d:
        return {}
    root = Path(os.path.expanduser(d))
    try:
        if not root.is_dir() or os.path.islink(root):
            return None
        out: dict[str, str] = {}
        for p in sorted(root.glob("*.patch"))[:50]:
            if os.path.islink(p):
                return None
            try:
                raw = p.read_bytes()
            except OSError:
                return None
            if len(raw) > DOCTOR_CLOSURE_MAX_FILE_BYTES:
                return None
            out[p.name] = hashlib.sha256(raw).hexdigest()
        return out
    except OSError:
        return None


def _closure_manifest_ok(files: list[tuple[str, Path]],
                         per: dict[str, str]) -> tuple[bool, str]:
    """Operator release manifest check (explicit trusted provisioning).

    ME_UPSTREAM_DOCTOR_MANIFEST points at an operator-held JSON manifest
    {files: {rel: sha256}} for the trusted release (e.g. A-published). The
    live closure must match EXACTLY: missing/extra/changed files refuse.
    Unset manifest = no manifest gate (pin/anchor rules still apply).
    """
    m = os.environ.get(ENV_UPSTREAM_DOCTOR_MANIFEST, "").strip()
    if not m:
        return True, ""
    mp = Path(os.path.expanduser(m))
    try:
        if mp.is_symlink() or not mp.is_file():
            return False, (f"{ENV_UPSTREAM_DOCTOR_MANIFEST} is not a regular "
                           "file; refusing")
        doc = json.loads(mp.read_text(encoding="utf-8"))
    except (OSError, ValueError) as exc:
        return False, f"release manifest unreadable: {exc}"
    want = doc.get("files") if isinstance(doc, dict) else None
    if not isinstance(want, dict):
        return False, "release manifest has no files object; refusing"
    want_s = {str(k): str(v) for k, v in want.items()}
    if set(want_s) != set(per):
        extra = sorted(set(per) - set(want_s))[:5]
        missing = sorted(set(want_s) - set(per))[:5]
        return False, ("closure != release manifest "
                       f"(extra={extra} missing={missing}); refusing")
    for rel, sha in want_s.items():
        if per.get(rel) != sha:
            return False, (f"closure file changed vs release manifest: {rel}; "
                           "refusing")
    return True, f"closure matches release manifest ({len(want_s)} files)"


def _anchor_doctor(data_dir: Path, doctor: Path) -> tuple[bool, str]:
    """Integrity anchor over the trusted module CLOSURE (not entrypoint).

    The product agent may provision the upstream owned checkout + expected
    approved patches/config but may NEVER redefine success by editing the
    verifier: the closure digest is anchored before turns (operator-pinned
    via ME_UPSTREAM_DOCTOR_SHA256, or matching ME_UPSTREAM_DOCTOR_MANIFEST,
    else persisted first-seen anchor) and checked on EVERY invocation/resume
    AND re-verified after each run (swap-during-run race). A tampered
    dependency emitting syntactically valid READY FAILs. Legacy
    entrypoint-only anchors (64hex) are NOT carried over: re-anchor the
    trusted release explicitly (no silent TOFU carryover, no bootstrapping
    trust after agent provisioning).

    No pin/manifest on first sight = unverified source: NEEDS_INPUT-grade
    refusal (operator must pin the release), never silent first-seen trust.
    """
    if doctor.is_symlink():
        return False, f"refusing symlinked doctor: {doctor}"
    files = _doctor_closure_files(doctor)
    digest, detail, per = _hash_closure(files)
    if digest is None:
        return False, detail
    ok_manifest, manifest_detail = _closure_manifest_ok(files, per)
    if not ok_manifest:
        return False, manifest_detail
    manifest_note = f"; {manifest_detail}" if manifest_detail else ""
    pinned = os.environ.get(ENV_UPSTREAM_DOCTOR_SHA, "").strip().lower()
    if pinned:
        if not re.fullmatch(r"[0-9a-f]{64}", pinned):
            return False, (f"{ENV_UPSTREAM_DOCTOR_SHA} malformed; refusing "
                           "(must be 64 hex chars)")
        if digest != pinned:
            return False, (f"doctor closure {digest[:16]}... does NOT match "
                           f"pinned {ENV_UPSTREAM_DOCTOR_SHA} "
                           f"{pinned[:16]}...; refusing (tamper or unapproved "
                           "doctor build)")
        _write_closure_anchor(data_dir, digest, per)
        return True, (f"doctor closure pinned+verified {digest[:16]}... "
                      f"({len(per)} files{manifest_note})")
    anchor = _doctor_anchor_path(data_dir)
    try:
        if anchor.is_symlink():
            return False, f"refusing symlinked anchor: {anchor}"
    except OSError:
        pass
    if anchor.is_file():
        try:
            recorded = json.loads(anchor.read_text(encoding="utf-8"))
        except (OSError, ValueError) as exc:
            return False, f"doctor anchor unreadable: {exc}"
        if not isinstance(recorded, dict) or \
                recorded.get("digest") != digest or \
                not isinstance(recorded.get("files"), dict):
            if isinstance(recorded, dict) and "digest" in recorded:
                return False, (f"doctor closure changed since anchor "
                               f"{str(recorded.get('digest'))[:16]}... (now "
                               f"{digest[:16]}...); refusing (re-anchor only "
                               "after verifying the A-published trusted "
                               "release)")
            return False, ("legacy entrypoint-only anchor: re-anchor the "
                           "trusted release explicitly (pinned digest via "
                           f"{ENV_UPSTREAM_DOCTOR_SHA} or matching "
                           f"{ENV_UPSTREAM_DOCTOR_MANIFEST}); refusing silent "
                           "TOFU carryover")
        return True, (f"doctor closure anchored {digest[:16]}... "
                      f"({len(per)} files{manifest_note})")
    # No anchor yet and no pin/manifest: the source is unverified (the agent
    # may have provisioned/edited it). Refuse silent first-seen trust.
    if manifest_detail:
        _write_closure_anchor(data_dir, digest, per)
        return True, (f"doctor closure manifest-verified {digest[:16]}... "
                      f"({len(per)} files{manifest_note})")
    return False, ("UNVERIFIED_DOCTOR_SOURCE: no pinned "
                   f"{ENV_UPSTREAM_DOCTOR_SHA} and no "
                   f"{ENV_UPSTREAM_DOCTOR_MANIFEST}; refusing silent "
                   "first-seen trust over agent-provisionable paths. Operator: "
                   "pin the A-published trusted release digest (or provide "
                   "its manifest), then resume.")


def _write_closure_anchor(data_dir: Path, digest: str,
                          per: dict[str, str]) -> bool:
    try:
        ensure_private_dir(supervisor_dir(data_dir))
        tmp = {"digest": digest, "files": per,
               "contract": DOCTOR_CONTRACT_REQUIRED}
        _doctor_anchor_path(data_dir).write_text(
            json.dumps(tmp, indent=2, sort_keys=True) + "\n", encoding="utf-8")
        os.chmod(_doctor_anchor_path(data_dir), 0o600)
        return True
    except OSError:
        return False


def _verify_closure_unchanged(doctor: Path, per: dict[str, str]) -> tuple[bool, str]:
    """Post-run re-verify: the closure must be identical after invocation.

    Closes the swap-during-run race (files replaced between anchor check and
    doctor exit). Directory listing is part of the check: added files refuse.
    """
    files = _doctor_closure_files(doctor)
    if {rel for rel, _ in files} != set(per):
        return False, "doctor closure file list changed during invocation"
    for rel, p in files:
        try:
            if os.path.islink(p):
                return False, f"closure file became symlink: {rel}"
            if hashlib.sha256(p.read_bytes()).hexdigest() != per[rel]:
                return False, f"closure file changed during invocation: {rel}"
        except OSError as exc:
            return False, f"closure re-verify failed {rel}: {exc}"
    return True, ""


def _run_doctor_subprocess(argv: list[str], *,
                           extra_env: dict[str, str] | None = None,
                           timeout_s: int = DOCTOR_TIMEOUT_S,
                           cwd: Path | None = None,
                           deadline_mono: float | None = None
                           ) -> tuple[int | None, bytes, str]:
    """Bounded doctor invocation: streaming caps, process-group lifecycle.

    Same hardening as agent turns, no communicate()-then-truncate loophole:
    concurrent draining threads cap memory DURING the run (per-stream cap
    DOCTOR_MAX_BYTES, no 4x flood allowance -- floods terminate the group),
    residual pipe-holding grandchildren are killed before close (no
    close/read deadlock), joins are bounded, the child is reaped (no
    orphans), SIGINT/SIGTERM during the run terminates the group and the
    caller observes _STOP_REQUESTED (loop persists state). The timeout is
    clamped to the SHARED remaining ACTIVE deadline so parallel probes never
    overshoot the wall budget.
    """
    global _doctor_proc
    if deadline_mono is not None:
        timeout_s = max(1.0, min(float(timeout_s),
                                 float(deadline_mono) - time.monotonic()))
    timeout_s = max(1.0, float(timeout_s))
    env = dict(os.environ)
    if extra_env:
        env.update(extra_env)
    try:
        proc = subprocess.Popen(
            argv, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
            stdin=subprocess.DEVNULL, start_new_session=True, env=env,
            cwd=str(cwd) if cwd is not None else None)
    except OSError as exc:
        return None, b"", f"spawn failed: {exc}"
    _doctor_proc = proc
    # Capture the group id NOW (leader alive): after it is reaped getpgid on
    # its pid raises ESRCH and a residual kill would silently no-op.
    try:
        doctor_pgid: int | None = os.getpgid(proc.pid)
    except (OSError, ProcessLookupError):
        doctor_pgid = None
    lock = threading.Lock()
    out_buf: dict = {"tail": b"", "truncated": False, "total": 0}
    err_buf: dict = {"tail": b"", "truncated": False, "total": 0}
    out_lines: list[str] = []
    err_lines: list[str] = []
    threads = [
        threading.Thread(target=_drain_thread,
                         args=(proc.stdout, out_buf, lock,
                               DOCTOR_MAX_BYTES, out_lines),
                         daemon=True),
        threading.Thread(target=_drain_thread,
                         args=(proc.stderr, err_buf, lock,
                               DOCTOR_MAX_BYTES, err_lines),
                         daemon=True),
    ]
    for t in threads:
        t.start()
    rc: int | None = 0
    note = ""
    deadline = time.monotonic() + timeout_s
    try:
        while True:
            if _STOP_REQUESTED["signo"] is not None:
                _terminate_group(proc)
                rc = stop_code()
                note = ("[SUPERVISOR doctor: interrupted by signal; "
                        "run persists as RUNNING]")
                break
            with lock:
                total = int(out_buf.get("total", 0)) + \
                    int(err_buf.get("total", 0))
            if total > DOCTOR_MAX_BYTES:
                _terminate_group(proc)
                rc = proc.returncode if proc.returncode is not None else 124
                note = ("[SUPERVISOR doctor: output flood cap exceeded "
                        f"({total}B > {DOCTOR_MAX_BYTES}B); process group "
                        "terminated]")
                break
            ret = proc.poll()
            if ret is not None:
                rc = ret
                for t in threads:
                    t.join(timeout=2.0)
                if any(t.is_alive() for t in threads):
                    _terminate_residual_group(doctor_pgid)
                    for t in threads:
                        t.join(timeout=5.0)
                break
            if time.monotonic() >= deadline or (
                    deadline_mono is not None
                    and time.monotonic() >= deadline_mono):
                _terminate_group(proc)
                rc = proc.returncode if proc.returncode is not None else 124
                note = ("[SUPERVISOR doctor: timeout exceeded "
                        "(shared ACTIVE budget); process group terminated]")
                break
            time.sleep(0.05)
    finally:
        _doctor_proc = None
        if proc.poll() is None:
            _terminate_group(proc)
            if rc == 0:
                rc = proc.returncode if proc.returncode is not None else 124
        elif rc == 0:
            # Leader already reaped: keep the loop's verdict (stop/timeout
            # codes included), only fill in an unset rc.
            rc = proc.returncode if proc.returncode is not None else rc
        try:
            proc.wait(timeout=KILL_GRACE_S)
        except (OSError, subprocess.SubprocessError):
            pass
        for t in threads:
            if t.is_alive():
                t.join(timeout=5.0)
        for stream in (proc.stdout, proc.stderr):
            try:
                if stream is not None:
                    stream.close()
            except OSError:
                pass
    out = bytes(out_buf["tail"]).decode("utf-8", "replace")
    serr = bytes(err_buf["tail"]).decode("utf-8", "replace")
    if out_buf["truncated"] or err_buf["truncated"]:
        serr += "\n[SUPERVISOR doctor: output truncated at byte cap]"
    if note:
        serr = (serr + "\n" + note) if serr else note
    return rc, out.encode("utf-8", "replace")[:DOCTOR_MAX_BYTES + 1], serr


def _report_contract_marker(doc: dict) -> str:
    """Versioned full-evidence contract marker (fail-closed until present)."""
    marker = doc.get("doctor_contract")
    if isinstance(marker, str) and marker:
        return marker
    checks = doc.get("checks")
    if isinstance(checks, dict):
        marker = checks.get("doctor_contract")
        if isinstance(marker, str) and marker:
            return marker
    return ""


def _check_unknown_probed(obj: object, path: str = "checks") -> str:
    """Recursive scan refusing unknown/probe:false markers in READY evidence.

    Any probed:false (no-probe reports never authorize READY), any explicit
    unknown/UNKNOWN sentinel value, or any None on a REQUIRED path refuses.
    Returns "" when clean, else the offending path.
    """
    if isinstance(obj, dict):
        for k, v in obj.items():
            if k == "probed" and v is False:
                return path
            bad = _check_unknown_probed(v, f"{path}.{k}")
            if bad:
                return bad
        return ""
    if isinstance(obj, list):
        for i, v in enumerate(obj):
            bad = _check_unknown_probed(v, f"{path}[{i}]")
            if bad:
                return bad
        return ""
    if isinstance(obj, str) and obj.strip().lower() in ("unknown", "n/a", "todo"):
        return path
    return ""


def _validate_doctor_report(doc: object) -> tuple[str, str, dict]:
    """Strict schema for upstream-platform-v1. Returns (verdict, reason, doc).

    verdict: READY | NEEDS_INPUT | FAILED. Fail-closed: the versioned
    full-evidence contract marker (DOCTOR_CONTRACT_REQUIRED, published early
    in setup-wire-contract.json) must be present, EVERY name in
    DOCTOR_REQUIRED_EVIDENCE must exist with verified values, and no
    missing/unknown/probe:false marker anywhere in the evidence may
    authorize READY. Arbitrary JSON keys, generic /healthz 200s, or a
    complete-looking cached report can NEVER yield READY. Cached/
    operator-written reports are rejected by the caller (only live
    subprocess stdout reaches here); this validates shape + substance.
    """
    if not isinstance(doc, dict):
        return "FAILED", "doctor report is not a JSON object", {}
    if doc.get("protocol") != UPSTREAM_DOCTOR_PROTOCOL:
        return "FAILED", (
            f"doctor protocol {doc.get('protocol')!r} != "
            f"{UPSTREAM_DOCTOR_PROTOCOL!r}"), {}
    marker = _report_contract_marker(doc)
    if marker != DOCTOR_CONTRACT_REQUIRED:
        return "FAILED", (
            f"versioned full doctor contract not present "
            f"(got {marker!r}, C requires {DOCTOR_CONTRACT_REQUIRED!r}; A to "
            "publish results/setup-doctor-contract.json; fail-closed)"), {}
    state = doc.get("state")
    if state not in ("READY", "NEEDS_INPUT", "FAILED"):
        return "FAILED", f"doctor state {state!r} not READY/NEEDS_INPUT/FAILED", {}
    checks = doc.get("checks")
    if not isinstance(checks, dict):
        return "FAILED", "doctor report has no checks object", {}
    # Required evidence names (published early; missing refuses READY).
    missing = [name for name in DOCTOR_REQUIRED_EVIDENCE
               if _nested_get(checks, name.split(".")[1:]) is _MISSING]
    if missing:
        return "FAILED", (
            f"doctor report missing required evidence: {','.join(missing)} "
            "(minimal/forged READY refused)"), {}
    # Provenance: pinned OpenBot repo+ref required (self-hash is NOT proof).
    up = checks.get("upstream") if isinstance(checks.get("upstream"), dict) else {}
    if up.get("repo") != UPSTREAM_REPO or up.get("ref") != UPSTREAM_PIN:
        return "FAILED", (
            f"doctor upstream provenance {up.get('repo')}@{up.get('ref')} "
            f"!= {UPSTREAM_REPO}@{UPSTREAM_PIN}"), {}
    lock = checks.get("sourcePin") if isinstance(checks.get("sourcePin"), dict) else {}
    if lock.get("ref") != UPSTREAM_PIN or lock.get("repo") != UPSTREAM_REPO:
        return "FAILED", (
            f"doctor sourcePin {lock.get('repo')}@{lock.get('ref')} "
            f"!= {UPSTREAM_REPO}@{UPSTREAM_PIN}"), {}
    try:
        files_n = int(lock.get("files", 0) or 0)
    except (TypeError, ValueError):
        files_n = 0
    if files_n <= 0:
        return "FAILED", "doctor sourcePin lists no files (not verified)", {}
    mode = str(checks.get("mode", "") or "")
    if mode not in ("full", "core"):
        return "FAILED", f"doctor mode {mode!r} not full/core", {}
    if state == "READY":
        if mode != "full":
            return "FAILED", (
                "doctor READY in core mode is not production READY "
                "(computer-plane dev/partial, never production)"), {}
        # The live contract requires probing; the real doctor demotes
        # probe=false READY itself, and any probed:false marker refuses here.
        if checks.get("probe") is False:
            return "FAILED", (
                "doctor READY with probe=false "
                "(no-probe reports never authorize READY)"), {}
        bad = _check_unknown_probed(checks)
        if bad:
            return "FAILED", (
                f"doctor READY with unverified marker at {bad} "
                "(missing/unknown/probe:false never authorize READY)"), {}
        cfg = checks.get("config") if isinstance(checks.get("config"), dict) else {}
        if cfg.get("gate") != "pass" or cfg.get("missing"):
            return "FAILED", (
                f"doctor READY with config gate != pass "
                f"(gate={cfg.get('gate')!r} missing={cfg.get('missing')!r})"), {}
        sup = checks.get("supervisor") if isinstance(
            checks.get("supervisor"), dict) else {}
        health = sup.get("health") if isinstance(sup.get("health"), dict) else {}
        if health.get("status") != "ok":
            return "FAILED", (
                "doctor READY with supervisor health != ok "
                "(arbitrary 200s never authorize READY)"), {}
        if health.get("docker") is not True:
            return "FAILED", (
                "doctor READY with supervisor docker != true "
                "(hardware not verified)"), {}
        if not str(sup.get("list", "") or "").startswith("ok"):
            return "FAILED", (
                "doctor READY without authenticated supervisor list "
                "(token not verified)"), {}
        if not checks.get("perUserBoundary"):
            return "FAILED", (
                "doctor READY without per-user boundary evidence"), {}
        pg = checks.get("postgres") if isinstance(
            checks.get("postgres"), dict) else {}
        if not pg.get("configured"):
            return "FAILED", (
                "doctor READY without Postgres binding "
                "(product store not verified)"), {}
        srv = checks.get("upstreamServer") if isinstance(
            checks.get("upstreamServer"), dict) else {}
        shealth = srv.get("health") if isinstance(srv.get("health"), dict) else {}
        if shealth.get("status") != "ok":
            return "FAILED", (
                "doctor READY with upstream server health != ok"), {}
        model = checks.get("model") if isinstance(checks.get("model"), dict) else {}
        if str(model.get("provider", "")) == "fixture":
            return "FAILED", "doctor READY with fixture model (never READY)", {}
        if not model.get("provider"):
            return "FAILED", "doctor READY with unknown model", {}
        intel = checks.get("intelligence") if isinstance(
            checks.get("intelligence"), dict) else {}
        if not intel.get("keyPresent"):
            return "FAILED", "doctor READY without Intelligence key", {}
        if not intel.get("selfHosted"):
            return "FAILED", (
                "doctor READY without self-hosted Intelligence "
                "(home privacy requires self-hosted)"), {}
        tel = checks.get("telemetry") if isinstance(
            checks.get("telemetry"), dict) else {}
        prod_tel = str(tel.get("product", "") or "").strip().lower()
        if prod_tel in ("1", "true"):
            return "FAILED", (
                "doctor READY with upstream product telemetry enabled "
                "(home default is off)"), {}
        if checks.get("failures"):
            return "FAILED", "doctor READY with failures listed", {}
        if checks.get("needs"):
            return "FAILED", "doctor READY with needs listed", {}
    return state, "doctor report schema ok", {"mode": mode}


_MISSING: object = object()


def _nested_get(checks: dict, parts: list[str]) -> object:
    cur: object = checks
    for part in parts:
        if not isinstance(cur, dict) or part not in cur:
            return _MISSING
        cur = cur[part]
    return cur


@register_check("upstream_platform", required=False,
                description="FULL OpenBot platform via trusted upstream-doctor")
def check_upstream_platform(data_dir: Path, cfg: dict | None, opts: dict) -> CheckResult:
    # Dynamic required set (required_ids) makes this REQUIRED in production.
    # The ONLY path to PASS is a live trusted upstream-doctor subprocess
    # reporting READY with strict schema (pinned source, probed services,
    # licensed Intelligence, authenticated model). Arbitrary contract JSON
    # keys, license FILESIZE, generic /healthz 200, Docker presence, or a
    # no-probe/cached report can NEVER authorize READY. Missing gates park
    # as NEEDS_INPUT (independent fixable work continues meanwhile).
    profile = _profile(opts)
    if profile != "production":
        return CheckResult("upstream_platform", "OPTIONAL",
                           evidence=f"{profile} profile: full platform bar not "
                           "required (production only)")
    # Legacy explicit core mode is never production READY.
    cfg_mode = ""
    if cfg:
        try:
            cfg_mode = str(((cfg.get("upstream") or {}).get("mode", "")) or "")
        except (AttributeError, TypeError):
            cfg_mode = ""
    # Unmigrated configs (no upstream section) never silently default: the
    # operator selects full|core explicitly (fresh installs default full at
    # setup time). Core is the upstream computer-plane dev/partial profile,
    # NOT the original Me task-broker runtime -- never production READY.
    cfg_mode = ""
    cfg_has_upstream = False
    if cfg:
        try:
            ups = cfg.get("upstream")
            if ups is not None:
                cfg_has_upstream = True
                cfg_mode = str((ups.get("mode", "")) or "")
        except (AttributeError, TypeError):
            cfg_mode = ""
    if not cfg_has_upstream and cfg is not None:
        return CheckResult("upstream_platform", "NEEDS_INPUT",
                           evidence="config has no upstream section "
                           "(pre-migration home; nothing selected)",
                           needs_reason="upstream profile unselected: re-run "
                           "setup with --upstream-mode full (production FULL "
                           "platform) or core (computer-plane dev/partial)",
                           next_action="Re-run setup with --upstream-mode full "
                           "or core (explicit choice is sticky on reruns), "
                           "then resume.")
    if cfg_mode.strip().lower() == "core":
        return CheckResult("upstream_platform", "NEEDS_INPUT",
                           evidence="config upstream.mode=core "
                           "(computer-plane dev/partial; FULL is the "
                           "production bar)",
                           needs_reason="upstream.mode=core is dev/partial "
                           "(per-user computers via supervisor, not the "
                           "original Me runtime); select FULL for production",
                           next_action="Re-run setup with --upstream-mode full "
                           "(default) for the FULL platform, or use "
                           "--profile configure for config-only runs.")
    doctor = _resolve_doctor_bin(data_dir, cfg, opts)
    contract = _upstream_contract_path(data_dir, cfg, opts)
    contract_note = f"contract={contract}" if contract else "no contract file"
    if doctor is None:
        return CheckResult("upstream_platform", "NEEDS_INPUT",
                           evidence=f"trusted upstream-doctor unavailable "
                           f"({contract_note}; A publishes "
                           "platform-wire-contract.json + upstream-doctor; "
                           "point ME_UPSTREAM_DOCTOR at the trusted installed "
                           "product path)",
                           needs_reason="upstream-doctor unavailable: genuine "
                           "operator gate (A-published doctor + licensed "
                           "Intelligence/model/hardware); independent fixable "
                           "checks continue meanwhile",
                           next_action="Provision the A-published trusted "
                           "infra-server checkout (pinned "
                           f"{UPSTREAM_REPO}@{UPSTREAM_PIN}), set "
                           f"{ENV_UPSTREAM_DOCTOR} to its src/cli.mjs (or "
                           "installed upstream-doctor bin) with "
                           f"{ENV_UPSTREAM_DOCTOR_SHA} pinned (or "
                           f"{ENV_UPSTREAM_DOCTOR_MANIFEST} manifest), then "
                           "resume. Contract JSON alone never authorizes READY.")
    ok, anchor_detail = _anchor_doctor(data_dir, doctor)
    if not ok:
        if "UNVERIFIED_DOCTOR_SOURCE" in anchor_detail:
            return CheckResult("upstream_platform", "NEEDS_INPUT",
                               evidence=f"doctor integrity: {anchor_detail}"[:500],
                               needs_reason="doctor source unverified: pin the "
                               "A-published trusted release before any agent "
                               "provisioning can be trusted",
                               next_action="Set ME_UPSTREAM_DOCTOR_SHA256 to "
                               "the A-published trusted closure digest (or "
                               "ME_UPSTREAM_DOCTOR_MANIFEST to its manifest), "
                               "then resume. Never TOFU-anchor an "
                               "agent-provisionable path.")
        return CheckResult("upstream_platform", "FAIL",
                           evidence=f"doctor integrity gate: {anchor_detail}"[:500],
                           next_action="Re-anchor the trusted release only after "
                           "verifying the A-published release (pinned closure "
                           f"digest via {ENV_UPSTREAM_DOCTOR_SHA} or matching "
                           f"{ENV_UPSTREAM_DOCTOR_MANIFEST}); then resume. "
                           "Agent edits to the doctor never authorize READY.")
    # Live invocation with the module-root cwd contract (the doctor resolves
    # its vendor manifest from its own module root, never our data dir).
    # Probing ENABLED; --no-probe never READY.
    cwd = _doctor_cwd(doctor)
    if doctor.name == "cli.mjs":
        node = shutil.which("node")
        if not node:
            return CheckResult("upstream_platform", "NEEDS_INPUT",
                               evidence="node unavailable to run the trusted "
                               "upstream-doctor (operator runtime gate)",
                               needs_reason="node runtime missing for doctor "
                               "probe; install the pinned Node >=24 on the "
                               "HOME target, then resume",
                               next_action="Install Node >=24.18.0 on the HOME "
                               "target (operator-owned path), then resume.")
        argv = [node, "--experimental-transform-types", str(doctor),
                "upstream-doctor"]
    else:
        argv = [str(doctor)]
    extra: dict[str, str] = {}
    if cfg_mode.strip().lower() in ("full", ""):
        # Coordinate the selected profile into the doctor env when the
        # operator has not set it explicitly (config is the record).
        if not os.environ.get("ME_UPSTREAM_MODE", "").strip():
            extra["ME_UPSTREAM_MODE"] = "full"
    deadline_mono = None
    try:
        deadline_mono = opts.get("_deadline_mono")
        if deadline_mono is not None:
            deadline_mono = float(deadline_mono)
    except (TypeError, ValueError):
        deadline_mono = None
    anchor_files = _doctor_closure_files(doctor)
    _, _, anchor_per = _hash_closure(anchor_files)
    rc, out_raw, serr_tail = _run_doctor_subprocess(
        argv, extra_env=extra, cwd=cwd, deadline_mono=deadline_mono)
    # Post-run closure re-verify (swap-during-run race): the exact anchored
    # files must be identical after invocation.
    if anchor_per:
        still_ok, changed = _verify_closure_unchanged(doctor, anchor_per)
        if not still_ok:
            return CheckResult("upstream_platform", "FAIL",
                               evidence=f"doctor integrity: {changed}"[:300],
                               next_action="The trusted doctor changed during "
                               "its own invocation; re-anchor only after "
                               "verifying the A-published release, then resume.")
    if rc is None:
        return CheckResult("upstream_platform", "FAIL",
                           evidence=f"doctor spawn failed: {serr_tail}"[:300],
                           next_action="Repair the trusted doctor path/node "
                           "runtime, then resume.")
    if _STOP_REQUESTED.get("signo") is not None:
        # Signal arrived during the doctor run: the runner already reaped it;
        # the loop top persists RUNNING/resumable (never claim from here).
        return CheckResult("upstream_platform", "FAIL",
                           evidence="interrupted during doctor invocation "
                           "(run persists as RUNNING; resume re-verifies)",
                           next_action="Resume the run; the doctor re-runs "
                           "from the anchored closure.")
    if len(out_raw) > DOCTOR_MAX_BYTES:
        return CheckResult("upstream_platform", "FAIL",
                           evidence="doctor output exceeds 64KiB cap; refusing",
                           next_action="Inspect the trusted doctor (bounded "
                           "JSON expected); re-run recheck.")
    try:
        doc = json.loads(out_raw.decode("utf-8"))
    except (UnicodeDecodeError, ValueError) as exc:
        return CheckResult("upstream_platform", "FAIL",
                           evidence=f"doctor output is not JSON: {exc}"[:300],
                           next_action="Repair the trusted doctor (must emit "
                           "upstream-platform-v1 JSON), then resume.")
    verdict, reason, info = _validate_doctor_report(doc)
    checks = doc.get("checks") if isinstance(doc, dict) else {}
    summary = ""
    if isinstance(checks, dict):
        needs = checks.get("needs") if isinstance(checks.get("needs"), list) else []
        failures = checks.get("failures") if isinstance(
            checks.get("failures"), list) else []
        summary = "; ".join(
            [str(x)[:160] for x in (failures + needs)][:4])
    evidence_base = (f"doctor={doctor.name} {anchor_detail}; "
                     f"protocol={UPSTREAM_DOCTOR_PROTOCOL} "
                     f"pin={UPSTREAM_PIN[:12]}...; {contract_note}")
    if verdict == "READY":
        intel = checks.get("intelligence") if isinstance(checks, dict) else None
        intel_note = ""
        if isinstance(intel, dict):
            intel_note = (f" intelligence keyPresent="
                          f"{bool(intel.get('keyPresent'))}")
        return CheckResult("upstream_platform", "PASS",
                           evidence=(evidence_base +
                                     f"; doctor state READY{intel_note}")[:900])
    if verdict == "NEEDS_INPUT":
        return CheckResult("upstream_platform", "NEEDS_INPUT",
                           evidence=(evidence_base + "; " + summary)[:900],
                           needs_reason=summary[:800] or
                           "doctor NEEDS_INPUT (operator license/model/"
                           "hardware gate)",
                           next_action="Resolve the doctor-reported operator "
                           "gates (env/file inputs only, never chat secrets), "
                           "then resume. Independent fixable checks continue "
                           "meanwhile.")
    return CheckResult("upstream_platform", "FAIL",
                       evidence=(evidence_base + "; " + (summary or reason))[:900],
                       next_action="Fix the doctor-reported platform fault "
                       "(misconfig/drift/unsafe SINGLE_USER/tamper), then "
                       "resume. Garbage/unknown reports never READY.")


@register_check("owner_token", required=False,
                description="owner token assertion (coordinator credential, when enabled)")
def check_owner_token(data_dir: Path, cfg: dict | None, opts: dict) -> CheckResult:
    if cfg is None:
        return CheckResult("owner_token", "FAIL", evidence="no config loaded",
                           next_action="Run setup first.")
    coord = cfg.get("coordinator") or {}
    if not coord.get("enabled"):
        return CheckResult("owner_token", "OPTIONAL",
                           evidence="coordination disabled (zero network); no "
                           "owner token to assert")
    try:
        import me_coordinator
        db_id = me_setup.read_db_installation_id(
            Path(str(cfg["service"]["db_path"])))
        cred = me_coordinator.credentials_file_for(cfg, data_dir)
        allow_lb = me_coordinator.allow_http_loopback_effective(coord)
        record, code = me_coordinator.load_status_record(
            cred, expected_installation_id=db_id or "",
            allow_http_loopback=allow_lb)
    except Exception as exc:
        return CheckResult("owner_token", "FAIL",
                           evidence=f"credential probe error: {exc}"[:300],
                           next_action="Inspect the coordinator credentials file "
                           "via `coordinator status`.")
    if record:
        return CheckResult("owner_token", "PASS",
                           evidence="owner token asserted (credentials file valid, "
                           "installation verified)")
    if code in ("missing_credentials_file", "credentials_unreadable"):
        return CheckResult("owner_token", "NEEDS_INPUT",
                           evidence="coordination enabled but no credential file",
                           needs_reason="owner activation ticket required "
                           "(one-time ticket via owner phone; STDIN-only "
                           "activate); mint and redeem, then resume",
                           next_action="Run `coordinator prepare` then "
                           "`coordinator activate` (STDIN ticket-only).")
    return CheckResult("owner_token", "FAIL",
                       evidence=f"credential file invalid: {code}",
                       next_action="Re-run `coordinator prepare/activate` with a "
                       "fresh ticket, then resume.")


@register_check("backup_coverage", required=False,
                description="full backup covers all configured upstream volumes")
def check_backup_coverage(data_dir: Path, cfg: dict | None, opts: dict) -> CheckResult:
    # Product scope decision (coordinator): operational agent readiness does
    # NOT claim backup-complete. Complete upstream backup (Postgres +
    # Intelligence threads + computer volumes) is an explicit SEPARATE
    # unsupported capability: backup.supported=false until a real verifiable
    # upstream backup path lands. The SQLite-only archive covers
    # sqlite+tasks+household ONLY and must never be labelled complete
    # full-platform. Full backup/restore commands refuse incomplete archives
    # explicitly (see me_lifecycle); actual legacy backup behavior preserved.
    #
    # Default (no --require-backup): OPTIONAL with the unsupported scope
    # stated, so operational READY stays reachable without disguising an
    # unimplemented capability as an operator gate. Explicit
    # --require-backup (or ME_REQUIRE_BACKUP=1) product policy: truthfully
    # UNSUPPORTED/NOT READY (FAIL with the concrete integration path), never
    # a checkbox PASS. Omission of cfg.volumes never hides full coverage
    # requirements in this mode.
    if _profile(opts) != "production":
        return CheckResult("backup_coverage", "OPTIONAL",
                           evidence="non-production profile: coverage bar not required")
    if cfg is None:
        return CheckResult("backup_coverage", "FAIL", evidence="no config loaded",
                           next_action="Run setup first.")
    if not _backup_required(opts):
        return CheckResult("backup_coverage", "OPTIONAL",
                           evidence="backup.supported=false (SQLite-only "
                           "sqlite+tasks+household; complete upstream "
                           "Postgres/Intelligence/computer backup "
                           "unsupported -- operational READY excludes backup "
                           "claims; see results/datastorage-contract.json)")
    # Explicit backup requirement: FULL bar from the storage contract.
    try:
        mode = str(((cfg.get("upstream") or {}).get("mode", "full")) or "full")
    except (AttributeError, TypeError):
        mode = "full"
    mode = mode.strip().lower() or "full"
    expected = ["agent-profiles", "agent-workspace", "postgres-data"]
    volumes = cfg.get("volumes") or {}
    declared = sorted(volumes.keys()) if isinstance(volumes, dict) else []
    missing_decl = [v for v in expected if v not in declared]
    scope_note = (
        f"declared=[{','.join(declared)[:200]}] "
        f"missing=[{','.join(missing_decl)[:200]}]")
    if mode != "full":
        if isinstance(volumes, dict) and volumes:
            return CheckResult("backup_coverage", "FAIL",
                               evidence="backup required: core dev/partial "
                               f"declares upstream volumes ({scope_note}) the "
                               "SQLite-only archive does not cover",
                               next_action="Select FULL and provision the "
                               "supported upstream backup scope per "
                               "results/datastorage-contract.json.")
        return CheckResult("backup_coverage", "FAIL",
                           evidence="backup required: core dev/partial has no "
                           "supported complete-backup path (explicitly "
                           "unsupported capability)",
                           next_action="Select FULL and provision the "
                           "supported upstream backup scope per "
                           "results/datastorage-contract.json.")
    return CheckResult("backup_coverage", "FAIL",
                       evidence="UNSUPPORTED backup capability (explicit): "
                       "no verifiable upstream snapshot path on this target "
                       f"for FULL volumes ({scope_note}); SQLite-only archive "
                       "covers sqlite+tasks+household ONLY, never "
                       "Postgres/Intelligence/computer files",
                       next_action="Concrete integration path: implement the "
                       "supported upstream backup per "
                       "results/datastorage-contract.json (pg_dump/volume "
                       "copy + Intelligence deployment backup + computer "
                       "volumes, verified by restore test); until then the "
                       "requirement stays NOT READY and full backup/restore "
                       "refuse explicitly.")


def _backup_required(opts: dict) -> bool:
    """Explicit backup requirement: --require-backup or ME_REQUIRE_BACKUP=1."""
    if opts.get("require_backup"):
        return True
    return str(os.environ.get(ENV_REQUIRE_BACKUP, "")).strip().lower() in (
        "1", "true", "yes")


@register_check("home_health", required=False,
                description="live home /healthz (required in production)")
def check_home_health(data_dir: Path, cfg: dict | None, opts: dict) -> CheckResult:
    if not _service_required(opts):
        return CheckResult("home_health", "OPTIONAL",
                           evidence="service runtime not required for this run")
    if cfg is None:
        return CheckResult("home_health", "FAIL", evidence="no config loaded",
                           next_action="Run setup first, then start the service.")
    host = str(cfg["service"]["host"])
    port = int(cfg["service"]["port"])
    body, error = me_setup.fetch_healthz(host, port)
    if body is None:
        return CheckResult("home_health", "FAIL", evidence=error[:400],
                           next_action="Start the service "
                           "(`python3 scripts/me_lifecycle.py start --data-dir DIR`) "
                           "and ensure /healthz answers status ok.")
    if body.get("status") != "ok":
        return CheckResult("home_health", "FAIL",
                           evidence=f"healthz status={body.get('status')!r}"[:300],
                           next_action="Inspect logs/<home-service>.log; the service "
                           "must answer status ok.")
    if body.get("contract") != me_setup.CONTRACT_VERSION:
        return CheckResult("home_health", "FAIL",
                           evidence=f"contract={body.get('contract')!r}"[:200],
                           next_action="Update to the H1 home-api-v1 contract.")
    if body.get("installation_id") != cfg.get("installation_id"):
        return CheckResult("home_health", "FAIL",
                           evidence="live installation_id differs from config",
                           next_action="Adopt explicitly with `setup "
                           "--adopt-service-id` after verifying the service.")
    return CheckResult("home_health", "PASS",
                       evidence=f"healthz ok contract={body.get('contract')} "
                       f"installation_id match")


@register_check("service_runtime", required=False,
                description="managed service process (required in production)")
def check_service_runtime(data_dir: Path, cfg: dict | None, opts: dict) -> CheckResult:
    if not _service_required(opts):
        return CheckResult("service_runtime", "OPTIONAL",
                           evidence="service runtime not required for this run")
    try:
        import me_lifecycle
    except ImportError as exc:
        return CheckResult("service_runtime", "FAIL",
                           evidence=f"lifecycle import: {exc}",
                           next_action="Repair the setup-infra checkout.")
    if cfg is None:
        return CheckResult("service_runtime", "FAIL", evidence="no config loaded",
                           next_action="Run setup first.")
    state, record = me_lifecycle.managed_state(data_dir, cfg)
    if state != "running":
        return CheckResult("service_runtime", "FAIL",
                           evidence=f"managed state={state}",
                           next_action="Start the service "
                           "(`python3 scripts/me_lifecycle.py start --data-dir DIR`).")
    return CheckResult("service_runtime", "PASS",
                       evidence=f"managed pid={record.get('pid')}")


# ---------------------------------------------------------------------------
# dynamic required set (trusted registry + opts/cfg -- NEVER agent-chosen)


def required_ids(opts: dict, cfg: dict | None = None) -> list[str]:
    """Explicit required selection per profile. Static flags are the base;
    production adds the live platform bar (upstream doctor) + home health/
    runtime; backup_coverage joins ONLY under explicit --require-backup
    product policy (unsupported capability, never an unconditional gate);
    owner_token joins when coordination is enabled. Unknown ids can never
    sneak in: only CHECKS keys.
    """
    ids = [cid for cid, spec in CHECKS.items() if spec.get("required")]
    if _service_required(opts):
        ids += ["home_health", "service_runtime"]
    if _profile(opts) == "production":
        ids += ["upstream_platform"]
        if _backup_required(opts):
            ids += ["backup_coverage"]
    if cfg is not None:
        try:
            if (cfg.get("coordinator") or {}).get("enabled"):
                ids += ["owner_token"]
        except (AttributeError, TypeError):
            pass
    # Fence: registry keys only, sorted for stable prompts/events.
    return sorted(set(i for i in ids if i in CHECKS))


# ---------------------------------------------------------------------------
# persisted state (atomic, versioned, 0600 files, 0700 dirs, no symlinks)


def supervisor_dir(data_dir: Path) -> Path:
    return data_dir / SUPERVISOR_DIRNAME


def state_path(data_dir: Path) -> Path:
    return supervisor_dir(data_dir) / STATE_FILENAME


def lock_path(data_dir: Path) -> Path:
    return supervisor_dir(data_dir) / LOCK_FILENAME


def _refuse_symlink(path: Path, what: str) -> None:
    if os.path.islink(path):
        raise RuntimeError(f"refusing {what}: {path} is a symlink")
    # Also refuse a symlinked supervisor dir or symlinked data dir directly
    # above it: following those would take private state outside the
    # installation-owned tree. System temp symlinks (e.g. /tmp -> private/tmp
    # on macOS) are NOT refused -- only the two installation-owned levels.
    cands: list[Path] = []
    if path.name in (STATE_FILENAME, LOCK_FILENAME, DOCTOR_ANCHOR_FILENAME):
        cands = [path.parent, path.parent.parent]
    elif path.name == SUPERVISOR_DIRNAME:
        cands = [path, path.parent]
    for cand in cands:
        try:
            if os.path.islink(cand):
                raise RuntimeError(
                    f"refusing {what}: {cand} is a symlink")
        except OSError:
            break


def ensure_private_dir(path: Path) -> None:
    _refuse_symlink(path, "supervisor dir")
    path.mkdir(parents=True, exist_ok=True)
    os.chmod(path, 0o700)


def write_atomic_private(path: Path, text: str) -> None:
    _refuse_symlink(path, "state write")
    path.parent.mkdir(parents=True, exist_ok=True)
    fd, tmp = tempfile.mkstemp(dir=str(path.parent), prefix=path.name + ".")
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as f:
            f.write(text)
            try:
                f.flush()
                os.fsync(f.fileno())
            except OSError:
                pass
        os.chmod(tmp, 0o600)
        os.replace(tmp, path)
        try:
            dirfd = os.open(path.parent, os.O_DIRECTORY)
        except OSError:
            dirfd = None
        if dirfd is not None:
            try:
                os.fsync(dirfd)
            except OSError:
                pass
            finally:
                os.close(dirfd)
    except BaseException:
        try:
            os.unlink(tmp)
        except OSError:
            pass
        raise


_INT_BOUNDS = {
    "max_attempts": (1, 50), "max_stagnant": (1, 20),
    "wall_timeout_s": (60, 14400), "attempt_timeout_s": (5, 3600),
    "attempts": (0, 10000), "stagnant_count": (0, 10000),
    "active_seconds": (0, 1e9),
}


def validate_state(doc: dict) -> dict:
    if not isinstance(doc, dict):
        raise ValueError("supervisor state is not an object")
    if doc.get("schema_version") != SCHEMA_VERSION:
        raise ValueError(
            f"unsupported supervisor state schema: {doc.get('schema_version')!r}")
    if doc.get("status") not in STATUSES:
        raise ValueError(f"bad status {doc.get('status')!r}")
    profile = str(doc.get("profile", "production"))
    if profile not in PROFILES:
        raise ValueError(f"bad profile {profile!r}")
    mode = str(doc.get("mode", "dev"))
    if mode not in MODES:
        raise ValueError(f"bad mode {mode!r}")
    for key, (lo, hi) in _INT_BOUNDS.items():
        val = doc.get(key)
        if not isinstance(val, (int, float)) or isinstance(val, bool):
            raise ValueError(f"bad {key}: {val!r}")
        if not (lo <= float(val) <= hi):
            raise ValueError(f"{key}={val!r} outside {lo}..{hi}")
    if not isinstance(doc.get("workspace"), str) or not doc["workspace"]:
        raise ValueError("bad workspace")
    if not isinstance(doc.get("opencode_session"), str):
        raise ValueError("bad opencode_session")
    if len(doc["opencode_session"]) > 128:
        raise ValueError("opencode_session too long")
    if not isinstance(doc.get("opts"), dict):
        raise ValueError("bad opts")
    if not isinstance(doc.get("checks"), list):
        raise ValueError("bad checks")
    for c in doc["checks"]:
        if not isinstance(c, dict) or c.get("status") not in (
                "PASS", "FAIL", "NEEDS_INPUT", "OPTIONAL"):
            raise ValueError(f"bad check entry {c!r}")
    for key in ("blocked_checks", "events"):
        if not isinstance(doc.get(key), list):
            raise ValueError(f"bad {key}")
    for key in ("run_id", "lock_token", "needs_reason", "ready_evidence",
                "last_verifier_digest", "prompt_scope", "data_dir"):
        if not isinstance(doc.get(key), str):
            raise ValueError(f"bad {key}")
    return doc


def new_run_state(*, data_dir: Path, workspace: Path, opts: dict) -> dict:
    now = time.time()
    return {
        "schema_version": SCHEMA_VERSION,
        "run_id": uuid.uuid4().hex[:16],
        "lock_token": uuid.uuid4().hex[:16],
        "data_dir": str(data_dir),
        "workspace": str(workspace),
        "profile": _profile(opts),
        "mode": str(opts.get("mode", "dev") or "dev"),
        "prompt_scope": opts.get("prompt_scope", "") or "setup-infra only",
        "opts": {k: v for k, v in opts.items()
                 if k not in ("opencode_bin_secret",)},
        "status": "RUNNING",
        "attempts": 0,
        "max_attempts": int(opts.get("max_attempts", DEFAULT_MAX_ATTEMPTS)),
        "max_stagnant": int(opts.get("max_stagnant", DEFAULT_MAX_STAGNANT)),
        "stagnant_count": 0,
        "last_verifier_digest": "",
        "started_at": now,
        "updated_at": now,
        "wall_timeout_s": int(opts.get("wall_timeout_s", DEFAULT_WALL_TIMEOUT_S)),
        "attempt_timeout_s": int(opts.get("attempt_timeout_s", DEFAULT_ATTEMPT_TIMEOUT_S)),
        "active_seconds": 0.0,
        "opencode_session": "",
        "checks": [],
        "blocked_checks": [],
        "needs_reason": "",
        "events": [],
        "ready_evidence": "",
    }


def save_state(data_dir: Path, state: dict) -> None:
    state["updated_at"] = time.time()
    state["schema_version"] = SCHEMA_VERSION
    # Strip in-memory-only keys (monotonic window anchors) before persisting.
    doc = {k: v for k, v in state.items() if not k.startswith("_")}
    # Bound events; details are redacted at write time (defense in depth).
    doc["events"] = list(doc.get("events", []) or [])[-DEFAULT_MAX_EVENTS:]
    # Never persist secrets or raw prompts: stash only digests + redacted
    # evidence. Prompts are rebuilt per turn from verifier feedback.
    # The supervisor dir itself is private (0700): enforce here, not only in
    # cmd_start, so direct save_state callers (drive/resume/tests) keep the
    # mode even when the dir was auto-created by the atomic write.
    ensure_private_dir(supervisor_dir(data_dir))
    write_atomic_private(state_path(data_dir),
                         json.dumps(doc, indent=2, sort_keys=True) + "\n")


def load_state(data_dir: Path) -> dict:
    sp = state_path(data_dir)
    _refuse_symlink(sp, "state load")
    try:
        raw = sp.read_text(encoding="utf-8")
    except OSError as exc:
        raise ValueError(f"unreadable supervisor state: {exc}")
    try:
        doc = json.loads(raw)
    except json.JSONDecodeError as exc:
        raise ValueError(f"supervisor state is not valid JSON: {exc}")
    return validate_state(doc)


def append_event(state: dict, etype: str, detail: str) -> None:
    events = state.setdefault("events", [])
    events.append({"t": int(time.time()), "type": etype,
                   "detail": redact(detail)[:1000]})
    while len(events) > DEFAULT_MAX_EVENTS:
        events.pop(0)


# ---------------------------------------------------------------------------
# active-seconds wall budget (parked NEEDS_INPUT/STOPPED time excluded)


def _sync_active(state: dict) -> None:
    t0 = state.get("_t0_mono")
    if t0 is None:
        return
    base = float(state.get("_active_base", state.get("active_seconds", 0.0)))
    state["active_seconds"] = base + max(0.0, time.monotonic() - float(t0))


def budget_remaining_s(state: dict) -> float:
    _sync_active(state)
    return float(state.get("wall_timeout_s", DEFAULT_WALL_TIMEOUT_S)) - \
        float(state.get("active_seconds", 0.0))


# ---------------------------------------------------------------------------
# locking (fcntl exclusive, crash-safe; concurrent runs refuse; PID reuse and
# zombies cannot fool it -- the kernel lock is authoritative, pid/lstart are
# message-only; stale content is overwritten by the next holder)


_LOCK_FD: int | None = None
_LOCK_TOKEN: str | None = None


def _process_lstart(pid: int) -> str:
    try:
        out = subprocess.check_output(
            ["ps", "-p", str(pid), "-o", "lstart="],
            stderr=subprocess.STDOUT, timeout=10, text=True)
        return out.strip()[:64]
    except (OSError, subprocess.SubprocessError):
        return ""


def acquire_lock(data_dir: Path, token: str) -> None:
    global _LOCK_FD, _LOCK_TOKEN
    if _LOCK_FD is not None:
        raise RuntimeError("this process already holds the supervisor lock; "
                           "refusing nested acquire")
    ensure_private_dir(supervisor_dir(data_dir))
    lp = lock_path(data_dir)
    _refuse_symlink(lp, "lock")
    fd = os.open(str(lp), os.O_CREAT | os.O_RDWR, 0o600)
    try:
        os.chmod(lp, 0o600)
    except OSError:
        pass
    try:
        fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
    except OSError:
        holder = ""
        try:
            with os.fdopen(os.dup(fd), "r", encoding="utf-8") as f:
                doc = json.loads(f.read() or "{}")
            pid = int(doc.get("pid", 0) or 0)
            lst = str(doc.get("lstart", ""))
            holder = f" (holder pid {pid}{', started ' + lst if lst else ''})"
        except (OSError, ValueError):
            pass
        try:
            os.close(fd)
        except OSError:
            pass
        raise RuntimeError(
            f"supervisor already running for {data_dir}{holder}; refusing "
            f"concurrent run. Use `status`, or `resume` after it exits.")
    try:
        os.ftruncate(fd, 0)
        payload = json.dumps({"pid": os.getpid(), "token": token,
                              "lstart": _process_lstart(os.getpid()),
                              "t": int(time.time())}) + "\n"
        os.write(fd, payload.encode("utf-8"))
        try:
            os.fsync(fd)
        except OSError:
            pass
    except OSError as exc:
        try:
            fcntl.flock(fd, fcntl.LOCK_UN)
        except OSError:
            pass
        try:
            os.close(fd)
        except OSError:
            pass
        raise RuntimeError(f"cannot write supervisor lock: {exc}")
    _LOCK_FD = fd
    _LOCK_TOKEN = token


def release_lock(data_dir: Path, token: str) -> None:
    global _LOCK_FD, _LOCK_TOKEN
    if _LOCK_FD is not None:
        if _LOCK_TOKEN == token:
            try:
                lock_path(data_dir).unlink(missing_ok=True)
            except OSError:
                pass
            try:
                fcntl.flock(_LOCK_FD, fcntl.LOCK_UN)
            except OSError:
                pass
            try:
                os.close(_LOCK_FD)
            except OSError:
                pass
        _LOCK_FD = None
        _LOCK_TOKEN = None
        return
    # No fd held here: token-checked stale cleanup only.
    lp = lock_path(data_dir)
    try:
        doc = json.loads(lp.read_text(encoding="utf-8"))
        if str(doc.get("token", "")) == token:
            lp.unlink(missing_ok=True)
    except (OSError, ValueError):
        pass


# ---------------------------------------------------------------------------
# verifier runner (parent authority)


def run_checks(data_dir: Path, opts: dict) -> tuple[list[CheckResult], dict | None]:
    try:
        cfg = me_setup.load_config(data_dir)
    except me_setup.SetupError:
        cfg = None
    results: list[CheckResult] = []
    for check_id in CHECKS:
        try:
            res = CHECKS[check_id]["handler"](data_dir, cfg, opts)
        except Exception as exc:  # verifiers fail closed, never throw past parent
            res = CheckResult(check_id, "FAIL", evidence=f"verifier error: {exc}"[:400],
                              next_action="Repair the setup-infra checkout and re-run recheck.")
        if res.status not in ("PASS", "FAIL", "NEEDS_INPUT", "OPTIONAL"):
            res = CheckResult(check_id, "FAIL",
                              evidence=f"{check_id} verifier returned bad status "
                              f"{res.status!r}",
                              next_action="Fix the supervisor verifier (code bug).")
        res.evidence = redact(res.evidence)
        res.next_action = redact(res.next_action)
        res.needs_reason = redact(res.needs_reason)
        results.append(res)
    return results, cfg


def overall_status(results: list[CheckResult], opts: dict | None = None,
                   cfg: dict | None = None) -> tuple[str, str]:
    """Parent decision. Returns (status, reason).

    Order (review #1, #7): bootstrapping gate first (no OpenCode, no model
    requests); then fixable FAILs keep the loop RUNNING (independent work
    continues while credential/license gates pend); NEEDS_INPUT parks only
    when no required FAIL remains. Any non-PASS on a required check blocks
    (OPTIONAL/unknown never count as pass).
    """
    opts = opts or {}
    by_id = {r.id: r for r in results}
    gate = by_id.get("opencode_cli")
    if gate is not None and gate.status != "PASS":
        return "NEEDS_INPUT", (gate.needs_reason or gate.evidence or
                               "opencode unavailable")[:800]
    required = required_ids(opts, cfg)
    # FAIL (or a missing/unknown result, or OPTIONAL on a required check)
    # means fixable work remains -> keep RUNNING. NEEDS_INPUT on required
    # checks is parked, not failed: independent work continues first, and we
    # park only when no required FAIL remains.
    failed = []
    missing = []
    for c in required:
        r = by_id.get(c)
        if r is None:
            missing.append(c)
        elif r.status == "FAIL":
            failed.append(r)
        elif r.status != "PASS" and r.status != "NEEDS_INPUT":
            # OPTIONAL/unknown on a required check blocks (never skip-as-pass).
            failed.append(r)
    if failed or missing:
        parts = [f"{r.id}: {r.evidence}" for r in failed]
        parts += [f"{c}: missing verifier" for c in missing]
        return "RUNNING", "; ".join(parts)[:800]
    needs = [by_id[c] for c in required
             if by_id[c].status == "NEEDS_INPUT"]
    if needs:
        r = needs[0]
        return "NEEDS_INPUT", (r.needs_reason or r.evidence)[:800]
    profile = _profile(opts)
    if profile == "configure":
        return "CONFIGURED", "configure profile verified (explicitly not complete)"
    if profile == "test":
        return "TEST_READY", "TEST profile verified (synthetic only, never production)"
    return "READY", "all required checks PASS with evidence"


def failing_feedback(results: list[CheckResult], required: list[str]) -> str:
    """Concrete per-check feedback + next commands for the next agent turn."""
    lines = []
    by_id = {r.id: r for r in results}
    for cid in required:
        r = by_id.get(cid)
        if r is None or r.status == "PASS":
            continue
        lines.append(f"- [{cid}] {r.status}: {r.evidence}")
        if r.next_action:
            lines.append(f"  FIX: {r.next_action}")
    parked = sorted({r.id for r in results if r.status == "NEEDS_INPUT"})
    if parked:
        lines.append("Parked external gates (do NOT block other fixes; do NOT "
                     f"ask repeatedly): {', '.join(parked)}")
    return "\n".join(lines)[:4000]


def verifier_digest(results: list[CheckResult], required: list[str]) -> str:
    """Normalized digest of REQUIRED verifier evidence (parent-side).

    Chat-only replies never touch this; timestamps/PIDs/random strings are
    normalized out, so only real evidence changes (e.g. prereqs 5 fail -> 1
    fail) reset the stagnation counter.
    """
    by_id = {r.id: r for r in results}
    parts = []
    for cid in sorted(required):
        r = by_id.get(cid)
        if r is None:
            parts.append(f"{cid}:MISSING")
        else:
            norm = digest_of(f"{r.status} {r.evidence}")
            parts.append(f"{cid}:{r.status}:{norm}")
    return hashlib.sha256("\n".join(parts).encode("utf-8")).hexdigest()[:16]


def digest_of(text: str) -> str:
    norm = text or ""
    # Strip timestamps / uuids / hashes / volatile numbers so chat-only
    # replies ("done!", rephrased progress) never count as progress.
    norm = re.sub(r"\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}(:\d{2})?([^\s]*)?", " ", norm)
    norm = re.sub(r"\b[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}\b", " ", norm, flags=re.I)
    norm = re.sub(r"\b[0-9a-f]{16,}\b", " ", norm, flags=re.I)
    norm = re.sub(r"\b\d+(\.\d+)+\b", " ", norm)
    norm = re.sub(r"\s+", " ", norm).strip().lower()
    return hashlib.sha256(norm.encode("utf-8")).hexdigest()[:16]


# ---------------------------------------------------------------------------
# agent prompt (DEV worker vs product provisioner -- explicit --mode)


def build_agent_prompt(*, data_dir: Path, workspace: Path, results: list[CheckResult],
                       required: list[str], attempt: int, prompt_scope: str,
                       mode: str = "dev") -> str:
    if mode == "provision":
        scope_rules = (
            "You are the product provisioner for the HOME-OWNED target "
            f"(workspace {workspace}, home data dir {data_dir}; scope: {prompt_scope}). "
            "Allowed in OPERATOR-OWNED paths: install trusted needed dependencies, "
            "pull verified upstream images (pinned, provenance-recorded), rerunnable "
            "config, service start. MUST NOT edit the trusted checker/supervisor or "
            "product source to game checks (me_supervisor.py, verifiers, product "
            "source are off-limits). Install NOTHING globally on the DEV machine; "
            "the existing OpenCode install is left alone. Provider/license keys stay "
            "in operator env/files only -- never chat them, never bake them."
        )
    else:
        scope_rules = (
            f"You are the DEV setup worker. Workspace: {workspace}. "
            f"Home data dir: {data_dir}. Scope: {prompt_scope}. "
            "Rules: setup-infra files only (scripts/, docs/, tests). Do NOT edit "
            "agentic-framework/, backend-server/, infra-server/, phone-app/, web-app/. "
            "Do NOT install heavy packages/images or anything global on THIS Mac; "
            "the provisioner (not you) handles home-target dependencies. "
            "Do NOT choose completion criteria, do NOT mark yourself done, do NOT "
            "claim upstream readiness from fixture configs. Do NOT delete history/user "
            "files; do NOT read user auth secrets."
        )
    lines = [
        scope_rules,
        "Completion criteria are owned by the parent supervisor, not by you: "
        "do NOT claim done; make real filesystem/config changes and stop.",
        f"Attempt {attempt}: the independent verifier (parent process) reports "
        "these REQUIRED checks failing. Fix each with real changes:",
        failing_feedback(results, required),
        "Reply with a short summary of the concrete commands you ran and "
        "files you changed. The supervisor re-verifies independently; "
        "chat-only replies without real fixes do not advance.",
    ]
    prompt = "\n".join(lines)
    return prompt[:8000]


# ---------------------------------------------------------------------------
# OpenCode subprocess (truly bounded concurrent draining, process-group kill,
# strict session parse, no secret/prompt persistence)

_SESSION_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_\-]{3,127}$")


def parse_session_id(lines: list[str]) -> str:
    """Strict session parse: JSON objects only, known envelope positions only.

    Accepts top-level sessionID/sessionId/session_id and one nested
    {"session": {"id"|"sessionID"|"sessionId"|"session_id"}} object. Never
    regex-scans arbitrary nested tool text (avoids fake IDs from tool output).
    """
    for line in lines:
        line = line.strip()
        if not line.startswith("{"):
            continue
        try:
            doc = json.loads(line)
        except ValueError:
            continue
        if not isinstance(doc, dict):
            continue
        for key in ("sessionID", "sessionId", "session_id"):
            val = doc.get(key)
            if isinstance(val, str) and _SESSION_RE.match(val):
                return val
        sub = doc.get("session")
        if isinstance(sub, dict):
            for key in ("id", "sessionID", "sessionId", "session_id"):
                val = sub.get(key)
                if isinstance(val, str) and _SESSION_RE.match(val):
                    return val
    return ""


def _terminate_group(proc: subprocess.Popen) -> None:
    """Bounded TERM -> KILL of the whole child process group (fixed deadlines)."""
    if proc.poll() is not None:
        return
    try:
        os.killpg(os.getpgid(proc.pid), signal.SIGTERM)
    except (OSError, ProcessLookupError):
        pass
    try:
        proc.wait(timeout=KILL_GRACE_S)
        return
    except subprocess.TimeoutExpired:
        pass
    try:
        os.killpg(os.getpgid(proc.pid), signal.SIGKILL)
    except (OSError, ProcessLookupError):
        pass
    try:
        proc.wait(timeout=KILL_GRACE_S)
    except (OSError, subprocess.SubprocessError):
        pass


def _drain_thread(stream, buf: dict, lock: threading.Lock,
                   max_bytes: int, kept_lines: list) -> None:
    """Read until EOF/error; keep the LAST max_bytes + last decoded lines.

    ALSO captures the first valid structured sessionID DURING the stream
    (not only from the EOF tail): a long normal turn can evict the initial
    session event from the bounded tail, so the session is latched as soon
    as it is seen. Bounded: only the last 262144 pending bytes are decoded
    per chunk for the incremental scan.
    """
    data = bytearray()
    pending = b""
    try:
        while True:
            try:
                chunk = stream.read(65536)
            except (OSError, ValueError):
                break
            if not chunk:
                break
            if isinstance(chunk, str):
                chunk = chunk.encode("utf-8", "replace")
            with lock:
                buf["total"] = int(buf.get("total", 0)) + len(chunk)
            data += chunk
            if len(data) > max_bytes:
                del data[:len(data) - max_bytes]
                buf["truncated"] = True
            pending += chunk[-262144:] if len(chunk) > 262144 else chunk
            if len(pending) > 262144:
                pending = pending[-262144:]
            # Incremental session latch (bounded): scan THIS chunk's lines
            # first (session is usually at turn start and would otherwise be
            # outside the trailing pending window), then the recent pending
            # tail as fallback. Latch once; never overwrite.
            if not buf.get("session"):
                try:
                    chunk_text = bytes(chunk[-65536:]).decode("utf-8", "replace")
                    found = parse_session_id(
                        [ln[:DEFAULT_PER_LINE_CAP]
                         for ln in chunk_text.splitlines()[:200]])
                except (OSError, ValueError):
                    found = ""
                if not found:
                    try:
                        sample = bytes(pending[-32768:]).decode("utf-8", "replace")
                        found = parse_session_id(
                            [ln[:DEFAULT_PER_LINE_CAP]
                             for ln in sample.splitlines()[-32:]])
                    except (OSError, ValueError):
                        found = ""
                if found:
                    with lock:
                        if not buf.get("session"):
                            buf["session"] = found
    finally:
        try:
            text = bytes(pending).decode("utf-8", "replace")
        except (OSError, ValueError):
            text = ""
        lines = text.splitlines()[-DEFAULT_KEPT_LINES:]
        lines = [ln[:DEFAULT_PER_LINE_CAP] for ln in lines]
        with lock:
            buf["tail"] = bytes(data)
            kept_lines.extend(lines[-DEFAULT_KEPT_LINES:])
            del kept_lines[:-DEFAULT_KEPT_LINES]


def _scoped_permission_env(*, workspace: Path,
                            data_dir: Path | None) -> dict[str, str]:
    """Scoped OPENCODE_PERMISSION for installation-owned paths only.

    The agent works in --dir <workspace> and the home data dir <data_dir>;
    both are OUTSIDE each other so every turn touches external_directory.
    Without a scoped allow the CLI auto-rejects (non-interactive) or stalls
    asking. We allow ONLY these two installation-owned trees via the
    OPENCODE_PERMISSION env (never modifies global
    ~/.config/opencode/opencode.jsonc, never allows all personal files).
    Operator-provided OPENCODE_PERMISSION is merged with operator rules
    winning (appended last): our taskpath allows never weaken an explicit
    operator deny.
    """
    scope: list[str] = []
    for base in (workspace, data_dir):
        if base is None:
            continue
        try:
            resolved = str(Path(base).resolve())
        except OSError:
            resolved = str(base)
        if resolved and resolved not in scope:
            scope.append(resolved)
    ours: dict[str, str] = {f"{p}/**": "allow" for p in scope}
    # Also allow the exact dir itself (pattern without /**).
    for p in scope:
        ours.setdefault(p, "allow")
    merged_ext: dict[str, str] = dict(ours)
    existing_raw = os.environ.get("OPENCODE_PERMISSION", "").strip()
    if existing_raw:
        try:
            existing = json.loads(existing_raw)
            if isinstance(existing, dict):
                ext = existing.get("external_directory")
                if isinstance(ext, dict):
                    for k, v in ext.items():
                        if isinstance(k, str) and isinstance(v, str):
                            merged_ext[k] = v
        except ValueError:
            pass
    return {"OPENCODE_PERMISSION": json.dumps(
        {"external_directory": merged_ext})}


def _terminate_residual_group(pgid: int | None) -> None:
    """Kill pipe-holding grandchildren after the leader already exited.

    The leader's pid is useless here (reaped: getpgid on it raises ESRCH and
    would silently skip the kill), so callers capture the process-group id at
    SPAWN while the leader is alive and pass it in. Kills by pgid regardless
    of leader state (best effort), then SIGKILL after the fixed grace. Never
    waits indefinitely. pgid None (spawn raced) is a safe no-op.
    """
    if pgid is None:
        return
    for sig in (signal.SIGTERM, signal.SIGKILL):
        try:
            os.killpg(pgid, sig)
        except (OSError, ProcessLookupError):
            return
        if sig == signal.SIGTERM:
            time.sleep(min(KILL_GRACE_S, 2.0))
            try:
                os.killpg(pgid, 0)
            except (OSError, ProcessLookupError):
                return


def parse_permission_events(out_lines: list[str],
                            err_lines: list[str],
                            *,
                            workspace: Path | None = None,
                            data_dir: Path | None = None) -> list[dict]:
    """Structured permission-needed signals from a turn (bounded).

    Detects: `permission requested: <tool> (<pattern>)` stderr notices,
    tool_use error states mentioning rejected permission, and `question`
    tool calls (which stall non-interactively). Classifies each as
    `taskpath` (inside workspace/data_dir install-owned trees -> covered by
    our scoped allow; a denial here is a scoping bug) vs `external`
    (outside install-owned trees -> agent left its scope; not an operator
    credential gate). Callers bound the count; this helper caps at 20.
    """
    scope: list[str] = []
    for base in (workspace, data_dir):
        if base is None:
            continue
        try:
            scope.append(str(Path(base).resolve()))
        except OSError:
            scope.append(str(base))

    def _class(path: str) -> str:
        for s in scope:
            if path == s or path.startswith(s.rstrip("/") + "/"):
                return "taskpath"
        return "external"

    events: list[dict] = []

    def _push(kind: str, detail: str, path: str = "") -> None:
        if len(events) >= 20:
            return
        cls = _class(path) if path else ("taskpath" if kind == "question"
                                         else "external")
        events.append({"kind": kind, "class": cls,
                       "detail": redact(detail)[:300],
                       "path": path[:300]})
    perm_re = re.compile(r"permission requested:\s*([A-Za-z0-9_]+)\s*\(([^)]*)\)")
    for ln in (err_lines[-50:] + out_lines[-50:]):
        m = perm_re.search(ln or "")
        if m:
            _push("permission-requested",
                  f"{m.group(1)} {m.group(2)}", m.group(2).strip())
    # JSON tool_use errors mentioning permission rejection.
    for ln in out_lines[-100:]:
        s = (ln or "").strip()
        if not s.startswith("{"):
            continue
        try:
            doc = json.loads(s)
        except ValueError:
            continue
        part = doc.get("part") if isinstance(doc, dict) else None
        if not isinstance(part, dict):
            continue
        tool = str(part.get("tool", ""))
        state = part.get("state") if isinstance(part.get("state"), dict) else {}
        status = str(state.get("status", ""))
        errmsg = str(state.get("error", ""))
        if "permission" in errmsg.lower() and "reject" in errmsg.lower():
            inp = state.get("input") if isinstance(state.get("input"), dict) else {}
            path = str(inp.get("filePath") or inp.get("path")
                       or inp.get("pattern") or "")
            _push("permission-denied", f"{tool} {errmsg[:160]}", path)
        if tool == "question" and status in ("completed", "pending", ""):
            _push("question-asked", f"question tool used ({status or 'seen'})")
    return events


# Setup OpenCode CLI model/auth is DISTINCT from the product native harness
# model. A fresh home can have the binary with no CLI auth: the turn then
# errors with structured provider/authentication failures. Those are a
# genuine operator gate (secure `opencode auth login` + resume), NOT
# chat-no-progress: parking as NEEDS_INPUT avoids repeated STALLED burn, and
# developer auth files are never read. Only CLI-level signals count (stderr
# notices + JSON error-type parts) -- agent prose mentioning auth is NOT a
# gate (avoids false parks from normal discussion).
_CLI_AUTH_RES = (
    re.compile(r"not authenticated\b"),
    re.compile(r"authentication (required|failed|error)"),
    re.compile(r"auth (required|failed|error)"),
    re.compile(r"\bopencode auth login\b"),
    re.compile(r"provider .*not (configured|authenticated|found|available)"),
    re.compile(r"no .*api key (configured|found|set)"),
    re.compile(r"invalid api key"),
    re.compile(r"\b401\b.*(unauthori[sz]ed|auth)"),
    re.compile(r"login required"),
)


def _is_cli_auth_error(out: str, serr: str, out_lines: list[str]) -> bool:
    """True when the CLI itself reports missing model auth (bounded scan)."""
    for ln in (serr or "").splitlines()[-30:]:
        low = ln or ""
        for rx in _CLI_AUTH_RES:
            if rx.search(low):
                return True
    for ln in (out_lines or [])[-60:]:
        s = (ln or "").strip()
        if not s.startswith("{"):
            continue
        try:
            doc = json.loads(s)
        except ValueError:
            continue
        if not isinstance(doc, dict):
            continue
        etype = str(doc.get("type", "") or "").lower()
        if etype in ("error", "auth_error", "auth-required"):
            return True
        part = doc.get("part") if isinstance(doc.get("part"), dict) else None
        if isinstance(part, dict):
            ptype = str(part.get("type", "") or "").lower()
            if ptype in ("error", "auth_error"):
                text = json.dumps(part)[:2000]
                for rx in _CLI_AUTH_RES:
                    if rx.search(text):
                        return True
    return False


def run_opencode_turn(*, binary: str, workspace: Path, prompt: str,
                       session_id: str, timeout_s: float,
                       max_output: int = DEFAULT_MAX_OUTPUT_BYTES,
                       auto: bool = True,
                       data_dir: Path | None = None) -> tuple[int, str, str, str]:
    """One bounded agent turn. Returns (rc, stdout_tail, stderr_tail, session).

    Memory is bounded DURING the run (concurrent draining threads with byte
    caps), not truncate-after-communicate. Total output across both streams
    is capped at 4x max_output: a flood terminates its own process group
    (bounded flood kill, reaped). On the wall deadline the whole process
    group is terminated (TERM, fixed grace, KILL) and reaped -- no orphans,
    including TERM-ignoring children and grandchildren (same group). When
    the leader exits but a grandchild still holds a pipe open, the residual
    group is killed so drain threads see EOF (no close/read deadlock).
    Session IDs latch DURING streaming (initial event survives tail eviction).
    """
    global _child_proc
    argv = [binary, "run", "--format", "json", "--dir", str(workspace)]
    if auto and supports_auto(binary):
        argv += ["--auto"]
    if session_id:
        argv += ["--session", session_id]
    argv.append(prompt)
    # Operator environment inherited unchanged: no XDG overrides means we do
    # not SET fake XDG paths -- legitimate existing vars pass through. The
    # ONLY addition is a scoped OPENCODE_PERMISSION allow for the two
    # installation-owned trees (workspace + data dir); global user config is
    # never modified and no personal paths are allowed.
    child_env = dict(os.environ)
    try:
        child_env.update(_scoped_permission_env(workspace=workspace,
                                                data_dir=data_dir))
    except OSError:
        pass
    try:
        proc = subprocess.Popen(
            argv, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
            stdin=subprocess.DEVNULL, start_new_session=True, env=child_env)
    except OSError as exc:
        return 127, "", redact(f"failed to spawn opencode: {exc}"), session_id
    _child_proc = proc
    # Capture the group id NOW (leader alive): after it is reaped getpgid on
    # its pid raises ESRCH and a residual kill would silently no-op.
    try:
        turn_pgid: int | None = os.getpgid(proc.pid)
    except (OSError, ProcessLookupError):
        turn_pgid = None
    lock = threading.Lock()
    out_buf: dict = {"tail": b"", "truncated": False, "total": 0,
                     "session": ""}
    err_buf: dict = {"tail": b"", "truncated": False, "total": 0,
                     "session": ""}
    out_lines: list[str] = []
    err_lines: list[str] = []
    threads = [
        threading.Thread(target=_drain_thread,
                         args=(proc.stdout, out_buf, lock, max_output, out_lines),
                         daemon=True),
        threading.Thread(target=_drain_thread,
                         args=(proc.stderr, err_buf, lock, max_output, err_lines),
                         daemon=True),
    ]
    for t in threads:
        t.start()
    old_int = signal.signal(signal.SIGINT, _handle_term)
    old_term = signal.signal(signal.SIGTERM, _handle_term)
    rc = 0
    note = ""
    deadline = time.monotonic() + max(1.0, float(timeout_s))
    flood_cap = int(max_output) * 4
    try:
        while True:
            if _STOP_REQUESTED["signo"] is not None:
                _terminate_group(proc)
                rc = stop_code()
                note = "[SUPERVISOR: interrupted by signal; run persists as RUNNING]"
                break
            with lock:
                total = int(out_buf.get("total", 0)) + int(err_buf.get("total", 0))
            if total > flood_cap:
                _terminate_group(proc)
                rc = proc.returncode if proc.returncode is not None else 124
                note = ("[SUPERVISOR: output flood cap exceeded "
                        f"({total}B > {flood_cap}B); process group terminated]")
                break
            ret = proc.poll()
            if ret is not None:
                rc = ret
                # Leader exited: grandchildren may still hold pipes open and
                # keep drain threads blocked. Bounded grace for natural EOF,
                # then kill the residual group so reads terminate (no
                # close/read deadlock), then bounded joins.
                for t in threads:
                    t.join(timeout=2.0)
                if any(t.is_alive() for t in threads):
                    _terminate_residual_group(turn_pgid)
                    for t in threads:
                        t.join(timeout=5.0)
                break
            if time.monotonic() >= deadline:
                _terminate_group(proc)
                rc = proc.returncode if proc.returncode is not None else 124
                note = ("[SUPERVISOR: attempt wall timeout exceeded; process "
                        "group terminated]")
                break
            time.sleep(0.05)
    finally:
        signal.signal(signal.SIGINT, old_int)
        signal.signal(signal.SIGTERM, old_term)
        _child_proc = None
        if proc.poll() is None:
            _terminate_group(proc)
            if rc == 0:
                rc = proc.returncode if proc.returncode is not None else 124
        elif rc == 0:
            # Leader already reaped: keep the loop's verdict (stop/timeout
            # codes included), only fill in an unset rc.
            rc = proc.returncode if proc.returncode is not None else rc
        try:
            proc.wait(timeout=KILL_GRACE_S)
        except (OSError, subprocess.SubprocessError):
            pass
        # Joins BEFORE closes: closing a pipe while a drain thread is blocked
        # in read() can deadlock. Threads already joined on the leader-exit
        # path; re-join bounded here for the timeout/signal paths.
        for t in threads:
            if t.is_alive():
                t.join(timeout=5.0)
        for stream in (proc.stdout, proc.stderr):
            try:
                if stream is not None:
                    stream.close()
            except OSError:
                pass
    out = bytes(out_buf["tail"]).decode("utf-8", "replace")
    serr = bytes(err_buf["tail"]).decode("utf-8", "replace")
    if out_buf["truncated"] or err_buf["truncated"]:
        serr += "\n[SUPERVISOR: output truncated at byte cap]"
    if note:
        serr = (serr + "\n" + note) if serr else note
    # Strict session reuse: latched DURING streaming first (survives tail
    # eviction), then bounded EOF tail, never reset from agent prose.
    new_session = (out_buf.get("session") or err_buf.get("session")
                   or parse_session_id(out_lines) or session_id)
    # CLI model/auth signal (P0-4): detected here where the bounded decoded
    # line buffers are available (survives byte-tail truncation); the drive
    # loop parks NEEDS_INPUT on the marker below.
    try:
        if _is_cli_auth_error(out, serr, out_lines + err_lines):
            serr += ("\n[SUPERVISOR cli-auth-required: OpenCode CLI reports "
                     "missing model authentication]")
    except (OSError, ValueError):
        pass
    # Structured permission-needed signals (bounded, classified). Taskpath
    # denials mean our scoped allow missed a path (fixable); external denials
    # mean the agent left its install-owned scope (feedback, not an operator
    # credential gate). Recorded on stderr tail (bounded) for drive events.
    try:
        for ev in parse_permission_events(out_lines, err_lines,
                                          workspace=workspace,
                                          data_dir=data_dir)[:8]:
            serr += (f"\n[SUPERVISOR permission:{ev['kind']}:{ev['class']}"
                     f" {ev['detail'][:160]}]")
    except (OSError, ValueError):
        pass
    return rc, redact(out), redact(serr), new_session


# ---------------------------------------------------------------------------
# main loop


def _opts_from_state(state: dict) -> dict:
    return dict(state.get("opts", {}))


def drive(state: dict, *, data_dir: Path, binary: str) -> int:
    opts = _opts_from_state(state)
    opts.setdefault("opencode_bin", binary)
    # Active-seconds window starts now (monotonic; parked time never accrues).
    state["_t0_mono"] = time.monotonic()
    state["_active_base"] = float(state.get("active_seconds", 0.0))
    auto = bool(opts.get("auto", True))
    # Whole-lifecycle signal handling: SIGINT/SIGTERM during CHECKS (not only
    # during the child turn) must persist resumable RUNNING and reap -- the
    # handler never waits, the loop observes the flag at the top and saves.
    outer_int = signal.signal(signal.SIGINT, _handle_term)
    outer_term = signal.signal(signal.SIGTERM, _handle_term)
    try:
        return _drive_loop(state, data_dir=data_dir, binary=binary, auto=auto,
                           opts=opts)
    finally:
        try:
            signal.signal(signal.SIGINT, outer_int)
        except (OSError, ValueError):
            pass
        try:
            signal.signal(signal.SIGTERM, outer_term)
        except (OSError, ValueError):
            pass


def _drive_loop(state: dict, *, data_dir: Path, binary: str, auto: bool,
                opts: dict) -> int:
    while True:
        _sync_active(state)
        if _STOP_REQUESTED["signo"] is not None:
            state["status"] = "RUNNING"
            append_event(state, "interrupted",
                         f"signal {stop_code()}; run persists as RUNNING (resumable)")
            save_state(data_dir, state)
            return stop_code()
        results, cfg = run_checks(data_dir, opts)
        required = required_ids(opts, cfg)
        # Share the remaining ACTIVE deadline with every probe/doctor inside
        # this iteration (checks clamp to it; never stack past the budget).
        try:
            opts["_deadline_mono"] = time.monotonic() + max(
                1.0, budget_remaining_s(state))
        except (TypeError, ValueError):
            opts["_deadline_mono"] = None
        # Verifier-evidence stagnation: normalized required-evidence digest.
        # External fixes (operator/manual) reset the counter without consuming
        # a turn; chat-only output never touches this digest.
        vdig = verifier_digest(results, required)
        if state.get("last_verifier_digest") and \
                vdig == state["last_verifier_digest"]:
            state["stagnant_count"] = int(state.get("stagnant_count", 0)) + 1
        else:
            state["stagnant_count"] = 0
        state["last_verifier_digest"] = vdig
        state["checks"] = [{"id": r.id, "status": r.status,
                            "evidence": r.evidence[:500],
                            "next": r.next_action[:500]} for r in results]
        status, reason = overall_status(results, opts, cfg)
        if status in TERMINAL_OK:
            state["status"] = status
            state["needs_reason"] = ""
            state["ready_evidence"] = "; ".join(
                f"{r.id}={r.evidence[:160]}" for r in results
                if r.status == "PASS")[:1500]
            if status == "READY" and not _backup_required(opts):
                # Precise readiness scope (P0-5): operational agent services
                # are verified; complete upstream backups are a SEPARATE
                # unsupported capability (backup.supported=false), never
                # claimed by READY.
                state["ready_evidence"] = (
                    state["ready_evidence"]
                    + "; backup.supported=false (operational services READY; "
                    "complete upstream backups excluded/unsupported)")[:1500]
            append_event(state, "terminal_ok",
                         f"{status}: {state['ready_evidence']}")
            save_state(data_dir, state)
            log(f"supervisor {status}: {state['ready_evidence']}")
            return 0
        if status == "NEEDS_INPUT":
            # Park only when no required FAIL remains (independent fixable
            # work was already attempted in earlier turns). Blocked checks
            # persist separately so we never re-ask repeatedly.
            state["status"] = "NEEDS_INPUT"
            state["needs_reason"] = reason[:800]
            state["blocked_checks"] = sorted(
                {r.id for r in results if r.status == "NEEDS_INPUT"})
            if reason != state.get("_last_needs", ""):
                append_event(state, "needs_input", reason)
                state["_last_needs"] = reason
            save_state(data_dir, state)
            err(f"supervisor NEEDS_INPUT: {redact(reason)}")
            return 4
        # RUNNING from here. Recheck-before-budget: a user fix applied while
        # parked (or at max attempts) was already classified above, so budget
        # failures only fire for still-RUNNING runs.
        if int(state.get("attempts", 0)) >= int(state.get("max_attempts", DEFAULT_MAX_ATTEMPTS)):
            state["status"] = "FAILED"
            append_event(state, "budget", "max attempts exhausted")
            save_state(data_dir, state)
            err("supervisor FAILED: attempt budget exhausted")
            return 1
        if int(state.get("stagnant_count", 0)) >= int(state.get("max_stagnant", DEFAULT_MAX_STAGNANT)):
            state["status"] = "STALLED"
            append_event(state, "stalled",
                         f"no verifier progress for {state['stagnant_count']} turns")
            save_state(data_dir, state)
            err("supervisor STALLED: repeated turns with no verifier progress "
                "(bounded; not infinite burn). Inspect status, fix manually, resume.")
            return 1
        remaining = budget_remaining_s(state)
        if remaining <= 0:
            state["status"] = "FAILED"
            append_event(state, "wall_timeout", "active-seconds wall budget exhausted")
            save_state(data_dir, state)
            err("supervisor FAILED: wall budget exhausted (active seconds only; "
                "parked time excluded)")
            return 1
        # Bootstrapping gate: no OpenCode, no model requests. Install is part
        # of user-invoked `start` consent unless --no-install opted out.
        opencode_bin = discover_opencode(opts.get("opencode_bin") or None)
        if not opencode_bin:
            if opts.get("allow_install"):
                try:
                    changed, detail = install_opencode(allow_install=True)
                    log(detail)
                except RuntimeError as exc:
                    state["status"] = "NEEDS_INPUT"
                    state["needs_reason"] = str(exc)[:500]
                    state["blocked_checks"] = ["opencode_cli"]
                    append_event(state, "needs_input", state["needs_reason"])
                    save_state(data_dir, state)
                    err(f"supervisor NEEDS_INPUT: {redact(state['needs_reason'])}")
                    return 4
                opencode_bin = discover_opencode(opts.get("opencode_bin") or None)
            if not opencode_bin:
                state["status"] = "NEEDS_INPUT"
                state["needs_reason"] = (
                    "opencode-not-installed: operator consent required to run "
                    f"the official installer ({OFFICIAL_INSTALL_URL}); re-run "
                    "without --no-install, or install manually and resume")
                state["blocked_checks"] = ["opencode_cli"]
                append_event(state, "needs_input", state["needs_reason"])
                save_state(data_dir, state)
                err(f"supervisor NEEDS_INPUT: {state['needs_reason']}")
                return 4
        # One more agent turn with concrete feedback. Attempt timeout is
        # clamped to the REMAINING whole budget (checks included).
        attempt = int(state.get("attempts", 0)) + 1
        eff_timeout = min(float(state.get("attempt_timeout_s",
                                          DEFAULT_ATTEMPT_TIMEOUT_S)),
                          max(5.0, budget_remaining_s(state)))
        prompt = build_agent_prompt(
            data_dir=data_dir, workspace=Path(state["workspace"]),
            results=results, required=required, attempt=attempt,
            prompt_scope=state.get("prompt_scope", "setup-infra only"),
            mode=state.get("mode", "dev"))
        state["attempts"] = attempt
        append_event(state, "attempt_start",
                     f"attempt {attempt}; failing={[c for c in required if ({r_id_map(results).get(c, None) or 'PASS'}) != 'PASS']}")
        save_state(data_dir, state)
        log(f"--- attempt {attempt}/{state['max_attempts']}: invoking opencode "
            f"(session {state.get('opencode_session') or 'new'}) ---")
        log(failing_feedback(results, required)[:1500])
        rc, out, serr, session = run_opencode_turn(
            binary=opencode_bin, workspace=Path(state["workspace"]), prompt=prompt,
            session_id=state.get("opencode_session", ""),
            timeout_s=eff_timeout, auto=auto, data_dir=data_dir)
        if session and session != state.get("opencode_session"):
            # Parsed session IDs only (never agent prose); never reset an
            # active session to empty from LLM text.
            state["opencode_session"] = session
        append_event(state, "attempt_end",
                     f"attempt {attempt} rc={rc} stagnant={state['stagnant_count']} "
                     f"out={len(out)}b err={len(serr)}b "
                     f"out_tail={redact(out[-300:])}")
        if serr.strip():
            append_event(state, "attempt_stderr", redact(serr[-500:]))
        # CLI model/auth gate (P0-4): the binary exists but has no provider
        # auth (fresh home). The turn cannot do work; parking as NEEDS_INPUT
        # with the secure `opencode auth login` path avoids repeated
        # chat-no-progress STALLED burn. Session is kept for resume. The
        # marker is appended by run_opencode_turn (survives tail eviction).
        if "cli-auth-required" in (serr or "") or _is_cli_auth_error(
                out, serr, out_lines_from_turn(out)):
            state["status"] = "NEEDS_INPUT"
            state["needs_reason"] = (
                "opencode-cli-auth-required: the OpenCode CLI has no model "
                "authentication (fresh home, binary present). Run `opencode "
                "auth login` in the operator shell (normal secure CLI login; "
                "never paste provider keys into chat, never read developer "
                "auth files), keep the default model, then resume.")[:800]
            state["blocked_checks"] = ["opencode_cli"]
            append_event(state, "needs_input", state["needs_reason"])
            save_state(data_dir, state)
            err(f"supervisor NEEDS_INPUT: {redact(state['needs_reason'])}")
            return 4
        save_state(data_dir, state)
        # Loop continues: the next iteration re-verifies (parent authority).


def out_lines_from_turn(out: str) -> list[str]:
    """Bounded line split of a turn tail for CLI-error scanning."""
    try:
        return out.splitlines()[-100:]
    except (AttributeError, ValueError):
        return []


def r_id_map(results: list[CheckResult]) -> dict[str, str]:
    return {r.id: r.status for r in results}


# ---------------------------------------------------------------------------
# CLI commands


def cmd_start(args) -> int:
    try:
        data_dir = me_setup.resolve_data_dir(args.data_dir)
    except me_setup.SetupError as exc:
        err(f"error: {exc}")
        return 2
    workspace = Path(args.workspace or str(Path.cwd())).resolve()
    if not workspace.is_dir():
        err(f"error: workspace {workspace} is not a directory")
        return 2
    profile = str(args.profile or "production")
    if profile not in PROFILES:
        err(f"error: --profile must be one of {list(PROFILES)}")
        return 2
    mode = str(args.mode or "dev")
    if mode not in MODES:
        err(f"error: --mode must be one of {list(MODES)}")
        return 2
    allow_install = bool(args.allow_install) and not bool(args.no_install)
    # Default: user-invoked `start` IS install consent (missing binary only).
    if not args.no_install and not args.allow_install:
        allow_install = True
    opts = {
        "profile": profile,
        "mode": mode,
        "require_service": bool(args.require_service),
        "allow_install": allow_install,
        "opencode_bin": args.opencode_bin or "",
        "max_attempts": int(args.max_attempts),
        "max_stagnant": int(args.max_stagnant),
        "wall_timeout_s": int(args.wall_timeout),
        "attempt_timeout_s": int(args.attempt_timeout),
        "prompt_scope": args.prompt_scope or "setup-infra only",
        "model": args.model or "",
        "auto": not bool(args.no_auto),
        "upstream_contract": args.upstream_contract or "",
        "upstream_doctor": args.upstream_doctor or "",
        "intelligence_url": args.intelligence_url or "",
        "require_backup": bool(args.require_backup),
    }
    ensure_private_dir(supervisor_dir(data_dir))
    token = uuid.uuid4().hex[:16]
    try:
        acquire_lock(data_dir, token)
    except RuntimeError as exc:
        err(f"error: {exc}")
        return 2
    binary = discover_opencode(args.opencode_bin or None)
    try:
        state = new_run_state(data_dir=data_dir, workspace=workspace, opts=opts)
        state["lock_token"] = token
        append_event(state, "start",
                     f"profile={profile} mode={mode} workspace={workspace} "
                     f"binary={binary or 'missing'}")
        save_state(data_dir, state)
        return drive(state, data_dir=data_dir, binary=binary or "")
    finally:
        release_lock(data_dir, token)


def cmd_status(args) -> int:
    try:
        data_dir = me_setup.resolve_data_dir(args.data_dir)
    except me_setup.SetupError as exc:
        err(f"error: {exc}")
        return 2
    sp = state_path(data_dir)
    if not sp.is_file():
        err(f"no supervisor run yet at {sp}; use `start` first")
        return 2
    try:
        state = load_state(data_dir)
    except ValueError as exc:
        err(f"error: unreadable supervisor state: {exc}")
        return 1
    opts = _opts_from_state(state)
    results, cfg = run_checks(data_dir, opts)
    live, _ = overall_status(results, opts, cfg)
    req = required_ids(opts, cfg)
    by_id = {r.id: r for r in results}
    out_lines = [
        f"status: {state.get('status')} (live verifiers now: {live}; "
        f"profile={state.get('profile')} mode={state.get('mode')})",
        f"attempts: {state.get('attempts')}/{state.get('max_attempts')} "
        f"stagnant: {state.get('stagnant_count')}/{state.get('max_stagnant')} "
        f"active: {float(state.get('active_seconds', 0.0)):.0f}s/"
        f"{state.get('wall_timeout_s')}s",
        f"session: {state.get('opencode_session') or 'none'}",
    ]
    for cid in sorted(by_id):
        r = by_id[cid]
        flag = "REQUIRED" if cid in req else "optional"
        out_lines.append(f"  [{r.status}] {cid} ({flag}): {r.evidence[:160]}")
        if r.status == "FAIL" and r.next_action:
            out_lines.append(f"      next: {r.next_action[:200]}")
    if state.get("blocked_checks"):
        out_lines.append(f"blocked: {', '.join(state['blocked_checks'])}")
    if state.get("needs_reason"):
        out_lines.append(f"needs: {redact(state['needs_reason'])}")
    if state.get("ready_evidence"):
        out_lines.append(f"ready: {state['ready_evidence'][:300]}")
    for ln in out_lines:
        log(ln)
    st = state.get("status")
    if st in TERMINAL_OK:
        return 0
    if st == "NEEDS_INPUT":
        return 4
    return 1


def cmd_recheck(args) -> int:
    try:
        data_dir = me_setup.resolve_data_dir(args.data_dir)
    except me_setup.SetupError as exc:
        err(f"error: {exc}")
        return 2
    opts: dict = {"profile": str(args.profile or "production"),
                  "require_service": bool(args.require_service),
                  "opencode_bin": args.opencode_bin or "",
                  "upstream_doctor": getattr(args, "upstream_doctor", "") or "",
                  "upstream_contract": getattr(args, "upstream_contract", "") or "",
                  "require_backup": bool(getattr(args, "require_backup", False))}
    results, cfg = run_checks(data_dir, opts)
    req = required_ids(opts, cfg)
    for r in sorted(results, key=lambda r: r.id):
        flag = "REQUIRED" if r.id in req else "optional"
        log(f"[{r.status}] {r.id} ({flag}): {r.evidence[:200]}")
        if r.status in ("FAIL", "NEEDS_INPUT") and r.next_action:
            log(f"    next: {r.next_action[:250]}")
    status, reason = overall_status(results, opts, cfg)
    log(f"overall: {status} {redact(reason)[:200]}")
    if status in TERMINAL_OK:
        return 0
    if status == "NEEDS_INPUT":
        return 4
    return 1


def cmd_resume(args) -> int:
    try:
        data_dir = me_setup.resolve_data_dir(args.data_dir)
    except me_setup.SetupError as exc:
        err(f"error: {exc}")
        return 2
    sp = state_path(data_dir)
    if not sp.is_file():
        err("no supervisor run to resume; use `start` first")
        return 2
    try:
        state = load_state(data_dir)
    except ValueError as exc:
        err(f"error: unreadable supervisor state: {exc}")
        return 1
    if state.get("status") in TERMINAL_OK:
        log(f"already {state.get('status')}; nothing to resume")
        return 0
    # Resume keeps attempts/session; operator may explicitly raise bounded
    # budgets (never silently), or start a fresh run safely instead.
    if args.max_attempts:
        state["max_attempts"] = int(args.max_attempts)
    if args.max_stagnant:
        state["max_stagnant"] = int(args.max_stagnant)
    if args.attempt_timeout:
        state["attempt_timeout_s"] = int(args.attempt_timeout)
    if args.wall_timeout:
        state["wall_timeout_s"] = int(args.wall_timeout)
    if args.require_service:
        state["opts"]["require_service"] = True
    try:
        validate_state(state)
    except ValueError as exc:
        err(f"error: persisted state out of bounds: {exc}")
        return 2
    if state.get("status") in ("STALLED", "FAILED", "NEEDS_INPUT"):
        # Operator resume re-arms the run after changing inputs; verifier
        # evidence (not attempts) decides from here.
        if state.get("status") == "STALLED":
            state["stagnant_count"] = 0
        state["status"] = "RUNNING"
        state["needs_reason"] = ""
        append_event(state, "resume",
                     f"attempts={state.get('attempts')} stagnant={state.get('stagnant_count')}")
    token = uuid.uuid4().hex[:16]
    state["lock_token"] = token
    try:
        acquire_lock(data_dir, token)
    except RuntimeError as exc:
        err(f"error: {exc}")
        return 2
    binary = discover_opencode(args.opencode_bin or state["opts"].get("opencode_bin") or None)
    # Missing binary is handled inside drive (bootstrap gate, no burn).
    try:
        save_state(data_dir, state)
        return drive(state, data_dir=data_dir, binary=binary or "")
    finally:
        release_lock(data_dir, token)


def cmd_install_check(args) -> int:
    binary = discover_opencode(args.opencode_bin or None)
    if binary:
        log(f"opencode present: {binary} ({opencode_version(binary)}) -- no action taken")
        return 0
    log(f"opencode missing. Official primary installer: {OFFICIAL_INSTALL_URL}")
    log(f"Releases/checksums: {OFFICIAL_RELEASES_URL}")
    log(f"Platform: {platform.system()} {platform.machine()} "
        f"(supports {list(SUPPORTED_SYSTEMS)} x {list(SUPPORTED_ARCHES)})")
    if args.allow_install:
        try:
            changed, detail = install_opencode(allow_install=True)
            log(detail)
            return 0
        except RuntimeError as exc:
            err(f"error: {exc}")
            return 3
    err("NEEDS_INPUT: opencode-not-installed; re-run with --allow-install or install manually")
    return 4


def build_parser() -> argparse.ArgumentParser:
    d = str(me_setup.default_data_dir())
    p = argparse.ArgumentParser(description="OpenCode setup supervisor (parent authority)")
    sub = p.add_subparsers(dest="cmd", required=True)

    def add_common(sp, include_consent: bool):
        sp.add_argument("--data-dir", default=d)
        sp.add_argument("--workspace", default="",
                        help="agent working dir (default: cwd; OpenCode --dir)")
        sp.add_argument("--profile", default="production",
                        choices=PROFILES,
                        help="production (full platform READY bar), configure "
                             "(CONFIGURED, not complete), test (TEST_READY, "
                             "fixture allowed, synthetic only)")
        sp.add_argument("--mode", default="dev", choices=MODES,
                        help="dev (setup-infra only, nothing heavy/global) or "
                             "provision (home-target provisioner)")
        sp.add_argument("--prompt-scope", default="setup-infra only")
        sp.add_argument("--require-service", action="store_true",
                        help="require live home health + managed runtime "
                             "(implied by production profile)")
        sp.add_argument("--opencode-bin", default=os.environ.get("OPENCODE_BIN", ""))
        sp.add_argument("--model", default=os.environ.get("OPENCODE_MODEL", ""))
        sp.add_argument("--no-auto", action="store_true",
                        help="do not pass --auto even when the CLI supports it")
        sp.add_argument("--max-attempts", type=int, default=DEFAULT_MAX_ATTEMPTS)
        sp.add_argument("--max-stagnant", type=int, default=DEFAULT_MAX_STAGNANT)
        sp.add_argument("--attempt-timeout", type=int, default=DEFAULT_ATTEMPT_TIMEOUT_S)
        sp.add_argument("--wall-timeout", type=int, default=DEFAULT_WALL_TIMEOUT_S)
        sp.add_argument("--upstream-contract", default="",
                        help="path to A-published platform contract JSON "
                             f"(or {ENV_UPSTREAM_CONTRACT})")
        sp.add_argument("--upstream-doctor", default="",
                        help="path to trusted upstream-doctor entry "
                             f"(or {ENV_UPSTREAM_DOCTOR}; default sibling "
                             "infra-server src/cli.mjs when present)")
        sp.add_argument("--intelligence-url", default="",
                        help=f"self-hosted Intelligence base URL (or {ENV_INTELLIGENCE_URL})")
        sp.add_argument("--require-backup", action="store_true",
                        help="explicit product policy: require complete "
                             "upstream backup coverage (unsupported "
                             "capability -- stays NOT READY until a real "
                             "verifiable backup path lands; default "
                             "operational READY excludes backup claims)")
        if include_consent:
            sp.add_argument("--allow-install", action="store_true",
                            help="explicit operator approval to install OpenCode "
                                 "if the binary is missing")
            sp.add_argument("--no-install", action="store_true",
                            help="opt out of the default user-invoked-start "
                                 "install consent (missing binary -> NEEDS_INPUT)")

    s = sub.add_parser("start", help="start a supervised OpenCode run")
    add_common(s, True)
    r = sub.add_parser("resume", help="resume a persisted RUNNING/STALLED/FAILED run")
    r.add_argument("--data-dir", default=d)
    r.add_argument("--opencode-bin", default=os.environ.get("OPENCODE_BIN", ""))
    r.add_argument("--require-service", action="store_true")
    r.add_argument("--max-attempts", type=int, default=0)
    r.add_argument("--max-stagnant", type=int, default=0)
    r.add_argument("--attempt-timeout", type=int, default=0)
    r.add_argument("--wall-timeout", type=int, default=0)
    c = sub.add_parser("recheck", help="run trusted verifiers once (no agent)")
    c.add_argument("--data-dir", default=d)
    c.add_argument("--profile", default="production", choices=PROFILES)
    c.add_argument("--require-service", action="store_true")
    c.add_argument("--opencode-bin", default=os.environ.get("OPENCODE_BIN", ""))
    c.add_argument("--upstream-doctor", default="")
    c.add_argument("--upstream-contract", default="")
    c.add_argument("--require-backup", action="store_true",
                   help="explicit product policy: require complete upstream "
                        "backup coverage (unsupported -- stays NOT READY)")
    t = sub.add_parser("status", help="show persisted run state")
    t.add_argument("--data-dir", default=d)
    i = sub.add_parser("install-check", help="check/install the OpenCode binary path")
    i.add_argument("--opencode-bin", default=os.environ.get("OPENCODE_BIN", ""))
    i.add_argument("--allow-install", action="store_true")
    return p


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    if args.cmd == "start":
        return cmd_start(args)
    if args.cmd == "status":
        return cmd_status(args)
    if args.cmd == "resume":
        return cmd_resume(args)
    if args.cmd == "recheck":
        return cmd_recheck(args)
    if args.cmd == "install-check":
        return cmd_install_check(args)
    raise AssertionError("unreachable")


if __name__ == "__main__":
    sys.exit(main())
