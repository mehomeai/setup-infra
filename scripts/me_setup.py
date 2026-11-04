#!/usr/bin/env python3
"""Rerunnable development setup/check/configuration entry for the Me home service.

Owned by setup-infra (tasks S1/S2). This is a development-machine bootstrapper, not
a production installer:

- Never requires root, never mutates global machine state (no sudo, no
  launchd/systemd units installed, no writes outside the chosen destination).
- Never downloads installers, never creates a real tunnel, never exposes a
  public endpoint. The dev service binds loopback only; the optional
  named-tunnel adapter (scripts/me_lifecycle.py) only writes config and fails
  closed without operator-supplied credentials and protection.
- Rerunnable: repeated setup preserves household data, tracks the authoritative
  installation_id from the home database (never an invented identity once the
  home service has opened its db), backs up changed config, and fails loudly on
  incompatible config instead of wiping anything.
- Secrets discipline: tunnel connector / admin credentials live under
  <data-dir>/secrets (mode 0700/0600) and phone enrollment material lives under
  <data-dir>/data/household/pairing. Neither is ever written to config.json,
  service.env, tracked files, or logs.
- Toolchain discovery: compatible Node/Python are discovered (explicit flags,
  environment, PATH, well-known version managers) rather than shipped as a
  username-specific absolute path.

Usage:
    python3 scripts/me_setup.py setup [--data-dir DIR] [--port N] [--host H] ...
    python3 scripts/me_lifecycle.py start|status|stop|bootstrap|backup|restore|tunnel|service ...
    python3 scripts/me_setup.py check [--data-dir DIR]
    python3 scripts/me_setup.py config-show [--data-dir DIR]

Environment overrides: ME_HOME_DATA_DIR, ME_HOME_PORT, ME_HOME_NODE,
ME_HOME_INFRA_CHECKOUT, ME_HOME_FRAMEWORK_CHECKOUT, ME_HOME_RUNTIME_PYTHON.
Exit codes: 0 ok, 1 operation/state failure, 2 usage/validation error,
3 prerequisite failure, 4 parked external dependency (lifecycle/tunnel only).
"""

from __future__ import annotations

import argparse
import datetime
import json
import os
import platform
import re
import shutil
import socket
import sqlite3
import subprocess
import sys
import tempfile
import uuid
from pathlib import Path

SCHEMA_VERSION = 1
DEFAULT_PORT = 7070  # matches H1 home-api-v1 local default (infra-server DEFAULT_PORT)
DEFAULT_HOST = "127.0.0.1"
NODE_MIN = (24, 18, 0)
NODE_MAX_MAJOR = 25  # >=24.18.0, <25
# Node --experimental-transform-types is only needed for TypeScript entrypoints
# (H1's spikes use it); the home service CLI is plain ESM and runs without it.
NODE_TS_FLAGS = ["--experimental-transform-types", "--disable-warning=ExperimentalWarning"]
CONTRACT_REL_PATH = "infra-server/contracts/home-api-v1.md"
CONTRACT_VERSION = "home-api-v1"  # version string published by H1's contract
BRIDGE_CONTRACT = "runtime-bridge-v1"  # agent runtime bridge published by H2
LOOPBACK_HOSTS = ("127.0.0.1", "::1", "localhost")
MIN_FREE_BYTES = 1 * 1024**3  # 1 GiB

# --- S7 home-coordination (home-coordinator-v1) + H7 notifications ------------
# S7 owns setup-side activation only: config/service generation + validation.
# The home (H8) owns the credential file + heartbeat loop; the backend (B7)
# owns the ticket/activation wire. Defaults are DISABLED with zero outbound
# network. Secrets (home_token, activationSecret, HOME_EXPO_ACCESS_TOKEN) are
# never persisted here, never logged, never shipped to the phone.
COORDINATOR_PROTOCOL = "home-coordinator-v1"
COORDINATOR_PROTOCOL_VERSION = "home-api-v1"  # wire version inside the file
COORDINATOR_DEFAULT_FILENAME = "backend-home-token.json"  # under <data-dir>/secrets
LOOPBACK_NAMES = ("127.0.0.1", "localhost", "::1")


def default_coordinator_credentials_file(data_dir: Path) -> Path:
    return Path(data_dir) / "secrets" / COORDINATOR_DEFAULT_FILENAME


def _loopback_host(hostname: str) -> bool:
    h = (hostname or "").strip().lower().strip("[]")
    return h in LOOPBACK_NAMES


def validate_https_url(value: str, *, field: str,
                       allow_http_loopback: bool = False) -> str:
    """Validate a public base URL. Returns the normalized URL string.

    Gate (mirrors H8 loadCoordinatorCredentials): `https:` always; plain
    `http:` ONLY for loopback hosts with explicit opt-in. Rejects userinfo,
    query, fragment, empty hosts, and lengths outside 1..500. Raises
    SetupError (usage/validation) on violation.
    """
    from urllib.parse import urlsplit
    raw = (value or "").strip()
    if not raw or len(raw) > 500:
        raise SetupError(f"{field}: must be 1..500 chars of https:// URL")
    try:
        parts = urlsplit(raw)
    except ValueError as exc:
        raise SetupError(f"{field}: invalid URL ({exc})")
    if not parts.hostname:
        raise SetupError(f"{field}: URL has no host")
    if parts.username or parts.password or "@" in (parts.netloc or ""):
        raise SetupError(f"{field}: URL must not carry userinfo")
    if parts.query or parts.fragment:
        raise SetupError(f"{field}: URL must not carry query/fragment")
    scheme = (parts.scheme or "").lower()
    if scheme == "https":
        pass
    elif scheme == "http" and allow_http_loopback and _loopback_host(parts.hostname or ""):
        pass
    else:
        if scheme == "http":
            raise SetupError(
                f"{field}: plain http:// is allowed ONLY for loopback hosts "
                f"{list(LOOPBACK_NAMES)} with explicit opt-in "
                "(--coordinator-allow-http-loopback)")
        raise SetupError(f"{field}: must be https:// (got {scheme or '?'}://)")
    return raw

# System locations that must never become (or contain) the home data dir.
_DENY_PREFIXES = (
    "/bin/", "/sbin/", "/usr/", "/etc/", "/System/", "/Library/",
    "/var/root/", "/private/etc/", "/private/var/root/",
)
_DENY_EXACT_EXTRA = ("/tmp", "/var/tmp")


class SetupError(Exception):
    """Fatal setup/validation failure (exit 2)."""


class PrereqError(Exception):
    """Prerequisite failure (exit 3)."""


def repo_root() -> Path:
    return Path(__file__).resolve().parent.parent


def default_data_dir() -> Path:
    env = os.environ.get("ME_HOME_DATA_DIR")
    if env:
        return Path(env).expanduser()
    return Path.home() / ".local" / "share" / "me-home"


def probe_runtime_bridge(framework_checkout: Path | None,
                         runtime_python: str | None = None) -> dict:
    """Probe the H2 agent runtime bridge without executing a run.

    Discovery: explicit flag > ME_HOME_RUNTIME_PYTHON env > the checkout's
    .venv/bin/python. Import is attempted with cwd=<checkout>/src (H2's
    src-layout) then cwd=<checkout>. Never fails the caller: when H2 is still
    being modified the result is status "unavailable-transient" with a rerun
    note, and setup continues. Set ME_HOME_SKIP_BRIDGE_PROBE=1 to skip the
    subprocess probe entirely (unit tests; resource-constrained runs).
    """
    if os.environ.get("ME_HOME_SKIP_BRIDGE_PROBE") == "1":
        return {"contract": BRIDGE_CONTRACT, "python": "", "import_cwd": "",
                "status": "skipped",
                "detail": "bridge probe skipped via ME_HOME_SKIP_BRIDGE_PROBE=1"}
    explicit = runtime_python or os.environ.get("ME_HOME_RUNTIME_PYTHON")
    candidates: list[str] = []
    if explicit:
        candidates.append(explicit)
    if framework_checkout is not None:
        venv_py = framework_checkout / ".venv" / "bin" / "python"
        candidates.append(str(venv_py))
    tried: list[str] = []
    for cand in candidates:
        if not cand or not Path(cand).is_file():
            tried.append(f"{cand or '<empty>'}: no such file")
            continue
        cwds = []
        if framework_checkout is not None:
            # H3's handoff documents the checkout root; H2's src-layout needs
            # src. Prefer the documented root, fall back to src, and record
            # whichever actually imports.
            cwds = [framework_checkout, framework_checkout / "src"]
        else:
            cwds = [Path.cwd()]
        for cwd in cwds:
            if not cwd.is_dir():
                continue
            try:
                subprocess.check_output(
                    [cand, "-c", "import me_runtime.bridge"],
                    stderr=subprocess.STDOUT, timeout=20, text=True, cwd=str(cwd))
                return {"contract": BRIDGE_CONTRACT, "python": cand,
                        "import_cwd": str(cwd), "status": "importable",
                        "detail": f"{cand} imports me_runtime.bridge (cwd {cwd})"}
            except (OSError, subprocess.SubprocessError) as exc:
                out = getattr(exc, "output", exc) or exc
                tried.append(f"{cand} (cwd {cwd}): {str(out)[:160]}")
    return {"contract": BRIDGE_CONTRACT,
            "python": explicit or (str(framework_checkout / ".venv" / "bin" / "python")
                                   if framework_checkout else ""),
            "import_cwd": "", "status": "unavailable-transient",
            "detail": ("runtime bridge not importable (H2 may still be modifying "
                       "home); rerun when stable. " + ("; ".join(tried)
                       if tried else "no candidate python"))}


def build_models(*, provider: str = "local", name: str = "llama3.1",
                 endpoint: str = "", allow_fixture: bool = False,
                 allow_remote: bool = False, allow_code_exec: bool = False,
                 cap_code_exec: bool = False, cap_web_fetch: bool = False,
                 cap_browser: bool = False, cap_animation: bool = False,
                 cap_egress: str = "", code_sandbox: str = "") -> dict:
    """Build the models/capability section from explicit operator flags.

    Fixture is selectable only with allow_fixture (synthetic tests only);
    remote providers only with allow_remote (key stays in operator shell).
    The local endpoint defaults to the ChatOllama base URL without /v1.

    Code execution runs ONLY in a one-shot Docker sandbox (R5 exec.py:
    ME_RUNTIME_SANDBOX must be "docker"; there is intentionally no host
    fallback, and missing docker/image is an honest prerequisite denial,
    never a download). So explicit --allow-code-exec plus --cap-code-exec
    configures code_sandbox="docker" automatically; an explicit
    --code-sandbox docker choice is also accepted (and requires both
    code-exec flags). Anything else is refused rather than guessed.
    """
    provider = (provider or "local").strip().lower()
    if provider not in ("local", "fixture", "openai", "anthropic"):
        raise SetupError(f"--model-provider must be local|fixture|openai|anthropic (got {provider!r})")
    if provider == "fixture" and not allow_fixture:
        raise SetupError("provider=fixture requires --allow-fixture-model "
                         "(synthetic tests only, never household data)")
    if provider in ("openai", "anthropic") and not allow_remote:
        raise SetupError(f"provider={provider} requires --allow-remote-model "
                         "(explicit opt-in; key stays in operator shell)")
    endpoint = (endpoint or "").strip()
    if provider == "local" and not endpoint:
        endpoint = "http://127.0.0.1:11434"  # ChatOllama base_url; no /v1
    if provider == "fixture":
        endpoint = ""  # fixture ignores endpoints; record none
    egress = [h.strip() for h in (cap_egress or "").split(",") if h.strip()]
    sandbox = (code_sandbox or "").strip().lower()
    if sandbox not in ("", "docker"):
        raise SetupError(f"--code-sandbox must be docker or empty (got {code_sandbox!r}); "
                         "refusing to guess sandbox backend")
    if sandbox == "docker" and not (allow_code_exec and cap_code_exec):
        raise SetupError("--code-sandbox docker requires --allow-code-exec "
                         "and --cap-code-exec together (explicit operator opt-in)")
    # R5 only executes inside ME_RUNTIME_SANDBOX=docker: auto-configure the
    # Docker sandbox when the operator explicitly enabled both gates. No host
    # fallback is ever configured here.
    if allow_code_exec and cap_code_exec and sandbox == "":
        sandbox = "docker"
    return {
        "provider": provider,
        "name": (name or "").strip() or ("fixture-echo" if provider == "fixture"
                                         else "llama3.1"),
        "endpoint": endpoint,
        "allow_fixture": bool(allow_fixture),
        "allow_remote": bool(allow_remote),
        "allow_code_exec": bool(allow_code_exec),
        "code_sandbox": sandbox,
        "use_responses_api": False,
        "capabilities": {
            "web_fetch": bool(cap_web_fetch),
            "browser": bool(cap_browser),
            "code_exec": bool(cap_code_exec),
            "animation": bool(cap_animation),
            "egress": egress,
        },
    }


def default_models() -> dict:
    """Local-first model + capability ceiling. Mirrors the exact H3/H2 env keys
    (read-only from infra-server/src/runtime-config.mjs and
    agentic-framework/src/me_runtime/models.py); this file never invents names.

    Local endpoint is the ChatOllama base URL WITHOUT /v1: H2's local adapter
    is ChatOllama(base_url=...), and H3's ".../v1" default would misconfigure
    it. Setup pins the correct value here and H3's default stays H3's bug to
    fix (recorded in docs; this repo does not edit infra-server).
    """
    return build_models()


# Native harness local route (B canonical local-model contract): the
# OpenAI-compatible SDK requires a NON-EMPTY key even for Ollama, so the
# selected-native env carries this documented NONSECRET placeholder constant
# -- never a real credential, never personal, baked nowhere secret lives.
# Real remote keys stay in the operator shell and are bound at trusted
# launch only (see me_lifecycle.build_home_env).
NATIVE_LOCAL_API_KEY_PLACEHOLDER = "ollama"
# Default container-reachable host for translated loopback endpoints.
# UNVERIFIED from setup: the A doctor owns the harness-namespace probe.
NATIVE_CONTAINER_HOST = "host.docker.internal"


def native_harness_env(models: dict) -> dict[str, str]:
    """ONE selected model mapped to the native harness env (non-secret).

    The native harness (B runtime-wire-contract: BOT_PROVIDER/BOT_MODEL/
    OPENAI_BASE_URL + provider keys from the operator shell) is the stack
    that actually serves product traffic in FULL mode. Supported local route
    per B canonical local-model contract: BOT_PROVIDER=openai +
    OPENAI_BASE_URL=<container-reachable base>/v1 + OPENAI_API_KEY=ollama.
    The SDK requires a non-empty key even for Ollama, so "ollama" is a
    documented NONSECRET placeholder constant -- NOT a credential. Real
    remote keys are NEVER baked here (operator shell only; local exception
    documented). BOT_PROVIDER=ollama is NOT a supported config and is
    rejected by the harness config check. Fixture has no native mapping
    (synthetic tests only).

    Container reachability: a loopback HOME_MODEL_ENDPOINT (host-legacy
    probe address) is translated to host.docker.internal for the container
    (port preserved). An explicit non-loopback operator URL (private Ollama
    container / custom base) is preserved as-is. Setup does NOT claim the
    translated URL is reachable from the container namespace -- host tags
    cannot prove that; the A doctor owns the actual harness-namespace probe
    (see setup-wire-contract.json handoff to A).
    """
    import urllib.parse as _urlparse
    models = models or {}
    provider = str(models.get("provider", "local") or "local").strip().lower()
    if provider == "fixture":
        return {}
    if provider not in ("local", "openai", "anthropic"):
        raise SetupError(
            f"native harness mapping: unsupported provider {provider!r} "
            "(must be local|openai|anthropic)")
    name = str(models.get("name", "") or "").strip() or "llama3.1"
    if provider == "local":
        endpoint = str(models.get("endpoint", "") or "").strip().rstrip("/")
        if not endpoint:
            endpoint = "http://127.0.0.1:11434"
        if not endpoint.startswith(("http://", "https://")):
            raise SetupError(
                f"native harness mapping: local endpoint {endpoint!r} "
                "malformed (must be http(s)://host:port)")
        base = _container_base_url(endpoint)
        if not base.endswith("/v1"):
            base += "/v1"
        return {"BOT_PROVIDER": "openai", "BOT_MODEL": name,
                "OPENAI_BASE_URL": base,
                "OPENAI_API_KEY": NATIVE_LOCAL_API_KEY_PLACEHOLDER}
    out = {"BOT_PROVIDER": provider, "BOT_MODEL": name}
    endpoint = str(models.get("endpoint", "") or "").strip().rstrip("/")
    if endpoint:
        # Operator-supplied base URL preserved as-is (container must already
        # reach it; only loopback translation applies to the local route).
        out["OPENAI_BASE_URL"] = endpoint
    return out


def _container_base_url(endpoint: str) -> str:
    """Translate a host-legacy base URL to a container-reachable default.

    Loopback hosts (127.0.0.1/localhost/::1 -- the host-legacy probe
    address kept in HOME_MODEL_ENDPOINT) become host.docker.internal (port
    and path preserved): 127.0.0.1 is the container's own loopback and can
    never reach host Ollama. Anything else is an explicit operator
    container URL and is preserved byte-for-byte. UNVERIFIED: setup cannot
    prove container-namespace reachability from host tags; the A doctor
    owns that probe.
    """
    import urllib.parse as _urlparse
    parts = _urlparse.urlsplit(endpoint)
    host = parts.hostname or ""
    if host not in ("127.0.0.1", "localhost", "::1"):
        return endpoint
    netloc = parts.netloc
    userinfo = ""
    hostport = netloc
    if "@" in netloc:
        userinfo, _, hostport = netloc.rpartition("@")
        userinfo += "@"
    if hostport.startswith("["):
        # IPv6 literal: [::1]:port
        _, _, rest = hostport.partition("]")
        port = rest[1:] if rest.startswith(":") else ""
    else:
        _, _, port = hostport.partition(":")
    rebuilt = userinfo + NATIVE_CONTAINER_HOST + (":" + port if port else "")
    return _urlparse.urlunsplit(
        (parts.scheme, rebuilt, parts.path, parts.query, parts.fragment))


def render_service_env(*, db_path: Path, host: str, port: int,
                       runtime_argv: list | None = None, runtime_cwd: str = "",
                       models: dict | None = None,
                       coordinator: dict | None = None,
                       notifications: dict | None = None,
                       upstream_mode: str | None = None) -> str:
    """Render config/service.env. Non-secret values only, shell-safe quoting.

    Every value is shlex.quote'd, so paths with spaces round-trip through
    `set -a; . config/service.env` without eval tricks. Secret values never
    appear here: the operator exports them in their own shell (see comments).
    Absent/false host flags are omitted (H2/H3 treat absent as false); only
    explicit opt-ins set values.

    The home process is ACTIVATED from this file: ME_UPSTREAM_MODE selects
    the A upstream profile, and the native harness vars (BOT_PROVIDER/
    BOT_MODEL/OPENAI_BASE_URL, non-secret routing only) carry the ONE
    selected FULL model -- config.json alone is not provisioning.
    """
    import shlex as _shlex
    models = models or default_models()
    caps = models.get("capabilities", {})
    lines = [
        "# Generated by setup-infra (rerunnable; safe to regenerate).",
        "# Non-secret values only. Load with: set -a; . config/service.env; set +a",
        f"HOME_DB={_shlex.quote(str(db_path))}",
        f"HOME_HOST={_shlex.quote(host)}",
        f"HOME_PORT={port}",
    ]
    if runtime_argv:
        lines.append(f"ME_RUNTIME_ARGV={_shlex.quote(json.dumps(runtime_argv))}")
    if runtime_cwd:
        lines.append(f"ME_RUNTIME_CWD={_shlex.quote(runtime_cwd)}")
    provider = models.get("provider", "local")
    lines.append(f"HOME_MODEL_PROVIDER={_shlex.quote(str(provider))}")
    if models.get("name"):
        lines.append(f"HOME_MODEL_NAME={_shlex.quote(str(models['name']))}")
    if provider != "fixture" and models.get("endpoint"):
        lines.append(f"HOME_MODEL_ENDPOINT={_shlex.quote(str(models['endpoint']))}")
    # Native harness activation (FULL mode serves product traffic through the
    # B runtime-wire-contract stack, not the legacy local probe): ME_UPSTREAM_MODE
    # selects the A upstream profile, and BOT_* carries the ONE selected model
    # (routing only; keys stay in the operator shell, never baked).
    if upstream_mode in ("full", "core"):
        lines.append(f"ME_UPSTREAM_MODE={_shlex.quote(upstream_mode)}")
    try:
        native = native_harness_env(models)
    except SetupError as exc:
        raise SetupError(f"service.env: {exc}")
    if native:
        lines.append("# Selected NATIVE model (B canonical route; what FULL "
                     "production serves). Container reachability of "
                     "OPENAI_BASE_URL is UNVERIFIED here (A doctor owns the "
                     "harness-namespace probe); loopback was translated to "
                     "host.docker.internal, explicit operator URLs preserved.")
    for k, v in native.items():
        if k == "OPENAI_API_KEY" and v == NATIVE_LOCAL_API_KEY_PLACEHOLDER:
            lines.append(f"{k}={_shlex.quote(str(v))}  # NONSECRET local-route "
                         "placeholder constant (SDK requires non-empty key; "
                         "not a credential -- real keys stay in operator shell)")
        else:
            lines.append(f"{k}={_shlex.quote(str(v))}")
    if provider == "fixture" and models.get("allow_fixture"):
        lines.append("HOME_ALLOW_FIXTURE_MODEL=1  # synthetic tests only, never household data")
        lines.append("# (fixture has no native BOT_* mapping: synthetic only, never production)")
    if provider in ("openai", "anthropic") and models.get("allow_remote"):
        lines.append("ME_RUNTIME_ALLOW_REMOTE=1  # explicit operator opt-in")
    if (provider == "openai" and models.get("use_responses_api")):
        lines.append("HOME_MODEL_USE_RESPONSES_API=true")
    if caps.get("web_fetch"):
        lines.append("HOME_CAP_WEB_FETCH=1")
    if caps.get("browser"):
        lines.append("HOME_CAP_BROWSER=1")
    if caps.get("animation"):
        lines.append("HOME_CAP_ANIMATION=1")
    if caps.get("code_exec"):
        lines.append("HOME_CAP_CODE_EXEC=1")
    if models.get("allow_code_exec"):
        lines.append("ME_RUNTIME_ALLOW_CODE_EXEC=1")
    if models.get("code_sandbox") == "docker":
        lines.append("ME_RUNTIME_SANDBOX=docker  # Docker-only code_exec; no host fallback")
    egress = [h for h in caps.get("egress", []) if h]
    if egress:
        lines.append(f"HOME_CAP_EGRESS={_shlex.quote(','.join(egress))}")
    # S7 coordinator (default disabled): reference the private file only when
    # the operator enabled coordination. The secret file itself is written by
    # `coordinator activate` (mode 0600); only its absolute PATH appears here.
    # Never persisted: activationSecret, home_token, HOME_EXPO_ACCESS_TOKEN.
    coord = coordinator or {}
    if coord.get("enabled") and coord.get("credentials_file"):
        lines.append(f"HOME_COORDINATOR_CREDENTIALS_FILE={_shlex.quote(str(coord['credentials_file']))}")
        if coord.get("allow_http_loopback"):
            lines.append("HOME_COORDINATOR_ALLOW_HTTP_LOOPBACK=1  # explicit dev/test loopback opt-in only")
    # H7 notifications (default disabled): public project id is config; the
    # optional access token is inherited from the operator shell only.
    notif = notifications or {}
    if notif.get("enabled"):
        lines.append("HOME_NOTIFICATIONS_ENABLED=1")
        if notif.get("expo_project_id"):
            lines.append(f"HOME_EXPO_PROJECT_ID={_shlex.quote(str(notif['expo_project_id']))}")
    lines += [
        "#",
        "# Secrets are NEVER stored here. Explicit opt-ins only, operator shell:",
        "#   export ME_RUNTIME_ALLOW_REMOTE=1                    # remote models",
        "#   export ME_RUNTIME_MODEL_API_KEY='<value>'           # shell only; never stored",
        "#   export HOME_ALLOW_FIXTURE_MODEL=1                   # synthetic fixture tests only",
        "#   export HOME_EXPO_ACCESS_TOKEN                       # optional push token; shell only",
        "#   (coordination secrets: activationSecret/home_token live ONLY in",
        "#    the 0600 coordinator credentials file, never here)",
    ]
    return "\n".join(lines) + "\n"


def _is_denied(path: Path) -> str | None:
    text = os.path.normpath(str(path))
    if text == "/":
        return "must not be the filesystem root"
    home = os.path.normpath(str(Path.home()))
    if text == home:
        return "must not be your home directory itself (pick a subdirectory)"
    if text in _DENY_EXACT_EXTRA:
        return f"{text} is a shared system temp dir (pick a subdirectory)"
    for prefix in _DENY_PREFIXES:
        if text == prefix.rstrip("/") or text.startswith(prefix):
            return f"{prefix.rstrip('/')} is a system location"
    try:
        root = os.path.normpath(str(repo_root()))
        if text == root or text.startswith(root + os.sep):
            return "must not live inside the setup-infra source checkout"
    except OSError:
        pass
    return None


def resolve_data_dir(raw: str | os.PathLike | None) -> Path:
    """Resolve and validate the destination dir. Raises SetupError if unsafe."""
    if raw is None or str(raw).strip() == "":
        raise SetupError("data dir is empty; pass --data-dir or set ME_HOME_DATA_DIR")
    text = str(raw)
    if "\0" in text:
        raise SetupError("data dir contains NUL")
    expanded = os.path.expanduser(text)
    if not os.path.isabs(expanded):
        expanded = os.path.abspath(os.path.join(os.getcwd(), expanded))
    canon = Path(os.path.normpath(expanded))
    reason = _is_denied(canon)
    if reason:
        raise SetupError(f"unsafe data dir {canon}: {reason}")
    if canon.exists() and not canon.is_dir():
        raise SetupError(f"data dir {canon} exists and is not a directory")
    return canon


def redact(text: str) -> str:
    """Redact secret-looking values from a log line."""
    def _sub(m: re.Match) -> str:
        return m.group(1) + "***redacted***"

    pattern = re.compile(
        r"(?i)((?:token|secret|password|passwd|private[_-]?key|api[_-]?key|"
        r"connector[_-]?credential|admin[_-]?credential|pairing[_-]?secret)\s*"
        r"[:=]\s*)([^\s,;\"']+)"
    )
    return pattern.sub(_sub, text)


def log(msg: str) -> None:
    print(redact(msg), flush=True)


def _node_version_ok(out: str) -> bool:
    m = re.match(r"v(\d+)\.(\d+)\.(\d+)", out.strip())
    if not m:
        return False
    major, minor, patch = int(m.group(1)), int(m.group(2)), int(m.group(3))
    return 24 <= major < NODE_MAX_MAJOR and (major, minor, patch) >= NODE_MIN


def _probe_node(candidate: str) -> tuple[str | None, str]:
    """Return (version string or None, detail) for one node candidate."""
    try:
        out = subprocess.check_output(
            [candidate, "--version"], stderr=subprocess.STDOUT, timeout=15, text=True
        ).strip()
    except (OSError, subprocess.SubprocessError):
        return None, f"{candidate}: unavailable"
    if _node_version_ok(out):
        return out, f"{candidate} ({out}) satisfies >=24.18.0 <25"
    return None, f"{candidate} ({out}) does not satisfy >=24.18.0 <25"


def discover_node(explicit: str | None = None) -> tuple[str | None, str]:
    """Discover a compatible Node binary. No hardcoded user paths.

    Order: explicit flag > ME_HOME_NODE env > PATH > well-known nvm layout
    (~/.nvm/versions/node/v*/bin/node, newest satisfying version wins).
    Returns (binary path or None, human-readable detail).
    """
    tried: list[str] = []

    def consider(cand: str | None) -> tuple[str | None, str] | None:
        if not cand:
            return None
        version, detail = _probe_node(cand)
        tried.append(detail)
        if version is not None:
            return cand, detail
        return None

    for cand in (explicit, os.environ.get("ME_HOME_NODE")):
        hit = consider(cand)
        if hit:
            return hit
    hit = consider(shutil.which("node"))
    if hit:
        return hit
    nvm = Path.home() / ".nvm" / "versions" / "node"
    if nvm.is_dir():
        found: list[tuple[tuple[int, int, int], str]] = []
        for child in sorted(nvm.iterdir(), reverse=True):
            if not child.is_dir():
                continue
            m = re.match(r"v?(\d+)\.(\d+)\.(\d+)", child.name)
            if not m:
                continue
            binary = child / "bin" / "node"
            if binary.is_file():
                found.append(((int(m.group(1)), int(m.group(2)), int(m.group(3))), str(binary)))
        found.sort(reverse=True)
        for _, binary in found:
            hit = consider(binary)
            if hit:
                return hit
    detail = "; ".join(tried) or "no node binary found (PATH empty of node, no nvm layout)"
    return None, detail + " [required >=24.18.0 <25]"


def find_node(explicit: str | None = None) -> tuple[str | None, str]:
    """Return (node binary path or None, human-readable detail)."""
    return discover_node(explicit)


def node_args_for(node_bin: str, entrypoint: Path) -> list[str]:
    """Build the node argv prefix for a home-service entrypoint.

    The known home CLI (src/cli.mjs) ALWAYS transitively imports
    vendor/.../worker.ts with non-erasable syntax (via server.mjs ->
    task-broker.mjs), so it requires --experimental-transform-types upfront
    even though its own suffix is .mjs -- matching H1's own documented
    `node --experimental-transform-types src/cli.mjs ...` invocations.
    TypeScript entrypoints (.ts) get the same flags. Other plain ESM files
    run with no flags. Anything else is refused rather than guessed.
    """
    # Known home CLI first: suffix alone would miss the transitive .ts import.
    try:
        if Path(entrypoint).name == "cli.mjs":
            return [node_bin, *NODE_TS_FLAGS]
    except (TypeError, ValueError):
        pass
    suffix = entrypoint.suffix.lower()
    if suffix == ".mjs" or (suffix == ".js" and "type" != "module"):
        return [node_bin]
    if suffix == ".js":
        return [node_bin]
    if suffix == ".ts":
        return [node_bin, *NODE_TS_FLAGS]
    raise SetupError(f"home entrypoint {entrypoint} has unsupported suffix {suffix!r}; "
                     "refusing to guess interpreter flags")


def resolve_checkout(explicit: str | None, env_var: str, default_name: str,
                     markers: tuple[str, ...], kind: str) -> Path | None:
    """Resolve a sibling source checkout without editing it. Returns None if absent.

    Order: explicit flag > env var > <setup-infra>/../<default_name>.
    Presence (not validity) is reported; callers distinguish a missing checkout
    (transient cross-repo dependency) from a broken one.
    """
    candidates: list[str | None] = [explicit, os.environ.get(env_var)]
    fallback = repo_root().parent / default_name
    for cand in candidates:
        if cand:
            return Path(cand).expanduser()
    if all(marker_file((fallback / m)) for m in markers):
        return fallback
    if explicit or os.environ.get(env_var):
        return Path(explicit or os.environ.get(env_var)).expanduser()  # type: ignore[arg-type]
    return None


def marker_file(p: Path) -> bool:
    return p.is_file()


def read_db_installation_id(db_path: Path) -> str | None:
    """Read the authoritative installation_id from the home SQLite db (read-only).

    Returns None when the db (or its meta row) does not exist yet -- i.e. the
    home service has never opened it. Never creates or modifies the database.
    """
    if not db_path.is_file():
        return None
    try:
        uri = f"file:{db_path}?mode=ro"
        with sqlite3.connect(uri, uri=True, timeout=5) as conn:
            row = conn.execute(
                "SELECT value FROM meta WHERE key = 'installation_id'").fetchone()
    except sqlite3.Error:
        return None
    if row and isinstance(row[0], str) and row[0].strip():
        return row[0]
    return None


def port_free(host: str, port: int) -> tuple[bool, str]:
    try:
        family = socket.AF_INET6 if ":" in host else socket.AF_INET
        with socket.socket(family, socket.SOCK_STREAM) as s:
            if family == socket.AF_INET:
                s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            s.bind((host, port))
        return True, "bindable"
    except OSError as exc:
        return False, f"not bindable: {exc}"


def fetch_healthz(host: str, port: int) -> tuple[dict | None, str]:
    """GET /healthz once (2s timeout). Returns (parsed body or None, error or '')."""
    import urllib.request

    url = f"http://{host}:{port}/healthz"
    try:
        with urllib.request.urlopen(url, timeout=2) as resp:  # noqa: S310 (loopback dev check)
            body = json.loads(resp.read().decode("utf-8"))
    except Exception as exc:
        return None, f"no home service answering at {url} ({exc})"
    if not isinstance(body, dict):
        return None, f"{url} answered non-JSON-object"
    return body, ""


def probe_healthz(host: str, port: int, expected_installation_id: str) -> str:
    """Describe /healthz vs config. Informational only; never raises.

    The H1 database is the durable authority for installation_id (it mints and
    persists the id on first open). A mismatch here means this config tracks a
    different service/db than the one listening -- adopt it explicitly with
    `setup --adopt-service-id` after verifying it is the intended service.
    """
    url = f"http://{host}:{port}/healthz"
    body, err = fetch_healthz(host, port)
    if body is None:
        return f"INFO: {err}; start the service per config home_api.launch"
    if body.get("status") != "ok":
        return f"WARN: {url} answered but status != ok: {redact(str(body)[:200])}"
    notes = []
    if body.get("contract") != CONTRACT_VERSION:
        notes.append(f"contract={body.get('contract')!r} (expected {CONTRACT_VERSION!r})")
    if body.get("installation_id") != expected_installation_id:
        notes.append("installation_id differs from this config "
                     f"(live={body.get('installation_id')!r}); adopt with "
                     "`setup --adopt-service-id` once verified")
    detail = "; ".join(notes) if notes else "contract + installation_id match this config"
    level = "WARN" if notes else "PASS"
    return f"{level}: {url} -> {detail}"


def contract_status() -> str:
    """Detect whether H1 has published the home API contract (read-only probe).

    Returns the contract version string when the H1 markdown exists, else the
    pending-h1 marker so downstream tooling knows service routes/versions are
    still an integration dependency.
    """
    sibling = repo_root().parent / CONTRACT_REL_PATH
    if sibling.is_file():
        return CONTRACT_VERSION
    return "pending-h1"


def check_prerequisites(data_dir: Path, host: str, port: int,
                        node_bin: str | None = None,
                        min_disk_mib: int = 1024) -> list[tuple[str, bool, str]]:
    """Collect (name, ok, detail) prerequisite results. No side effects.

    The 1 GiB production guard stands. An explicit --min-disk-mib below 1024
    is a labelled dev-only override for synthetic local checks: it passes the
    gate but logs that the result is NOT a provisioned installation.
    """
    results: list[tuple[str, bool, str]] = []

    system = platform.system().lower()
    if system == "darwin":
        results.append(("os", True, f"{platform.system()} {platform.release()} "
                                    f"({platform.machine()}): supported dev platform"))
    elif system == "linux":
        results.append(("os", True, "Linux: declared future deployment boundary; "
                                    "dev validation happens on macOS"))
    else:
        results.append(("os", False, f"{platform.system()}: unsupported "
                                     "(dev: macOS, declared future: Linux)"))

    if hasattr(os, "geteuid"):
        try:
            results.append(("non-root", os.geteuid() != 0,
                            "running as root is refused" if os.geteuid() == 0
                            else f"uid={os.geteuid()}: no root/global mutations"))
        except OSError as exc:
            results.append(("non-root", False, f"uid check failed: {exc}"))
    else:
        results.append(("non-root", True, "uid check not applicable on this platform"))

    node_path, node_detail = find_node(node_bin)
    results.append(("node24", node_path is not None, node_detail))
    results.append(("python", sys.version_info >= (3, 10),
                    f"{platform.python_version()}: {'ok' if sys.version_info >= (3, 10) else 'need >=3.10'}"))

    if not (1 <= port <= 65535):
        results.append(("port-range", False, f"{port}: out of 1-65535"))
    elif port < 1024:
        results.append(("port-range", False, f"{port}: privileged (<1024) needs root; "
                                             "this setup never uses root"))
    else:
        results.append(("port-range", True, f"{port}: unprivileged"))

    if host not in LOOPBACK_HOSTS:
        results.append(("loopback-host", False,
                        f"{host}: dev setup binds loopback only {LOOPBACK_HOSTS}; "
                        "public endpoints need the production tunnel boundary"))
    else:
        results.append(("loopback-host", True, f"{host}: loopback-only dev binding"))

    parent = data_dir if data_dir.exists() else data_dir.parent
    while not parent.exists():
        parent = parent.parent
    try:
        free = shutil.disk_usage(parent).free
        need_bytes = min_disk_mib * 1024**2
        ok = free >= need_bytes
        detail = f"{free // 1024**2} MiB free under {parent} (need >={min_disk_mib} MiB)"
        if ok and min_disk_mib < 1024:
            detail += (" [DEV OVERRIDE: synthetic local check only -- "
                       "not a provisioned installation]")
        results.append(("disk", ok, detail))
    except OSError as exc:
        results.append(("disk", False, f"disk check failed: {exc}"))

    try:
        data_dir.mkdir(parents=True, exist_ok=True)
        probe = data_dir / ".write-probe"
        probe.write_text("ok", encoding="utf-8")
        probe.unlink(missing_ok=True)
        results.append(("writable-dest", True, f"{data_dir}: writable by current user"))
    except OSError as exc:
        results.append(("writable-dest", False, f"{data_dir}: not writable: {exc}"))

    return results


# --- config handling -------------------------------------------------------

SERVICE_SUBDIRS = ("config", "data/household", "data/household/pairing",
                   "logs", "tmp", "backups", "secrets")


def config_path(data_dir: Path) -> Path:
    return data_dir / "config" / "config.json"


def load_config(data_dir: Path) -> dict:
    path = config_path(data_dir)
    if not path.is_file():
        raise SetupError(f"no config yet at {path}; run `setup` first")
    try:
        cfg = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise SetupError(f"existing config at {path} is unreadable/invalid: {exc}")
    if not isinstance(cfg, dict):
        raise SetupError(f"existing config at {path} is not a JSON object")
    if cfg.get("schema_version") != SCHEMA_VERSION:
        raise SetupError(
            f"existing config schema_version={cfg.get('schema_version')!r} "
            f"is not supported by this setup (v{SCHEMA_VERSION}); refusing to "
            "overwrite. Back up household data and migrate explicitly.")
    # Vocabulary matches H1's home-api-v1 (installation_id in /healthz etc.).
    for key in ("installation_id", "service", "tunnel"):
        if key not in cfg:
            raise SetupError(f"existing config at {path} is missing {key!r}; "
                             "refusing to overwrite. Inspect or re-run after backup.")
    for secret_key in ("tunnel_connector_credential", "admin_credential",
                       "pairing_secret", "private_key",
                       "activationSecret", "activation_secret", "home_token"):
        if secret_key in json.dumps(cfg):
            raise SetupError(f"existing config at {path} embeds {secret_key!r}; "
                             "credentials must live in secrets/, never in config.json")
    # S7/H7 sections are optional on old configs (backward compat) but are
    # validated when present: no secrets, URL shapes, explicit loopback opt-in.
    coord = cfg.get("coordinator")
    if coord is not None:
        if not isinstance(coord, dict):
            raise SetupError(f"existing config at {path} has invalid coordinator section")
        for key in ("backend_url", "public_home_url", "credentials_file"):
            val = coord.get(key, "")
            if val and not isinstance(val, str):
                raise SetupError(f"existing config at {path} has invalid coordinator.{key}")
        allow_lb = bool(coord.get("allow_http_loopback", False))
        for key in ("backend_url", "public_home_url"):
            val = (coord.get(key) or "").strip()
            if val:
                validate_https_url(val, field=f"coordinator.{key}",
                                   allow_http_loopback=allow_lb)
        cred = (coord.get("credentials_file") or "").strip()
        if cred and "\0" in cred:
            raise SetupError(f"existing config at {path} has invalid coordinator.credentials_file")
    notif = cfg.get("notifications")
    if notif is not None:
        if not isinstance(notif, dict):
            raise SetupError(f"existing config at {path} has invalid notifications section")
        pid = (notif.get("expo_project_id") or "")
        if pid and (not isinstance(pid, str) or len(pid) > 128):
            raise SetupError(f"existing config at {path} has invalid notifications.expo_project_id")
    ups = cfg.get("upstream")
    if ups is not None:
        if not isinstance(ups, dict):
            raise SetupError(f"existing config at {path} has invalid upstream section")
        if str(ups.get("mode", "full")).strip().lower() not in ("full", "core"):
            raise SetupError(f"existing config at {path} has invalid upstream.mode "
                             "(must be full|core)")
    return cfg


def build_config(*, data_dir: Path, host: str, port: int,
                 installation_id: str, now: str, node_found: str,
                 installation_source: str = "reserved-pending-first-start",
                 node_bin: str = "", node_args: list | None = None,
                 infra_checkout: str = "", runtime_bridge: dict | None = None,
                 models: dict | None = None, service_env: str = "",
                 public_home_url: str = "",
                 coordinator_backend_url: str = "",
                 coordinator_credentials_file: str = "",
                 coordinator_allow_http_loopback: bool = False,
                 coordinator_enabled: bool = False,
                 notifications_enabled: bool = False,
                 expo_project_id: str = "",
                 upstream_mode: str | None = "full") -> dict:
    db_path = data_dir / "data" / "home.sqlite"  # H1 `--db` target (single-host SQLite)
    import shlex as _shlex
    node_ref = _shlex.quote(node_bin) if node_bin and " " in node_bin else (node_bin or "node")
    _extra_flags = " ".join(node_args or [])
    _start_prefix = f"{node_ref} {_extra_flags} src/cli.mjs" if _extra_flags else f"{node_ref} src/cli.mjs"
    _seed_prefix = _start_prefix
    return {
        "schema_version": SCHEMA_VERSION,
        "installation_id": installation_id,
        # How installation_id was obtained. The home database (and the live
        # service reading it) is authoritative; "reserved-*" is a placeholder
        # replaced on first start/restore/adopt. Never an invented identity
        # once the home service has opened its db.
        "installation_source": installation_source,
        "created_at": now,
        "updated_at": now,
        "platform": {
            "os": platform.system(),
            "release": platform.release(),
            "arch": platform.machine(),
        },
        "runtime": {
            "node_required": ">=24.18.0 <25",
            "node_found": node_found,
            "node_bin": node_bin,
        },
        "paths": {
            "infra_checkout": infra_checkout,
            "service_env": service_env,
        },
        "service": {
            "host": host,
            "port": port,
            "base_url": f"http://{host}:{port}",
            "db_path": str(db_path),
            "data_dir": str(data_dir),
            "household_dir": str(data_dir / "data" / "household"),
            "log_dir": str(data_dir / "logs"),
            "tmp_dir": str(data_dir / "tmp"),
        },
        "runtime_bridge": runtime_bridge or {"contract": BRIDGE_CONTRACT,
                                             "status": "unprobed"},
        "models": models or default_models(),
        **({"upstream": {
            # Production config derives FULL by default (user steering: FULL
            # upstream OpenBot platform + licensed self-hosted Intelligence is
            # the primary integration). Core is the upstream computer-plane
            # dev/partial profile (per-user computers via supervisor) -- NOT
            # the original Me task-broker runtime -- and never production
            # READY. upstream_mode=None (absent pre-migration config
            # preserved) omits this section entirely: the supervisor then
            # parks NEEDS_INPUT until the operator selects explicitly.
            "mode": upstream_mode,
            "note": ("full (default): FULL upstream platform + licensed "
                     "self-hosted Intelligence primary; core: upstream "
                     "computer-plane dev/partial (per-user computers, not "
                     "the original Me runtime), never production READY"),
        }} if upstream_mode in ("full", "core") else {}),
        "home_api": {
            # H1 (infra-server) owns this contract; setup only records readiness.
            # Human-readable: CONTRACT_REL_PATH (authoritative for H1).
            # Machine-readable: infra-server/contracts/home-api-v1.openapi.json.
            "contract": CONTRACT_REL_PATH,
            "contract_status": contract_status(),
            "auth": {
                "scheme": "bearer",
                "token_prefix": "ht1_",
                "identity": "server-derived from the session token; "
                            "client-supplied user IDs are never identity",
            },
            "anonymous_paths": ["/healthz", "/readyz", "/v1/pair"],
            "launch": {
                "db": str(db_path),
                "node": node_bin or "node (discovered at start time)",
                "node_args": node_args or [],
                "start": f"{_start_prefix} start --db={db_path} "
                         f"--host={host} --port={port}  # run from an infra-server checkout",
                "seed_dev_only": f"{_seed_prefix} seed-dev --db={db_path}  # DEVELOPMENT ONLY fixture users",
                "note": "The home service itself is owned and run by H1; this setup "
                        "only reserves its loopback binding, database path, and config. "
                        "Prefer scripts/me_lifecycle.py start over hand-running this.",
            },
        },
        "tunnel": {
            "mode": "disabled",
            "provider": "cloudflare",
            "tunnel_kind": "named tunnel (production only; never Quick Tunnel)",
            "hostname": "",
            "note": "Dev setup creates no tunnel and no public endpoint. "
                    "Production boundary: docs/production-tunnel-boundary.md.",
        },
        "coordinator": {
            # S7 home-coordination (home-coordinator-v1). Default DISABLED:
            # no outbound network until the operator configures a public URL,
            # redeems a one-time ticket (`coordinator activate`, ticket-only,
            # never an account JWT), and the home (H8) heartbeats with the
            # persisted home_token. Only non-secret references live here; the
            # home_token itself lives ONLY in credentials_file (mode 0600).
            "enabled": bool(coordinator_enabled),
            "backend_url": coordinator_backend_url or "",
            "public_home_url": public_home_url or "",
            "credentials_file": (coordinator_credentials_file
                                 or str(default_coordinator_credentials_file(data_dir))),
            "allow_http_loopback": bool(coordinator_allow_http_loopback),
            "note": ("Disabled by default (zero network). `coordinator prepare` "
                     "records the public URL; `coordinator activate` redeems the "
                     "one-time ticket over HTTPS and writes the 0600 credentials "
                     "file; the home heartbeats automatically (H8). Service "
                     "reload/restart required after changes; never auto-restarts "
                     "active jobs."),
        },
        "notifications": {
            # H7 opt-in private task push (home-notifications-v1). Default
            # DISABLED: zero outbound network. Operator opt-in
            # (HOME_NOTIFICATIONS_ENABLED=1) + per-phone consent required.
            # Payloads are metadata-only; the optional access token stays in
            # the operator shell (HOME_EXPO_ACCESS_TOKEN), never stored here.
            "enabled": bool(notifications_enabled),
            "expo_project_id": (expo_project_id or "").strip()[:128],
            "note": ("Disabled by default. Enable only with explicit operator "
                     "opt-in; no automatic third-party resources are created."),
        },
        "credentials": {
            "policy": "credentials live outside config.json and tracked files",
            "tunnel_connector": {"location": str(data_dir / "secrets"),
                                 "in_phone_qr": False},
            "admin": {"location": str(data_dir / "secrets"),
                      "separate_from_phone_enrollment": True},
            "phone_enrollment": {
                "location": str(data_dir / "data" / "household" / "pairing"),
                "scope": "per-device, revocable; issued by the home service, "
                         "never by this setup script",
            },
        },
        "deployment_boundary": {
            "development": "macOS + Node 24 (validated by this setup)",
            "future": "Linux (declared boundary; not installed by this setup)",
            "service_manager": "none: this setup installs no launchd/systemd "
                               "unit and claims no production installer",
        },
    }


def write_atomic(path: Path, text: str, mode: int = 0o644) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    fd, tmp = tempfile.mkstemp(dir=str(path.parent), prefix=path.name + ".")
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as f:
            f.write(text)
        os.chmod(tmp, mode)
        os.replace(tmp, path)
    except BaseException:
        try:
            os.unlink(tmp)
        except OSError:
            pass
        raise


def ensure_layout(data_dir: Path) -> None:
    for sub in SERVICE_SUBDIRS:
        (data_dir / sub).mkdir(parents=True, exist_ok=True)
    secrets = data_dir / "secrets"
    os.chmod(secrets, 0o700)
    readme = secrets / "README.md"
    if not readme.exists():
        readme.write_text(
            "# secrets (untracked, mode 0700)\n\n"
            "Tunnel connector credentials and admin credentials belong here as\n"
            "individual files with mode 0600, provisioned by the trusted\n"
            "provisioning component -- never by phone pairing, never in\n"
            "config.json, never in tracked files or logs.\n\n"
            "Phone enrollment material belongs under data/household/pairing/\n"
            "and is per-device revocable. See infra-server/docs/connection-and-pairing.md.\n",
            encoding="utf-8",
        )
    keep = data_dir / "data" / "household" / ".keep"
    if not keep.exists() and not any(keep.parent.iterdir()):
        keep.write_text("household data root; setup never deletes this tree\n",
                        encoding="utf-8")


def do_setup(data_dir: Path, host: str, port: int, adopt_service_id: bool = False,
             *, node_bin: str | None = None, infra_checkout: str | None = None,
             framework_checkout: str | None = None, runtime_python: str | None = None,
             model_provider: str = "local", model_name: str = "llama3.1",
             model_endpoint: str = "", allow_fixture_model: bool = False,
             allow_remote_model: bool = False, allow_code_exec: bool = False,
             cap_code_exec: bool = False, cap_web_fetch: bool = False,
             cap_browser: bool = False, cap_animation: bool = False,
             cap_egress: str = "", code_sandbox: str = "",
             min_disk_mib: int = 1024,
             public_home_url: str = "",
             coordinator_backend_url: str = "",
             coordinator_credentials_file: str = "",
             coordinator_allow_http_loopback: bool = False,
             coordinator_enabled: bool = False,
             notifications_enabled: bool = False,
             expo_project_id: str = "",
             upstream_mode: str | None = None) -> int:
    results = check_prerequisites(data_dir, host, port, node_bin=node_bin,
                                  min_disk_mib=min_disk_mib)
    failed = [(n, d) for n, ok, d in results if not ok]
    for name, ok, detail in results:
        log(f"[{'PASS' if ok else 'FAIL'}] {name}: {detail}")
    if failed:
        log("prerequisites failed; no config written")
        return 3

    cfg_file = config_path(data_dir)
    now = datetime.datetime.now(datetime.timezone.utc).isoformat()
    node_path, node_detail = find_node(node_bin)
    db_abs = data_dir / "data" / "home.sqlite"
    # Authoritative identity: the home database mints installation_id on first
    # open and H1 reuses it afterwards. Prefer it over any reservation.
    db_installation_id = read_db_installation_id(db_abs)
    infra_dir = resolve_checkout(infra_checkout, "ME_HOME_INFRA_CHECKOUT",
                                 "infra-server", ("src/cli.mjs", "src/server.mjs"),
                                 "home service")
    framework_dir = resolve_checkout(framework_checkout, "ME_HOME_FRAMEWORK_CHECKOUT",
                                     "agentic-framework", ("docs/runtime-bridge-v1.md",),
                                     "agent framework")
    bridge = probe_runtime_bridge(framework_dir, runtime_python)
    # S7/H7 options: env fallbacks (flags win when non-empty). All default
    # disabled; nothing here performs network I/O or writes secrets.
    public_home_url = (public_home_url or os.environ.get("ME_HOME_PUBLIC_URL", "") or "").strip()
    coordinator_backend_url = (coordinator_backend_url
                               or os.environ.get("ME_HOME_COORDINATOR_BACKEND_URL", "") or "").strip()
    coordinator_credentials_file = (coordinator_credentials_file
                                    or os.environ.get("ME_HOME_COORDINATOR_CREDENTIALS_FILE", "")
                                    or "").strip()
    expo_project_id = (expo_project_id or os.environ.get("HOME_EXPO_PROJECT_ID", "") or "").strip()[:128]
    # Upstream mode: explicit flag wins; else preserve the existing explicit
    # mode on reruns (never silently overwrite); fresh installs default full.
    # Core is the upstream computer-plane dev/partial profile, NOT the
    # original Me task-broker runtime. Absent pre-migration configs stay
    # absent unless the operator chooses (supervisor parks NEEDS_INPUT).
    _flag_mode = (upstream_mode or "").strip().lower() if upstream_mode else ""
    if _flag_mode and _flag_mode not in ("full", "core"):
        log("error: --upstream-mode must be full|core (default full; "
            "core is computer-plane dev/partial, never production READY)")
        return 2
    if public_home_url:
        try:
            public_home_url = validate_https_url(
                public_home_url, field="--public-home-url",
                allow_http_loopback=coordinator_allow_http_loopback)
        except SetupError as exc:
            log(f"error: {exc}")
            return 2
    if coordinator_backend_url:
        try:
            coordinator_backend_url = validate_https_url(
                coordinator_backend_url, field="--coordinator-backend-url",
                allow_http_loopback=coordinator_allow_http_loopback)
        except SetupError as exc:
            log(f"error: {exc}")
            return 2
    if coordinator_credentials_file:
        if "\0" in coordinator_credentials_file:
            log("error: --coordinator-credentials-file contains NUL")
            return 2
        expanded = os.path.expanduser(coordinator_credentials_file)
        if not os.path.isabs(expanded):
            log("error: --coordinator-credentials-file must be an absolute path "
                "(operator-chosen, outside git and shared config)")
            return 2
    try:
        models = build_models(provider=model_provider, name=model_name,
                              endpoint=model_endpoint,
                              allow_fixture=allow_fixture_model,
                              allow_remote=allow_remote_model,
                              allow_code_exec=allow_code_exec,
                              cap_code_exec=cap_code_exec,
                              cap_web_fetch=cap_web_fetch,
                              cap_browser=cap_browser,
                              cap_animation=cap_animation,
                              cap_egress=cap_egress,
                              code_sandbox=code_sandbox)
    except SetupError as exc:
        log(f"error: {exc}")
        return 2
    existing: dict | None = None
    if cfg_file.is_file():
        existing = load_config(data_dir)  # validates; raises instead of wiping
        if (existing.get("service", {}).get("host") != host
                or existing.get("service", {}).get("port") != port):
            stamp = datetime.datetime.now(datetime.timezone.utc).strftime("%Y%m%dT%H%M%SZ")
            backup = data_dir / "backups" / f"config-{stamp}.json"
            backup.parent.mkdir(parents=True, exist_ok=True)
            shutil.copy2(cfg_file, backup)
            log(f"existing config backed up to {backup}")
        installation_id = existing["installation_id"]
        installation_source = existing.get("installation_source", "reserved-pending-first-start")
        if db_installation_id and db_installation_id != installation_id:
            stamp = datetime.datetime.now(datetime.timezone.utc).strftime("%Y%m%dT%H%M%SZ")
            backup = data_dir / "backups" / f"config-{stamp}.json"
            shutil.copy2(cfg_file, backup)
            log(f"home database holds authoritative installation_id; "
                f"adopting {db_installation_id} (config backed up to {backup})")
            installation_id = db_installation_id
            installation_source = "home-database"
        created = existing.get("created_at", now)
    else:
        if db_installation_id:
            installation_id, installation_source = db_installation_id, "home-database"
        else:
            installation_id = str(uuid.uuid4())
            installation_source = "reserved-pending-first-start"
        created = now

    ensure_layout(data_dir)
    try:
        node_argv = node_args_for(node_path or "node",
                                  Path(infra_dir) / "src" / "cli.mjs") if infra_dir else []
    except SetupError:
        node_argv = []
    # Preserve operator coordinator/notifications choices across reruns when
    # flags are absent (enabling is sticky; to disable, edit config.json or
    # use the coordinator/notifications setup flags explicitly).
    _prev_coord = (existing or {}).get("coordinator", {}) or {}
    _prev_notif = (existing or {}).get("notifications", {}) or {}
    if not public_home_url:
        public_home_url = str(_prev_coord.get("public_home_url", "") or "")
    if not coordinator_backend_url:
        coordinator_backend_url = str(_prev_coord.get("backend_url", "") or "")
    if not coordinator_credentials_file:
        coordinator_credentials_file = str(
            _prev_coord.get("credentials_file", "")
            or str(default_coordinator_credentials_file(data_dir)))
    eff_allow_lb = bool(coordinator_allow_http_loopback
                        or _prev_coord.get("allow_http_loopback", False))
    eff_coord_enabled = bool(coordinator_enabled or _prev_coord.get("enabled", False))
    eff_notif_enabled = bool(notifications_enabled or _prev_notif.get("enabled", False))
    if not expo_project_id:
        expo_project_id = str(_prev_notif.get("expo_project_id", "") or "")
    _prev_ups = (existing or {}).get("upstream", None)
    _prev_mode = ""
    if isinstance(_prev_ups, dict):
        _prev_mode = str(_prev_ups.get("mode", "") or "").strip().lower()
        if _prev_mode not in ("full", "core"):
            _prev_mode = ""
    if _flag_mode:
        eff_mode: str | None = _flag_mode
    elif existing is None:
        eff_mode = "full"  # fresh install default (user steering: FULL primary)
    elif _prev_mode:
        eff_mode = _prev_mode  # sticky explicit choice on reruns
    else:
        eff_mode = None  # absent pre-migration config preserved (no silent default)
    cfg = build_config(data_dir=data_dir, host=host, port=port,
                       installation_id=installation_id, now=now, node_found=node_detail,
                       installation_source=installation_source,
                       node_bin=node_path or "",
                       node_args=node_argv[1:] if node_argv else [],
                       infra_checkout=str(infra_dir) if infra_dir else "",
                       runtime_bridge=bridge, models=models,
                       service_env=str(data_dir / "config" / "service.env"),
                       public_home_url=public_home_url,
                       coordinator_backend_url=coordinator_backend_url,
                       coordinator_credentials_file=coordinator_credentials_file,
                       coordinator_allow_http_loopback=eff_allow_lb,
                       coordinator_enabled=eff_coord_enabled,
                       notifications_enabled=eff_notif_enabled,
                       expo_project_id=expo_project_id,
                       upstream_mode=eff_mode)
    cfg["created_at"] = created
    write_atomic(cfg_file, json.dumps(cfg, indent=2, sort_keys=True) + "\n")

    bridge_argv: list | None = None
    bridge_cwd = ""
    if bridge.get("status") == "importable" and bridge.get("python"):
        bridge_argv = [bridge["python"], "-m", "me_runtime.bridge"]
        bridge_cwd = bridge.get("import_cwd", "")
    env_text = render_service_env(db_path=db_abs, host=host, port=port,
                                  runtime_argv=bridge_argv,
                                  runtime_cwd=bridge_cwd, models=models,
                                  coordinator=cfg.get("coordinator"),
                                  notifications=cfg.get("notifications"),
                                  upstream_mode=eff_mode)
    write_atomic(data_dir / "config" / "service.env", env_text)

    # Restrict secrets dir on every run (defensive; never touches household data).
    os.chmod(data_dir / "secrets", 0o700)
    log(f"setup complete: installation_id={installation_id} (source: {installation_source})")
    log(f"config: {cfg_file}")
    log(f"service env (non-secret): {data_dir / 'config' / 'service.env'}")
    log(f"household data preserved at: {data_dir / 'data' / 'household'}")
    if bridge.get("status") != "importable":
        log(f"WARN: runtime-bridge: {bridge.get('detail')} "
            f"[transient H2 dependency; rerun when stable]")
    else:
        log(f"runtime-bridge: {bridge.get('detail')}")
    if infra_dir is None:
        log("WARN: infra-server checkout not found (explicit --infra-checkout, "
            "ME_HOME_INFRA_CHECKOUT, or ../infra-server) [transient H1 dependency; "
            "lifecycle commands need it]")
    log(f"home_api contract status: {cfg['home_api']['contract_status']} "
        f"({CONTRACT_REL_PATH})")
    if cfg["home_api"]["contract_status"] == "pending-h1":
        log("handoff: H1 has not published the home API contract yet; "
            "service routes/versions remain an integration dependency")
    if adopt_service_id:
        return adopt_live_service_id(data_dir, host, port)
    return 0


def adopt_live_service_id(data_dir: Path, host: str, port: int) -> int:
    """Adopt the running H1 service's installation_id into this config.

    The H1 database mints and persists the authoritative installation_id on
    first open. A fresh config therefore tracks a reservation until the real
    service starts; this explicit step (with backup) aligns the two after the
    operator verifies the listening service is the intended one.
    """
    body, err = fetch_healthz(host, port)
    if body is None:
        log(f"adopt failed: {err}")
        return 1
    if body.get("status") != "ok" or body.get("contract") != CONTRACT_VERSION:
        log(f"adopt failed: unexpected health surface: {redact(str(body)[:200])}")
        return 1
    live_id = body.get("installation_id")
    if not live_id:
        log("adopt failed: live service reported no installation_id")
        return 1
    cfg = load_config(data_dir)
    if cfg["installation_id"] == live_id:
        log(f"adopt: config already tracks live installation_id={live_id}")
        return 0
    stamp = datetime.datetime.now(datetime.timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    backup = data_dir / "backups" / f"config-{stamp}.json"
    shutil.copy2(config_path(data_dir), backup)
    cfg["installation_id"] = live_id
    cfg["installation_source"] = "live-service"
    cfg["updated_at"] = datetime.datetime.now(datetime.timezone.utc).isoformat()
    write_atomic(config_path(data_dir), json.dumps(cfg, indent=2, sort_keys=True) + "\n")
    log(f"adopt: config backed up to {backup}")
    log(f"adopt: installation_id now tracks the live service ({live_id})")
    return 0


def do_check(data_dir: Path) -> int:
    try:
        data_dir = resolve_data_dir(data_dir)
    except SetupError as exc:
        log(f"FAIL: {exc}")
        return 2
    ok = True
    try:
        cfg = load_config(data_dir)
        log(f"PASS: config valid (schema v{cfg['schema_version']}, "
            f"installation_id={cfg['installation_id']})")
        host = cfg["service"]["host"]
        port = int(cfg["service"]["port"])
        expected_installation_id = cfg["installation_id"]
    except (SetupError, KeyError, ValueError) as exc:
        log(f"FAIL: config: {exc}")
        return 1
    for sub in SERVICE_SUBDIRS:
        p = data_dir / sub
        if p.is_dir() and os.access(p, os.W_OK):
            log(f"PASS: dir {sub}")
        else:
            log(f"FAIL: dir {sub} missing or not writable")
            ok = False
    secrets = data_dir / "secrets"
    try:
        mode = oct(secrets.stat().st_mode & 0o777)
        if mode == "0o700":
            log("PASS: secrets dir mode 0700")
        else:
            log(f"FAIL: secrets dir mode {mode}, expected 0o700")
            ok = False
    except OSError as exc:
        log(f"FAIL: secrets dir: {exc}")
        ok = False
    for name, good, detail in check_prerequisites(data_dir, host, port):
        if name in ("writable-dest",):
            continue  # already covered above
        log(f"[{'PASS' if good else 'FAIL'}] {name}: {detail}")
        if name in ("os", "non-root", "node24", "python",
                    "port-range", "loopback-host", "disk") and not good:
            ok = False
    free, note = port_free(host, port)
    log(f"[{'PASS' if free else 'WARN'}] service-port: {host}:{port} {note} "
        f"{'(service may already hold it)' if not free else ''}")
    if not free:
        # Something listens: check whether it is OUR home service (H1 contract).
        log(probe_healthz(host, port, expected_installation_id))
    household = data_dir / "data" / "household"
    if household.is_dir():
        log("PASS: household data dir present (never deleted by setup)")
    else:
        log("FAIL: household data dir missing")
        ok = False
    # S7 coordinator: default disabled (zero network). Validate references
    # only; the secret file itself is checked by `coordinator status/check`.
    coord = cfg.get("coordinator", {}) or {}
    if not isinstance(coord, dict):
        log("FAIL: coordinator section invalid")
        ok = False
    elif coord.get("enabled"):
        for key in ("backend_url", "public_home_url"):
            val = (coord.get(key) or "").strip()
            if val:
                try:
                    validate_https_url(val, field=f"coordinator.{key}",
                                       allow_http_loopback=bool(coord.get("allow_http_loopback")))
                except SetupError as exc:
                    log(f"FAIL: coordinator: {exc}")
                    ok = False
        cred = (coord.get("credentials_file") or "").strip()
        if not cred:
            log("FAIL: coordinator enabled but credentials_file is empty")
            ok = False
        else:
            log("PASS: coordinator enabled "
                f"(public_home_url={'set' if coord.get('public_home_url') else 'unset'}, "
                "secret file reference only, service reload required after changes)")
    else:
        log("PASS: coordinator disabled (default, zero network)")
    # H7 notifications: default disabled (zero network). Public project id
    # only; the access token stays in the operator shell, never stored.
    notif = cfg.get("notifications", {}) or {}
    if not isinstance(notif, dict):
        log("FAIL: notifications section invalid")
        ok = False
    elif notif.get("enabled"):
        log("PASS: notifications enabled (opt-in; no automatic third-party resources)")
    else:
        log("PASS: notifications disabled (default, zero network)")
    return 0 if ok else 1


def do_config_show(data_dir: Path) -> int:
    try:
        cfg = load_config(resolve_data_dir(data_dir))
    except SetupError as exc:
        log(f"FAIL: {exc}")
        return 2
    print(json.dumps(cfg, indent=2, sort_keys=True))
    return 0


def build_parser() -> argparse.ArgumentParser:
    default_dir = str(default_data_dir())
    default_port = int(os.environ.get("ME_HOME_PORT", str(DEFAULT_PORT)))
    p = argparse.ArgumentParser(description="Me home dev setup/check (no root, no tunnel)")
    sub = p.add_subparsers(dest="cmd", required=True)
    s = sub.add_parser("setup", help="validate prereqs and (re)generate config")
    s.add_argument("--data-dir", default=default_dir)
    s.add_argument("--host", default=DEFAULT_HOST)
    s.add_argument("--port", type=int, default=default_port)
    s.add_argument("--adopt-service-id", action="store_true",
                   help="after setup, adopt the live H1 service installation_id "
                        "(verified via /healthz) into this config")
    s.add_argument("--node", default=os.environ.get("ME_HOME_NODE", ""),
                   help="explicit node binary (default: discover >=24.18.0 <25)")
    s.add_argument("--infra-checkout", default=os.environ.get("ME_HOME_INFRA_CHECKOUT", ""),
                   help="explicit infra-server checkout path")
    s.add_argument("--framework-checkout",
                   default=os.environ.get("ME_HOME_FRAMEWORK_CHECKOUT", ""),
                   help="explicit agentic-framework checkout path")
    s.add_argument("--runtime-python", default=os.environ.get("ME_HOME_RUNTIME_PYTHON", ""),
                   help="explicit runtime bridge python")
    s.add_argument("--allow-remote-model", action="store_true",
                   help="explicit opt-in: permit remote model endpoints (key stays "
                        "in operator shell, never stored)")
    s.add_argument("--model-provider", default="local",
                   help="home model provider: local|fixture|openai|anthropic")
    s.add_argument("--model-name", default="",
                   help="model name (default per provider; fixture-echo for fixture)")
    s.add_argument("--model-endpoint", default="",
                   help="model endpoint URL (local default is the ChatOllama base "
                        "URL without /v1; never set for fixture)")
    s.add_argument("--allow-fixture-model", action="store_true",
                   help="explicit opt-in: fixture model for synthetic tests only, "
                        "never household data")
    s.add_argument("--allow-code-exec", action="store_true",
                   help="explicit opt-in: runtime gate for bounded code execution "
                        "(needs --cap-code-exec too)")
    s.add_argument("--cap-code-exec", action="store_true",
                   help="home capability ceiling: allow code_exec grants")
    s.add_argument("--cap-web-fetch", action="store_true",
                   help="home capability ceiling: allow web_fetch grants")
    s.add_argument("--cap-browser", action="store_true",
                   help="home capability ceiling: allow browser grants")
    s.add_argument("--cap-animation", action="store_true",
                   help="home capability ceiling: allow animation grants")
    s.add_argument("--cap-egress", default="",
                   help="comma-separated egress allowlist (HOME_CAP_EGRESS)")
    s.add_argument("--code-sandbox", default="",
                   help="code execution sandbox backend: docker (requires "
                        "--allow-code-exec and --cap-code-exec; auto-configured "
                        "to docker when both are given; empty disables)")
    s.add_argument("--min-disk-mib", type=int, default=1024,
                   help="minimum free MiB (default 1024 production guard; lower "
                        "only as an explicit dev-only synthetic override)")
    s.add_argument("--public-home-url", default=os.environ.get("ME_HOME_PUBLIC_URL", ""),
                   help="public home base URL for endpointHint/pairing "
                        "(https:// always; http:// loopback only with "
                        "--coordinator-allow-http-loopback)")
    s.add_argument("--coordinator-backend-url",
                   default=os.environ.get("ME_HOME_COORDINATOR_BACKEND_URL", ""),
                   help="known backend base URL (recorded non-secret; activate "
                        "uses the ticket's backend_url and must match when set)")
    s.add_argument("--coordinator-credentials-file",
                   default=os.environ.get("ME_HOME_COORDINATOR_CREDENTIALS_FILE", ""),
                   help="absolute path of the private 0600 credentials file "
                        "(default <data-dir>/secrets/backend-home-token.json)")
    s.add_argument("--coordinator-allow-http-loopback", action="store_true",
                   help="explicit dev/test opt-in: allow http:// loopback "
                        "backend/public URLs (never for production)")
    s.add_argument("--coordinator-enabled", action="store_true",
                   help="explicit opt-in: enable home-coordinator wiring "
                        "(default disabled, zero network; service reload "
                        "required after changes)")
    s.add_argument("--notifications-enabled", action="store_true",
                   help="explicit opt-in: enable task push notifications "
                        "H7 (default disabled, zero network)")
    s.add_argument("--expo-project-id", default=os.environ.get("HOME_EXPO_PROJECT_ID", ""),
                   help="optional public Expo project id (app config, never a "
                        "credential; access token stays in operator shell)")
    s.add_argument("--upstream-mode", default=None, choices=("full", "core"),
                   help="upstream platform profile recorded in config "
                        "(default full on fresh installs: FULL OpenBot + "
                        "licensed self-hosted Intelligence primary; core is "
                        "the upstream computer-plane dev/partial profile, "
                        "never production READY; omitted on reruns preserves "
                        "the existing explicit choice)")
    c = sub.add_parser("check", help="validate prereqs and existing config")
    c.add_argument("--data-dir", default=default_dir)
    v = sub.add_parser("config-show", help="print current config (no secrets by design)")
    v.add_argument("--data-dir", default=default_dir)
    return p


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    try:
        if args.cmd == "setup":
            data_dir = resolve_data_dir(args.data_dir)
            return do_setup(data_dir, args.host, int(args.port),
                            adopt_service_id=args.adopt_service_id,
                            node_bin=args.node or None,
                            infra_checkout=args.infra_checkout or None,
                            framework_checkout=args.framework_checkout or None,
                            runtime_python=args.runtime_python or None,
                            model_provider=args.model_provider,
                            model_name=args.model_name or "",
                            model_endpoint=args.model_endpoint or "",
                            allow_fixture_model=args.allow_fixture_model,
                            allow_remote_model=args.allow_remote_model,
                            allow_code_exec=args.allow_code_exec,
                            cap_code_exec=args.cap_code_exec,
                            cap_web_fetch=args.cap_web_fetch,
                            cap_browser=args.cap_browser,
                            cap_animation=args.cap_animation,
                            cap_egress=args.cap_egress or "",
                            code_sandbox=args.code_sandbox or "",
                            min_disk_mib=int(args.min_disk_mib),
                            public_home_url=args.public_home_url or "",
                            coordinator_backend_url=args.coordinator_backend_url or "",
                            coordinator_credentials_file=args.coordinator_credentials_file or "",
                            coordinator_allow_http_loopback=args.coordinator_allow_http_loopback,
                            coordinator_enabled=args.coordinator_enabled,
                            notifications_enabled=args.notifications_enabled,
                            expo_project_id=args.expo_project_id or "",
                            upstream_mode=args.upstream_mode)
        if args.cmd == "check":
            return do_check(Path(args.data_dir))
        if args.cmd == "config-show":
            return do_config_show(Path(args.data_dir))
    except SetupError as exc:
        log(f"error: {exc}")
        return 2
    except PrereqError as exc:
        log(f"prerequisite error: {exc}")
        return 3
    raise AssertionError("unreachable")


if __name__ == "__main__":
    sys.exit(main())
