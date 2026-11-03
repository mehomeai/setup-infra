#!/usr/bin/env python3
"""S7 cloud-coordination activation (setup-infra ownership).

Setup-side only: prepare/activate/status/check for home-coordinator-v1
(file) over home-api-v1 (wire). The home (H8, infra-server/src/coordinator.mjs)
owns the credential file + automatic heartbeat loop; the backend (B7,
backend-server/docs/home-activation-v1.md) owns the ticket/activation wire.
This module never edits siblings, never duplicates the heartbeat loop, and
performs network I/O ONLY in `activate` (single ticket-only POST, no retries).

Discipline (load-bearing):
- Ticket JSON arrives via STDIN only (bounded, one-time). NEVER via argv
  (process listings leak argv), and NEVER an account JWT: activate sends NO
  `Authorization` header (the ticket IS the authorization).
- Own installation_id is matched BEFORE any network. Mismatch => no fetch,
  ticket untouched.
- endpointHint comes from LOCAL setup config (public_home_url / tunnel
  hostname), never from the ticket or any backend hint.
- backend_url comes from the ticket JSON; validated HTTPS (explicit
  loopback-http opt-in only), no userinfo/query/fragment; redirects are
  failures (never followed); request/response/body/time all bounded; exactly
  one attempt, NO automatic redeem retries.
- Unknown redemption outcome (timeout/disconnect) => do NOT replay the same
  ticket. Mint a FRESH owner recovery ticket and redeem once (rotation
  invalidates prior verifiers).
- The persisted file matches home-coordinator-v1 EXACTLY (7 keys incl.
  protocol_version home-api-v1), written atomically to the protected
  secrets path (parent 0700, file 0600, no final symlink). Token/path
  contents are NEVER printed or logged. Destination writability is
  preflighted BEFORE the fetch to avoid a response-before-safe-storage gap;
  when storage still fails after a 201, the credential is lost locally and
  the operator must recover via a fresh ticket (documented in the message).

Exit codes: 0 ok, 1 operation/state failure, 2 usage/validation.
"""

from __future__ import annotations

import io
import json
import os
import re
import socket
import stat
import sys
import tempfile
import urllib.error
import urllib.parse
import urllib.request
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

import me_setup

PROTOCOL = "home-coordinator-v1"
PROTOCOL_VERSION = "home-api-v1"
TICKET_MAX_BYTES = 16 * 1024
RESPONSE_MAX_BYTES = 64 * 1024
FILE_MAX_BYTES = 16 * 1024
REQUEST_TIMEOUT_DEFAULT_MS = 10_000
REQUEST_TIMEOUT_MIN_MS = 1_000
REQUEST_TIMEOUT_MAX_MS = 30_000

HOME_ID_RE = re.compile(r"^[a-z0-9][a-z0-9_-]{2,63}$")
INSTALLATION_ID_RE = re.compile(r"^[\x20-\x7E]{1,128}$")
HOME_TOKEN_RE = re.compile(r"^me_home_[A-Za-z0-9_-]{32,128}$")
EXPECTED_FILE_KEYS = ("protocol", "backend_url", "home_id", "installation_id",
                      "home_token", "endpoint_hint", "protocol_version")

LOOPBACK_NAMES = ("127.0.0.1", "localhost", "::1")


class CoordinatorError(Exception):
    """Usage/validation failure (exit 2)."""


class ActivationError(Exception):
    """Operation/state failure (exit 1). Carries a redacted message."""

    def __init__(self, message: str, *, unknown_outcome: bool = False):
        super().__init__(message)
        self.unknown_outcome = unknown_outcome


def log(msg: str) -> None:
    print(me_setup.redact(msg), flush=True)


def err(msg: str) -> None:
    print(me_setup.redact(msg), file=sys.stderr, flush=True)


def redact_home_id(home_id: str) -> str:
    s = str(home_id or "")
    if not s:
        return ""
    if len(s) <= 8:
        return s[:2] + "…"
    return s[:7] + "…" + s[-4:]


def _is_loopback(hostname: str) -> bool:
    return (hostname or "").strip().lower().strip("[]") in LOOPBACK_NAMES


def allow_http_loopback_effective(cfg_coord: dict) -> bool:
    """Explicit opt-in only: config flag OR operator env (own shell)."""
    if bool((cfg_coord or {}).get("allow_http_loopback", False)):
        return True
    raw = os.environ.get("HOME_COORDINATOR_ALLOW_HTTP_LOOPBACK", "")
    return raw == "1" or raw.strip().lower() == "true"


def validate_backend_url(value: str, *, allow_http_loopback: bool = False) -> str:
    return me_setup.validate_https_url(
        value, field="backend_url",
        allow_http_loopback=allow_http_loopback)


def validate_endpoint_hint(value: str, *, allow_http_loopback: bool = False) -> str:
    return me_setup.validate_https_url(
        value, field="endpointHint (local public_home_url)",
        allow_http_loopback=allow_http_loopback)


def resolve_public_url(cfg: dict, *, explicit: str = "") -> str:
    """Resolve the LOCAL public home URL. Never trusts backend hints.

    Order: explicit flag > ME_HOME_PUBLIC_URL env > config
    coordinator.public_home_url > tunnel hostname (named tunnel, stable).
    """
    coord = (cfg.get("coordinator") or {}) if isinstance(cfg, dict) else {}
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
            return cand
    raise CoordinatorError(
        "no local public home URL configured: pass --public-url, set "
        "ME_HOME_PUBLIC_URL, run `setup --public-home-url https://<host>`, or "
        "`tunnel configure --hostname <stable-name>` first (named tunnel, "
        "stable hostname; never Quick Tunnel)")


def authoritative_db_path(data_dir: Path, cfg: dict) -> Path:
    """Resolve the home SQLite path without creating anything."""
    try:
        raw = cfg["service"]["db_path"]
        if isinstance(raw, str) and raw.strip():
            return Path(raw)
    except (KeyError, TypeError):
        pass
    return data_dir / "data" / "home.sqlite"


def own_installation_id(data_dir: Path, cfg: dict) -> str:
    """Authoritative installation: home SQLite DB ONLY, never config reservation.

    The home database mints installation_id on first open. A fresh `setup`
    only reserves a placeholder until the loopback home starts; binding a B7
    ticket to that reservation would mint a credential the real first-started
    home (different UUID) can never use (H8 wrong_home). Fail closed BEFORE
    any network so the ticket stays unconsumed.
    """
    db_path = authoritative_db_path(data_dir, cfg)
    db_id = me_setup.read_db_installation_id(db_path)
    if db_id:
        return db_id
    raise CoordinatorError(
        "home database has no authoritative installation_id yet "
        f"(db: {db_path}); start the loopback home once (`start` then `stop`, "
        "or `bootstrap`) so it mints its installation_id, then run "
        "`coordinator prepare` again. Do NOT bind tickets to the "
        "pre-start config reservation.")


def credentials_file_for(cfg: dict, data_dir: Path, *,
                         explicit: str = "") -> Path:
    coord = (cfg.get("coordinator", {}) or {}) if isinstance(cfg, dict) else {}
    raw = ((explicit or "").strip()
           or (os.environ.get("ME_HOME_COORDINATOR_CREDENTIALS_FILE", "") or "").strip()
           or str(coord.get("credentials_file", "") or "").strip()
           or str(me_setup.default_coordinator_credentials_file(data_dir)))
    expanded = os.path.expanduser(raw)
    if not os.path.isabs(expanded):
        raise CoordinatorError(
            "coordinator credentials file must be an absolute path "
            "(operator-chosen, outside git and shared config)")
    return Path(os.path.normpath(expanded))


def parse_ticket_stdin(*, max_bytes: int = TICKET_MAX_BYTES) -> dict:
    """Read the bounded one-time ticket JSON from STDIN. Never from argv."""
    data = sys.stdin.read(max_bytes + 1)
    if not data:
        raise CoordinatorError(
            "no ticket JSON on STDIN: pipe the one-time activation JSON "
            "(backend_url, ticketId, activationSecret, installationId) "
            "from the owner phone; never pass secrets via argv")
    if len(data) > max_bytes:
        raise CoordinatorError(
            f"ticket JSON exceeds {max_bytes} bytes; refusing to parse")
    try:
        ticket = json.loads(data)
    except json.JSONDecodeError as exc:
        raise CoordinatorError(f"ticket JSON is not valid JSON ({exc})")
    if not isinstance(ticket, dict):
        raise CoordinatorError("ticket JSON must be an object")
    for secret_carrier in ("accountToken", "accountJwt", "authorization",
                           "homeToken", "home_token"):
        if secret_carrier in ticket:
            raise CoordinatorError(
                f"ticket must not carry {secret_carrier!r}: activation is "
                "ticket-only, never an account JWT or home token")
    return ticket


def _ticket_str(ticket: dict, *names: str) -> str:
    for name in names:
        val = ticket.get(name)
        if isinstance(val, str) and val.strip():
            return val.strip()
    return ""


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    """Redirects are failures (never followed, no token forwarding)."""

    def redirect_request(self, req, fp, code, msg, headers, newurl):
        raise ActivationError(
            "backend redirect refused (redirects are failures; check "
            "backend_url; no credentials forwarded)")


def _build_opener() -> urllib.request.OpenerDirector:
    # Private credential transport: explicit direct connection only. An empty
    # ProxyHandler disables ambient HTTP(S)_PROXY / curl-config proxies that
    # could otherwise exfiltrate the one-time ticket or home token, and keeps
    # dev loopback off any corporate egress.
    return urllib.request.build_opener(_NoRedirect, urllib.request.ProxyHandler({}))


# --- hard-total-deadline transport (isolated subprocess) -------------------
# urllib's per-socket inactivity timeout resets on every recv, so a peer
# trickling 1 byte per interval inside a single read(n) (or inside header
# readline) can run forever without tripping it. The ONLY portable stdlib
# hard bound covering DNS/connect/headers/body is to run the single POST in
# an isolated short-lived child and kill/reap it on a parent monotonic
# deadline (subprocess.run/communicate timeout). Secret payload travels ONLY
# on the child stdin pipe; the homeToken-bearing reply returns ONLY on the
# bounded stdout pipe; neither ever touches argv, env, logs, or disk. The
# child reuses this module's validated transport (_do_transport_once); there
# is no source-copied second implementation.
TRANSPORT_HELPER_FLAG = "--transport-helper"
TRANSPORT_STDIN_MAX_BYTES = 32 * 1024
TRANSPORT_STDOUT_MAX_BYTES = 256 * 1024
PARENT_STDOUT_CAP_BYTES = 1 * 1024 * 1024


def _transport_child_env() -> dict:
    """Child env with ambient proxy variables stripped (defense in depth).

    The child also uses ProxyHandler({}) so urllib never consults proxies;
    stripping here guarantees no host-global proxy can exfiltrate the ticket
    even if urllib behavior regresses, and keeps dev loopback direct.
    """
    env = dict(os.environ)
    for key in list(env.keys()):
        low = key.lower()
        if low in ("http_proxy", "https_proxy", "all_proxy", "no_proxy") or low.endswith("_proxy"):
            del env[key]
    return env


def _read_bounded_stream(stream, limit: int) -> bytes:
    """Read at most limit+1 bytes (cap+1 detects oversize uniformly)."""
    chunks: list[bytes] = []
    total = 0
    while True:
        chunk = stream.read(min(65536, limit + 1 - total))
        if not chunk:
            break
        if isinstance(chunk, str):
            chunk = chunk.encode("utf-8")
        chunks.append(chunk)
        total += len(chunk)
        if total > limit:
            break
    return b"".join(chunks)


def _do_transport_once(*, backend_url: str, payload: dict,
                       timeout_s: float) -> tuple[int, bytes]:
    """Single validated POST. Shared by the isolated child (only caller).

    No Authorization header, no redirects (refused), no retries, no proxy.
    Returns (status, bounded body). Raises ActivationError with generic
    messages only (never exception text or body content).
    """
    import base64 as _b64  # local import: child keeps stdlib-only footprint
    _ = _b64
    base = (backend_url or "").rstrip("/")
    url = f"{base}/v1/homes/activate"
    try:
        req_body = json.dumps(payload).encode("utf-8")
    except (TypeError, ValueError):
        raise CoordinatorError("cannot encode activation request")
    if len(req_body) > TRANSPORT_STDIN_MAX_BYTES:
        raise CoordinatorError("activation request too large")
    req = urllib.request.Request(
        url, data=req_body, method="POST",
        headers={"Content-Type": "application/json",
                 "Accept": "application/json"})
    if any(str(k).lower() == "authorization" for k, _ in req.header_items()):
        raise AssertionError("unreachable: Authorization must never be set")
    opener = _build_opener()
    try:
        with opener.open(req, timeout=timeout_s) as resp:
            status = int(getattr(resp, "status", 200) or 200)
            raw = _read_bounded_stream(resp, RESPONSE_MAX_BYTES)
    except ActivationError:
        raise
    except urllib.error.HTTPError as exc:
        code = int(exc.code or 0)
        try:
            raw = _read_bounded_stream(exc, RESPONSE_MAX_BYTES)
        except (OSError, ValueError):
            raw = b""
        finally:
            try:
                exc.close()
            except OSError:
                pass
        if len(raw) > RESPONSE_MAX_BYTES:
            raise ActivationError(
                "backend response exceeds 64 KiB; refusing to parse with UNKNOWN "
                "persistence outcome; do NOT replay this ticket. Mint a FRESH "
                "owner recovery ticket and redeem once.",
                unknown_outcome=True)
        return code, bytes(raw)
    except (urllib.error.URLError, TimeoutError, socket.timeout, OSError):
        raise ActivationError(
            "activation transport failed with UNKNOWN server outcome; do NOT "
            "retry the same ticket. Mint a FRESH owner recovery ticket "
            "(existingHomeId) and redeem once.",
            unknown_outcome=True)
    except Exception:
        raise ActivationError(
            "activation failed with UNKNOWN server outcome; do NOT retry the "
            "same ticket; mint a FRESH owner recovery ticket (existingHomeId) "
            "and redeem once.",
            unknown_outcome=True)
    if len(raw) > RESPONSE_MAX_BYTES:
        raise ActivationError(
            "backend response exceeds 64 KiB; refusing to parse with UNKNOWN "
            "persistence outcome; do NOT replay this ticket. Mint a FRESH "
            "owner recovery ticket and redeem once.",
            unknown_outcome=True)
    return status, bytes(raw)


def _transport_child_main() -> int:
    """Isolated transport child: stdin envelope -> stdout envelope.

    Stdin (bounded 32 KiB): {"backend_url": str, "payload": dict,
                             "timeout_s": float, "allow_http_loopback": bool}
    Stdout (bounded <256 KiB): {"ok": true, "status": int, "body_b64": str}
      or {"ok": false, "code": "unknown"|"redirect"|"oversize"|"usage"}.
    All messages generic; no secret, body, or exception text is ever echoed
    to stdout/stderr. Exit 0 with an envelope on every controlled path;
    exit 2 only when the envelope itself is unusable (parent maps to UNKNOWN).
    """
    import base64 as _b64
    import sys as _sys
    try:
        raw_in = _sys.stdin.buffer.read(TRANSPORT_STDIN_MAX_BYTES + 1)
    except OSError:
        _sys.stdout.write(json.dumps({"ok": False, "code": "unknown"}))
        return 0
    if not raw_in or len(raw_in) > TRANSPORT_STDIN_MAX_BYTES:
        _sys.stdout.write(json.dumps({"ok": False, "code": "usage"}))
        return 0
    try:
        env = json.loads(raw_in.decode("utf-8"))
    except (UnicodeDecodeError, ValueError):
        _sys.stdout.write(json.dumps({"ok": False, "code": "usage"}))
        return 0
    if not isinstance(env, dict):
        _sys.stdout.write(json.dumps({"ok": False, "code": "usage"}))
        return 0
    backend_url = env.get("backend_url", "")
    payload = env.get("payload", {})
    try:
        timeout_s = float(env.get("timeout_s", 10.0))
    except (TypeError, ValueError):
        _sys.stdout.write(json.dumps({"ok": False, "code": "usage"}))
        return 0
    allow_lb = bool(env.get("allow_http_loopback", False))
    if not isinstance(backend_url, str) or not backend_url or len(backend_url) > 500:
        _sys.stdout.write(json.dumps({"ok": False, "code": "usage"}))
        return 0
    if not isinstance(payload, dict):
        _sys.stdout.write(json.dumps({"ok": False, "code": "usage"}))
        return 0
    timeout_s = max(0.2, min(float(timeout_s), 30.0))
    try:
        validate_backend_url(backend_url, allow_http_loopback=allow_lb)
    except (CoordinatorError, me_setup.SetupError):
        _sys.stdout.write(json.dumps({"ok": False, "code": "usage"}))
        return 0
    try:
        status, raw = _do_transport_once(
            backend_url=backend_url, payload=payload, timeout_s=timeout_s)
    except ActivationError as exc:
        msg = str(exc)
        if "redirect refused" in msg:
            _sys.stdout.write(json.dumps({"ok": False, "code": "redirect"}))
        elif "exceeds 64 KiB" in msg:
            _sys.stdout.write(json.dumps({"ok": False, "code": "oversize"}))
        else:
            _sys.stdout.write(json.dumps({"ok": False, "code": "unknown"}))
        return 0
    except CoordinatorError:
        _sys.stdout.write(json.dumps({"ok": False, "code": "usage"}))
        return 0
    except Exception:
        _sys.stdout.write(json.dumps({"ok": False, "code": "unknown"}))
        return 0
    try:
        body_b64 = _b64.b64encode(bytes(raw)).decode("ascii")
    except (ValueError, TypeError):
        _sys.stdout.write(json.dumps({"ok": False, "code": "unknown"}))
        return 0
    out = json.dumps({"ok": True, "status": int(status), "body_b64": body_b64})
    if len(out.encode("utf-8")) > TRANSPORT_STDOUT_MAX_BYTES:
        _sys.stdout.write(json.dumps({"ok": False, "code": "oversize"}))
        return 0
    _sys.stdout.write(out)
    return 0


def post_activate(*, backend_url: str, payload: dict,
                   timeout_ms: int) -> tuple[int, bytes]:
    """Single ticket-only POST with a HARD whole-request TOTAL deadline.

    The monotonic clock starts BEFORE spawn and covers child startup +
    DNS/connect/headers/body: the parent kills/reaps the isolated child at
    the deadline (no threads, no retries, no proxy). Returns (status, bounded
    body) for any completed HTTP response (201 AND error statuses share the
    uniform 64 KiB cap). Transport/timeout/oversize failures raise
    ActivationError(unknown_outcome=True); redirect refusal raises a known
    ActivationError. No exception or body content is echoed (generic messages
    only, so arbitrary secrets can never leak to logs).
    """
    import base64 as _b64
    import subprocess as _sp
    import time as _time
    try:
        total_s = int(timeout_ms) / 1000.0
    except (TypeError, ValueError):
        raise CoordinatorError("invalid timeout")
    if not (REQUEST_TIMEOUT_MIN_MS <= int(timeout_ms) <= REQUEST_TIMEOUT_MAX_MS):
        raise CoordinatorError(
            f"--timeout-ms must be {REQUEST_TIMEOUT_MIN_MS}..{REQUEST_TIMEOUT_MAX_MS}")
    try:
        envelope = json.dumps({"backend_url": backend_url, "payload": payload,
                               "timeout_s": float(total_s),
                               "allow_http_loopback": True}).encode("utf-8")
    except (TypeError, ValueError):
        raise CoordinatorError("cannot encode activation request")
    if len(envelope) > TRANSPORT_STDIN_MAX_BYTES:
        raise CoordinatorError("cannot encode activation request")
    # Hard deadline starts BEFORE spawn so child startup is charged.
    t0 = _time.monotonic()
    deadline = t0 + total_s
    proc = None
    try:
        proc = _sp.Popen(
            [__import__("sys").executable, str(Path(__file__).resolve()),
             TRANSPORT_HELPER_FLAG],
            stdin=_sp.PIPE, stdout=_sp.PIPE, stderr=_sp.DEVNULL,
            env=_transport_child_env(), close_fds=True)
    except OSError:
        raise ActivationError(
            "activation transport failed with UNKNOWN server outcome; do NOT "
            "retry the same ticket. Mint a FRESH owner recovery ticket "
            "(existingHomeId) and redeem once.",
            unknown_outcome=True)
    try:
        remaining = deadline - _time.monotonic()
        if remaining <= 0:
            raise ActivationError(
                "activation timed out (whole-request budget exceeded) with "
                "UNKNOWN server outcome; do NOT retry the same ticket. Mint a "
                "FRESH owner recovery ticket (existingHomeId) and redeem once.",
                unknown_outcome=True)
        try:
            out, _ = proc.communicate(input=envelope, timeout=remaining)
        except _sp.TimeoutExpired:
            try:
                proc.kill()
            except OSError:
                pass
            try:
                proc.wait(timeout=5)
            except OSError:
                pass
            raise ActivationError(
                "activation timed out (whole-request budget exceeded) with "
                "UNKNOWN server outcome; do NOT retry the same ticket. Mint a "
                "FRESH owner recovery ticket (existingHomeId) and redeem once.",
                unknown_outcome=True)
        except (OSError, ValueError):
            raise ActivationError(
                "activation transport failed with UNKNOWN server outcome; do NOT "
                "retry the same ticket. Mint a FRESH owner recovery ticket "
                "(existingHomeId) and redeem once.",
                unknown_outcome=True)
        try:
            rc = proc.wait(timeout=5)
        except OSError:
            rc = proc.returncode
        if rc is None:
            try:
                proc.kill()
            except OSError:
                pass
            raise ActivationError(
                "activation transport failed with UNKNOWN server outcome; do NOT "
                "retry the same ticket. Mint a FRESH owner recovery ticket "
                "(existingHomeId) and redeem once.",
                unknown_outcome=True)
        if out is None:
            out = b""
        if len(out) > PARENT_STDOUT_CAP_BYTES:
            raise ActivationError(
                "backend response exceeds 64 KiB; refusing to parse with UNKNOWN "
                "persistence outcome; do NOT replay this ticket. Mint a FRESH "
                "owner recovery ticket and redeem once.",
                unknown_outcome=True)
        try:
            doc = json.loads((out or b"").decode("utf-8"))
        except (UnicodeDecodeError, ValueError):
            raise ActivationError(
                "activation transport failed with UNKNOWN server outcome; do NOT "
                "retry the same ticket. Mint a FRESH owner recovery ticket "
                "(existingHomeId) and redeem once.",
                unknown_outcome=True)
        if not isinstance(doc, dict):
            raise ActivationError(
                "activation transport failed with UNKNOWN server outcome; do NOT "
                "retry the same ticket. Mint a FRESH owner recovery ticket "
                "(existingHomeId) and redeem once.",
                unknown_outcome=True)
        if doc.get("ok") is True:
            try:
                status = int(doc.get("status", 0))
                raw = _b64.b64decode(doc.get("body_b64", ""), validate=True)
            except (ValueError, TypeError):
                raise ActivationError(
                    "activation transport failed with UNKNOWN server outcome; do NOT "
                    "retry the same ticket. Mint a FRESH owner recovery ticket "
                    "(existingHomeId) and redeem once.",
                    unknown_outcome=True)
            if len(raw) > RESPONSE_MAX_BYTES:
                raise ActivationError(
                    "backend response exceeds 64 KiB; refusing to parse with UNKNOWN "
                    "persistence outcome; do NOT replay this ticket. Mint a FRESH "
                    "owner recovery ticket and redeem once.",
                    unknown_outcome=True)
            return status, bytes(raw)
        code = str(doc.get("code", "unknown"))
        if code == "redirect":
            raise ActivationError(
                "backend redirect refused (redirects are failures; check "
                "backend_url; no credentials forwarded)")
        if code == "oversize":
            raise ActivationError(
                "backend response exceeds 64 KiB; refusing to parse with UNKNOWN "
                "persistence outcome; do NOT replay this ticket. Mint a FRESH "
                "owner recovery ticket and redeem once.",
                unknown_outcome=True)
        raise ActivationError(
            "activation transport failed with UNKNOWN server outcome; do NOT "
            "retry the same ticket. Mint a FRESH owner recovery ticket "
            "(existingHomeId) and redeem once.",
            unknown_outcome=True)
    finally:
        if proc is not None:
            try:
                if proc.poll() is None:
                    try:
                        proc.kill()
                    except OSError:
                        pass
                    try:
                        proc.wait(timeout=5)
                    except OSError:
                        pass
            except OSError:
                pass
            for stream in (proc.stdin, proc.stdout, proc.stderr):
                try:
                    if stream is not None:
                        stream.close()
                except OSError:
                    pass


def validate_activation_response(body: dict, *, own_id: str,
                                 sent_hint: str) -> dict:
    """Validate the 201 activation body identity/types. Raises on mismatch."""
    if not isinstance(body, dict):
        raise ActivationError("backend activation reply is not a JSON object")
    home_id = body.get("homeId")
    installation_id = body.get("installationId")
    home_token = body.get("homeToken")
    endpoint_hint = body.get("endpointHint")
    protocol_version = body.get("protocolVersion")
    mode = body.get("mode")
    if not isinstance(home_id, str) or not HOME_ID_RE.match(home_id):
        raise ActivationError("backend reply has invalid homeId")
    if installation_id != own_id:
        raise ActivationError(
            "backend reply installationId does not match this home "
            "(wrong_home); refusing to persist")
    if not isinstance(home_token, str) or not HOME_TOKEN_RE.match(home_token):
        raise ActivationError("backend reply has invalid homeToken shape")
    if not isinstance(endpoint_hint, str) or not endpoint_hint:
        raise ActivationError("backend reply has invalid endpointHint")
    if endpoint_hint != sent_hint:
        raise ActivationError(
            "backend reply endpointHint does not match the locally configured "
            "public URL; refusing to persist")
    if protocol_version != PROTOCOL_VERSION:
        raise ActivationError(
            f"backend reply protocolVersion must be {PROTOCOL_VERSION!r}")
    if mode not in ("new", "recovery"):
        raise ActivationError("backend reply has invalid mode")
    return {"homeId": home_id, "installationId": installation_id,
            "homeToken": home_token, "endpointHint": endpoint_hint,
            "protocolVersion": protocol_version, "mode": mode}


def preflight_destination(path: Path) -> None:
    """Fail fast BEFORE the fetch when safe storage is impossible."""
    if "\0" in str(path):
        raise CoordinatorError("credentials destination contains NUL")
    parent = path.parent
    try:
        parent.mkdir(parents=True, exist_ok=True)
    except OSError as exc:
        raise CoordinatorError(f"credentials parent not creatable: {exc}")
    try:
        if os.path.islink(path) or (path.parent / path.name).is_symlink():
            raise CoordinatorError(
                "credentials destination must not be a symlink")
    except OSError as exc:
        raise CoordinatorError(f"cannot stat credentials destination: {exc}")
    if path.exists() and not path.is_file():
        raise CoordinatorError("credentials destination exists and is not a file")
    probe = parent / (".write-probe-" + str(os.getpid()))
    try:
        probe.write_text("ok", encoding="utf-8")
        probe.unlink(missing_ok=True)
    except OSError as exc:
        raise CoordinatorError(f"credentials parent not writable: {exc}")
    try:
        mode = stat.S_IMODE(os.stat(parent).st_mode & 0o777)
        if mode != 0o700:
            try:
                os.chmod(parent, 0o700)
            except OSError as exc:
                raise CoordinatorError(
                    f"credentials parent mode {oct(mode)} cannot be set to 0700: {exc}")
    except OSError as exc:
        raise CoordinatorError(f"cannot stat credentials parent: {exc}")


def persist_credentials_file(path: Path, *, backend_url: str,
                             home_id: str, installation_id: str,
                             home_token: str,
                             endpoint_hint: str) -> None:
    """Atomically write the EXACT home-coordinator-v1 file (0600, no symlink).

    Raises ActivationError when storage fails. Callers treat a post-201
    storage failure as a lost credential: the server rotated/issued a token
    this home never stored, so recovery requires a FRESH ticket (rotation
    invalidates the lost one).
    """
    if os.path.islink(path):
        raise ActivationError(
            "refusing to write: credentials destination is a symlink "
            "(lost credential after consume: mint a FRESH owner recovery "
            "ticket and redeem once; never replay this ticket)")
    parent = path.parent
    try:
        parent.mkdir(parents=True, exist_ok=True)
        os.chmod(parent, 0o700)
    except OSError:
        raise ActivationError(
            "cannot prepare credentials parent (lost credential after "
            "consume: the server may have issued a token never stored "
            "locally; mint a FRESH owner recovery ticket and redeem once; "
            "never replay this ticket)")
    doc = {
        "protocol": PROTOCOL,
        "backend_url": backend_url,
        "home_id": home_id,
        "installation_id": installation_id,
        "home_token": home_token,
        "endpoint_hint": endpoint_hint,
        "protocol_version": PROTOCOL_VERSION,
    }
    text = json.dumps(doc, indent=2, sort_keys=True) + "\n"
    if len(text.encode("utf-8")) > FILE_MAX_BYTES:
        raise ActivationError("credential document exceeds 16 KiB; refusing")
    fd, tmp = tempfile.mkstemp(dir=str(parent), prefix=path.name + ".")
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as f:
            f.write(text)
            try:
                f.flush()
                os.fsync(f.fileno())
            except OSError:
                pass
        os.chmod(tmp, 0o600)
        if os.path.islink(path):
            raise ActivationError(
                "refusing to write: destination became a symlink "
                "(lost credential after consume: mint a FRESH owner recovery "
                "ticket and redeem once; never replay this ticket)")
        os.replace(tmp, path)
        os.chmod(path, 0o600)
        try:
            dirfd = os.open(parent, os.O_DIRECTORY)
        except OSError:
            dirfd = None
        if dirfd is not None:
            try:
                os.fsync(dirfd)
            except OSError:
                pass
            finally:
                os.close(dirfd)
    except ActivationError:
        try:
            os.unlink(tmp)
        except OSError:
            pass
        raise
    except OSError:
        try:
            os.unlink(tmp)
        except OSError:
            pass
        raise ActivationError(
            "cannot store credentials (lost credential after consume: the "
            "server may have issued a token never stored locally; mint a "
            "FRESH owner recovery ticket and redeem once; never replay this "
            "ticket)")
    # Post-write gates: regular file, owner-only, exact schema re-read.
    # All fire after a consumed 201, so every message carries the FRESH
    # recovery guidance (never a same-ticket retry).
    try:
        if os.path.islink(path):
            raise ActivationError(
                "stored file is a symlink; refusing (lost credential: mint a "
                "FRESH owner recovery ticket and redeem once)")
        st = os.stat(path)
        if not stat.S_ISREG(st.st_mode):
            raise ActivationError(
                "stored credentials path is not a regular file "
                "(lost credential: mint a FRESH owner recovery ticket and "
                "redeem once)")
        if st.st_mode & 0o077:
            raise ActivationError(
                "stored credentials file is not owner-only (0600) "
                "(lost credential: mint a FRESH owner recovery ticket and "
                "redeem once)")
        if st.st_size <= 0 or st.st_size > FILE_MAX_BYTES:
            raise ActivationError(
                "stored credentials file has invalid size "
                "(lost credential: mint a FRESH owner recovery ticket and "
                "redeem once)")
    except OSError:
        raise ActivationError(
            "cannot verify stored credentials (lost credential: mint a FRESH "
            "owner recovery ticket and redeem once)")


def load_status_record(path: Path, *, expected_installation_id: str = "",
                       allow_http_loopback: bool = False) -> tuple[dict | None, str | None]:
    """Validate the persisted file like H8. Returns (record, error_code)."""
    try:
        if not path.is_absolute():
            return None, "invalid_credentials_path"
        if os.path.islink(path):
            return None, "invalid_credentials_file"
        try:
            st = os.stat(path)
        except OSError:
            return None, "credentials_unreadable"
        if not stat.S_ISREG(st.st_mode):
            return None, "invalid_credentials_file"
        if st.st_size <= 0 or st.st_size > FILE_MAX_BYTES:
            return None, "invalid_credentials_file"
        if st.st_mode & 0o077:
            return None, "invalid_credentials_permissions"
        try:
            parsed = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError, UnicodeDecodeError):
            return None, "invalid_credentials_format"
        if not isinstance(parsed, dict):
            return None, "invalid_credentials_format"
        if set(parsed.keys()) != set(EXPECTED_FILE_KEYS):
            return None, "invalid_credentials_format"
        for key in EXPECTED_FILE_KEYS:
            if not isinstance(parsed[key], str):
                return None, "invalid_credentials_format"
        if parsed["protocol"] != PROTOCOL:
            return None, "invalid_credentials_format"
        if parsed["protocol_version"] != PROTOCOL_VERSION:
            return None, "invalid_credentials_format"
        if not HOME_ID_RE.match(parsed["home_id"]):
            return None, "invalid_credentials_format"
        if not INSTALLATION_ID_RE.match(parsed["installation_id"]):
            return None, "invalid_credentials_format"
        if not HOME_TOKEN_RE.match(parsed["home_token"]):
            return None, "invalid_credentials_format"
        try:
            me_setup.validate_https_url(
                parsed["backend_url"], field="backend_url",
                allow_http_loopback=allow_http_loopback)
            me_setup.validate_https_url(
                parsed["endpoint_hint"], field="endpoint_hint",
                allow_http_loopback=allow_http_loopback)
        except me_setup.SetupError:
            return None, "invalid_credentials_format"
        if expected_installation_id and parsed["installation_id"] != expected_installation_id:
            return None, "wrong_home"
        return parsed, None
    except OSError:
        return None, "credentials_unreadable"


# --- lifecycle entry points (called by me_lifecycle coordinator CLI) ---------

def do_prepare(data_dir: Path, cfg: dict, *, public_url: str = "",
               backend_url: str = "", credentials_file: str = "",
               allow_http_loopback: bool = False,
               update_config: bool = True) -> int:
    """Record the authoritative install + local public URL (no network)."""
    try:
        allow_lb = bool(allow_http_loopback) or allow_http_loopback_effective(
            (cfg.get("coordinator", {}) or {}))
        resolved_public = resolve_public_url(cfg, explicit=public_url)
        resolved_public = validate_endpoint_hint(
            resolved_public, allow_http_loopback=allow_lb)
        if backend_url:
            backend_url = validate_backend_url(
                backend_url, allow_http_loopback=allow_lb)
        cred_path = credentials_file_for(cfg, data_dir, explicit=credentials_file)
        installation_id = own_installation_id(data_dir, cfg)
        preflight_destination(cred_path)
    except (CoordinatorError, me_setup.SetupError) as exc:
        err(f"error: {me_setup.redact(str(exc))}")
        return 2
    if update_config:
        try:
            fresh = me_setup.load_config(data_dir)
            coord = dict(fresh.get("coordinator", {}) or {})
            coord.update({
                "backend_url": backend_url or str(coord.get("backend_url", "") or ""),
                "public_home_url": resolved_public,
                "credentials_file": str(cred_path),
                "allow_http_loopback": allow_lb,
            })
            fresh["coordinator"] = coord
            fresh["updated_at"] = __import__("datetime").datetime.now(
                __import__("datetime").timezone.utc).isoformat()
            me_setup.write_atomic(
                me_setup.config_path(data_dir),
                json.dumps(fresh, indent=2, sort_keys=True) + "\n")
            env_text = me_setup.render_service_env(
                db_path=Path(fresh["service"]["db_path"]),
                host=fresh["service"]["host"],
                port=int(fresh["service"]["port"]),
                models=fresh.get("models"),
                coordinator=fresh.get("coordinator"),
                notifications=fresh.get("notifications"))
            me_setup.write_atomic(data_dir / "config" / "service.env", env_text)
        except (OSError, me_setup.SetupError, KeyError, ValueError) as exc:
            err(f"error: cannot record coordinator prepare: {me_setup.redact(str(exc))}")
            return 1
    log(f"coordinator prepare ok: installation_id={installation_id}")
    log("coordinator prepare ok: public URL recorded (see config coordinator.public_home_url); "
        "backend ticket still required via `coordinator activate` (STDIN only)")
    return 0


def do_activate(data_dir: Path, cfg: dict, *, timeout_ms: int = REQUEST_TIMEOUT_DEFAULT_MS,
                allow_http_loopback: bool = False) -> int:
    """Redeem the STDIN ticket once and persist the private file."""
    if not (REQUEST_TIMEOUT_MIN_MS <= int(timeout_ms) <= REQUEST_TIMEOUT_MAX_MS):
        err(f"error: --timeout-ms must be {REQUEST_TIMEOUT_MIN_MS}..{REQUEST_TIMEOUT_MAX_MS}")
        return 2
    try:
        ticket = parse_ticket_stdin()
    except CoordinatorError as exc:
        err(f"error: {exc}")
        return 2
    ticket_backend = _ticket_str(ticket, "backend_url", "backendUrl")
    ticket_id = _ticket_str(ticket, "ticketId", "ticket_id")
    secret = _ticket_str(ticket, "activationSecret", "activation_secret", "ticketSecret")
    ticket_install = _ticket_str(ticket, "installationId", "installation_id")
    if not ticket_backend:
        err("error: ticket JSON is missing backend_url")
        return 2
    if not ticket_id:
        err("error: ticket JSON is missing ticketId")
        return 2
    if not secret:
        err("error: ticket JSON is missing activationSecret")
        return 2
    if not ticket_install:
        err("error: ticket JSON is missing installationId")
        return 2
    try:
        allow_lb = bool(allow_http_loopback) or allow_http_loopback_effective(
            (cfg.get("coordinator", {}) or {}))
        # Authoritative install BEFORE any network: mismatch never fetches,
        # so the ticket stays usable.
        installation_id = own_installation_id(data_dir, cfg)
        if ticket_install != installation_id:
            err("error: ticket installationId does not match this home "
                "(wrong_home); no request sent, ticket NOT consumed. Mint a "
                "ticket for this installation instead.")
            return 1
        backend_url = validate_backend_url(ticket_backend, allow_http_loopback=allow_lb)
        cfg_backend = str(((cfg.get("coordinator", {}) or {}).get("backend_url")) or "").strip()
        if cfg_backend and cfg_backend.rstrip("/") != backend_url.rstrip("/"):
            err("error: ticket backend_url does not match the locally configured "
                "coordinator.backend_url; refusing (possible misdirection). "
                "Update local config first via `setup --coordinator-backend-url`.")
            return 1
        # Endpoint comes from LOCAL setup config only; never from the ticket.
        endpoint_hint = validate_endpoint_hint(
            resolve_public_url(cfg), allow_http_loopback=allow_lb)
        cred_path = credentials_file_for(cfg, data_dir)
        preflight_destination(cred_path)
    except (CoordinatorError, me_setup.SetupError) as exc:
        err(f"error: {me_setup.redact(str(exc))}")
        return 2
    payload = {"ticketId": ticket_id, "activationSecret": secret,
               "installationId": installation_id, "endpointHint": endpoint_hint,
               "protocolVersion": PROTOCOL_VERSION}
    try:
        status, raw = post_activate(backend_url=backend_url, payload=payload,
                                    timeout_ms=int(timeout_ms))
    except ActivationError as exc:
        err(f"error: {me_setup.redact(str(exc))}")
        if exc.unknown_outcome:
            err("recovery: ask the owner account to mint a FRESH recovery ticket "
                "(POST /v1/homes/activation-tickets { installationId, "
                "existingHomeId }) and redeem it once here; rotation "
                "invalidates any lost credential. NEVER replay this ticket.")
        return 1
    if status != 201:
        # Generic status codes only. The backend error body is untrusted and
        # may echo secrets; it is parsed only to confirm JSON shape and NEVER
        # printed, logged, or redacted-echoed (redact cannot know an arbitrary
        # 256-bit base64 secret).
        try:
            if raw:
                parsed = json.loads(raw.decode("utf-8") or "{}")
                if not isinstance(parsed, dict):
                    parsed = {}
            else:
                parsed = {}
        except (json.JSONDecodeError, UnicodeDecodeError, ValueError):
            parsed = {}
        _ = parsed  # shape-checked only; content never surfaced
        if status == 410:
            err("error: ticket expired or already used (410); it is consumed. "
                "Mint a FRESH owner recovery ticket (existingHomeId) and redeem once.")
        elif status in (400, 403):
            err(f"error: backend rejected the request ({status}); ticket NOT "
                "consumed (validation runs before consume). Fix the request "
                "and retry with the SAME ticket.")
        elif status == 429:
            err("error: backend rate-limited (429); ticket outcome UNKNOWN. "
                "Prefer a FRESH recovery ticket over replaying this one.")
        else:
            err(f"error: backend activation failed ({status}) with UNKNOWN "
                "persistence outcome; do NOT replay this ticket. Mint a FRESH "
                "owner recovery ticket and redeem once.")
        return 1
    try:
        body = json.loads(raw.decode("utf-8"))
    except (json.JSONDecodeError, UnicodeDecodeError):
        err("error: backend 201 reply is not valid JSON with UNKNOWN local "
            "outcome; do NOT replay the ticket. Mint a FRESH owner recovery "
            "ticket and redeem once.")
        return 1
    try:
        valid = validate_activation_response(body, own_id=installation_id,
                                             sent_hint=endpoint_hint)
    except ActivationError as exc:
        err(f"error: {me_setup.redact(str(exc))} (ticket is consumed server-side; "
            "mint a FRESH owner recovery ticket and redeem once)")
        return 1
    try:
        persist_credentials_file(cred_path, backend_url=backend_url,
                                 home_id=valid["homeId"],
                                 installation_id=installation_id,
                                 home_token=valid["homeToken"],
                                 endpoint_hint=endpoint_hint)
    except ActivationError as exc:
        # The 201 was consumed server-side but never stored locally: the lost
        # credential cannot be recovered by retrying. Mint a FRESH owner
        # recovery ticket (existingHomeId); NEVER replay this ticket and do
        # NOT retry the same ticket expecting the lost token to reappear.
        err(f"error: {me_setup.redact(str(exc))} (credential lost after "
            "consume: mint a FRESH owner recovery ticket (existingHomeId) "
            "and redeem once; never replay this ticket)")
        return 1
    try:
        fresh = me_setup.load_config(data_dir)
        coord = dict(fresh.get("coordinator", {}) or {})
        coord.update({"enabled": True, "backend_url": backend_url,
                      "public_home_url": endpoint_hint,
                      "credentials_file": str(cred_path),
                      "allow_http_loopback": allow_lb})
        fresh["coordinator"] = coord
        fresh["updated_at"] = __import__("datetime").datetime.now(
            __import__("datetime").timezone.utc).isoformat()
        me_setup.write_atomic(me_setup.config_path(data_dir),
                              json.dumps(fresh, indent=2, sort_keys=True) + "\n")
        env_text = me_setup.render_service_env(
            db_path=Path(fresh["service"]["db_path"]),
            host=fresh["service"]["host"], port=int(fresh["service"]["port"]),
            models=fresh.get("models"), coordinator=fresh.get("coordinator"),
            notifications=fresh.get("notifications"))
        me_setup.write_atomic(data_dir / "config" / "service.env", env_text)
    except (OSError, me_setup.SetupError, KeyError, ValueError) as exc:
        err("warning: credentials stored but config reference update failed "
            f"({me_setup.redact(str(exc))}); set coordinator.enabled + "
            "credentials_file manually, then reload the service")
        return 1
    # Redacted by construction: never token, secret, or file content.
    log(f"coordinator activate ok: mode={valid['mode']} "
        f"home={redact_home_id(valid['homeId'])} installation verified")
    log("service reload required: restart the home (`stop`/`start` or reload "
        "the service unit) so HOME_COORDINATOR_CREDENTIALS_FILE takes effect; "
        "never auto-restarting active jobs here")
    return 0


def describe_status(data_dir: Path, cfg: dict) -> tuple[int, dict]:
    """Redacted coordinator state for status/check. Never token/secret/path content."""
    coord = (cfg.get("coordinator", {}) or {}) if isinstance(cfg, dict) else {}
    enabled = bool(coord.get("enabled", False))
    allow_lb = allow_http_loopback_effective(coord)
    # Authoritative DB id only. A pre-start config reservation must NEVER be
    # reported as verified: status/check fail closed without throwing.
    db_path = authoritative_db_path(data_dir, cfg)
    db_id = me_setup.read_db_installation_id(db_path)
    db_missing = not bool(db_id)
    installation_id = db_id or ""
    cred_path = None
    try:
        cred_path = credentials_file_for(cfg, data_dir)
    except CoordinatorError:
        cred_path = None
    record, code = (None, "missing_credentials_file")
    if cred_path is not None:
        record, code = load_status_record(
            cred_path, expected_installation_id=installation_id,
            allow_http_loopback=allow_lb)
        # Without a DB identity there is nothing to verify against: a file
        # matching the config reservation alone is not proof.
        if db_missing:
            if record is not None:
                code = "missing_home_database"
            record = None
    verified = bool(record) and not db_missing
    if db_missing and enabled:
        code = code if code not in (None, "missing_credentials_file") else "missing_home_database"
    state = {"enabled": enabled,
             "configured": cred_path is not None,
             "config_error": None,
             "status": "disabled",
             "home": redact_home_id(record["home_id"]) if record else None,
             "installation_verified": verified,
             "backend_configured": bool((coord.get("backend_url") or "").strip()),
             "public_url_configured": bool((coord.get("public_home_url") or "").strip()
                                           or str((cfg.get("tunnel", {}) or {}).get("hostname", "") or "").strip())}
    if not enabled:
        state["status"] = "disabled"
    elif verified:
        state["status"] = "configured"
    else:
        state["status"] = "config_error"
        state["config_error"] = code
    return 0, state


def do_status(data_dir: Path) -> int:
    try:
        data_dir, cfg = me_setup.resolve_data_dir(data_dir), None
        cfg = me_setup.load_config(data_dir)
    except me_setup.SetupError as exc:
        err(f"error: {exc}")
        return 2
    _, state = describe_status(data_dir, cfg)
    # Redacted: home id shown truncated, never token/secret/path content.
    out_lines = [
        f"enabled: {str(state['enabled']).lower()}",
        f"status: {state['status']}",
        f"installation_verified: {str(state['installation_verified']).lower()}",
        f"home: {state['home'] or 'null'}",
        f"backend_configured: {str(state['backend_configured']).lower()}",
        f"public_url_configured: {str(state['public_url_configured']).lower()}",
    ]
    if state.get("config_error"):
        out_lines.append("config_error: configuration_error "
                         "(see `coordinator check`; fix file/config, no network attempted)")
    print("\n".join(out_lines), flush=True)
    if state["status"] == "disabled":
        err("note: coordinator disabled (default, zero network); "
            "`prepare` + `activate` then reload the service to enable")
    return 0


def do_check(data_dir: Path) -> int:
    """Strict local validation (no network). Exit 0 valid, 1 invalid, 2 usage."""
    try:
        data_dir = me_setup.resolve_data_dir(data_dir)
        cfg = me_setup.load_config(data_dir)
    except me_setup.SetupError as exc:
        err(f"error: {exc}")
        return 2
    rc, state = describe_status(data_dir, cfg)
    _ = rc
    coord = cfg.get("coordinator", {}) or {}
    ok = True
    if not coord.get("enabled"):
        log("PASS: coordinator disabled (default, zero network)")
        return 0
    for key in ("backend_url", "public_home_url"):
        val = (coord.get(key) or "").strip()
        if val:
            try:
                me_setup.validate_https_url(
                    val, field=f"coordinator.{key}",
                    allow_http_loopback=allow_http_loopback_effective(coord))
                log(f"PASS: coordinator.{key} valid")
            except me_setup.SetupError as exc:
                log(f"FAIL: coordinator: {exc}")
                ok = False
        elif key == "public_home_url":
            log("FAIL: coordinator enabled but public_home_url is empty")
            ok = False
    if state["status"] == "configured" and state["installation_verified"]:
        log("PASS: credentials file valid (0600, exact schema, installation match)")
    else:
        log(f"FAIL: credentials file: {state.get('config_error') or 'missing/invalid'} "
            "(no network attempted; fix file/config or re-activate with a fresh ticket)")
        ok = False
    return 0 if ok else 1


if __name__ == "__main__":
    # Isolated transport child entry: same-file reuse of the validated
    # transport (no source copy). Parent spawns:
    #   sys.executable me_coordinator.py --transport-helper
    # with the secret envelope on stdin and reads the bounded reply on stdout.
    import sys as _sys_main
    if len(_sys_main.argv) == 2 and _sys_main.argv[1] == TRANSPORT_HELPER_FLAG:
        _sys_main.exit(_transport_child_main())
