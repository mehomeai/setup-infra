# Production tunnel boundary (Cloudflare, named tunnel)

Design boundary for the future production home endpoint. **Nothing here is
provisioned by the dev setup**: `me_setup.py` leaves `tunnel.mode: disabled`,
creates no tunnel, publishes no route, and stores no provider credentials.
This document tells a future production installer what to use and what to
avoid, per `infra-server/docs/connection-and-pairing.md` (read that first).

## Required shape

- **Named tunnel via `cloudflared` outbound connector**, owned by the household's
  own Cloudflare account. The home initiates outbound connections only; no
  inbound firewall hole, no home listener on a public interface.
- **Durable hostname** (e.g. `home.<family-domain>`). Quick Tunnels
  (`trycloudflare.com`) are documented by Cloudflare for development/testing
  only and must never back a household deployment.
- **Protection before route**: create Cloudflare Access protection first, then
  publish the application route. Start closed on failure. If Access is used,
  validate its token at the origin as Cloudflare documents; Access checks do
  **not** replace Me's own paired-device + household/user authorization.
- **Origin scope**: publish only the intended home application gateway. Model,
  database, worker, and management services bind private interfaces. The same
  device/user checks apply to event streams, artifacts, browser previews, and
  uploads — not just chat.
- **Supported provider tooling only**: `cloudflared` releases and Cloudflare
  Zero Trust dashboard/API. No custom tunnel protocol, no ad-hoc signature
  scheme for pairing (use maintained auth libraries + platform key storage).

## Credential separation (normative)

| Credential | Holder | May it reach a phone? | Rotation |
| --- | --- | --- | --- |
| Cloudflare account / API / zone admin | Trusted provisioning only (least privilege) | Never | Independent |
| Tunnel connector credential (`cert.json` / token) | Home connector host only, `secrets/` mode `0600` | Never — not in pairing QR, not an API token | Authenticated rotation |
| Home installation identity | Home service; public parts registered with backend/paired clients | Public identity reference only | Authenticated rotation + recovery |
| Pairing invitation secret | Single-use exchange, setup/authorized admin → phone | Yes (one invitation, short-lived, high-entropy) | Expires/consumed atomically |
| Phone device key / enrollment | That phone (private key stays on device); home stores verifier | Device-bound credential only | Per-device revoke/rotate |
| Home API session token | Authorized phone, audience = that home/API | Short-lived session use | Renew via device credential |

Service tokens (client-ID/secret), if ever used for edge integration, are
per-device scoped, stored, rotated, and revoked per device — never one shared
fleet secret baked into the app. Provider credential headers stay distinct
from home API authorization headers, and secrets never appear in logs.

## Pairing admission without weakening the boundary

A not-yet-paired phone must reach enrollment without already holding the normal
edge credential. Options: backend-mediated enrollment, or a tightly limited
pairing endpoint with its own short-lived admission. Never bypass protection
for the whole home API to make pairing work. Anonymous health responses reveal
only minimal readiness.

## Production installer expectations (future, not claimed)

A production installer built on this boundary must additionally cover: stable
hostname recovery, connector credential rotation, hostname/key rotation that is
itself authenticated, revocation propagation windows (including backend-issued
revocation while the home is offline), offline behavior (honest offline state),
backup/restore of household data, and release compatibility between the
installer, home service, backend, and phone. The dev setup in this repository
claims none of that; it validates prerequisites and writes local config only.

## Two protection modes (S4): phone path vs provider edge path

`tunnel configure` requires one explicit `--protection` mode (default
`home-pairing`, the supported phone flow). Both modes share the named-tunnel
shape above (stable hostname, least-privilege credential file, catch-all 404)
and both fail closed on unknown contracts, non-loopback bindings, unknown or
mixed modes, and configs missing their mode's enforcement markers.

**`home-pairing` (default, phone-compatible).** No Access barrier by design:
cloudflared forwards HTTPS straight to the loopback Me Home API, and the home
enforces the actual protection — one-time invitation enrollment, per-device
revocable credentials/session auth on every private route, H5 per-IP failure
budgets on the public pair/session endpoints (`429` + `Retry-After`), minimal
anonymous health only. This is the mode the current phone (Me per-device/
session credentials, no Access JWT) can actually use. Pairing admission is
honestly `manual-external`: the operator delivers each one-time invitation
out-of-band; no automated backend-mediated enrollment is claimed.

**`cloudflare-access` (optional provider edge path, NOT phone-app-ready).**
Requires `--access-team` + `--access-aud` and emits the official
`originRequest.access` block (required/teamName/audTag), so the connector
validates the Access JWT before proxying. Native phone clients cannot complete
Access login, so do not pretend this mode works with the current phone; edge
auth here is explicitly manual/external, and per-device home auth stays
mandatory regardless.

`scripts/me_lifecycle.py tunnel` is a real configuration/launch adapter over an
existing `cloudflared` binary plus an externally supplied least-privileged
credential file. It writes config and optionally launches the connector; it
never provisions accounts, hostnames, or DNS.

```yml
# Generated by setup-infra tunnel configure (rerunnable). Shown: the
# cloudflare-access rendering. home-pairing renders the same file WITHOUT
# the access: block (plus a "# Protection mode: home-pairing" marker).
tunnel: <Tunnel-UUID>
credentials-file: /path/<Tunnel-UUID>.json   # PATH ONLY, never content
ingress:
  - hostname: home.example.com
    service: http://127.0.0.1:7070
    originRequest:
      connectTimeout: 10s
      access:                              # connector-enforced (verified
        required: true                     # against provider docs)
        teamName: <Zero-Trust-team>
        audTag:
          - <Access-application-AUD-tag>
  - service: http_status:404               # catch-all stays last
```

This is the official `originRequest.access` schema (provider origin-parameters
reference): with `required: true`, the connector validates the Access JWT
(`Cf-Access-Jwt-Assertion` header) against the team + AUD tag(s) before
proxying to the origin. Recording a team name without this block was never
enforcement; `tunnel configure` now refuses without `--access-team` plus at
least one `--access-aud` tag (get the AUD tag from the Access application
overview), and `tunnel run` refuses any config file missing these markers.
Edge Access app + policy must still exist before the route carries traffic,
and per-device home auth stays mandatory regardless of edge admission.

Pairing admission is honestly `manual-external` until a backend-mediated flow
exists: enrollment of each phone remains a manual, out-of-band operator step
(setup's bootstrap prints the one-time invitation locally). Claiming an
automated backend-mediated enrollment that is not implemented would be a fake;
the config records the declared intent plus its manual status.

Guarantees: credential content is never logged, never in argv (only `--config`
path), never in a phone QR; `tunnel run` without a configured tunnel or
without `cloudflared` exits `4` (parked) instead of inventing connectivity;
no Quick Tunnel support. Exact commands once the user provisions credentials:

```sh
chmod 0600 secrets/tunnel-cred.json   # externally provisioned, least-privilege
python3 scripts/me_lifecycle.py tunnel configure --hostname home.example.com \
  --credential-file secrets/tunnel-cred.json \
  --access-team myteam --access-aud <AUD-tag-from-Access-app> \
  --pairing-admission manual-external
python3 scripts/me_lifecycle.py tunnel status   # shows protection + validate hints
python3 scripts/me_lifecycle.py tunnel run      # needs cloudflared; else exit 4
```

## Parked for the user (credential-dependent live checks)

Deliberately NOT done in this task, no exceptions: creating a Cloudflare
account/team/tunnel/hostname, downloading or updating `cloudflared`, running a
live tunneled connection, validating Access token enforcement end to end, and
the mobile Expo install / web/native builds plus browser/model binary
downloads (all parked under the coordinator's disk-capacity constraint).
When the user provisions credentials, `tunnel configure` + `tunnel run` +
`tunnel status` are the exact commands to exercise; until then the adapter is
verified by its fail-closed unit tests only.
