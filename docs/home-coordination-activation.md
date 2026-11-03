# S7 cloud-coordination activation (setup-infra handoff)

Setup-side activation for `home-coordinator-v1` (file) over `home-api-v1`
(wire). Authoritative contracts live with their owners — this file only tells
the operator what to run, in what order, and what must stay manual:

- Wire (backend owns): `backend-server/docs/home-activation-v1.md` (B7:
  ticket-only `POST /v1/homes/activate`, recovery, error codes).
- Home file + heartbeat loop (home owns):
  `infra-server/contracts/home-coordination-v1.md` (exact file schema, env
  keys, redacted status) and `infra-server/docs/home-h8-handoff.md` (what H8
  runs automatically once the file exists).
- Phone pairing + notifications (homes owns): `infra-server/contracts/home-api-v1.md`,
  `infra-server/contracts/home-notifications-v1.md` (H7, exact contract).

S7 never duplicates the H8 heartbeat loop, never writes outside
`setup-infra`, never commits/deploys, never downloads. Defaults are disabled
with zero outbound network. Secrets (`activationSecret`, `home_token`,
`HOME_EXPO_ACCESS_TOKEN`) are never persisted, never logged, never shipped
to the phone.

## Exact operator sequence

`DIR` below is the home data dir (default `~/.local/share/me-home`).

```sh
# 0. Provision + let the home database mint its authoritative identity.
python3 scripts/me_setup.py setup --data-dir DIR --port 7070
python3 scripts/me_lifecycle.py start --data-dir DIR     # DB mints installation_id; config adopts it
python3 scripts/me_lifecycle.py stop --data-dir DIR

# 1. Manual hardware/tunnel gate (see below): provision the named tunnel,
#    then record it locally (config only, starts nothing).
chmod 0600 DIR/secrets/tunnel-cred.json   # externally provisioned, least-privilege
python3 scripts/me_lifecycle.py tunnel configure --data-dir DIR \
  --hostname home.example.com --credential-file DIR/secrets/tunnel-cred.json

# 2. Owner phone mints the one-time activation ticket (owner account auth;
#    a dev fixture credential mints test tickets ONLY in synthetic loopback
#    tests — never a production identity):
#      POST {backend}/v1/homes/activation-tickets
#        { "installationId": "<from `config-show`>", "displayName": "Cabin Home" }   # new, or
#        { "installationId": "<same>", "existingHomeId": "home_..." }                 # recovery
#    Copy the one-time JSON { backend_url, ticketId, activationSecret,
#    installationId, mode, homeId?, expiresAt } to the home operator.
#    Never an account JWT, never a provider secret.

# 3. Prepare: authoritative install + locally configured public URL.
#    No network, no secrets. endpointHint comes from HERE, never from a ticket.
python3 scripts/me_lifecycle.py coordinator prepare --data-dir DIR \
  [--public-url https://home.example.com]   # else tunnel hostname; loopback http needs --allow-http-loopback (dev only)

# 4. Activate: single ticket-only POST, ticket JSON via STDIN ONLY
#    (never argv — process listings leak argv; never an account JWT).
python3 scripts/me_lifecycle.py coordinator activate --data-dir DIR \
  [--allow-http-loopback] [--timeout-ms 10000] < ticket.json
#    201 -> persists the EXACT home-coordinator-v1 file (7 keys incl.
#           protocol_version home-api-v1) to DIR/secrets/backend-home-token.json
#           (parent 0700, file 0600, atomic, no symlink). Token/path contents
#           are never printed. Non-secret reference recorded in config.json +
#           config/service.env (HOME_COORDINATOR_CREDENTIALS_FILE).

# 5. Service reload REQUIRED (activate never auto-restarts active jobs —
#    a restart would interrupt running agent work):
python3 scripts/me_lifecycle.py stop --data-dir DIR && python3 scripts/me_lifecycle.py start --data-dir DIR
#    or: regenerate units (`service --format launchd|systemd`) + reload the
#    service manager with the CURRENT config (guard re-checks the restore
#    journal + loopback binding before exec).

# 6. Verify (redacted; never token/secret/path content):
python3 scripts/me_lifecycle.py coordinator status --data-dir DIR
python3 scripts/me_lifecycle.py coordinator check --data-dir DIR
#    Backend discovery (owner account): GET /v1/homes/{homeId}/status -> online:true
#    (the home heartbeats automatically every ~60s; first beat ~1.5s after start).

# 7. Pair phones LOCALLY (trusted invitation, no backend hint):
python3 scripts/me_lifecycle.py bootstrap --data-dir DIR --user alice --format pairing-v1
#    -> home-pairing-v1 JSON { protocol, home_url, installation_id,
#       invitation_id, invitation_secret, user_id, expires_at? } on stdout only.
#    Deliver out-of-band; default raw format is unchanged (backward compatible).
```

## Optional: notifications (H7, default disabled)

```sh
python3 scripts/me_setup.py setup --data-dir DIR --notifications-enabled \
  --expo-project-id "<public-expo-project-id>"
# Public project id is config; the optional provider token stays in the
# operator shell ONLY (never persisted, never logged, never shipped):
export HOME_EXPO_ACCESS_TOKEN='<value>'   # then start / reload the service
python3 scripts/me_lifecycle.py stop --data-dir DIR && python3 scripts/me_lifecycle.py start --data-dir DIR
```

Exact contract: `infra-server/contracts/home-notifications-v1.md`
(metadata-only payloads, fixed `https://exp.host` origin, redirects refused,
per-phone consent + operator opt-in both required). No automatic
third-party resources are created by setup.

## Manual hardware/tunnel gates (never automated by setup)

Deliberately NOT done by any setup command — the operator provisions them
with the provider's own tooling, then records references via `tunnel
configure` / `--public-home-url`:

- A Cloudflare account/team/tunnel/hostname on the household's own domain
  (named tunnel, stable hostname; Quick Tunnels refused), plus the DNS route.
- The least-privileged tunnel connector credential (`chmod 0600`,
  externally created; path only in config, content never logged/never in argv).
- `cloudflared` installed from supported provider tooling (run stays parked
  at exit 4 until present).
- Optional provider edge path (`--protection cloudflare-access`) additionally
  needs the Access application + AUD tag; native phone clients cannot complete
  it — the default `home-pairing` mode is the phone path.
- A reachable backend (`backend_url`, `https://` in production) and the owner
  phone/account that mints tickets.

## Failure handling (do not improvise)

- Wrong installation (`wrong_home`): no request is ever sent; the ticket is
  NOT consumed. Mint a ticket for the correct installation instead.
- Rejected request (`400`/`403`): the ticket is NOT consumed (validation runs
  before consume). Fix the request and retry with the SAME ticket.
- Consumed/expired (`410`): the ticket is burned. Mint a FRESH owner
  recovery ticket (`existingHomeId`) and redeem once. Replaying an old ticket
  reports `410` and MUST NOT resurrect the old credential.
- Unknown redemption outcome (timeout/disconnect after POST): do NOT retry
  the same ticket (replay would report `410` without revealing whether the
  first attempt persisted). Mint a FRESH owner recovery ticket
  (`existingHomeId`) and redeem once; rotation invalidates any lost token.
- Lost credential (file deleted, e.g. full restore, or post-201 storage
  failure): reactivation needed — fresh ticket, same flow. Old tickets replay
  `410`. There is no recovery path that reads a token back out of the
  backend; the server stores sha256 verifiers only.
- Auth `401`/`403` on heartbeats: H8 suspends network until the file changes;
  fix/rotate the file (rotation recovers without restart).
- Transient (`5xx`/`429`/network/bad body/redirect): H8 stays offline and
  reschedules with backoff; private conversations/tasks/pairing keep working.

## File + env reference (non-authoritative summary)

Private file (S7 writes, H8 reads; absolute path outside git/shared config):

```json
{
  "protocol": "home-coordinator-v1",
  "backend_url": "https://backend.example.test",
  "home_id": "home_…",
  "installation_id": "123e4567-…",
  "home_token": "me_home_…",
  "endpoint_hint": "https://home.example.test",
  "protocol_version": "home-api-v1"
}
```

Gates: exact 7 keys, `https:` (or loopback `http:` with explicit
`HOME_COORDINATOR_ALLOW_HTTP_LOOPBACK=1` only), no userinfo/query/fragment,
final component not a symlink, regular file `1..16 KiB`, owner-only mode.
`installation_id` must equal the live home DB id or the coordinator reports
`wrong_home` with zero network. Env: `HOME_COORDINATOR_CREDENTIALS_FILE`
(disabled when unset), `HOME_COORDINATOR_INTERVAL_MS` (`5000..600000`),
`HOME_COORDINATOR_TIMEOUT_MS` (`1000..30000`). `HOME_*` never crosses into
runtime bridge children. Coordinator status is redacted by construction.
