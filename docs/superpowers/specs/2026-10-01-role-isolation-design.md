# Role isolation and per-identity login — design

Status: approved in conversation (single-laptop topology, three live officers).
Authors: project owner + assistant. Supersedes ADR-0046 for the `roles`
deployment; the `combined` deployment and every existing test are unchanged.

## 1. Problem

The M8 console is one browser origin backed by one `web-api` process. Every
officer's unlocked private key sits in one process's memory, every screen
(sender, investigator, officers, attack lab) is reachable from the same tab,
and `/officers/{id}/documents` and `/pages/{n}` check no caller identity.
`demo/pki/` additionally holds the raw private key of every identity and is
mounted into almost every container. The spec (Section 3/14.4) says private
keys never leave the owner's agent and that a `recipient-agent` runs per
officer workstation. Defence-engineer judges will see the gap immediately.

## 2. Goal and success criteria

One laptop, several isolated "workstations". A judge watching a multi-window
demo should be able to *verify*, not take on trust, that:

1. Each officer's console talks to a different backend that holds only that
   officer's key material (`docker exec` proves it).
2. Login is a real cryptographic gate: the Argon2id keystore passphrase.
3. A session for one identity is useless against another identity's backend
   (403) and against routes outside the console's role (404).
4. No container has an internet route; the verifier runs with no network.

Acceptance: `make roles-up` + `make demo-isolation` pass; new negative tests
pass; `make test` stays green; the demo choreography in Section 9 runs
end-to-end in the browser.

Non-goals: real separate hosts, hardware tokens/TOTP, TLS on loopback,
officer-to-officer network segmentation (Docker cannot do this without
breaking the quorum paths — recorded as a residual gap), any protocol change.

## 3. Topology

One image (`traceseal/web-api`), selected by `ROLE`:

| Role | Console host | Holds (private) | Routers |
|---|---|---|---|
| `officer` ×3 (a,b,c; d,e profile-off) | `officer-x.localhost` | own keystore only | session, own `/officers/{id}/*` |
| `command` | `command.localhost` | `sender-1`, `forensics-1` keystores | session, system, ledger, monitor, distribute, investigate, attacklab, roster |
| `authority` | `authority.localhost` | `ca-root` + `admin-1..3` keystores | session, identity, roster, ledger |
| `ops` | `ops.localhost` | nothing | system, ledger, monitor, roster (read-only, no login) |
| `all` | `localhost:8080` | everything (dev) | everything, auth off — current behaviour |

`command` merges sender and investigator because `released_documents` (the
original patch library the investigation aligns against) legitimately lives
in the document owner's process memory; splitting it would force clean
plaintext to disk. Residual: noted in the threat model.

Routing is by **hostname**, not port. Browsers do not isolate cookies by
port, so `:8101`/`:8102` consoles would overwrite each other's login;
`*.localhost` names are distinct origins (cookies, storage, same-origin
policy) and resolve to loopback in Chrome, Edge and Firefox with no hosts
edit. One nginx container keeps the single published loopback port
(ADR-0049 unchanged) and picks the upstream by `server_name`; `localhost:8080`
serves a landing page linking to every console.

## 4. Authentication and sessions

- `POST /session/login {passphrase}`: unlocks this backend's principal's
  keystore (`agent.keystore.unlock_keystore`). `command` unlocks
  `sender-1` and `forensics-1` (same operator passphrase). `authority`
  unlocks the `ca-root` custodian keystore. Success mints a 256-bit random
  token, held in memory, delivered as an `HttpOnly; SameSite=Strict` cookie
  named per identity (`ts_session_<identity>`).
- Idle timeout 5 min, absolute 30 min (env-overridable for rehearsal).
  Expiry and logout drop the token and the in-memory identity.
- Lockout: 5 consecutive failures → exponential backoff (30 s doubling, cap
  5 min), `429` + `Retry-After`. Constant-time token comparison.
- `GET /session` (no auth) returns `{role, identity_id, auth_required,
  authenticated, cert_hash, idle_expires_at, abs_expires_at,
  allowed_screens}`; the UI renders from `allowed_screens`, the server is
  the enforcement point.
- Every non-public route depends on `require_principal`. For officer
  routes the path `officer_id` must equal the configured identity **and** the
  token's principal, else 403. Unknown routes for a role do not exist
  (router not mounted → 404).
- Admin approvals on `authority` take that admin's own keystore passphrase
  in the request body (unlock → sign → discard); no admin key is ever held
  in session memory. This keeps two-person enrolment real.
- Security events (login ok/fail/lockout, logout, expiry, 401, 403) go to a
  per-backend ring buffer (200), exposed to that console only
  (`GET /security/events`). No new ledger record types (protocol untouched).
- `auth_required` defaults to `False` for role `all` and `ops`, `True`
  otherwise; tests exercise both.

Honest limits: sessions live in process memory (restart logs everyone out);
loopback HTTP without TLS; the keystore passphrase is the only factor.

## 5. Key isolation (vault split)

- Provisioning (`make roles-provision`) runs the existing `ca.seed` +
  enrolment ceremony for officers a,b,c in a staging dir, then distributes:
  - `demo/public/registry.json` — public registry, mounted `/pki:ro` (rw
    for `authority` only, which writes it on enrolment finalise).
  - `demo/vault/<id>/<id>.json` for unattended services only
    (`ledger-0..3`, `keyrelease-0..4`), mounted `/vault:ro` with
    `VAULT_DIR=/vault`.
  - Encrypted keystores `demo/keystores/<id>.keystore.json` for every
    interactive principal, each mounted individually into its own backend.
  - Staging with raw private keys is purged by default.
- Code: `VAULT_DIR` (defaults to `PKI_DIR`, preserving every current path and
  test) is honoured by `ledger.main`/`ledger.service`, `keyrelease.main`/
  `keyrelease.service`, and `web_api` settings. Interactive backends obtain
  identities from the unlocked session, never from a raw file.
- Passphrases are distinct per identity, generated with `secrets` at
  provisioning, written only to gitignored `demo/CREDENTIALS.local.txt`;
  nothing in the repo or docs states them.
- `LEDGER_BACKEND=lite` only; the Fabric profile keeps its current layout.

## 6. Enrolment on the authority console

`propose-enrol` currently loads the officer's private key to self-sign the
CSR. In `roles` mode the officer's own console produces it: an authenticated
`POST /officers/{id}/enrolment-request` writes the self-signed CSR
(canonical CBOR) to `demo/enrol-inbox/<id>.csr` (shared dir, officer rw,
authority ro). The authority proposes from the inbox, each of two admins
approves with their own passphrase, the custodian finalises. Officers
enrolled by provisioning show as already active; the flow is the optional
live segment. If the inbox flow slips, provisioning-time enrolment is the
fallback and this section is documented as not delivered.

## 7. UI

Same React bundle; role discovered from `GET /session`.
- `all`: unchanged. Others: login gate, then role-scoped nav.
- Persistent identity bar: identity id, certificate fingerprint, "keys live
  in container `<name>`", lock state, idle countdown, Lock button.
- Per-role accent colour so windows are recognisable at a glance.
- Security-events panel (login/403/lockout) on officer and command consoles.
- Footer states the isolation level truthfully: separate containers with
  disjoint key material on one host, not separate physical machines.

## 8. Deployment

`docker-compose.roles.yml` overlay (compose `!override` for the narrowed
ledger/keyrelease mounts); `web-api` stays defined for `combined` and for
`docker compose run … pytest`. `web/nginx.roles.conf` maps host → upstream.
Memory: only a,b,c start by default; d,e behind profile `officers-extra`.
Make targets: `roles-provision`, `roles-up`, `roles-down`, `demo-isolation`.

`demo-isolation` performs real checks and prints a pass/fail table:
each officer container sees only its own keystore and no raw identity JSON;
no container (except none) has a default route / egress; `ops` holds no
private material; cross-identity token → 403; wrong role route → 404; the
verifier is run with `--network none`.

## 9. Demo choreography (documented in `docs/ROLES_DEMO.md`)

1. Four windows: `command`, `officer-a`, `officer-b`, `ops` on the projector.
2. `make demo-isolation` on a terminal.
3. Command releases a document; A and B log in with their own passphrases
   and open it; fingerprints differ.
4. B tries A's copy → denied; `ops` shows `OPEN_DENIED` land live.
5. Stop `keyrelease-3`; decryption still succeeds (threshold).
6. Command investigates the "leak", accuses, exports `.tsev`; verifier with
   `--network none` verifies it.

## 10. Risks

- Registry freshness: single-writer (`authority`) + provisioning; services
  re-read per call (verified in plan task P2.1 before relying on it).
- Argon2 memory ×N simultaneous unlocks: bounded by three live officers.
- `*.localhost` on some browsers/corporate machines: fallback is
  `officer-a.127.0.0.1.nip.io`-free — documented alternative is a hosts-file
  edit; the landing page shows both.
- Scope: five phases, each independently shippable and demo-able (see plan).
