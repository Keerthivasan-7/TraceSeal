# Role Isolation and Per-Identity Login Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Replace the single all-seeing console with per-role backends and per-identity cryptographic login, so each officer's key material and console are isolated on one laptop and verifiably so.

**Architecture:** One `web-api` image started with `ROLE` (`officer|command|authority|ops|all`) mounts only that role's routers behind a session guard. Login = Argon2id keystore unlock → random in-memory session token (HttpOnly cookie, per-identity name). nginx routes by `*.localhost` hostname to the role backend. Private key files are split out of `demo/pki` into per-service vault mounts (`VAULT_DIR`) and per-principal encrypted keystores.

**Tech Stack:** Python 3.12 / FastAPI / pytest (run inside the `web-api` image), `agent.keystore` (Argon2id+AES-GCM), Docker Compose overlay (`!override`), nginx `map $host`, React 18 + TypeScript strict + Zustand + TanStack Query.

**Spec:** `docs/superpowers/specs/2026-10-01-role-isolation-design.md`

## Global Constraints

- `ROLE=all` (default) must behave exactly as today; all existing tests stay green unchanged.
- No new cryptography: unlock via `agent.keystore.unlock_keystore`; token = `secrets.token_urlsafe(32)`; compare with `hmac.compare_digest`.
- No network egress added; only `web` publishes a port (loopback, ADR-0049 unchanged). No CDN/remote assets.
- Idle timeout 300 s, absolute 1800 s (env `SESSION_IDLE_S`, `SESSION_ABS_S`); lockout after 5 failures, backoff 30 s doubling, cap 300 s.
- Cookie: `ts_session_<identity-or-role>`, `HttpOnly; SameSite=Strict; Path=/`.
- Passphrases never appear in the repo, docs, logs or chat; only in gitignored `demo/roles/CREDENTIALS.local.txt` (mode 0600).
- No claims beyond what is enforced: UI footer says "separate containers with disjoint key material on one host".
- Python typed (mypy-clean), ruff-clean; TypeScript strict. Every security-relevant function gets negative tests.
- Git: commit only when the user asks (project CLAUDE.md). Plan steps say "checkpoint" where a commit would go.
- Test loop (fast, no rebuild): from repo root
  `docker compose run --rm -v "$PWD/packages:/app/packages" -e PYTHONPATH=/app/packages/web-api/src:/app/packages/ledger/src:/app/packages/keyrelease/src:/app/packages/agent/src:/app/packages/ca/src web-api python -m pytest -q packages/web-api/tests/<file>`

## Review Focus

- Two consoles in the same browser profile logging in at once → cookies must not collide (hostname origins + per-identity cookie names). Test: two TestClients with different identities do not see each other's sessions.
- Session expiring while a document is open → decrypted pages and identity must be dropped, next request 401. Test with injected clock.
- Path `officer_id` differing from the session identity, including URL-encoded variants and case changes → 403, never served. Test.
- Login hammering after lockout, including with the *correct* passphrase during backoff → 429, not 200. Test.
- Role `ops` and `all` must keep working with no cookie; role `officer` must 404 (not 401) for routes outside its role so routes aren't enumerable as "exists but locked". Test.
- Restart / re-seed: services re-read registry per call (verified: `ledger.service.lookup_public_key`, `keyrelease.service.lookup_*`), but identities load once at start → provisioning must seed before starting services (ADR-0051). Covered by `roles-provision` ordering and the isolation check.

---

## File Structure

| File | Responsibility |
|---|---|
| `packages/web-api/src/web_api/auth.py` (new) | `SessionManager`, `LockoutTracker`, `EventLog`, cookie name helper, `require_session` / `officer_scope` dependencies |
| `packages/web-api/src/web_api/roles.py` (new) | `ROLE_SCREENS`, role→router assembly (`routers_for(role)`) |
| `packages/web-api/src/web_api/routes/session.py` (new) | `GET /session`, `POST /session/login`, `POST /session/logout`, `GET /security/events` |
| `packages/web-api/src/web_api/identities.py` (new) | `resolve_identity(settings, app_state, identity_id)` — session-unlocked identity or (role `all`) raw file |
| `packages/web-api/src/web_api/config.py` | + `role`, `identity_id`, `auth_enabled`, timeouts, `vault_dir`, `enrol_inbox_dir` |
| `packages/web-api/src/web_api/state.py` | + `unlocked`, `sessions`, `lockout`, `events`, `end_session()` |
| `packages/web-api/src/web_api/main.py` | role-aware assembly, sweeper, injectable clock |
| `routes/officers.py`, `routes/identity.py` | split into read/roster vs agent/admin routers; use `resolve_identity` |
| `routes/distribute.py`, `routes/investigate.py` | `resolve_identity` instead of `load_identity` |
| `packages/ledger/src/ledger/{service,main}.py`, `packages/keyrelease/src/keyrelease/{service,main}.py` | `vault_dir` / `VAULT_DIR` |
| `packages/agent/src/agent/provision_roles.py` (new) | vault/public/keystore distribution, credential generation, staging purge |
| `docker-compose.roles.yml` (new) | role services + narrowed mounts + nginx override |
| `web/nginx.roles.conf` (new) | host→upstream map |
| `web/src/{session.ts,screens/Login.tsx,screens/Landing.tsx,components/IdentityBar.tsx,components/SecurityEvents.tsx}` (new); `App.tsx`, `Shell.tsx`, `api.ts`, `Inbox.tsx`, `Identity.tsx` | role-aware UI |
| `scripts/demo_isolation.py` (new), `Makefile` | `roles-provision`, `roles-up`, `roles-down`, `demo-isolation` |
| `docs/{DECISIONS.md,THREAT_MODEL.md,ROLES_DEMO.md,ARCHITECTURE.md}` | ADR-0052…0057, residuals, choreography |

---

## Phase 1 — Roles and session auth (works in-process, no Docker changes)

### Task 1: Config, auth primitives

**Files:** Create `web_api/auth.py`, `tests/test_auth_units.py`; Modify `web_api/config.py`.

**Interfaces:**
- Produces: `Settings.role: str`, `Settings.identity_id: str | None`, `Settings.auth_enabled: bool`, `Settings.idle_timeout_s: float`, `Settings.abs_timeout_s: float`, `Settings.vault_dir: Path` (defaults to `pki_dir`), `Settings.enrol_inbox_dir: Path`.
- Produces: `SessionManager(idle_timeout_s, abs_timeout_s, clock)` with `create(principal_id: str, identity_ids: list[str]) -> Session`, `validate(token: str | None) -> Session | None` (touches idle clock, expires), `revoke_all() -> list[Session]`, `sweep() -> list[Session]`, `time_left(session) -> tuple[float, float]`.
- Produces: `LockoutTracker(clock)` with `retry_after() -> float`, `record_failure() -> None`, `record_success() -> None`.
- Produces: `EventLog(maxlen=200)` with `add(kind: str, detail: str) -> None`, `recent() -> list[dict[str, object]]`.
- Produces: `cookie_name(settings: Settings) -> str`.

- [ ] **Step 1: Write failing unit tests** (`test_auth_units.py`): token is ≥32 bytes of entropy and differs per session; `validate` returns the session, then `None` after idle timeout using an injected clock; `validate` returns `None` after absolute timeout even when kept active; `validate(None)`/garbage → `None`; second `create` for the same backend does not auto-revoke (revocation is the caller's job via `revoke_all`); lockout: 4 failures → `retry_after()==0`, 5th → 30, 6th → 60, cap 300, success resets; `EventLog` keeps only the newest 200; `cookie_name` for officer-a is `ts_session_officer-a`, for command is `ts_session_command`.
- [ ] **Step 2: Run, expect FAIL** (module missing).
- [ ] **Step 3: Implement** `auth.py` primitives and `Settings` fields. Session store keyed by `sha256(token)` hex; `validate` hashes the presented token and looks it up, then `hmac.compare_digest` on the stored hash. `auth_enabled`: env `AUTH_REQUIRED` if set, else `role not in {"all","ops"}`.
- [ ] **Step 4: Run, expect PASS.** Checkpoint.

### Task 2: AppState, identity resolver, session routes

**Files:** Create `web_api/identities.py`, `routes/session.py`, `tests/test_session.py`; Modify `state.py`, `deps.py`.

**Interfaces:**
- Consumes: Task 1 primitives.
- Produces: `AppState.unlocked: dict[str, Identity]` (with `officer_sessions` as a read-only property alias), `AppState.sessions`, `.lockout`, `.events`, `AppState.end_session(session)` (pops that session's unlocked identities and any `open_sessions` keys for them).
- Produces: `resolve_identity(settings, app_state, identity_id) -> Identity` — returns unlocked identity; in role `all` falls back to `load_identity(settings.vault_dir / f"{id}.json")`; otherwise `HTTPException(401, "not logged in")`.
- Produces: routes `GET /session`, `POST /session/login`, `POST /session/logout`, `GET /security/events`; `ROLE_PRINCIPALS`: officer→`[identity_id]`, command→`["sender-1","forensics-1"]`, authority→`["ca-root"]`.

- [ ] **Step 1: Failing tests** (`test_session.py`) against an app built with `Settings(role="officer", identity_id="officer-a", ...)` and a keystore created for officer-a under a test passphrase: `GET /session` unauthenticated → `{"role":"officer","identity_id":"officer-a","auth_required":true,"authenticated":false,"allowed_screens":["inbox"]}`; wrong passphrase → 401 and an event; correct → 200, `Set-Cookie` named `ts_session_officer-a` with `HttpOnly` and `SameSite=strict`, body never contains the token; `GET /session` afterwards shows `authenticated: true` and time-left fields; logout → 200, identity gone from `app_state.unlocked`, next `GET /session` unauthenticated; missing keystore → 503 with a message naming the identity; login for role `ops` → 404; five wrong passphrases then the *correct* one → 429 with `Retry-After`; a fresh login replaces the previous session (old token → unauthenticated).
- [ ] **Step 2: Run, expect FAIL.**
- [ ] **Step 3: Implement** state additions, `identities.py`, `session.py`. Login: check lockout → unlock all principals' keystores (`settings.keystore_dir / f"{id}.keystore.json"`) → `TamperError` ⇒ `record_failure`, event `login_failed`, 401 → success ⇒ `record_success`, `revoke_all` previous (calling `end_session` on each), create, store identities, event `login_ok`, set cookie.
- [ ] **Step 4: Run, expect PASS.** Checkpoint.

### Task 3: Guards and role-scoped assembly

**Files:** Create `web_api/roles.py`, `tests/test_roles.py`; Modify `web_api/auth.py` (+ `require_session`, `officer_scope`), `routes/officers.py`, `routes/identity.py`, `main.py`.

**Interfaces:**
- Produces: `ROLE_SCREENS: dict[str, list[str]]` = all→all eight, command→`[command,distribute,monitor,investigate,ledger,attacklab]`, officer→`[inbox]`, authority→`[identity,ledger]`, ops→`[command,monitor,ledger]`.
- Produces: `officers.roster_router` (`GET /officers`), `officers.agent_router` (documents/open/pages), `officers.legacy_router` (`unlock`/`lock`, role `all` only); `identity.read_router` (`/identity/registry`, `/identity/proposals`), `identity.admin_router` (propose/approve/finalize/revoke).
- Produces: `create_app(settings=None, *, clock=time.monotonic)`.

- [ ] **Step 1: Failing tests** (`test_roles.py`): *officer role*: no cookie → `GET /officers/officer-a/documents` 401; after login 200; `/officers/officer-b/documents` 403 (and `%6Fficer-b`, `OFFICER-A` variants never 200); `/distribute/analyze`, `/identity/registry`, `/investigate/open`, `/attacklab/results`, `/system/status` → 404; `unlock` → 404. *Expiry*: with injected clock advance 301 s → 401 and `officer-a` absent from `unlocked`, `open_sessions` emptied. *command role*: login unlocks `sender-1` and `forensics-1`; `/officers/officer-a/documents` → 404; `/identity/registry` → 200 (read), `/identity/officers/officer-a/propose-enrol` → 404. *ops role*: `/system/status` 200 with no cookie, `/session/login` 404, `/distribute/analyze` 404, `/identity/proposals` 200. *two backends*: officer-a and officer-b apps in one test do not accept each other's cookies. *role all*: `GET /session` → `auth_required:false`; existing unlock flow still works.
- [ ] **Step 2: Run, expect FAIL.**
- [ ] **Step 3: Implement.** `require_session` reads `cookie_name(settings)`; returns `None` when `not settings.auth_enabled`; else validate → on `None` log event `auth_missing|auth_expired` and raise 401. `officer_scope(officer_id: str, session=Depends(require_session))`: when role is `officer`, `officer_id != settings.identity_id` (exact, case-sensitive, after FastAPI's own decoding) → event `scope_violation`, 403; `session.principal_id != officer_id` → 403. `create_app` includes `roles.routers_for(settings.role)` each with `dependencies=[Depends(require_session)]` when `auth_enabled`; agent_router additionally `Depends(officer_scope)`. Middleware calls `app_state.sessions.sweep()` and `end_session` for each expired session before every request; a lifespan task does the same every 5 s so idle decrypted pages do not linger.
- [ ] **Step 4: Run new tests + full `packages/web-api/tests`, expect PASS** (no regressions in role `all`). Checkpoint.

### Task 4: Wire sender/forensics identities through the resolver

**Files:** Modify `routes/distribute.py:172`, `routes/investigate.py:117,240`; Test `tests/test_identity_resolution.py`.

- [ ] **Step 1: Failing tests:** in role `command` with a logged-in session, `resolve_identity("sender-1")` returns the session identity and `distribute` does not read `settings.vault_dir` (point it at an empty dir); without login → 401; role `all` still reads the file.
- [ ] **Step 2: Run, expect FAIL.** **Step 3:** replace the three `load_identity(settings.pki_dir / …)` sites with `resolve_identity(settings, app_state, SENDER_ID|FORENSICS_ID)`; add `AppStateDep` to the investigate helpers that lack it. **Step 4: Run web-api suite, expect PASS.** Checkpoint.

**Phase 1 exit:** `docker compose run … pytest packages/web-api/tests` green; `ruff` + `mypy` clean for `web_api`.

---

## Phase 2 — Key isolation and deployment

### Task 5: `VAULT_DIR` in ledger and key-release

**Files:** Modify `ledger/service.py:119-133`, `ledger/main.py`, `keyrelease/service.py:79-90`, `keyrelease/main.py`; Tests: one new test each.

- [ ] **Step 1: Failing tests:** `create_app(..., pki_dir=pki, vault_dir=other)` loads the identity from `other` and the registry from `pki`; with `vault_dir=None` behaviour is unchanged (existing tests). **Step 2: FAIL. Step 3:** add `vault_dir: Path | None = None`, `identity = load_identity((vault_dir or pki_dir) / f"{id}.json")`; mains read `VAULT_DIR` (default = `PKI_DIR`). **Step 4: run `make test-ledger test-keyrelease`, PASS.** Checkpoint.

### Task 6: Provisioning

**Files:** Create `agent/provision_roles.py`, `agent/tests/test_provision_roles.py`.

**Interfaces:**
- Produces: `provision(staging: Path, roles_dir: Path, *, officers=ALL_OFFICERS, rng=secrets.SystemRandom()) -> dict[str, str]` returning `{principal: passphrase}`; `sync_public(staging, roles_dir)`; `purge_staging(staging)`; CLI `python -m agent.provision_roles [--purge]`.
- Layout written: `roles_dir/vault/<id>/<id>.json` for `ledger-0..3`, `keyrelease-0..4`; `roles_dir/keystores/<id>.keystore.json` for officers a–e, `admin-1..3`, `ca-root` (custodian), and `sender-1` + `forensics-1` (command operator, one shared passphrase); `roles_dir/public/registry.json`; `roles_dir/CREDENTIALS.local.txt` (0600).

- [ ] **Step 1: Failing tests** (fake identities as in `test_seed_keystores.py`): every vault dir holds exactly one file named for its identity; officer keystores each unlock with their own passphrase and *not* with another officer's; command keystores both unlock with the command passphrase; no raw `*.json` private file exists anywhere under `roles_dir` except `vault/`; `public/registry.json` contains no `secret` substring; credentials file mode `0o600`, lists every principal, passphrases are unique; `purge_staging` removes every private `*.json` but keeps `registry.json`; passphrases have ≥ 4 words from a 128-word embedded list. **Step 2–4:** implement, run `make test-agent`, PASS. Checkpoint.

### Task 7: Compose overlay and nginx host routing

**Files:** Create `docker-compose.roles.yml`, `web/nginx.roles.conf`; Modify `.gitignore` (`demo/roles/`).

- [ ] **Step 1:** Write `x-role-api` anchor (image `traceseal/web-api:m8`, internal network, env `PKI_DIR=/pki`, `KEYSTORE_DIR=/app/demo/keystores`, `BLOB_DIR=/app/demo/blob`, ledger/keyrelease URLs, `SESSION_*`). Services: `agent-officer-{a,b,c}` (`ROLE=officer`, `IDENTITY_ID`, `hostname`, mounts: `demo/roles/public:/pki:ro`, `demo/blob:/app/demo/blob:ro`, **only** `demo/roles/keystores/<id>.keystore.json`, `demo/agent-state/<id>` rw, `demo/roles/enrol-inbox` rw); `agent-officer-{d,e}` same with `profiles: [officers-extra]`; `console-command` (keystores sender-1 + forensics-1, `demo/blob` rw, `demo/out`, `docs`, `attacklab`); `console-authority` (keystores ca-root + admin-1..3, `public` rw, inbox ro); `console-ops` (public ro, nothing else). Override `ledger-N`/`keyrelease-N` with `volumes: !override` (`public:/pki:ro`, `vault/<id>:/vault:ro`, data) and `VAULT_DIR=/vault`; `web-api` gets `profiles: [combined]`; `web` mounts `nginx.roles.conf`, `depends_on: !override` the role services.
- [ ] **Step 2:** `nginx.roles.conf`: `map $host $role_upstream` for `command|authority|ops|officer-{a..e}.localhost`; `resolver 127.0.0.11 valid=10s ipv6=off;` `location /api/ { if ($role_upstream = "") { return 404; } rewrite ^/api/(.*)$ /$1 break; proxy_pass $role_upstream; … }` (lazy DNS so profile-off officers don't break startup); SPA fallback and the existing security headers/CSP unchanged.
- [ ] **Step 3: Verify:** `docker compose -f docker-compose.yml -f docker-compose.roles.yml config` parses; `nginx -t` inside a throwaway `nginx:1.29.1-alpine3.22` with the file mounted passes. Checkpoint.

### Task 8: Make targets and bring-up rehearsal

**Files:** Modify `Makefile` (+ `.PHONY`); Create `scripts/roles_provision.sh` (bash, also runnable under Git Bash).

- [ ] **Step 1:** `roles-provision`: wipe `demo/pki demo/blob demo/data demo/roles demo/agent-state` → `docker compose run --rm ca` (seed) → `docker compose run --rm --entrypoint python web-api -m agent.provision_roles` → `docker compose -f … up -d ledger-0..3 keyrelease-0..4` → wait for health → enrol officers a,b,c via `ca.demo_m4.enrol_officer(..., pki_dir=/app/demo/pki)` → `agent.provision_roles --sync-public --purge`. `roles-up`: `up -d --build` for the overlay; `roles-down`.
- [ ] **Step 2: Run `make roles-provision roles-up` (or the script on Windows)** and confirm: `curl -s -H "Host: officer-a.localhost" http://127.0.0.1:8080/api/session` → role `officer`, `authenticated:false`; `Host: ops.localhost` → role `ops`; `Host: localhost` → 404. Checkpoint.

**Phase 2 exit:** isolated stack up from one command; ledger/KR running on narrowed mounts; officers a–c enrolled; staging purged.

---

## Phase 3 — UI

### Task 9: Session plumbing, login gate, role shell

**Files:** Create `web/src/session.ts`, `screens/Login.tsx`, `screens/Landing.tsx`; Modify `App.tsx`, `Shell.tsx`, `api.ts`, `store.ts`.

**Interfaces:** `SessionInfo = {role; identity_id; auth_required; authenticated; cert_hash: string|null; idle_expires_in_s; abs_expires_in_s; allowed_screens: Screen[]; container: string}`; `useSession()` (TanStack Query, 5 s refetch); `api()` invalidates `["session"]` on 401.

- [ ] **Step 1:** `session.ts` + `Landing` (shown when `/api/session` is 404: lists `command|authority|ops|officer-a..c .localhost:8080` links). **Step 2:** `Login` (passphrase field, lockout countdown from `Retry-After`, no passphrase persistence, `autocomplete=off`). **Step 3:** `App` renders Landing / Login / console by session; role `all` and `ops` skip Login. `Shell` nav filtered by `allowed_screens`; initial screen = first allowed. **Step 4:** `npm run build` (inside `web/`) and `npx tsc --noEmit` clean. Checkpoint.

### Task 10: Identity bar, accent, events, officer Inbox mode

**Files:** Create `components/IdentityBar.tsx`, `components/SecurityEvents.tsx`; Modify `Shell.tsx`, `Inbox.tsx`, `tailwind`/CSS tokens for `data-role` accents.

- [ ] **Step 1:** `IdentityBar`: identity id, `compactId(cert_hash)`, `keys live in container {container}`, countdown, Lock button (`POST /session/logout`). **Step 2:** per-role accent via `data-role` on the root (officer-a/b/c distinct hues; command, authority, ops distinct). **Step 3:** `SecurityEvents` panel polls `/security/events` (officer and command consoles). **Step 4:** `Inbox` in officer mode: no officer tab row, no unlock card (login did it), forwarding-demo control kept. Footer text: "separate containers with disjoint key material on one host — not separate physical machines". **Step 5:** build + typecheck; manual check in the browser pane at `http://officer-a.localhost:8080` (screenshots). Checkpoint.

**Phase 3 exit:** four tabs, each with its own login and scoped nav, work against the real stack.

---

## Phase 4 — Authority console (enrolment with dual control)

### Task 11: Officer-produced CSR and per-admin approvals

**Files:** Modify `routes/officers.py` (agent: `POST /officers/{id}/enrolment-request`), `routes/identity.py` (admin routes), `state.py`; Tests `tests/test_authority.py`.

**Interfaces:** CSR file `demo/roles/enrol-inbox/<officer>.csr.json` = `{envelope_cbor, signer_id, signature}` (hex); `ApproveRequest.passphrase: str | None`; `ProposeEnrolRequest.passphrase`, `ProposeRevokeRequest.passphrase` (admin-1's, in roles mode).

- [ ] **Step 1: Failing tests:** officer logged in → `enrolment-request` writes a CSR whose self-signature verifies; authority `propose-enrol` reads it from the inbox (no officer key access: point the officer vault at an empty dir); approval with admin-1's passphrase succeeds, with admin-2's passphrase for admin-1 → 401, with no passphrase in a role with auth → 400, and no admin identity remains in `unlocked` afterwards; finalize needs the custodian session (401 without login) and updates `public/registry.json` in place using the existing public entry plus certificate fields (no officer private key read); role `all` flow and `tests/helpers.enrol_officer` unchanged. **Step 2–4:** implement; run web-api suite. Checkpoint.

### Task 12: Identity screen for the authority

**Files:** Modify `web/src/screens/Identity.tsx`.

- [ ] Add passphrase prompt on each Approve / Propose / Finalize action when `session.role === "authority"`; "Request enrolment" button on the officer Inbox that calls `enrolment-request`. Build + typecheck. Checkpoint.

**Fallback (stated in spec §6):** if Task 11/12 slip, provisioning-time enrolment (Task 8) already covers officers a–c; document the authority flow as not delivered.

---

## Phase 5 — Proof, docs, rehearsal

### Task 13: `demo-isolation`

**Files:** Create `scripts/demo_isolation.py` (runs on the host, shells to `docker`), Modify `Makefile`.

- [ ] Real checks, printed as a PASS/FAIL table, non-zero exit on any FAIL: (1) each `agent-officer-x` holds exactly one `*.keystore.json` and no raw identity JSON (`docker exec … find`); (2) `ledger-N`/`keyrelease-N` vault holds only their own identity; (3) `console-ops` has no keystore or vault; (4) no running traceseal container has a default route (`docker exec … ip route`) except none; (5) cross-identity: log in to officer-a, replay its cookie against officer-b → 403/401; (6) command-role route in officer console → 404; (7) `verifier` runs with `--network none` and verifies a bundle. Checkpoint.

### Task 14: Docs, ADRs, rehearsal

**Files:** Modify `docs/DECISIONS.md` (ADR-0052 hostname-origin isolation, 0053 session model, 0054 vault split, 0055 command role merge, 0056 provisioning layout, 0057 authority console), `docs/THREAT_MODEL.md` (residuals: same host, in-memory sessions, no TLS on loopback, command role holds both sender/forensics, no network segmentation between officer containers), `docs/ARCHITECTURE.md`, `docs/REQUIREMENTS_TRACE.md`; Create `docs/ROLES_DEMO.md`.

- [ ] Write ADRs (3–6 lines each), update the threat model and requirement trace, write `ROLES_DEMO.md` with the Section 9 choreography and recovery steps (restart order, ADR-0051 gotcha, `*.localhost` fallback via hosts file). Run the whole choreography once in the browser pane; fix what breaks. Run `make test` and `make lint`. Checkpoint.

---

## Self-review

- **Spec coverage:** §3 topology → T3, T7; §4 auth → T1–T3; §5 vault → T5–T6; §6 enrolment → T11–T12; §7 UI → T9–T10; §8 deployment/`demo-isolation` → T7, T8, T13; §9 choreography → T14; §10 risks → Review Focus + T14.
- **Placeholders:** none; where code is not inlined the step names the exact file, signature, and assertion set the tests pin.
- **Type consistency:** `Session.principal_id`, `AppState.unlocked`, `resolve_identity`, `cookie_name`, `ROLE_SCREENS` used identically across tasks.
- **Known gap to watch:** `docker compose run` for tests picks up the baked image unless the fast-loop volume/`PYTHONPATH` override is used — use it, or rebuild with `docker compose build web-api`.
