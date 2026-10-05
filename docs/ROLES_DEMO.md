# Isolated-roles demo

Several browser windows, one per workstation. Each window is a separate origin
(`*.localhost`) backed by a separate container that holds only its own key material.
Design: `docs/superpowers/specs/2026-10-01-role-isolation-design.md`; decisions:
ADR-0053…0058 in `docs/DECISIONS.md`; residual risks: `docs/THREAT_MODEL.md`
("Role isolation").

**What this is and is not.** Separate containers with disjoint key material on one
host, with real per-identity login. It is *not* separate physical machines, and the
passphrases are demo-grade. Say so before a judge asks.

## Bring-up

No `make` on Windows? Use the script (Git Bash); `make roles-*` just calls it.

```bash
bash scripts/roles.sh provision   # RESETS demo state; seeds PKI, distributes keys, enrols officers a and b
bash scripts/roles.sh up          # builds images, starts every console
python scripts/demo_isolation.py  # real probes: 20+ checks, exit status 1 on any FAIL
python scripts/roles_e2e.py       # the whole scenario through the live consoles
```

`provision` replaces the combined deployment (they share `demo/data` and `demo/blob`).
The generated passphrases are in `demo/roles/CREDENTIALS.local.txt` (gitignored; on a
Windows host the file mode is not enforced). Officers C, D and E exist but only start on demand (`bash scripts/demo_actions.sh start-officer-c`, or
`docker compose -f docker-compose.yml -f docker-compose.roles.yml --profile officers-extra up -d agent-officer-d`). Officer C
is deliberately **not enrolled and not running** at the start: the demo admits C live through the authority console.

| Window | URL | Holds |
|---|---|---|
| Launcher | `http://localhost:8080` | nothing (links) |
| Command | `http://command.localhost:8080` | `sender-1`, `forensics-1` keystores |
| Officer A / B (C joins live) | `http://officer-a.localhost:8080` … | only its own keystore |
| Authority | `http://authority.localhost:8080` | `ca-root` + `admin-1..3` keystores |
| Operations | `http://ops.localhost:8080` | nothing (read-only, no login) |

Each console has its own accent colour and a tab title with its identity. If a
`*.localhost` name does not resolve, add `127.0.0.1 command.localhost officer-a.localhost …`
to the hosts file.

## Choreography (about 8 minutes; everything below was run end-to-end)

1. **Four windows, side by side:** Command, Officer A, Officer B, Operations (project this
   one). Point at the identity bar: *keys live in container …*, certificate fingerprint,
   auto-lock countdown.
2. **Prove it, don't claim it.** In a terminal: `python scripts/demo_isolation.py`. It
   audits every container's mounts, lists each officer's filesystem, tries to reach the
   internet from every container, and replays one officer's session token against another.
3. **Login is the keystore.** Type a wrong passphrase on Officer A (refused), then A's own.
   Try B's passphrase on A: refused. Five failures trigger a backoff that also blocks the
   correct passphrase.
4. **Command releases a document** to officer-a and officer-b (Distribute: analyse, quality
   gate, release). Operations shows the ledger move.
5. **Each officer opens it on their own workstation.** The pages are assembled in memory,
   served `Cache-Control: no-store`, and wiped when the session locks or expires.
   The two copies are forensically distinct.
6. **Isolation under load.** On Command, the Officer Inbox does not exist (404, not
   "forbidden"). Officer A's session against Officer B's documents: 403.
7. **Forwarding.** On Officer B use *Forwarding demo* → try officer-a's copy. It is refused
   by the key-release quorum: the certificate presented is not B's, so no key grant is
   ever issued. (No ledger record is written on this path; see "Corrections" below.)
8. **Kill a key-release node** (`docker compose -f docker-compose.yml -f docker-compose.roles.yml stop keyrelease-3`).
   Decryption still works. Stop two more and it is refused (`only 2 shares obtained, need >= 3`).
   Start them again before continuing.
9. **The leak travels as a file.** On Officer A, with a page open: *Simulated insider leak*
   → *Phone photo*. A PNG lands in Downloads. On Command: Investigate → *Upload artifact* →
   that file. The pipeline accuses officer-a, and only officer-a. Issue the evidence report
   and download the `.tsev`.
10. **Offline verification.** `python scripts/demo_isolation.py --bundle path/to/case.tsev`
    verifies it in a container with `--network none`. `python scripts/roles_e2e.py`
    additionally shows that one flipped byte in the signed bundle, or a swapped report PDF,
    is rejected.
11. **Two-person enrolment (the live "officer C joins" beat).** Start officer-c (`bash scripts/demo_actions.sh start-officer-c`), request enrolment on its console;
    on the Authority console log in as the custodian, *Propose* (admin-1's passphrase),
    approve as admin-1 and admin-2 *each with their own passphrase*, then *Finalise*.
    One admin's passphrase cannot sign for another.

## Corrections to older material

- The Officer Inbox text and `docs/JUDGE_DEMO_SCRIPT_9MIN.md` (step "Forwarding denied")
  said a forwarding attempt is "denied and logged as OPEN_DENIED". Verified against the
  running stack: the attempt is denied by the key-release nodes' identity check (HTTP 403),
  but **no `open-denied` ledger record is written on that path**; that record only comes
  from the later client-side SealedHeader check. The Inbox text now says what happens; the
  judge script has not been changed and should be.

## Recovery

- After any unplanned restart of `ledger-*`/`keyrelease-*` they simply reload their vault
  identity; sessions on the consoles are in memory, so restarting a console logs everyone
  out of it (log in again).
- `docker compose run` on a service that depends on a running one can recreate that
  dependency with the *base* file. Always pass `--no-deps` for ad-hoc runs, or include the
  overlay: `-f docker-compose.yml -f docker-compose.roles.yml`.
- Full reset: `bash scripts/roles.sh provision` (wipes ledger data and rotates every passphrase).
- Back to the combined console: `bash scripts/roles.sh down`, then the combined runbook
  in `docs/DEMO_SCRIPT.md` (it re-seeds from scratch).
