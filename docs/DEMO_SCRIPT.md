# Demo Script

The full script for `docs/SPEC.md` Section 18, under 10 minutes, driven
through the web console at `http://127.0.0.1:8080` (started via `make up`
or `make demo`). Every step below is real: real ML-DSA/ML-KEM operations,
a real 4-replica ledger, a real 5-node key-release quorum, real pixel-level
forensic detection. Nothing is mocked, pre-recorded, or hardcoded.

Two steps (7 and 8) aren't native UI buttons yet and need a terminal
alongside the browser — called out explicitly below, not glossed over.

**Stop the Fabric services before recording — they slow everything down
and aren't used by this demo.** `make demo` brings up the full stack,
including the 4-org Fabric network (4 orderers + 4 peers + gateway +
tools), even though LedgerLite is the default backend every step here
actually uses. On a resource-constrained Docker Desktop, running Fabric
alongside everything else was measured to push a single `/distribute/
analyze` call from ~50s to over 300s (timing out nginx's proxy entirely)
purely from CPU/memory contention — not a code bug, confirmed by watching
the container's CPU pinned near 100% the whole time. Free it up once,
right after `make demo`:

```bash
docker compose stop orderer1.org1.traceseal.local orderer2.org2.traceseal.local \
  orderer3.org3.traceseal.local orderer4.org4.traceseal.local \
  peer0.org1.traceseal.local peer0.org2.traceseal.local \
  peer0.org3.traceseal.local peer0.org4.traceseal.local \
  fabric-gateway fabric-tools
```

If you ever restart `web-api` by hand mid-session, restart `web` (nginx)
too — nginx holds a keepalive connection to the old process and returns
502s until it reconnects.

**Before recording:** run `make demo` (or `make demo-m8`) to wipe and
reseed `demo/pki`/`demo/blob`/`demo/data`, bring up every service fresh,
and seed officer keystores — so the console starts from a clean state with
no leftover test documents or officers from prior runs. See the "Reset
before you record" section at the end if you've already been clicking
around and want a clean slate again.

The demo passphrase for every officer's keystore (Officer Inbox screen)
is `traceseal-demo-2026` — fixed and documented (`agent.seed_keystores`),
never a stand-in for a real deployment's passphrase policy.

---

## 1. Command Center — air-gap posture (30s)

Open the console. The **Command Center** screen is the default landing
screen.

- Point out the **Air-gap posture** panel: `traceseal_internal (internal:
  true — no runtime egress)`, "Cloud dependencies: NONE".
- Click **RUN LIVE EGRESS TEST**. It genuinely attempts an outbound HTTPS
  request to `1.1.1.1` from inside the container network and reports it
  blocked — say so explicitly: *"this isn't a claim, it's a live attempt
  that just failed."*
- Note the ledger height and replica-integrity badges are already live
  data, not placeholders.

## 2. Identity — enrolment with real quorum (90s)

Click **Identity**.

- For **officer-a**, click **Propose**, then approve as **admin-1** and
  **admin-2** (two separate clicks — the quorum bar fills to 2/2), then
  **Finalise enrol**. Officer-a flips to `ACTIVE` with a real cert hash.
- Repeat for officer-b (needed as a second recipient later — Tardos
  collusion resistance needs at least 2).
- **Show the guard rail:** propose officer-c, approve with only
  **admin-1**, then try **Finalise enrol** immediately — it's rejected
  (quorum not met). This is the real "a single admin cannot enrol a ghost
  identity" moment from the spec.
- Finish officer-c's quorum with admin-2 so it's available for step 5.

## 3. Distribute — upload, quality gate, release (90s)

Click **Distribute**. Drop in a real multi-page PDF (a few pages of dense
text — enough for 200+ mark positions; a single short page will correctly
be *refused* by the Tardos planner as insufficient for genuine collusion
resistance at 2+ recipients, which is itself worth narrating as an honesty
feature, not a bug).

- While it's analyzing, narrate: *"this is genuinely rendering two
  physical pixel variants of every eligible word on every page right
  now."* It takes real seconds because it's real work.
- Toggle **Show mark positions** to show the overlay of exactly which
  words are carrying the fingerprint.
- Point at the **Quality gate** panel: real SSIM scores per page/variant,
  both comfortably over the 0.98 threshold — *"if this ever failed, release
  would be blocked, not just warned."*
- Check **officer-a** and **officer-b**, click **Release to 2 officers**.
  Note the `doc-xxxxxxxxxxxx` ID and the real ledger tx hash that comes
  back.

## 4. Officer Inbox — open all copies, switch officers (60s)

Click **Officer Inbox**.

- Unlock **officer-a** (passphrase above), open the document, flip through
  its pages in the viewer. Point out the footer line: *"assembled entirely
  in memory, never written to disk."*
- Click **Lock session**, switch to **officer-b**, unlock, open the same
  document. Note the pages look visually identical — the difference is a
  1.5-pixel shift per marked word, invisible at normal viewing.

## 5. Forwarding denied, live (30s)

Still on Officer Inbox, with officer-a's session unlocked and the document
open:

- Under **Forwarding demo**, click **Try `<doc-id>` as officer-b**. It's
  denied immediately with a clear message, and the denial is logged.
- Switch to **Monitor**, pick the same document, and point at the **red
  "Forwarding attempts denied"** entry at the bottom of its timeline —
  *"that's the event appearing live, exactly as the spec asks for."*

## 6. Leak simulation → Investigate (90s)

Click **Investigate**.

- Enter the `doc-id` from step 3, page `0`.
- Leave mode on **Simulate a leak**, officer **officer-a**, distortion
  **Screen camera** — this runs a real, seeded distortion pipeline
  (resample, moiré, gamma, blur, noise, JPEG) on officer-a's own
  just-opened page, standing in for "photographed with a phone."
- Click **Open investigation**. Narrate while it runs: real ORB/RANSAC
  alignment, real per-position template matching, real Tardos accusation
  — *"decryption itself produced this fingerprint back in step 4; this is
  just reading it back off a photo of the result."*
- Flip through the pipeline tabs: **Detected** (the raw capture),
  **Aligned** (homography-corrected), **Heatmap** (every mark position
  color-coded by its recovered bit — green/red/amber for erased).
- Point at the suspects panel: officer-a's session scores well above the
  threshold line and is flagged **accused**; read the summary sentence
  aloud, including its own honesty caveat ("a statistical conclusion...
  not a legal determination of guilt or intent").
- Click **Issue evidence report**, then download **case.tsev** and
  **report.pdf**.

## 7. Collusion resistance — Attack Lab (30s, no live 3-officer UI yet)

There's no interactive "merge 3 officers' real copies" button in the web
console yet — say so plainly rather than faking it. The real evidence for
collusion resistance lives in the Attack Lab screen instead:

- Click **Attack Lab**, click **Run quick demo** — a real, seeded, small
  run of the same collusion-attack code (majority/minority pirate
  strategies among synthetic sessions) executes live and reports 100%
  top-1 accuracy with 0 innocent accusations.
- Scroll to the full benchmark table below it (`docs/RESULTS.md`, real,
  never hand-edited) and point at the `collusion_*_c2/c3/c4` rows —
  majority/minority/random/interleave all resolve correctly; only
  `patch_averaging` (which blends pixels rather than picking a discrete
  bit) has no single bit-error-rate, honestly reported as `n/a`.

## 8. Insider attack — tamper with one ledger replica (60s, terminal + UI)

This needs a terminal next to the browser; there's no "corrupt a replica"
button (nor should there be).

```bash
# Stop one replica so we can safely edit its data-at-rest.
docker compose stop ledger-2

# Corrupt one stored record's hash directly in that replica's own database.
docker compose run --rm --entrypoint python ledger-2 -c "
import sqlite3
conn = sqlite3.connect('/data/ledger-2.db')
conn.execute('UPDATE records SET record_hash = randomblob(32) WHERE height = 1')
conn.commit()
"

# Bring the corrupted replica back up.
docker compose start ledger-2
```

Switch to the **Ledger** screen and refresh: `ledger-2`'s card flips to a
red status dot with `first bad 1`, while the overall badge still reads
**quorum agrees** — *"one replica is compromised, the other three still
agree, and we know exactly which one lied and from where."*

## 9. Export + independent verification, then tamper it (60s)

Move the `case.tsev` your browser downloaded in step 6 into `./demo/`
(both `verifier` and `forensics` already mount that directory), then:

```bash
docker compose run --rm verifier traceseal-verify demo/case.tsev
# -> VALID: ... signature, ledger proofs, commitments, and Tardos scores
#    all independently re-verified ...
```

This CLI depends on `tscore` only — no ledger, no PKI, no network access
(G4: "no trust in the server"). Now flip one byte and show it fail:

```bash
docker compose run --rm forensics \
  python -m forensics.tamper_demo demo/case.tsev demo/case_tampered.tsev
docker compose run --rm verifier traceseal-verify demo/case_tampered.tsev
# -> INVALID: ...
```

---

## Reset before you record

To start from a genuinely clean state (no leftover test officers,
documents, or investigations from earlier clicking around):

```bash
make demo
```

This wipes `demo/pki`, `demo/blob`, `demo/data`, `demo/keystores`, brings
every service up fresh, and seeds officer keystores — ready for step 1.

## A known gotcha if Docker restarts mid-session

If Docker Desktop or any container restarts *between* seeding and
recording, see `docs/DECISIONS.md` ADR-0051: the `ca` container
unconditionally regenerates every identity on every start, which can
desync already-running `ledger-*`/`keyrelease-*` replicas' cached keys
from the fresh registry. If enrolment or decrypt suddenly fails with a
signature-verification error after an unplanned restart, the fix is:

```bash
docker compose restart ledger-0 ledger-1 ledger-2 ledger-3 \
  keyrelease-0 keyrelease-1 keyrelease-2 keyrelease-3 keyrelease-4
docker compose run --rm --entrypoint python web-api -m agent.seed_keystores
```

Then re-run the enrolment ceremony for any officer enrolled before the
restart.
