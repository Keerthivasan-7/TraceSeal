# 9-Minute Judge Demo Script

A tight, timed, word-for-word script for presenting TraceSeal to the SIH
panel. Everything in it was verified working end-to-end today, through the
actual web console, not simulated for the writeup. Total runtime: 9:00.

One thing from the full `docs/DEMO_SCRIPT.md` is deliberately **cut**
here: the CLI verifier/tamper round-trip (step 9 there — proving a
`.tsev` evidence bundle can be independently re-verified with no server
trust). It needs its own terminal sequence and doesn't add as much for a
defense-panel audience as seeing a ledger replica get caught lying live,
which *is* included below. The verifier round-trip is kept in reserve
under "If asked."

This script needs a terminal window next to the browser for one segment
(7:05–7:55) — have both visible before you start.

---

## Before the judges walk in (run once, ~4 minutes, not part of the 9)

On a machine with `make` (Linux/Mac):
```bash
make demo
```

On this Windows machine (`make` is not installed here — use the manual
sequence, which is exactly what was verified working today):
```bash
docker compose run --rm web-api python -m pytest -q packages/web-api/tests
rm -rf demo/pki demo/blob demo/data demo/keystores demo/out demo/agent-state demo/checkpoints
mkdir -p demo/pki demo/blob demo/data demo/keystores demo/out
docker compose run --rm ca
docker compose up -d --build
docker compose stop orderer1.org1.traceseal.local orderer2.org2.traceseal.local \
  orderer3.org3.traceseal.local orderer4.org4.traceseal.local \
  peer0.org1.traceseal.local peer0.org2.traceseal.local \
  peer0.org3.traceseal.local peer0.org4.traceseal.local \
  fabric-gateway fabric-tools
docker compose run --rm --entrypoint python web-api -m agent.seed_keystores
```

Then, **always** (this is the ADR-0051 gotcha — the `ca` step above just
reseeded every key, so anything already running needs to reload):
```bash
docker compose restart ledger-0 ledger-1 ledger-2 ledger-3 \
  keyrelease-0 keyrelease-1 keyrelease-2 keyrelease-3 keyrelease-4
docker compose run --rm --entrypoint python web-api -m agent.seed_keystores
```

Open `http://127.0.0.1:8080` in the browser you'll present from, and load
it once before judges arrive so there's no cold-start delay on camera.
Keystore passphrase for every officer: `traceseal-demo-2026`.

Have a real multi-page PDF ready to drop in at minute 2:15 — a few pages
of dense text. (`demo/sample.pdf` works.)

---

## The script

### 0:00–0:25 — Cold open (Command Center)

**Say:**
> "TraceSeal answers one question: when a classified document leaks, who
> leaked it? Our answer is that we don't watermark documents after the
> fact — decryption itself produces the fingerprint. There is never a
> clean, unmarked copy of this document anywhere after it leaves this
> screen."

**Do:** Console is already open on Command Center.

### 0:25–1:00 — Air-gap proof (Command Center)

**Say:**
> "Before anything else — this entire system runs with zero runtime
> network egress. Watch."

**Do:** Click **RUN LIVE EGRESS TEST**.

**Say (as the result appears):**
> "That's not a claim on a slide, that's a live attempt to reach the
> outside internet, from inside this container network, that just failed.
> The ledger height and replica status you see are live data too — this
> screen is reading from a real 4-node ledger right now."

### 1:00–2:15 — Identity: real quorum enrolment

**Do:** Click **Identity**.

**Say:**
> "Before anyone can receive a document, they have to be enrolled — and
> enrolment needs two administrators to agree, not one."

**Do:** For **officer-a**: click **Propose** → approve as **admin-1** →
approve as **admin-2** → **Finalise enrol**. Repeat for **officer-b**.

**Say (while it processes):**
> "Every one of those approvals is a real post-quantum signature —
> ML-DSA-65 — being verified by an offline root CA we control ourselves.
> officer-a and officer-b are enrolled with real certificate hashes now."

### 2:15–3:45 — Distribute: quality-gated release

**Do:** Click **Distribute**. Drop in the sample PDF.

**Say (while it analyzes):**
> "Right now, this machine is rasterizing two physically different pixel
> variants of every eligible word on every page — that's the fingerprint
> carrier. This takes real seconds because it's real image processing,
> not a spinner."

**Do:** Toggle **Show mark positions**. Point at the **Quality gate**
panel.

**Say:**
> "Every marked position is checked against a structural-similarity
> threshold before release is even allowed — if the visual difference
> were ever detectable, release is blocked, not just flagged."

**Do:** Check **officer-a** and **officer-b**, click **Release to 2
officers**.

**Say:**
> "That's a real transaction hash, just written to the ledger."

### 3:45–4:45 — Officer Inbox: in-memory-only assembly

**Do:** Click **Officer Inbox**. Unlock **officer-a**, open the document.

**Say:**
> "This officer's copy is being assembled from encrypted fragments right
> now, in memory, on their own machine — never written to disk, no temp
> file, nothing a forensic disk scan could ever recover."

**Do:** Lock session, switch to **officer-b**, unlock, open the same
document.

**Say:**
> "Same document, visually identical to the eye — but every marked word
> is shifted by about a pixel and a half, differently, for officer-b than
> for officer-a. That's the fingerprint."

### 4:45–5:05 — Forwarding denied

**Do:** Under **Forwarding demo**, click **Try `<doc-id>` as officer-b**.

**Say:**
> "And if officer-a tries to hand their copy to officer-b directly,
> outside the system — denied immediately, and logged."

### 5:05–7:05 — The payoff: leak → investigate → accuse

**Do:** Click **Investigate**. Enter the doc ID, page 0, officer-a,
distortion **Screen camera**. Click **Open investigation**.

**Say (while it runs):**
> "We're simulating the realistic worst case — someone photographed this
> page on their phone. Watch: real feature-matching alignment, real
> per-position pixel detection, real accusation scoring. This is the
> exact same fingerprint that was silently written into officer-a's copy
> back when they opened it two minutes ago — we're just reading it back
> off a photo."

**Do:** Flip through **Detected → Aligned → Heatmap**. Point at the
suspects panel.

**Say:**
> "officer-a's session scores well above the threshold and is flagged.
> And to be precise about what this actually proves —" *(read the summary
> sentence aloud)* — "this is a statistical conclusion from pixel
> correlation, suitable for investigative and evidentiary review. We do
> not claim it proves intent, and we're not going to pretend otherwise in
> front of you."

**Do:** Click **Issue evidence report**.

**Say:**
> "That produces a signed evidence bundle and a PDF report an investigator
> can act on."

### 7:05–7:15 — Ledger integrity (before the tamper)

**Do:** Click **Ledger**.

**Say:**
> "Everything you've just seen — every enrolment, every release, every
> decrypt, this investigation — is on a 4-replica ledger, and right now
> all four independently agree."

### 7:15–7:55 — Insider attack: catch a compromised replica lying

**Say:**
> "Now watch what happens if one of those four replicas is compromised —
> say, an insider with disk access edits its stored history directly."

**Do (terminal):**
```bash
docker compose stop ledger-2
docker compose run --rm --entrypoint python ledger-2 -c "
import sqlite3
conn = sqlite3.connect('/data/ledger-2.db')
conn.execute('UPDATE records SET record_hash = randomblob(32) WHERE height = 1')
conn.commit()
"
docker compose start ledger-2
```

**Do (browser):** Switch back to the **Ledger** screen, refresh.

**Say (as it updates):**
> "ledger-2 just flipped to divergence detected, 'first bad height 1' —
> the other three replicas still independently agree with each other. We
> know exactly which replica lied and exactly where the history was
> altered, without trusting any single node to tell us the truth about
> itself."

### 7:55–8:30 — Closing value statement

**Say:**
> "To be direct about what's real and what isn't: every cryptographic
> operation you saw — key encapsulation, every signature, every hash
> chain — is a standard, audited post-quantum primitive: ML-KEM-768,
> ML-DSA-65, SLH-DSA. Nothing here is invented cryptography. The one
> component we've deliberately simulated — a lightweight ledger standing
> in for a future Hyperledger Fabric backend — is labeled as such
> everywhere it appears, in the UI and in our documentation, because we'd
> rather tell you exactly what's real than let a demo imply more than we
> can back up. That discipline is the same reason our accusation report
> says 'statistical conclusion,' not 'proof of guilt.' For a system meant
> to protect classified documents, we think that honesty is not optional —
> it's the actual product."

### 8:30–9:00 — Buffer / hand-off to questions

**Say:**
> "That's the full protocol, live, end to end — including catching a
> compromised node in the act. Happy to go deeper into collusion
> resistance across three or more colluding officers, or show you
> independent, server-free verification of an evidence bundle — whichever
> you'd find more useful."

---

## If asked (kept in reserve, not in the 9 minutes)

- **"What if multiple officers collude and compare copies?"** → Attack Lab
  screen, click **Run quick demo** — a real, seeded collusion-attack run
  reports accuracy live. Full benchmark table is in `docs/RESULTS.md`.
- **"Can someone verify this evidence without trusting your servers?"** →
  `docs/DEMO_SCRIPT.md` step 9 — the standalone `traceseal-verify` CLI
  depends only on `tscore`, no network access, and independently
  re-verifies a `.tsev` bundle downloaded in the Investigate step, then
  fails loudly on a single tampered byte:
  ```bash
  docker compose run --rm verifier traceseal-verify demo/case.tsev
  docker compose run --rm forensics python -m forensics.tamper_demo demo/case.tsev demo/case_tampered.tsev
  docker compose run --rm verifier traceseal-verify demo/case_tampered.tsev
  ```

## Fallback if something errors live

- Any screen shows "API unavailable": check it's a real validation
  message first (e.g., Investigate correctly refuses a session that was
  never opened) before assuming it's broken — read the message aloud, it's
  usually telling you exactly what precondition is missing.
- If enrolment/decrypt suddenly fails with a signature error after any
  unplanned container restart: `docs/DECISIONS.md` ADR-0051 — restart
  `ledger-*`/`keyrelease-*` and re-run `agent.seed_keystores`.
