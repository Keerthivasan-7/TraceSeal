# 9-Minute Judge Demo — "Every officer is their own workstation"

Everything below was run on the real stack and timed. Numbers quoted in the speech are
measured, not rounded up. Total: **9:00**. Companion docs: `docs/ROLES_DEMO.md`
(how it is built), `docs/THREAT_MODEL.md` ("Role isolation" = what it does *not* defend).

## The story (say this to yourself first)

A leaked document must point to **one person**, and nobody — not even the sender — may hold
a clean copy. This demo shows it the way it would really run: **separate workstations, each
holding only its own keys, each with its own login** — and a new officer who joins *live*,
admitted only by two administrators who each type their own passphrase. Then it proves the
claims instead of asserting them.

Three claims, each *demonstrated* in the room:

1. **There is never a clean copy.** Decrypting *is* fingerprinting — each officer's copy is different.
2. **The workstations are genuinely isolated, and joining needs two people.** One passphrase, one container, one set of keys — probed live. No single admin can admit an officer.
3. **The evidence stands without trusting us.** A container with *no network* verifies it; one flipped bit breaks it.

The wow moments, in order: the isolation proof streaming line by line · **officer C's workstation
powers on and is admitted by two admins' passphrases** · three officers get visibly identical but
forensically different copies · the leak travels between machines as a **file** · the accusation ·
the evidence verified offline then **destroyed by one bit** · an insider edits a ledger on disk and
gets caught.

---

## Before the room (T-30 min — not part of the 9)

**1. Clean state.** Rotates every passphrase, wipes ledger and documents, enrols **only officers A and B**.
Officer C's workstation is *not running* and C is *not enrolled* — that's the point.

```bash
bash scripts/roles.sh provision
docker compose -f docker-compose.yml -f docker-compose.roles.yml up -d --no-build agent-officer-a agent-officer-b console-command console-authority console-ops web
```

**2. Dry-check (safe: leaves no demo data behind).**

```bash
python scripts/demo_isolation.py        # expect: ==> 18 passed, 0 failed, 1 skipped
```

**Do not** rehearse the full flow without resetting afterwards — it leaves a document, an investigation
and (if you enrol C) an enrolment on the ledger, and a judge will see them on the Ops screen. And do not
run `demo_isolation.py` *during* the demo after officers are logged in without `--no-login`: it logs A and B
in itself, which replaces the sessions open in your browser.

**3. Passphrases — you will type seven.** `cat demo/roles/CREDENTIALS.local.txt`, put these on a phone or
paper, **not** on the projected screen: `command`, `officer-c`, `authority-custodian`, `admin-1`, `admin-2`,
`officer-a`, `officer-b`. (`admin-1` is typed twice — to propose, then to approve.) Practise the sequence once.
Never show the file.

**4. Windows.** Separate *browser windows* (not tabs), zoom 110–125 %, all **logged out**, each pre-loaded once:

| Window | URL | Accent | Used for |
|---|---|---|---|
| **Command** | `command.localhost:8080` | amber | release, investigate |
| **Authority** | `authority.localhost:8080` | pink | admitting officer C |
| **Officer C** | `officer-c.localhost:8080` | purple | the new officer *(will show an error until you start it — that's fine; pre-load it after step 5 of the enrolment beat, or just open it live)* |
| **Officer A** | `officer-a.localhost:8080` | green | decrypt, leak |
| **Officer B** | `officer-b.localhost:8080` | blue | decrypt, forwarding |
| **Ops** | `ops.localhost:8080` | cyan | live ledger feed → Ledger screen at the end |
| Terminal | Git Bash in the repo root | — | commands below |

Six windows is a lot. Suggested: **Ops and Command always visible**; put **Authority + Officer C side by side** for
the enrolment beat (one virtual desktop, `Win+Ctrl+→`), and **Officer A + Officer B side by side** for the next.
The accent colours and tab titles tell you which is which.

**5. Files.** `demo/sample.pdf` ready for the file picker. Downloads folder free of old `leak-*.png` / `case*.tsev`.

**6. Terminal — use Git Bash, not plain PowerShell.** In PowerShell, `bash` is the WSL launcher (a different Linux without
your Docker setup) and the `bash scripts/…` lines fail. Open **Git Bash** (Start menu), `cd` to the repo root, and run from there.
From PowerShell you can still call it explicitly: `& "C:\Program Files\Gitinash.exe" scripts/demo_actions.sh start-officer-c`.
Pre-type these (don't press Enter):

```bash
python scripts/demo_isolation.py
bash scripts/demo_actions.sh start-officer-c
python scripts/verify_offline.py "$HOME/Downloads/case.tsev"
bash scripts/demo_actions.sh tamper-ledger
```

**Known timings to plan around:** analysing the sample PDF takes **~50 s**; release ~2 s; each decrypt ~3 s;
investigation ~2 s; signing the report <1 s; officer C's workstation starts in ~5 s.

---

## Timeline

| Clock | Beat | Where |
|---|---|---|
| 0:00 | **Hook** | Ops (Command Center) |
| 0:40 | Command login + drop the PDF (50 s render starts) | Command |
| 1:00 | **Isolation proof**, narrated over the render | Terminal |
| 2:10 | **Officer C joins live** — two admins, two passphrases | Terminal → Officer C → Authority |
| 3:40 | Quality gate, release to **A, B and C** | Command |
| 4:20 | **Officers A and B decrypt** — own passphrase each | Officer A, Officer B |
| 5:05 | Forwarding refused | Officer B |
| 5:30 | **The leak travels as a file** → accusation → signed report | Officer A → Command |
| 7:00 | **Offline verification, then one bit** | Terminal |
| 7:45 | **Insider edits a ledger on disk — caught** | Terminal + Ops |
| 8:35 | Close — what is real, what is not | any |

**If you are behind schedule, cut in this order:** (1) the ledger tamper (7:45), (2) forwarding (5:05), (3) the
quality-gate commentary. **Never** cut the enrolment, the leak, or the offline verification.

---

## Beat by beat

### 0:00 — Hook (40 s) · *Ops window, Command Center*

**Do:** Ops window is already up. Click **Run live egress test** and leave the result on screen.

**Say:**
> "When a classified document leaks, the question is *who*. Almost every system answers that with a watermark added afterwards — which means a clean copy existed first, and someone had it.
> We did it the other way round. Nobody ever holds a clean copy. **The act of decrypting is what produces the fingerprint** — a different one for every officer, every time.
> This is air-gapped: that result is a live attempt to reach the internet from inside the network. It just failed.
> What you'll see are separate workstations — separate windows, containers and keys. I'll show you, and then I'll *prove* it."

### 0:40 — Command login and upload (20 s) · *Command window*

**Do:** Type the **command** passphrase → **Unlock**. Point at the bar: *keys live in container console-command*, *unlocked: sender-1, forensics-1*, the **auto-lock** countdown. **Distribute** → drop zone → `demo/sample.pdf`. Progress bar starts. Switch to the terminal.

**Say:**
> "This is the document owner. That passphrase decrypted two keys inside *this* container and nowhere else. The page is being rasterised twice, in two physically different versions of every marked word — real image processing, so it takes real seconds. While it works, let me show you what 'separate' means."

### 1:00 — The isolation proof (70 s) · *Terminal*

**Do:** **Enter** on `python scripts/demo_isolation.py`. Lines stream in over ~15 s.

**Say (point at specific lines as they appear):**
> "This isn't a slide — it's probing the running system now.
> **No container mounts a directory holding anyone's keys.** Every key file is mounted into exactly one owner — seventeen key paths audited.
> *(officer lines)* Officer A's container sees **one** keystore — its own. It cannot read B's. Same for B.
> *(egress line)* Fifteen containers, each tried to reach the internet. None can.
> *(session lines)* We log A in, take its session token and replay it against B: **refused**. A's session on B's documents: **403**. The officer console doesn't even *have* the sender's routes — a 404, not 'access denied'. You can't attack what isn't there."

**Fill (the render usually still has ~40 s):**
> "The threat we design for is a compromised workstation. If someone owns officer A's machine, they get officer A's documents and nothing else — no other officer's key is on that disk. And notice: there are only **two** officers running. A third is about to join."

### 2:10 — Officer C joins live (90 s) · *Terminal → Officer C → Authority*

**Do (terminal):** **Enter** on `bash scripts/demo_actions.sh start-officer-c` → *officer-c workstation is UP — not enrolled yet*.

**Say:**
> "Officer C's workstation wasn't even running. I've just powered it on. Before C can receive anything they have to be **enrolled** — and no single administrator can do that."

**Do (Officer C window):** log in with C's passphrase. The amber banner says *officer-c has status "not enrolled"*. Click **Request enrolment** → *Request … sent*.

**Say:**
> "C's console just built a certificate request and **signed it with C's own private key, on C's own machine**. The authority never sees that key — only a request that proves C holds it."

**Do (Authority window):** log in with the **custodian** passphrase → **Identity**. officer-c shows *NOT ENROLLED* → **Propose** → prompt *Sign as admin-1* → type admin-1's passphrase → **Sign**. The pending proposal shows **0/2 approvals**. Click **admin-1 approve** → type admin-1's passphrase. Click **admin-2 approve** → type **admin-2's** passphrase. It reads **2/2** → **Finalise enrol**.

**Say (while typing):**
> "Two-of-three administrators — and each one has to type **their own passphrase**. The system unlocks that admin's key for one signature and throws it away: there's no 'logged-in admin' who can approve twice. If I typed admin-1's passphrase for admin-2 — *(optional, 5 s)* — it's refused."
>
> *(optional beat: click **admin-3 approve**, type admin-1's passphrase → red "incorrect passphrase for admin-3")*
>
> "And the CA root key is unlocked by a separate custodian login to finalise. Three different people's secrets to admit one officer."

**Do:** switch to **Officer C** — the banner is gone and the bar now shows **C's certificate fingerprint** (refreshes within 5 s).

**Say:** "C is certified. Nobody else's key was touched, and C's key never left C's container."

### 3:40 — Quality gate and release (40 s) · *Command*

**Do:** back on **Command** — the analysis is done. Tick **Show mark positions**. Point at **Quality gate**. Tick **officer-a**, **officer-b**, **officer-c** (C appears *active* now) → **Release to 3 officers**. Ops feed shows *DOC REGISTER*.

**Say:**
> "Five pages, **245 marked word positions**, each a word shifted a pixel and a half — invisible to a person. The quality gate: similarity **0.985**, and if it ever dropped below the bar **release would be blocked, not just flagged**.
> I'm releasing to A, B and **the officer we admitted a minute ago**. The key is split five ways across five key-release nodes, committed to the ledger before anything is released."

**Say before they ask (point at the "degraded" badge):**
> "That 'degraded' badge matters: this small document can only certify resistance to **two** colluding officers, not three — and the system **tells you that** instead of overclaiming."

### 4:20 — Officers A and B decrypt (45 s) · *Officer A window, then Officer B window*

**Do (A):** type a **wrong** passphrase — refused. Then A's own → **Unlock**. Point at the bar (*keys live in container agent-officer-a*, certificate fingerprint). **Open** the document (~3 s).
**Do (B):** log in, **Open**.

**Say (A):**
> "A wrong passphrase isn't a password mismatch — it's a *cryptographic failure*: the key store simply won't decrypt. Officer A's copy was just assembled **in memory, on this workstation**, from fragments the key quorum released after committing to the ledger first. Never on disk — served with caching disabled, and wiped when this session locks."
**Say (B):**
> "Officer B opens the *same* document. To your eye: identical. But every marked word is shifted differently — a pixel and a half left or right, per officer, per session. **That is the fingerprint.** There was never a clean version — only A's, B's and C's."

**Do:** glance at Ops — *DECRYPT REQUEST, KEYGRANT, OPEN EVENT, RECEIPT*. Say: "Every decrypt is a signed ledger record."

### 5:05 — Forwarding refused (25 s) · *Officer B*

**Do:** under **Forwarding demo** click **Try doc-… as officer-a**. The red message appears.

**Say:**
> "Now B tries to open *A's* copy as if it were theirs. **Refused** — the key-release nodes check that certificate against the requester's own enrolment, it isn't B's, so no key grant is ever issued. There's nothing to forward: the copy only works for the person it was made for."

**Do not say** "…and it's logged as OPEN_DENIED" — on this path no such record is written.

### 5:30 — The leak, the accusation, the report (90 s) · *Officer A → Command*

**Do (Officer A):** under the open page, **Simulated insider leak** → **Phone photo**. A `leak-doc-….png` lands in Downloads.

**Say:**
> "Now the bad day. Officer A is the insider. This button is *our simulation* of photographing a screen — a camera model with blur, noise and perspective. To be straight: it's **synthetic**; we haven't evaluated real phone photos yet and our results file says so.
> What matters is how it travels. The investigator **cannot read A's screen** — different machine. It reaches them the way a real leak would: **as a file.**"

**Do (Command):** **Investigate** → pick the document ID → page index `0` → **Upload artifact** → that PNG → **Open investigation** (~2 s). Click **Detected → Aligned → Heatmap**. Point at the suspects.

**Say:**
> "No session ID, no log lookup — just the photo. It aligns it to the original, reads which way each marked word was shifted, and scores every decrypt session on the ledger against it.
> Of 245 marks, **about forty** are readable from a degraded photo — enough: officer A scores **about 34** against a threshold of **about 27**. The other officers score around **zero**. One accused, and only one.
> And the system's own sentence, because it matters: *'a statistical conclusion from per-position pixel correlation, suitable for investigative and evidentiary review — not a legal determination of guilt or intent.'* We won't claim more than the maths supports."

**Do:** **Issue evidence report** → *Report issued & signed* → click **case.tsev** to download.

**Credibility line (if asked how often it works):**
> "On this scenario we ran 32 simulated captures — camera and print-scan, two pages each: 32 correct, **zero** wrongly accused. Across 180 attack-lab trials, zero innocent accusations — it's in our results file."

### 7:00 — Offline verification, then one bit (45 s) · *Terminal*

**Do:** `python scripts/verify_offline.py "$HOME/Downloads/case.tsev"` *(PowerShell: `"$env:USERPROFILE\Downloads\case.tsev"`; if the browser saved `case (1).tsev`, use that)*. It prints **ORIGINAL → VALID**, then **TAMPERED → REJECTED**.

**Say:**
> "The question a defence engineer should ask: *why trust your server?* You shouldn't. That file is being verified in a container with **no network at all** — no ledger, no keys, no server. It re-checks every signature, ledger proof and commitment, and re-scores the accusation from scratch. **Valid.**
> Now I flip **one bit** inside the signed bundle… **rejected: signature verification failed.** The evidence can't be quietly edited — not by us, not by anyone."

### 7:45 — An insider edits the ledger — caught (50 s) · *Terminal + Ops*

**Do:** switch **Ops** to **Ledger** — four replicas, badge reads **quorum agrees**. Run `bash scripts/demo_actions.sh tamper-ledger` (~10–15 s). Within ~5 s the badge flips to **divergence detected** and **ledger-2** shows *first bad height 1*; the other three stay valid.

**Say (over the wait):**
> "Last attack: an insider with disk access to one ledger replica. I'm overwriting a hash in its stored history.
> *(when it flips)* **There.** Replica two reports divergence at height one; the other three still agree. We know **which** replica lied and **where** — without trusting any single node to tell us the truth about itself."

### 8:35 — Close (25 s) · *any window*

**Say:**
> "What's real and what isn't, because in this field that's the whole product. **Real:** standard post-quantum primitives — ML-KEM-768, ML-DSA-65, SLH-DSA, nothing invented; separate containers with disjoint keys; real per-person login; officers admitted only by two administrators' passphrases; a three-of-five key quorum; evidence that verifies with the network unplugged.
> **Not claimed:** separate containers on **one laptop**, not separate machines; the ledger is our lightweight LedgerLite, labelled so; the leak photo was simulated; and the accusation is a statistical conclusion, not a verdict.
> Nobody holds a clean copy. Every officer is their own machine. And nobody joins without two people agreeing. Thank you."

---

## Judge Q&A — honest answers

| They ask | Answer |
|---|---|
| *"Are those really separate machines?"* | No — separate containers with disjoint key material on one host. A compromise of the host defeats it; it's in the threat model. For production each would be its own device. |
| *"Can one admin enrol someone alone?"* | No: two of three admins, each signing with their *own* passphrase (demonstrated), plus a separate CA-custodian login. No admin key is kept in session memory. |
| *"What if officers collude and compare copies?"* | Tardos codes are built for that. Command → **Attack Lab** → **Run quick demo** (real, seeded subset); full table in `docs/RESULTS.md`. This sample certifies resistance to 2 colluders (the "degraded" badge). |
| *"Real phone photos?"* | Not evaluated yet — `attacklab/real/` is empty and `RESULTS.md` says so. Captures use a synthetic camera/scan model; the pipeline is the real one. |
| *"Is the ledger a blockchain? Post-quantum?"* | The demo runs LedgerLite (4 replicas, hash-chained, quorum-signed) — labelled simulated. A Fabric 3 SmartBFT backend is built and verified; Fabric's own transport stays classical (stated in the docs). Application signatures are post-quantum. |
| *"Retyping the text or reading it aloud?"* | Out of scope — not attributable by this system. We don't claim it. |
| *"Legally admissible?"* | We claim only "suitable for investigative and evidentiary review." Not a legal determination. |
| *"Why 50 seconds to analyse?"* | It renders two pixel-variants of 245 word positions across five pages and runs the quality gate. Real work. |
| *"Is the passphrase MFA?"* | The passphrase *is* the keystore decryption key (Argon2id). Single factor, demo-grade, typed on stage. Hardware tokens are the production answer. |
| *"What if a session is stolen?"* | 256-bit random token stored hashed, HttpOnly + SameSite=Strict, 5-minute idle auto-lock that wipes decrypted pages, valid only on the console that issued it. |
| *"What if a key-release node dies?"* | Three of five suffice — see Reserve: we kill one live, and decryption still works; below three it refuses. |

## Say / don't say

- **Don't say** "denied and logged as OPEN_DENIED" for the forwarding attempt: it is refused by the key-release nodes; no ledger record is written on that path.
- **Don't say** "separate machines", "real phone photo", "proves guilt", "legally admissible", "Fabric is running" (this demo runs LedgerLite).
- **Do say** "simulated", "statistical conclusion", "separate containers on one host", "the system tells you what it can and can't certify".

## If something goes wrong

| Symptom | Fix (≤ 15 s) |
|---|---|
| A window shows the login again | Its idle auto-lock fired — log in again; that's the feature. (Pages are wiped; re-**Open** the document.) |
| Officer C's window says "API unavailable" | Its workstation isn't running: `bash scripts/demo_actions.sh start-officer-c`, wait ~5 s, reload. |
| Authority → **Propose** says "has not submitted an enrolment request" | Do **Request enrolment** on Officer C's window first (it logs in with C's own passphrase). |
| "incorrect passphrase for admin-N" | You typed another admin's passphrase. Retry with the right one (5 failures per admin trigger a backoff). |
| Command's Distribute doesn't list officer-c as active | Wait ≤ 5 s (it refreshes), or switch screens and back. |
| Analysis still running when you return | Keep talking about the line you were on; it finishes ~50 s after the drop. Don't click. |
| Investigate: "was not released via this session" | The Command console was restarted; release the document again (50 s). |
| Download not found | Browser saved it as `case (1).tsev` — pass that name. |
| Accusation looks weak | Re-capture with **Print + scan** instead of **Phone photo** (measured scores slightly higher). |
| Everything is broken | `bash scripts/roles.sh provision` (~4 min; resets and re-enrols A and B), then the `up -d --no-build …` line above. |

## Reserve (only if time remains or a judge asks)

- **Kill a key-release node.** `bash scripts/demo_actions.sh kill-node`, then **Open** again on Officer B — still opens (three of five). Then `kill-quorum` and **Open**: refused (*only 2 shares obtained, need >= 3*). **Always** finish with `bash scripts/demo_actions.sh restore-nodes` and wait ~5 s — the investigation needs those nodes.
- **Collusion.** Command → **Attack Lab** → **Run quick demo**.
- **Air gap, again.** Command Center → **Run live egress test**.
- **Re-run the proof.** `python scripts/demo_isolation.py --no-login` (the flag keeps browser sessions alive).

## Corrections vs. the earlier script

The older `docs/JUDGE_DEMO_SCRIPT_9MIN.md` still says a forwarding attempt is "denied and logged as OPEN_DENIED" and describes the
single-console demo. That claim is inaccurate (verified on the running stack) — use this script instead.
