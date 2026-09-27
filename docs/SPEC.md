# TraceSeal — Master Build Spec

> Source of truth for the project. `CLAUDE.md` at the repo root is a working
> summary of this document plus process rules; when they disagree, this file
> wins unless a later ADR in `DECISIONS.md` supersedes it.

---

## 0. Role and how to work

Lead engineer building **TraceSeal**, an offline, air-gapped platform for
secure multi-recipient document distribution with post-quantum signatures,
per-decryption forensic fingerprints, and a tamper-evident ledger. It is a
Smart India Hackathon entry for Problem Statement 26237 (Ministry of Defence,
Indian Navy / WESEE). The judges are defence and security engineers.
Correctness and honesty matter more than visual flash.

Working rules:

1. **First action:** create `CLAUDE.md` (a concise summary of this spec, the
   rules below, and the commands to build, test and demo) and
   `docs/ARCHITECTURE.md` (a component diagram in Mermaid plus the protocol
   sequence diagrams from Section 7). Then enter plan mode and propose the
   plan for Milestone M0 only.
2. **Build milestone by milestone** (Section 17). Do not start a milestone
   until the previous one's acceptance criteria pass. At the end of each
   milestone, run the full test suite and `make demo-m<N>`, then summarise
   what works, what is simulated, and what is next.
3. **Never fake security.** No hardcoded "VALID" results, no mocked signature
   verification outside unit-test doubles, no invented metrics. If something
   is simulated (for example LedgerLite instead of Fabric), label it in the
   UI and README.
4. **Zero runtime network egress.** Every container runs on an internal
   Docker network (`internal: true`). No CDNs, no Google Fonts, no telemetry,
   no cloud APIs, no remote model downloads at runtime. Vendor all frontend
   assets. Build-time downloads are allowed only in Dockerfiles, with pinned
   versions and checksums.
5. **Use standard primitives only.** Never invent cryptography. Use liboqs
   for ML-KEM, ML-DSA and SLH-DSA, and `cryptography` for AES-GCM and HKDF.
6. **Ask before** changing the core protocol, adding a heavyweight
   dependency, or dropping a requirement. For everything else, make a
   sensible decision and record it in `docs/DECISIONS.md` (ADR style, 3 to 6
   lines each).
7. Keep functions small and typed (Python type hints plus mypy; TypeScript
   strict). Every security-relevant function gets unit tests, including
   negative tests.

---

## 1. The problem (requirements checklist)

Track these IDs in `docs/REQUIREMENTS_TRACE.md`, mapping each to code and tests.

| ID | Requirement |
|---|---|
| R1 | Unique, invisible forensic watermark generated **at the moment of decryption** |
| R2 | Watermark specific to each recipient **and** each decryption session |
| R3 | All decrypted copies visually identical, forensically distinct |
| R4 | Each decryption event cryptographically bound to the recipient's identity |
| R5 | Decryption record signed with the **recipient's own private key** |
| R6 | NIST PQC for key exchange (ML-KEM, FIPS 203) and signatures (ML-DSA FIPS 204 / SLH-DSA FIPS 205) instead of classical algorithms |
| R7 | Immutable audit layer on blockchain / DLT |
| R8 | No single administrator or compromised account can alter or delete audit records |
| R9 | Extract the watermark from a leaked copy |
| R10 | Look up the extracted watermark against the ledger |
| R11 | Return a cryptographically verifiable record identifying the responsible recipient |
| R12 | Fully offline and air-gapped operation |
| R13 | No cloud KMS dependency |
| R14 | No public blockchain dependency |

Additional product goals:

| ID | Goal |
|---|---|
| G1 | Copies are bound to their owner. A forwarded copy cannot be opened by anyone else, and the failed attempt is logged. |
| G2 | Attribution survives screenshots, JPEG compression, crops, phone photos of a screen, and print-and-scan. |
| G3 | Collusion-resistant: 2 or 3 recipients mixing their copies are still traced, with a provable false-accusation bound. |
| G4 | A standalone verifier lets a third party check an evidence bundle without trusting the TraceSeal server. |
| G5 | No single admin can enrol a ghost identity or swap someone's keys (anti-framing). |

---

## 2. The core idea (do not deviate)

**Decryption itself produces the fingerprint. A clean plaintext never exists
anywhere after the sender's preparation step.**

This follows the proven traitor-tracing pattern used by broadcast content
protection (AACS "sequence keys"), applied to documents:

1. The sender's station rasterises each page of the PDF and selects **mark
   positions** (word boxes). For each position it renders two visually
   indistinguishable variants (bit 0 and bit 1), then removes those regions
   from the base page.
2. The base pages are encrypted under `K_base`, derived from `K_A ⊕ K_B`.
   Each variant patch is encrypted under its own key, derived from a variant
   master secret `S_v`.
3. **One distribution package**, identical for all recipients ("broadcast
   encrypt"), contains the encrypted base pages and **both** encrypted
   variants of every position. `K_A` is wrapped to each recipient's ML-KEM
   public key by the sender.
4. `K_B` and `S_v` are Shamir-split 3-of-5 across **Key-Release nodes** run by
   different authorities. These nodes never see `K_A`, so they can never
   decrypt content.
5. To decrypt, a recipient signs a decryption request with ML-DSA. The
   Key-Release nodes assign a fresh **Tardos codeword** to the session and
   commit the signed record to the ledger. **Only after ledger finality** do
   they issue a **KeyGrant**: `K_B` plus exactly one variant key per position
   (the ones selected by the codeword), wrapped to the recipient's ML-KEM key.
6. The recipient's agent reconstructs the pages. The assembled copy is
   fingerprinted by construction, because the recipient holds only one
   variant per position. A modified client cannot produce an unmarked copy.
7. For a leak, the forensic station (which holds the originals and both
   variants in a sealed vault) performs **informed** detection per position,
   runs Tardos accusation, and verifies the ledger evidence chain.

Residual trust assumption (state it in docs and the pitch): framing an
innocent recipient would require the sender **and** a threshold of
Key-Release nodes to collude. Asymmetric fingerprinting is future work.

---

## 3. Security non-negotiables

- AES-256-GCM with random 96-bit nonces. The AAD always includes the
  SHA3-256 hash of the relevant header. Never reuse a nonce under the same key.
- Key derivation: HKDF-SHA3-256 with explicit, versioned `info` strings (for
  example `b"traceseal/v1/variant/" + doc_id + idx + bit`).
- ML-KEM-768 for all key wrapping, using a KEM-DEM construction (encapsulate,
  HKDF the shared secret, then AES-GCM the payload).
- ML-DSA-65 for all operational signatures. SLH-DSA-SHA2-128s for the offline
  root CA and ledger checkpoints.
- Private keys are generated **on the owner's agent** and never leave it.
  Keystores are encrypted with Argon2id-derived keys; seal to TPM if
  available (optional, behind a flag).
- Recipient-side plaintext exists **only in memory**. No temp files, no
  swap-able caches. Zero buffers where the language allows.
- Every signed structure uses canonical CBOR (deterministic encoding) and
  includes `version`, `domain` (a signing-context string) and `nonce`, which
  prevents cross-protocol and replay attacks.
- Every ledger write is idempotent on `(type, session_id)`. Duplicate nonces
  are rejected.
- Constant-time comparison for all MACs, hashes and tokens.

---

## 4. Components

| Component | Responsibility |
|---|---|
| `ca` | Offline root CA (SLH-DSA) issuing ML-DSA and ML-KEM certificates, after the enrolment quorum approves on the ledger |
| `sender-station` | Document intake, rasterisation, mark-position selection, variant rendering, packaging, `K_A` wrapping, quality gate |
| `keyrelease` (x5) | Shamir shares of `K_B` and `S_v`; codeword assignment; commit-before-release; KeyGrant issuance |
| `ledger` | `LedgerBackend` interface with two implementations: **LedgerLite** (4 replicas with an ML-DSA 3-of-4 quorum, for development) and **Fabric 3.x SmartBFT** (the target) |
| `recipient-agent` | One per officer workstation (localhost). Holds the keystore, signs requests, unwraps grants, assembles pages in memory, serves them to the viewer, enforces copy binding (G1) |
| `forensics` | Artifact intake, page identification, alignment, per-position detection, Tardos accusation, evidence verification, signed report |
| `verifier-cli` | Standalone `traceseal-verify bundle.tsev` that checks everything offline (G4) |
| `attack-lab` | Reproducible distortion and collusion harness with metrics |
| `web` | React UI for the Command Center, Distribute, Inbox/Viewer, Monitor, Investigate, Ledger, Identity and Attack Lab |

---

## 5. Tech stack (pinned)

- **Python 3.12**: FastAPI, Pydantic v2, SQLAlchemy 2 + Alembic,
  `liboqs-python` (built against a pinned liboqs release inside Docker),
  `cryptography`, `argon2-cffi`, `cbor2`, PyMuPDF, OpenCV (headless), NumPy,
  SciPy, scikit-image (SSIM), Pillow, Tesseract via `pytesseract`, `pytest`,
  `hypothesis`, `mypy`, `ruff`.
- **Frontend**: React 18 + TypeScript (strict) + Vite + Tailwind + shadcn/ui +
  TanStack Query + Zustand + Recharts. All fonts and assets are local.
  Optional later: wrap in Tauri for a desktop feel.
- **Storage**: PostgreSQL 16 (metadata); MinIO or a local filesystem blob
  store (ciphertext only).
- **Ledger target**: Hyperledger Fabric 3.x with the SmartBFT orderer,
  chaincode in Go. The chaincode verifies ML-DSA signatures inside records
  using Cloudflare CIRCL.
- **Deployment**: Docker Compose, `make` targets, internal network only.
- **Shamir**: implement GF(256) byte-wise Shamir yourself (small, well
  tested) or use a vetted library. Add test vectors either way.

---

## 6. Repository layout

```
traceseal/
  CLAUDE.md
  Makefile
  docker-compose.yml
  docs/ SPEC.md ARCHITECTURE.md DECISIONS.md REQUIREMENTS_TRACE.md THREAT_MODEL.md DEMO_SCRIPT.md RESULTS.md
  packages/
    tscore/          # shared Python lib: crypto, cbor schemas, shamir, tardos, formats
    sender/          # sender-station service
    keyrelease/      # key-release node service
    ledger/          # LedgerBackend interface + LedgerLite + Fabric adapter
    agent/           # recipient-agent
    forensics/       # forensic engine + service
    verifier/        # standalone CLI (depends only on tscore)
    attacklab/       # distortion + collusion harness
  chaincode/traceseal/   # Go chaincode (M6)
  fabric-network/        # Fabric 3 SmartBFT config (M6)
  web/                   # React app
  demo/                  # seed script, sample classified-style PDF (synthetic content only)
  tests/                 # integration + e2e
```

---

## 7. Protocols (implement exactly; drawn as Mermaid sequence diagrams in ARCHITECTURE.md)

### 7.1 Enrolment (G5)

1. The officer's agent generates ML-DSA-65 and ML-KEM-768 key pairs locally
   and creates a CSR signed with ML-DSA.
2. An admin submits `ENROLL_PROPOSE{officer_id, unit, role, csr_hash}` to the
   ledger.
3. At least **M-of-N approvers** (default 2 of 3, configurable) submit
   `ENROLL_APPROVE`, each ML-DSA signed.
4. The CA issues certificates only after the ledger shows quorum approval.
   The certificate hash goes on the ledger as `ENROLL_FINAL`.
5. Revocation mirrors this: `REVOKE_PROPOSE` plus quorum, then
   `REVOKE_FINAL`. Every service checks certificate status against the
   ledger state.

### 7.2 Document registration and distribution

1. The sender uploads a PDF and selects recipients from the identity
   registry (**public keys only**) and a policy (expiry, max opens, export
   allowed or denied).
2. The sender station builds the package (Section 9), runs the quality gate,
   generates `K_A` and `K_B` and `S_v`, sends Shamir shares of `K_B` and
   `S_v` to the 5 Key-Release nodes (each share wrapped to that node's
   ML-KEM key), and wraps `K_A` to each recipient.
3. The ledger records
   `DOC_REGISTER{doc_id, H(package), recipient_cert_hashes[], policy_hash, positions_count, tardos_params}`,
   signed by the sender.
4. The sender station then securely erases `K_A`, `K_B` and `S_v` from
   memory. The original plus the variant set goes to the **forensic vault**
   (encrypted under the forensic station's ML-KEM key).

### 7.3 Decryption session (R1 to R5, commit-before-release)

1. The recipient agent builds
   `DecryptRequest{doc_id, H(package), recipient_cert_hash, session_id, nonce, agent_time}`
   and signs it with ML-DSA.
2. A Key-Release coordinator verifies the signature, certificate status,
   policy (expiry, open count) and replay protection.
3. Codeword assignment: `X_session ~ Tardos(p)` using the document's secret
   bias vector `p`. Compute `commit = SHA3-256(doc_id ‖ session_id ‖ X ‖ salt)`.
   Store `(X, salt)` encrypted to the forensic vault key.
4. Ledger write: `DECRYPT_REQUEST{request, signature, codeword_commitment}`.
   **Wait for finality** (quorum certificate).
5. At least 3 nodes contribute shares. The coordinator reconstructs `K_B`
   and `S_v` transiently, derives the selected variant keys `k_{i, X_i}`,
   builds `KeyGrant{session_id, K_B, [k_{i,X_i}]}`, and wraps it to the
   recipient's ML-KEM key. The ledger records
   `KEYGRANT_ISSUED{session_id, H(grant_ciphertext)}`, co-signed by the
   contributing nodes. Zeroise the secrets.
6. The agent unwraps the grant, computes `K_base = HKDF(K_A ⊕ K_B)`, decrypts
   the base pages and the selected variants, assembles the pages **in
   memory**, and returns `RECEIPT{session_id, H(assembled_pages)}` signed
   with ML-DSA. The ledger records it.

### 7.4 Copy binding and open events (G1)

- Every package delivered to a recipient carries a
  `SealedHeader{session_id?, recipient_cert_hash, doc_id, policy_id}` signed
  by the Key-Release quorum.
- On open, the agent requires a keystore unlock, verifies the header
  signature, and checks `recipient_cert_hash == local identity`. On a match
  it proceeds and logs `OPEN_EVENT`. On a mismatch it refuses and logs
  `OPEN_DENIED{presented_by, owner, doc_id}`. This is the
  **forwarding-detection** feature.
- Offline queueing: if the ledger is unreachable, the agent queues signed
  events and flushes them later. It never opens a document without, at
  minimum, the queued signed event.

### 7.5 Investigation (R9 to R11)

1. The investigator uploads an artifact (PDF, PNG or JPG, screenshot, phone
   photo, or scan). The ledger records
   `INVESTIGATION_OPENED{case_id, H(artifact)}`.
2. The forensic pipeline (Section 11) produces the suspects and their scores.
3. For each suspect session: reveal `(X, salt)` from the vault, check the
   commitment on the ledger, and verify the DecryptRequest ML-DSA signature,
   the KeyGrant co-signatures, the receipt, the ledger inclusion proof and
   the quorum certificates.
4. Produce an **evidence bundle** `case.tsev` (a zip containing canonical
   CBOR and JSON, the artifact hash, the extracted soft bits, accusation
   scores, threshold, parameters, ledger proofs, certificates and the signed
   report), plus a human-readable PDF report. The bundle is signed by the
   forensic station (ML-DSA) and committed as `REPORT_ISSUED`.
5. `traceseal-verify case.tsev` must independently re-verify every
   signature, commitment, inclusion proof and the accusation arithmetic,
   using only `tscore`.

---

## 8. Formats

- All wire and ledger objects are Pydantic models with canonical CBOR
  encoding, carrying `version: 1` and `domain` strings such as
  `"traceseal/decrypt-request/v1"`.
- The distribution package (`.tspkg`) holds a manifest (page sizes, DPI,
  position table with page index, bounding box and patch shape), the
  encrypted base pages (one AES-GCM blob per page) and the encrypted
  variants (two blobs per position).
- Ledger records are generic `{type, payload_cbor, signatures[], prev_hash}`.
  Block = `{height, records_merkle_root, prev_block_hash, median_time,
  quorum_cert[]}`. Checkpoints every K blocks are signed with SLH-DSA by the
  root authority.

---

## 9. Variant / watermark engine (the heart of the product)

**Decision: sealed documents are distributed as rasterised pages** (300 DPI,
lossless PNG inside the encrypted package). This removes copy-paste text,
covers embedded images, and makes variants precise. Record it as an ADR.

Mark positions:
- Use PyMuPDF word boxes. Prefer words of 4 or more characters, spread
  uniformly over the page area. Enforce a minimum spacing and cap the count
  per page. Skip headers and footers, which are likely to be cropped.
- Target a total length `ℓ` from the Tardos parameters (Section 10). If the
  document is too short to reach `ℓ`, the UI warns and lowers the supported
  coalition size `c0`.

Variant types (implement A first; B and C are behind flags and evaluated in
the attack lab):
- **A. Micro-shift:** variant 0 is shifted by `-δ` and variant 1 by `+δ`
  horizontally (and optionally vertically), with `δ` tunable (start at 2 px
  at 300 DPI, about 0.5 pt). Re-render from the vector page so there are no
  resampling artefacts.
- **B. Glyph micro-scale:** width scale `1 ± ε` (start at ε = 0.02) anchored
  at the word centre.
- **C. Stroke-weight / intensity micro-variation**, a small morphological
  change for print robustness.

Base page = the page with every mark region replaced by background (white,
or an inpainted local background). Each patch is the word region plus
padding, so assembly is a simple paste.

**Quality gate (R3):** for every assembled page, compare
variant-0-everywhere against variant-1-everywhere using SSIM and a
maximum-pixel-delta report. A page must meet SSIM ≥ 0.98 (tunable) against
the original rendering. Produce a side-by-side visual diff report and fail
packaging if the gate fails.

Optional extension (after M8): q-ary alphabets (four shift directions) for
shorter codes.

---

## 10. Tardos fingerprinting (G3)

- Implement the **binary symmetric Tardos scheme** (Škorić et al. score
  function) with the arcsine bias distribution and cutoff `t`.
- Parameters per document: `n` (number of recipients, including expected
  future sessions), `c0` (maximum coalition, default 3), `ε1`
  (false-accusation bound, default 1e-4). Compute
  `ℓ ≈ ⌈π²/2 · c0² · ln(n/ε1)⌉`, then add margin. Document the formula and
  its asymptotic nature, and validate empirically.
- Accusation uses **soft or erasure-aware scores**: positions not detected
  (cropped, unreadable) are skipped, and the threshold `Z` is rescaled to the
  number of observed positions. Output every session with score > Z, plus
  the scores of all sessions, so a histogram can be shown.
- Tests: a Monte-Carlo simulation (a Hypothesis/pytest suite marked slow)
  showing that the empirical innocent-accusation rate is ≤ ε1 and the
  coalition detection rate for c ≤ c0 under the attack strategies majority,
  minority, random, interleave and all-0/all-1.

---

## 11. Forensic pipeline

1. **Normalise:** decode the artifact. For a PDF, render it at 300 DPI.
2. **Page detection:** document contour detection plus a perspective-
   correction homography for photos, with fallbacks (full frame; manual
   4-corner selection in the UI).
3. **Identify document and page:** OCR the text (Tesseract, offline, `eng`)
   and fuzzy-match it against the vault; use a perceptual-hash tiebreak.
4. **Fine registration:** ORB or AKAZE features matched against the original
   base-plus-variant-0 rendering, then a RANSAC homography, then local ECC
   refinement (`cv2.findTransformECC`) per region.
5. **Per-position decision (informed detection):** for each position, crop
   the aligned region and compute normalised cross-correlation against
   rendered variant 0 and variant 1 (after the same blur the attack
   introduces; estimate the blur from edge sharpness). Output a soft value
   `s_i ∈ [-1, 1]` and a confidence. If confidence is below threshold, mark
   an erasure.
6. **Accusation:** run Tardos over all issued sessions for that document.
7. **Evidence verification:** as in Section 7.5.
8. **Report:** a statistical conclusion only, for example "consistent with
   session S-xxxx issued to Officer C; score 41.2 against threshold 18.7
   (ε1 = 1e-4); N positions observed; all cryptographic checks VALID". Never
   claim guilt or intent. Always include a limitations section.

---

## 12. Ledger

```python
class LedgerBackend(Protocol):
    def submit(self, record: SignedRecord) -> TxId: ...
    def wait_final(self, tx: TxId, timeout_s: float) -> FinalityProof: ...
    def get(self, tx: TxId) -> tuple[SignedRecord, InclusionProof]: ...
    def query(self, type: str, **filters) -> list[SignedRecord]: ...
    def verify_chain(self) -> ChainReport: ...   # per-replica integrity + cross-replica agreement
```

- **LedgerLite (M1 to M5):** 4 replica processes with separate volumes and
  separate ML-DSA keys. A leader proposes a block, and it becomes final at
  ≥ 3 of 4 signatures (the quorum certificate). There is no view change;
  label it "tamper-evident replicated log, not full BFT". `verify_chain`
  detects a direct database edit on any single replica and shows which
  replica diverged.
- **Fabric 3.x SmartBFT (M6):** 4 orderers across 4 organisations plus
  peers. Go chaincode validates record schemas, **verifies ML-DSA signatures
  in payloads** (CIRCL), enforces idempotency and enrolment quorum rules, and
  stores records. Validator organisations additionally co-sign block hashes
  with ML-DSA; the co-signatures are stored in the next block. Document that
  Fabric's internal transport is still ECDSA and that evidence verification
  depends only on PQC signatures. A stretch goal is a PQC BCCSP fork.
- **SLH-DSA checkpoints** every K blocks are exported to a file and a
  printable QR sheet ("write-once media").

---

## 13. Policy

Per document: expiry, maximum sessions per recipient, maximum opens, export
allowed (demo flag), print allowed, and whether a re-auth is required per
open. The agent enforces local rules; Key-Release enforces session issuance.
Policy violations become ledger events.

---

## 14. UI (serious security-software aesthetic: dark neutral, one accent colour, dense but readable)

1. **Command Center:** an air-gap status panel (network interfaces, egress
   test result, "Cloud dependencies: NONE"), counts of documents, sessions,
   open investigations and ledger height, a chain-integrity badge per
   replica, and recent events.
2. **Identity:** the registry with enrolment proposals, approvals progress
   (M-of-N), and a revocation flow.
3. **Distribute:** upload a PDF, pick recipients and policy, see the
   mark-position overlay (debug toggle), the quality-gate report and the
   Tardos parameters, then release.
4. **Officer Inbox / Viewer** (served via each officer's agent; the demo
   runs 5 agents): unlock keystore, open, view pages. Include a "switch
   officer" demo control and a forwarding demo (try to open another
   officer's copy, see it denied, and see the event appear).
5. **Monitor:** a session timeline per document (request, finality, grant,
   receipt, opens).
6. **Investigate:** upload an artifact and watch live pipeline stages with
   the intermediate images (detected page, aligned overlay, per-position
   heatmap of soft bits), a suspects table with a score histogram and
   threshold line, and an **Evidence Graph** (document, session, recipient,
   signatures, ledger blocks, artifact, report; clickable nodes). Export the
   `.tsev` bundle and the PDF report.
7. **Ledger:** integrity per replica, a tamper-detection view, and "view
   cryptographic proof" drill-downs. No crypto-exchange-style block explorer.
8. **Attack Lab:** run suites and view the results tables and charts from
   `docs/RESULTS.md`.

---

## 15. Attack lab (G2, G3; results must be real)

- Distortions (seeded and reproducible): JPEG q ∈ {90, 70, 50, 30}; resize
  ×{0.75, 0.5}; crop {10, 30, 50}%; rotation ±{1, 3}°; perspective warp;
  Gaussian blur σ ∈ {0.5, 1, 1.5}; noise; brightness and contrast; a
  simulated screen-camera pipeline (resample, moiré pattern, gamma, blur,
  noise, JPEG); a simulated print-scan pipeline (halftone, blur, noise,
  slight rotation).
- A real-capture folder `attacklab/real/` for phone photos and scans added
  manually. The harness evaluates them identically.
- Collusion: c ∈ {2, 3, 4} using per-position strategies (majority, minority,
  random, interleave) and patch averaging.
- Metrics per condition: bit error rate on detected positions, erasure rate,
  top-1 correct attribution, innocent accusations across all sessions, and
  runtime. Write a markdown table to `docs/RESULTS.md` and a CSV to
  `attacklab/out/`.
- **Never** edit results by hand. The table header records the git commit,
  the parameters and the seed.

---

## 16. Testing

- Unit: KEM-DEM round trip and tamper rejection; ML-DSA sign/verify plus a
  wrong-key rejection; Shamir with any 3-of-5 and a 2-of-5 failure; HKDF
  domain separation; canonical CBOR determinism; the Tardos simulation;
  variant assembly determinism; the quality gate.
- Negative and security: replay of a DecryptRequest, a forged signature, a
  revoked certificate, opening another officer's copy, KeyGrant before
  finality (must be impossible), editing one LedgerLite replica's database,
  a tampered package byte, a tampered evidence bundle (the verifier must
  fail).
- End-to-end: `make e2e` enrols 5 officers, distributes a document, runs 5
  sessions, leaks officer C's copy via simulated screen capture,
  investigates, and verifies the bundle with the CLI. It must pass in CI
  with no network.

---

## 17. Milestones and acceptance criteria

| M | Scope | Acceptance |
|---|---|---|
| M0 | Repo skeleton, Compose, `tscore` crypto wrappers (liboqs), CBOR schemas, Shamir, CLAUDE.md and docs skeleton | Crypto unit tests green; `make up` starts all containers with no egress (proven by a test that attempts an external connection and expects failure) |
| M1 | Variant engine + quality gate + Tardos library | A 3-page sample PDF produces 5 assembled copies; the quality gate passes; the Tardos simulation meets its bounds |
| M2 | Forensics on clean screenshots | Top-1 attribution across 5 sessions from clean PNG screenshots is 100%, with 0 innocent accusations |
| M3 | Full crypto protocol: sender, key-release x5, agent, LedgerLite, commit-before-release, receipts | `make e2e` passes; the grant-before-finality test proves it is impossible |
| M4 | Copy binding, open events, forwarding detection, enrolment quorum, revocation | Negative tests pass; the UI demo shows OPEN_DENIED |
| M5 | Evidence bundle + standalone verifier + signed PDF report + UI Investigate flow with Evidence Graph | Verifier passes on a genuine bundle and fails on each tampering case |
| M6 | Fabric 3 SmartBFT backend + Go chaincode with ML-DSA verification + ML-DSA block co-signing + SLH-DSA checkpoints | The e2e passes on Fabric; LedgerLite remains selectable |
| M7 | Attack lab: synthetic suites, real-capture evaluation, collusion; tune δ and ε | `docs/RESULTS.md` is generated; phone-photo and print-scan results are reported honestly |
| M8 | UI polish, Command Center, demo script, threat model, pitch assets | `make demo` runs the full story in under 10 minutes |

---

## 18. Demo script (`make demo`, documented in docs/DEMO_SCRIPT.md)

1. Show the Command Center: air-gap status is green and the egress test
   failed as expected.
2. Enrol officers A to E with M-of-N approvals. Show that a single admin
   cannot enrol a ghost identity.
3. Distribute `OPERATION_PLAN.pdf` (synthetic content) to A to E and show
   the quality gate.
4. Open all 5 copies side by side: visually identical.
5. Officer D tries to open Officer C's copy: denied, and the event appears
   live.
6. Leak: Officer C's page is photographed with a phone (or simulated).
   Investigate and name session S-xxxx (Officer C) with score, threshold and
   ε1. All signatures and proofs are VALID.
7. Collusion: A, B and C merge their copies; all three are accused and no
   innocents.
8. Insider attack: edit one ledger replica's database directly; integrity
   fails on that replica and the quorum holds.
9. Export the evidence bundle and verify it on a separate machine with
   `traceseal-verify`. Tamper with one byte and show that verification
   fails.

---

## 19. Documentation deliverables

`README.md` (quick start and honest limitations), `ARCHITECTURE.md`,
`THREAT_MODEL.md` (STRIDE table covering each attack and its mitigation,
plus residual risks: the analog hole via retyping, sender and key-release
collusion framing, compromise of the officer's endpoint while viewing),
`DECISIONS.md`, `REQUIREMENTS_TRACE.md`, `RESULTS.md`, `DEMO_SCRIPT.md`.

---

## 20. Out of scope / honesty rules

- Do not claim legal admissibility. Say "suitable for investigative and
  evidentiary review".
- Do not claim protection against someone retyping or reading the document
  aloud. It is out of scope; the semantic canary layer is future work.
- Do not claim Fabric is PQC end-to-end unless the BCCSP fork is actually
  implemented.
- The demo uses only synthetic documents and synthetic officers.
