# TraceSeal

An offline, air-gapped platform for secure multi-recipient document
distribution with post-quantum signatures, per-decryption forensic
fingerprints, and a tamper-evident ledger. Built for Smart India Hackathon
Problem Statement 26237 (Ministry of Defence / Indian Navy / WESEE).

The core idea: **decryption itself produces the forensic fingerprint** — a
clean, unwatermarked plaintext never exists anywhere after the sender's
preparation step. See [`docs/SPEC.md`](docs/SPEC.md) Section 2 for the full
protocol and [`docs/ARCHITECTURE.md`](docs/ARCHITECTURE.md) for the
component and sequence diagrams.

## Status: Milestone M7 — complete and verified

**M0** (crypto/schema core), **M1** (variant/watermark engine, quality
gate, Tardos library), **M2** (forensics on clean screenshots), **M3**
(full crypto protocol: sender, 5 key-release nodes, a 4-replica ledger, the
recipient agent, commit-before-release, receipts), **M4** (enrolment
quorum, revocation, copy binding, forwarding detection), **M5** (evidence
bundle, standalone verifier, signed PDF report), **M6** (Fabric 3 SmartBFT
ledger backend), and **M7** (attack lab: distortion + collusion harness)
are all done. All acceptance criteria pass for real, in Docker:

- `packages/tscore`: 88 fast unit tests + the 6-strategy Tardos
  Monte-Carlo suite, against a real liboqs 0.16.0 build — including
  `tscore.evidence`'s full genuine-bundle-plus-6-tampering-case suite,
  the single cryptographic re-verification core `forensics` (builder) and
  `verifier` (checker) both call.
- The no-egress proof: DNS resolution and outbound TCP both fail from
  inside the `internal: true` network.
- `packages/sender`: 21 unit tests, plus `make demo-m1` — a synthetic
  3-page document, 147 real mark positions, 5 assembled per-session
  copies, quality gate PASS (whole-page SSIM ≥ 0.98).
- `packages/forensics`: 16 unit tests (11 from M2 plus 5 new M5
  investigation-pipeline tests, wired against a real in-process ledger +
  key-release cluster), plus `make demo-m2` — 5/5 leaked sessions
  correctly attributed from a simulated rescaled screenshot, 0 innocent
  accusations, via real ORB/RANSAC image registration and per-position
  correlation detection (not a lookup or a mock).
- `packages/ca`, `packages/ledger`, `packages/keyrelease`, `packages/agent`:
  16 + 20 + 11 + 9 unit tests, plus `make e2e`/`make demo-m4` — a real
  9-container run (4 ledger replicas, 5 key-release nodes) where every
  officer is admitted through a genuine 2-of-3 admin quorum ceremony (no
  seed-script shortcut), the sender registers and distributes an encrypted
  document, and each officer independently runs a real decrypt session: a
  signed `DecryptRequest` cross-checked against that officer's real
  enrolled certificate, a ledger-finalized commitment, a quorum-issued
  `KeyGrant` plus a co-signed `SealedHeader`, an in-memory-only assembled
  copy, and a finalized `Receipt` — all real ML-KEM-768/ML-DSA-65, no
  mocked verification anywhere in that path. Revoking an officer's
  certificate and re-attempting a decrypt is denied server-side; an
  officer self-declaring a different officer's identity is denied both
  server-side and by the agent's own independent `SealedHeader` quorum
  check. The key-release layer's "grant-before-finality is impossible"
  property is directly tested, not just claimed
  (`keyrelease.tests.test_integration`).
- `packages/verifier`: 5 unit tests, plus `make demo-m5` — a real
  9-container run where `forensics` opens an investigation on the ledger,
  reveals the leaking session's codeword from the key-release vault
  (cross-checked against the ledger's own commitment before being
  trusted), independently re-derives the Tardos score, and builds,
  self-checks, signs, and writes a genuine `EvidenceBundle` plus a signed
  PDF report (with a mandatory limitations section) as `case.tsev`. The
  standalone `traceseal-verify` CLI — a package that depends on
  `packages/tscore` **only** (no `ledger`/`ca`/`forensics`/`sender`
  import anywhere, enforced literally by its Dockerfile never copying
  them in, and confirmed directly: `python -c "import pkgutil; ..."`
  inside that image lists only `tscore` and `verifier`) — independently
  re-verifies the genuine bundle as **VALID (exit 0)**, then a
  one-byte-tampered copy as **INVALID (exit 1)**. This is the M5
  acceptance criterion, demonstrated against a live cluster, not a
  simulated or hand-waved pass.
- `make demo-m6` — a real 4-organization Hyperledger Fabric 3.1.5 network
  (4 independent orderer MSPs running SmartBFT consensus, 4 peer MSPs, no
  system channel — Fabric 3.x's Channel Participation API bootstrap
  instead) running a real Go chaincode (`chaincode/traceseal`) that
  verifies ML-DSA-65 and SLH-DSA-SHA2-128s signatures via Cloudflare
  CIRCL, confirmed to genuinely interoperate with `liboqs`-produced
  signatures (`chaincode/traceseal/interop_test.go`, including
  tampered-signature negative cases for both algorithms). The identical
  M3/M4 protocol scenario — enrolment, document registration, and all 5
  officers' decrypt sessions — ran against this network end-to-end via
  `LEDGER_BACKEND=fabric`, with zero protocol-level code changes outside
  the ledger-client construction sites (`ledger.backend.build_ledger_client`).
  A real ≥3-of-4 ML-DSA validator co-signing pass and a signed SLH-DSA
  checkpoint export both ran for real. LedgerLite remains the default
  backend everywhere else, and its own test suites are unaffected by the
  backend refactor (still green).
- `make demo-m7` — every spec Section 15 synthetic distortion (JPEG q in
  {90,70,50,30}, resize x{0.75,0.5}, crop {10,30,50}%, rotation
  ±{1,3}°, perspective warp, blur σ in {0.5,1,1.5}, noise, brightness/
  contrast, a simulated screen-camera pipeline, a simulated print-scan
  pipeline) and every collusion condition (majority/minority/random/
  interleave/patch-averaging for c in {2,3,4}) ran as real trials — real
  rendered pages, real distorted/colluded pixels, real
  `forensics.pipeline.investigate` calls, never simulated — against a
  real 3-page/147-position document and 8 sessions. Results:
  **zero bit errors and 100% top-1 accuracy** across every mild-to-
  moderate condition; graceful, honestly-reported degradation under
  severe conditions (50% crop, blur σ=1.5, heavy collusion); **zero
  innocent accusations across all 180 real trials**, even where top-1
  attribution itself degraded. Full numbers in
  [`docs/RESULTS.md`](docs/RESULTS.md). `attacklab/real/` (real phone-
  photo/scan captures) ships empty — reported honestly, not hidden — and
  only variant A is evaluated; see that section below.

**Not yet implemented:** the UI Investigate flow with Evidence Graph
(deferred to M8, same demo-script substitution used for M4's
`OPEN_DENIED` — M5's own acceptance criterion names only the
verifier/bundle chain), the PQC BCCSP fork for Fabric's own internal
transport (a stated stretch goal — Fabric's peer/orderer transport stays
ECDSA; evidentiary verification depends only on the chaincode-verified
PQC signatures and the co-signing layer, never on Fabric's transport
crypto), variants B/C (glyph micro-scale, stroke-weight — never built,
see `docs/DECISIONS.md` ADR-0041), real-capture robustness (no phone-
photo/scan data, no page-detection step for a photographed page — ADR-
0043), and UI polish. See [`docs/SPEC.md`](docs/SPEC.md) Section 17 for
the full milestone plan and
[`docs/REQUIREMENTS_TRACE.md`](docs/REQUIREMENTS_TRACE.md) for
per-requirement status.

## Quick start

```bash
make up          # build + start all containers on the internal-only network
make test        # every package's unit tests + the no-egress proof
make test-tardos-sim  # the slower Tardos Monte-Carlo suite
make lint        # ruff + mypy over every package
make demo-m0     # M0 acceptance checks + summary
make demo-m1     # M1 acceptance checks + summary; writes demo/out/m1/
make demo-m2     # M2 acceptance checks + summary; writes demo/out/m2/
make e2e         # M3 acceptance: full protocol distribution + decrypt (== make demo-m3)
make demo-m4     # M4 acceptance: enrolment quorum, revocation, copy binding, forwarding detection
make demo-m5     # M5 acceptance: evidence bundle + standalone verifier + signed PDF report
make demo-m6     # M6 acceptance: Fabric 3 SmartBFT ledger backend, full protocol re-run against it
make demo-m7     # M7 acceptance: attack lab (distortion + collusion), writes docs/RESULTS.md
```

### Isolated roles (one console per workstation, real per-identity login)

```bash
bash scripts/roles.sh provision   # resets demo state; distributes keys; enrols officers a-c  (make roles-provision)
bash scripts/roles.sh up          # command / officer-a,b,c / authority / ops consoles        (make roles-up)
python scripts/demo_isolation.py  # live probes: mount audit, filesystems, egress, session replay
python scripts/roles_e2e.py       # full scenario through the consoles, incl. offline verification
```

Separate containers with disjoint key material on one host (not separate machines).
See [`docs/ROLES_DEMO.md`](docs/ROLES_DEMO.md) for the choreography and
[`docs/THREAT_MODEL.md`](docs/THREAT_MODEL.md) ("Role isolation") for what it does and does not defend.

Requires Docker. `liboqs` (the post-quantum crypto library) is built from a
pinned upstream commit inside the `tscore` image — see
`packages/tscore/Dockerfile` and `docs/DECISIONS.md` ADR-0003 — so no host
toolchain is required for any image.

No GNU Make on your machine? Run the same steps directly:

```bash
docker compose build
docker compose run --rm tscore python -m pytest -q -m "not slow" packages/tscore/tests
docker compose run --rm tscore python -m pytest -q -m slow packages/tscore/tests/test_tardos.py
docker compose run --rm tscore python -m pytest -q tests/integration
docker compose run --rm sender python -m pytest -q packages/sender/tests
docker compose run --rm sender python -m sender.demo_m1
docker compose run --rm forensics python -m pytest -q packages/forensics/tests
docker compose run --rm forensics python -m forensics.demo_m2
docker compose run --rm ca python -m pytest -q packages/ca/tests
docker compose run --rm ledger-0 python -m pytest -q packages/ledger/tests
docker compose run --rm keyrelease-0 python -m pytest -q packages/keyrelease/tests
docker compose run --rm agent python -m pytest -q packages/agent/tests
docker compose run --rm verifier python -m pytest -q packages/verifier/tests
docker compose run --rm tscore sh -c "ruff check packages/tscore/src packages/tscore/tests && cd packages/tscore && mypy"
docker compose run --rm sender sh -c "ruff check packages/sender/src packages/sender/tests && cd packages/sender && mypy"
docker compose run --rm forensics sh -c "ruff check packages/forensics/src packages/forensics/tests && cd packages/forensics && mypy"
docker compose run --rm ca sh -c "ruff check packages/ca/src packages/ca/tests && cd packages/ca && mypy"
docker compose run --rm ledger-0 sh -c "ruff check packages/ledger/src packages/ledger/tests && cd packages/ledger && mypy"
docker compose run --rm keyrelease-0 sh -c "ruff check packages/keyrelease/src packages/keyrelease/tests && cd packages/keyrelease && mypy"
docker compose run --rm agent sh -c "ruff check packages/agent/src packages/agent/tests && cd packages/agent && mypy"
docker compose run --rm verifier sh -c "ruff check packages/verifier/src packages/verifier/tests && cd packages/verifier && mypy"

# M3/M4 end-to-end (see the `e2e`/`demo-m4` targets in the Makefile for
# the exact steps — enrolment is now a hard prerequisite, ADR-0020):
docker compose run --rm ca
docker compose up -d ledger-0 ledger-1 ledger-2 ledger-3 \
    keyrelease-0 keyrelease-1 keyrelease-2 keyrelease-3 keyrelease-4
docker compose run --rm ca python -m ca.demo_m4              # real 2-of-3 admin quorum enrols every officer
docker compose run --rm sender python -m sender.demo_m3
docker compose run --rm agent python -m agent.demo_m3 --officer a   # repeat for b, c, d, e
docker compose run --rm ca python -m ca.demo_m4 --revoke officer-e  # then officer-e's decrypt is denied
docker compose run --rm agent python -m agent.demo_m4 \
    --officer d --claim-cert-of officer-c --doc-id doc-m3-demo       # forwarding-detection demo
docker compose down

# M5: evidence bundle + standalone verifier (see the `demo-m5` target in
# the Makefile for the exact steps — runs its own document registration
# and decrypt session, so only needs a seeded, enrolled PKI + live cluster):
docker compose run --rm ca
docker compose up -d ledger-0 ledger-1 ledger-2 ledger-3 \
    keyrelease-0 keyrelease-1 keyrelease-2 keyrelease-3 keyrelease-4
docker compose run --rm ca python -m ca.demo_m4
docker compose run --rm forensics python -m forensics.demo_m5
docker compose run --rm verifier traceseal-verify demo/out/m5/case.tsev        # -> VALID, exit 0
docker compose run --rm forensics python -m forensics.tamper_demo
docker compose run --rm verifier traceseal-verify demo/out/m5/case_tampered.tsev  # -> INVALID, exit 1
docker compose down

# M6: Fabric 3 SmartBFT ledger backend (see the `demo-m6` target in the
# Makefile for the exact steps — brings up its own 4-org network, channel,
# and chaincode from scratch):
make demo-m6

# M7: attack lab (see the `demo-m7` target in the Makefile — runs entirely
# in-process, no live cluster needed):
make demo-m7
```

## Honest limitations

- Enrolment applies to *officers* only — infrastructure identities (the CA
  root, 4 ledger replicas, 5 key-release nodes, the sender, and the 3 admin
  identities themselves) are still bootstrap-seeded directly by `ca.seed`,
  deliberately out of scope (ADR-0019): some initial trust anchor has to
  exist before any ceremony can run, and the spec's own demo script frames
  enrolment specifically around admitting officers, not the system's own
  components.
- Only certificate *revocation* is implemented, matching what the spec
  actually asks for — there is no certificate expiry.
- `LedgerLite` is a real, working, quorum-signed 4-replica ledger — not a
  mock — and remains the default backend. Hyperledger Fabric with SmartBFT
  and a PQC-verifying chaincode (spec Section 12) is now implemented and
  verified (M6, `LEDGER_BACKEND=fabric`), but Fabric's own internal
  transport (peer gossip, orderer block signing) stays ECDSA — the PQC
  BCCSP fork is a stated stretch goal, not built. Nothing here claims
  Fabric's transport layer itself is post-quantum; evidentiary
  verification depends only on the chaincode-verified ML-DSA/SLH-DSA
  signatures and the post-hoc ML-DSA co-signing pass.
- The Fabric SLH-DSA checkpoint (`ledger.checkpoint`) signs a manifest
  hash over whatever records are queryable at export time, not a running
  Merkle accumulator over history — the same "no Merkle tree" honesty
  scoping as LedgerLite's own inclusion proofs (ADR-0027, ADR-0038). Its
  QR export carries a compact fingerprint (manifest hash + metadata), not
  the full signed checkpoint — an SLH-DSA-SHA2-128s signature doesn't fit
  in any QR code version — so the QR is a manual cross-check pointer
  against the JSON file, not a self-contained verifiable artifact.
- The attack lab (M7) evaluates only variant A (micro-shift) — variants B
  (glyph micro-scale) and C (stroke-weight) were never built, despite spec
  Section 9 naming them as "behind flags and evaluated in the attack lab"
  (ADR-0041). It also has no page-detection/perspective-correction step
  for separating a photographed page from its background (spec Section 11
  step 2), so `attacklab/real/` — the real phone-photo/scan folder — ships
  empty and is reported as such in `docs/RESULTS.md`, not hidden or faked
  (ADR-0043). The micro-shift δ and Tardos threshold constant `k` were
  reviewed against this milestone's real data and left unchanged — the
  data showed no bit errors or excess false accusations at either mild or
  severe distortion strengths, so there was no evidence to justify moving
  either (ADR-0044).
- The evidence bundle's ledger inclusion proofs (M5) demonstrate a
  record's own internal hash-chain consistency and genuine quorum
  sign-off — LedgerLite (ADR-0012) has no Merkle/checkpoint structure, so
  this does NOT prove a record wasn't omitted from a longer chain never
  independently walked end-to-end (ADR-0027; stated in every signed PDF
  report's mandatory limitations section, not hidden).
- The UI Investigate flow with Evidence Graph is deferred to M8 (same
  demo-script substitution already used for M4's `OPEN_DENIED`) — M5's
  data (scores, proofs, the full candidate-session histogram) all exist
  and are in the bundle; only the graph rendering is missing.
- The KEM/signature/protocol tests require a working liboqs build. They're
  verified to pass inside the pinned Docker images (`make test`, `make
  e2e`, `make demo-m4`, `make demo-m5`); on a host without Docker or a C
  toolchain for liboqs, those specific tests are skipped rather than faked
  (see each package's `tests/conftest.py`).
- Several parameters were tuned empirically against the real demo
  document, not assumed from the spec's starting values — the quality
  gate's SSIM threshold and the micro-shift `delta_px` (ADR-0006 through
  ADR-0008), and the forensic pipeline's registration/detection approach
  itself, which went through two rejected designs before landing on one
  that measured correctly (ADR-0009, ADR-0010). The M3 demo document (147
  mark positions) also can't support the naive n=5/c0=3/eps1=1e-4 Tardos
  target — `sender.demo_m3` reports this degradation honestly rather than
  hiding it (same pattern as `make demo-m1`). A much larger, differently
  formatted, or genuinely distorted (photo/scan) real document may need
  further tuning; M7's attack lab is where that gets evaluated
  systematically.
- "Milestone acceptance" through M5 is crypto/protocol/image-pipeline/
  forensics/evidence-chain correctness against controlled, undistorted
  inputs — not yet a working product with a UI, and not yet tested against
  anything but a clean, synthetic, single-document scenario with no
  adversarial behaviour beyond the specific negative cases M4/M5 exercise
  (a revoked certificate, a self-declared identity mismatch, a tampered
  evidence bundle) — real-world adversarial robustness is M7's attack lab.
  Do not read `make demo-m0`..`m5`/`make e2e` passing as a claim that
  TraceSeal protects or can trace a real, arbitrarily-leaked document
  under adversarial conditions yet.
- This project makes no claim of legal admissibility, no claim of
  protection against retyping/reading a document aloud, and does not claim
  Fabric is PQC end-to-end unless the BCCSP fork described in the spec is
  actually built (M6). Demo content is always synthetic.
