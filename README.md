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

## Status: Milestone M4 — complete and verified

**M0** (crypto/schema core), **M1** (variant/watermark engine, quality
gate, Tardos library), **M2** (forensics on clean screenshots), **M3**
(full crypto protocol: sender, 5 key-release nodes, a 4-replica ledger, the
recipient agent, commit-before-release, receipts), and **M4** (enrolment
quorum, revocation, copy binding, forwarding detection) are all done. All
acceptance criteria pass for real, in Docker:

- `packages/tscore`: 78 fast unit tests + the 6-strategy Tardos
  Monte-Carlo suite, against a real liboqs 0.16.0 build.
- The no-egress proof: DNS resolution and outbound TCP both fail from
  inside the `internal: true` network.
- `packages/sender`: 21 unit tests, plus `make demo-m1` — a synthetic
  3-page document, 147 real mark positions, 5 assembled per-session
  copies, quality gate PASS (whole-page SSIM ≥ 0.98).
- `packages/forensics`: 11 unit tests, plus `make demo-m2` — 5/5 leaked
  sessions correctly attributed from a simulated rescaled screenshot, 0
  innocent accusations, via real ORB/RANSAC image registration and
  per-position correlation detection (not a lookup or a mock).
- `packages/ca`, `packages/ledger`, `packages/keyrelease`, `packages/agent`:
  16 + 19 + 7 + 9 unit tests, plus `make e2e`/`make demo-m4` — a real
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

**Not yet implemented:** evidence bundles and the standalone verifier, the
Fabric backend, the attack lab, and the web UI. See
[`docs/SPEC.md`](docs/SPEC.md) Section 17 for the full milestone plan and
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
```

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
docker compose run --rm tscore sh -c "ruff check packages/tscore/src packages/tscore/tests && cd packages/tscore && mypy"
docker compose run --rm sender sh -c "ruff check packages/sender/src packages/sender/tests && cd packages/sender && mypy"
docker compose run --rm forensics sh -c "ruff check packages/forensics/src packages/forensics/tests && cd packages/forensics && mypy"
docker compose run --rm ca sh -c "ruff check packages/ca/src packages/ca/tests && cd packages/ca && mypy"
docker compose run --rm ledger-0 sh -c "ruff check packages/ledger/src packages/ledger/tests && cd packages/ledger && mypy"
docker compose run --rm keyrelease-0 sh -c "ruff check packages/keyrelease/src packages/keyrelease/tests && cd packages/keyrelease && mypy"
docker compose run --rm agent sh -c "ruff check packages/agent/src packages/agent/tests && cd packages/agent && mypy"

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
  mock — but it is not the pinned target backend. Hyperledger Fabric with
  SmartBFT and a PQC-verifying chaincode (spec Section 12) is M6; nothing
  here claims Fabric-level Byzantine fault tolerance.
- There is no evidence bundle or standalone verifier yet (M5): a leaked
  document can be forensically attributed (M2's pipeline) but there's no
  cryptographically-verifiable, independently-checkable evidence package
  tying that attribution to the ledger's own signed records.
- The KEM/signature/protocol tests require a working liboqs build. They're
  verified to pass inside the pinned Docker images (`make test`, `make
  e2e`, `make demo-m4`); on a host without Docker or a C toolchain for
  liboqs, those specific tests are skipped rather than faked (see each
  package's `tests/conftest.py`).
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
- "Milestone acceptance" through M4 is crypto/protocol/image-pipeline/
  forensics correctness against controlled, undistorted inputs — not yet a
  working product with a UI, and not yet tested against anything but a
  clean, synthetic, single-document scenario with no adversarial behaviour
  beyond the specific negative cases M4 exercises (a revoked certificate, a
  self-declared identity mismatch) — real-world adversarial robustness is
  M7's attack lab. Do not read `make demo-m0`..`m4`/`make e2e` passing as a
  claim that TraceSeal protects or can trace a real, arbitrarily-leaked
  document under adversarial conditions yet.
- This project makes no claim of legal admissibility, no claim of
  protection against retyping/reading a document aloud, and does not claim
  Fabric is PQC end-to-end unless the BCCSP fork described in the spec is
  actually built (M6). Demo content is always synthetic.
