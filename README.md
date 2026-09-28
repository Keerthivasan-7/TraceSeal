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

## Status: Milestone M2 — complete and verified

**M0** (crypto/schema core), **M1** (variant/watermark engine, quality
gate, Tardos library) and **M2** (forensics on clean screenshots) are all
done. All acceptance criteria pass for real, in Docker:

- `packages/tscore`: 57 fast unit tests + the 6-strategy Tardos
  Monte-Carlo suite, against a real liboqs 0.16.0 build.
- The no-egress proof: DNS resolution and outbound TCP both fail from
  inside the `internal: true` network.
- `packages/sender`: 14 unit tests, plus `make demo-m1` — a synthetic
  3-page document, 147 real mark positions, 5 assembled per-session
  copies, quality gate PASS (whole-page SSIM ≥ 0.98).
- `packages/forensics`: 11 unit tests, plus `make demo-m2` — 5/5 leaked
  sessions correctly attributed from a simulated rescaled screenshot, 0
  innocent accusations, via real ORB/RANSAC image registration and
  per-position correlation detection (not a lookup or a mock).

**Not yet implemented:** encryption/packaging (`.tspkg`), the
key-release/ledger/agent/verifier services, OCR/vault document lookup,
photo/scan robustness, the Fabric backend, the attack lab, and the web UI.
See [`docs/SPEC.md`](docs/SPEC.md) Section 17 for the full milestone plan
and [`docs/REQUIREMENTS_TRACE.md`](docs/REQUIREMENTS_TRACE.md) for
per-requirement status.

## Quick start

```bash
make up          # build + start all containers on the internal-only network
make test        # crypto + sender + forensics unit tests + the no-egress proof
make test-tardos-sim  # the slower Tardos Monte-Carlo suite
make lint        # ruff + mypy over every package
make demo-m0     # M0 acceptance checks + summary
make demo-m1     # M1 acceptance checks + summary; writes demo/out/m1/
make demo-m2     # M2 acceptance checks + summary; writes demo/out/m2/
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
docker compose run --rm tscore sh -c "ruff check packages/tscore/src packages/tscore/tests && cd packages/tscore && mypy"
docker compose run --rm sender sh -c "ruff check packages/sender/src packages/sender/tests && cd packages/sender && mypy"
docker compose run --rm forensics sh -c "ruff check packages/forensics/src packages/forensics/tests && cd packages/forensics && mypy"
```

## Honest limitations

- No protocol services exist yet: nothing can be enrolled, distributed
  (for real — M1's variant engine has no encryption or packaging around
  it), decrypted, or investigated against a real vault. `tscore` provides
  the crypto primitives and Tardos library; `sender` the image-processing
  pipeline; `forensics` registration/detection/accusation against a
  document it's already told about — not yet a real end-to-end product.
- The KEM/signature unit tests require a working liboqs build. They're
  verified to pass inside the pinned Docker image (`make test`); on a host
  without Docker or a C toolchain for liboqs, those specific tests are
  skipped rather than faked (see `packages/tscore/tests/conftest.py`).
- Several parameters were tuned empirically against the real demo
  document, not assumed from the spec's starting values — the quality
  gate's SSIM threshold and the micro-shift `delta_px` (ADR-0006 through
  ADR-0008), and the forensic pipeline's registration/detection approach
  itself, which went through two rejected designs before landing on one
  that measured correctly (ADR-0009, ADR-0010). A much larger, differently
  formatted, or genuinely distorted (photo/scan) real document may need
  further tuning — that's expected, and the mechanism supports it; M7's
  attack lab is where that gets evaluated systematically.
- "Milestone acceptance" so far is crypto/image-pipeline/forensics
  correctness against controlled, undistorted inputs — not a working
  product, and not yet tested against anything but clean, known-document
  screenshots. Do not read `make demo-m0`/`m1`/`m2` passing as a claim
  that TraceSeal protects or can trace a real, arbitrarily-leaked document
  yet.
- This project makes no claim of legal admissibility, no claim of
  protection against retyping/reading a document aloud, and does not claim
  Fabric is PQC end-to-end unless the BCCSP fork described in the spec is
  actually built (M6). Demo content is always synthetic.
