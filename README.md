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

## Status: Milestone M1 — complete and verified

**M0** (repo skeleton, the `tscore` crypto/schema library — ML-KEM-768,
ML-DSA-65, SLH-DSA-SHA2-128s via liboqs, AES-256-GCM, HKDF-SHA3-256,
hand-rolled GF(256) Shamir, canonical CBOR — Docker Compose on an
internal-only network) and **M1** (the variant/watermark engine, quality
gate, and Tardos fingerprinting library) are both done. All acceptance
criteria pass for real, in Docker:

- `packages/tscore`: 57 fast unit tests + the 6-strategy Tardos
  Monte-Carlo suite, against a real liboqs 0.16.0 build.
- The no-egress proof: DNS resolution and outbound TCP both fail from
  inside the `internal: true` network.
- `packages/sender`: 14 unit tests, plus `make demo-m1` — a synthetic
  3-page document, 147 real mark positions, 5 assembled per-session
  copies, quality gate PASS (whole-page SSIM ≥ 0.98).

**Not yet implemented:** encryption/packaging (`.tspkg`), the
key-release/ledger/agent/forensics/verifier services, the Fabric backend,
the attack lab, and the web UI. See [`docs/SPEC.md`](docs/SPEC.md)
Section 17 for the full milestone plan and
[`docs/REQUIREMENTS_TRACE.md`](docs/REQUIREMENTS_TRACE.md) for
per-requirement status.

## Quick start

```bash
make up          # build + start all containers on the internal-only network
make test        # crypto + sender unit tests + the no-egress proof
make test-tardos-sim  # the slower Tardos Monte-Carlo suite
make lint        # ruff + mypy over packages/tscore and packages/sender
make demo-m0     # M0 acceptance checks + summary
make demo-m1     # M1 acceptance checks + summary; writes demo/out/m1/
```

Requires Docker. `liboqs` (the post-quantum crypto library) is built from a
pinned upstream commit inside the `tscore` image — see
`packages/tscore/Dockerfile` and `docs/DECISIONS.md` ADR-0003 — so no host
toolchain is required for either image.

No GNU Make on your machine? Run the same steps directly:

```bash
docker compose build
docker compose run --rm tscore python -m pytest -q -m "not slow" packages/tscore/tests
docker compose run --rm tscore python -m pytest -q -m slow packages/tscore/tests/test_tardos.py
docker compose run --rm tscore python -m pytest -q tests/integration
docker compose run --rm sender python -m pytest -q packages/sender/tests
docker compose run --rm sender python -m sender.demo_m1
docker compose run --rm tscore sh -c "ruff check packages/tscore/src packages/tscore/tests && cd packages/tscore && mypy"
docker compose run --rm sender sh -c "ruff check packages/sender/src packages/sender/tests && cd packages/sender && mypy"
```

## Honest limitations

- No protocol services exist yet: nothing can be enrolled, distributed
  (for real — M1's variant engine has no encryption or packaging around
  it), decrypted, or investigated. `tscore` only provides the underlying
  crypto primitives and the Tardos library; `sender` only provides the
  image-processing pipeline.
- The KEM/signature unit tests require a working liboqs build. They're
  verified to pass inside the pinned Docker image (`make test`); on a host
  without Docker or a C toolchain for liboqs, those specific tests are
  skipped rather than faked (see `packages/tscore/tests/conftest.py`).
- The quality gate's SSIM threshold and the micro-shift `delta_px` were
  both tuned empirically against the real demo document, not assumed —
  see `docs/DECISIONS.md` ADR-0006 through ADR-0008 for exactly what was
  measured and why. A much larger or differently-formatted real document
  may need retuning; that's expected and the mechanism supports it.
- "Milestone acceptance" so far is crypto/image-pipeline correctness and a
  real network-isolation proof — not a working product. Do not read
  `make demo-m0`/`make demo-m1` passing as a claim that TraceSeal itself
  protects a document yet.
- This project makes no claim of legal admissibility, no claim of
  protection against retyping/reading a document aloud, and does not claim
  Fabric is PQC end-to-end unless the BCCSP fork described in the spec is
  actually built (M6). Demo content is always synthetic.
