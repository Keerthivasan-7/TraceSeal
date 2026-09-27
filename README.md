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

## Status: Milestone M0

Repo skeleton, the shared `tscore` crypto/schema library (ML-KEM-768,
ML-DSA-65, SLH-DSA-SHA2-128s via liboqs, AES-256-GCM, HKDF-SHA3-256,
hand-rolled GF(256) Shamir secret sharing, canonical CBOR), Docker Compose
on an internal-only network, and this docs skeleton.

**Not yet implemented:** the variant/watermark engine, Tardos
fingerprinting, the sender/key-release/ledger/agent/forensics/verifier
services, the Fabric backend, the attack lab, and the web UI. See
[`docs/SPEC.md`](docs/SPEC.md) Section 17 for the full milestone plan and
[`docs/REQUIREMENTS_TRACE.md`](docs/REQUIREMENTS_TRACE.md) for per-requirement
status.

## Quick start

```bash
make up          # build + start all containers on the internal-only network
make test        # crypto unit tests + the no-egress proof
make lint        # ruff + mypy over packages/tscore
make demo-m0     # runs the M0 acceptance checks and prints a summary
```

Requires Docker. `liboqs` (the post-quantum crypto library) is built from a
pinned upstream commit inside the `tscore` image — see
`packages/tscore/Dockerfile` and `docs/DECISIONS.md` ADR-0003 — so no host
toolchain is required.

## Honest limitations (M0)

- No protocol services exist yet: nothing can be enrolled, distributed,
  decrypted, or investigated. `tscore` only provides the underlying
  primitives (KEM-DEM, signatures, Shamir, canonical CBOR).
- The KEM/signature unit tests require a working liboqs build and are only
  guaranteed to run inside the pinned Docker image (`make test`); on a host
  without Docker or a C toolchain for liboqs, those specific tests are
  skipped rather than faked (see `packages/tscore/tests/conftest.py`).
- "Milestone acceptance" at this stage is crypto-primitive correctness and
  a real network-isolation proof — not a working product. Do not read
  `make demo-m0` passing as a claim that TraceSeal itself works yet.
- This project makes no claim of legal admissibility, no claim of
  protection against retyping/reading a document aloud, and does not claim
  Fabric is PQC end-to-end unless the BCCSP fork described in the spec is
  actually built (M6). Demo content is always synthetic.
