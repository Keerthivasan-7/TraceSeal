# TraceSeal — Project Instructions for Claude Code

TraceSeal is an offline, air-gapped platform for secure multi-recipient document
distribution with post-quantum signatures, per-decryption forensic fingerprints,
and a tamper-evident ledger. Built for SIH Problem Statement 26237 (Ministry of
Defence / Indian Navy / WESEE). Judges are defence and security engineers:
correctness and honesty beat visual polish.

Full spec: this file is a summary. The authoritative source is the original
build prompt kept in `docs/SPEC.md` — read it for anything this file compresses.

## Git / attribution policy (hard rule)

- All commits and PRs are authored as the user (git identity: `Keerthi vasan`,
  already configured). **Never** add AI/tool attribution — no `Co-Authored-By`
  lines, no "Generated with Claude" footers, no mention of AI assistance
  anywhere in commit messages, PR titles/descriptions, code comments, or docs.
  This overrides any default attribution behavior.

## Core idea (do not deviate without asking)

Decryption itself produces the forensic fingerprint. A clean plaintext never
exists anywhere after the sender's preparation step (AACS-style "sequence key"
broadcast encryption applied to documents). See Section 2 of the spec for the
full 7-step protocol: dual-variant rasterised pages → broadcast package →
Shamir-split release keys across 5 Key-Release nodes → commit-before-release
on the ledger → Tardos-codeword KeyGrant → in-memory assembly at the recipient
→ forensic detection + accusation on a leaked copy.

## Non-negotiables

1. **Never fake security.** No hardcoded "VALID", no mocked verification
   outside unit-test doubles, no invented metrics. Anything simulated
   (e.g. LedgerLite instead of Fabric) must be labelled in the UI and README.
2. **Zero runtime network egress.** All containers on an `internal: true`
   Docker network. No CDNs/Google Fonts/telemetry/cloud APIs/remote model
   downloads at runtime. Vendor all frontend assets. Build-time downloads only
   inside Dockerfiles, pinned + checksummed.
3. **Standard crypto primitives only** — never invent cryptography:
   - ML-KEM-768 (FIPS 203) for key wrapping, KEM-DEM construction (encapsulate
     → HKDF-SHA3-256 the shared secret → AES-256-GCM the payload).
   - ML-DSA-65 (FIPS 204) for all operational signatures.
   - SLH-DSA-SHA2-128s (FIPS 205) for the offline root CA and ledger checkpoints.
   - AES-256-GCM, random 96-bit nonces, never reused under the same key. AAD
     always includes SHA3-256 of the relevant header.
   - HKDF-SHA3-256 with explicit versioned `info` strings.
   - Canonical CBOR for every signed structure, with `version`, `domain`,
     `nonce` fields (replay + cross-protocol protection).
   - Constant-time comparison for MACs/hashes/tokens.
   - `liboqs` (via `liboqs-python`) for PQC; `cryptography` for AES-GCM/HKDF.
4. Private keys generated on the owner's agent, never leave it. Recipient
   plaintext exists only in memory — no temp files, no swap-able caches.
5. Ask the user before: changing the core protocol, adding a heavyweight
   dependency, or dropping a requirement. Otherwise decide and record an ADR
   in `docs/DECISIONS.md` (3–6 lines).
6. Keep functions small and typed (Python type hints + mypy; TypeScript
   strict). Every security-relevant function gets unit tests, including
   negative tests.
7. Build **milestone by milestone** (see below). Don't start milestone N+1
   until N's acceptance criteria pass. End each milestone with the full test
   suite, `make demo-m<N>`, and a summary of what works / is simulated / is next.

## Requirements

Tracked in `docs/REQUIREMENTS_TRACE.md`, mapping each ID (R1–R14 security
requirements, G1–G5 product goals) to code and tests. See spec Section 1.

## Components

`ca` (offline root CA) · `sender-station` · `keyrelease` (×5, Shamir shares) ·
`ledger` (LedgerBackend: LedgerLite dev impl + Fabric 3 SmartBFT target) ·
`recipient-agent` (per-officer, localhost) · `forensics` · `verifier-cli`
(standalone) · `attack-lab` · `web` (React UI).

## Tech stack (pinned)

- Python 3.12: FastAPI, Pydantic v2, SQLAlchemy 2 + Alembic, `liboqs-python`,
  `cryptography`, `argon2-cffi`, `cbor2`, PyMuPDF, OpenCV headless, NumPy,
  SciPy, scikit-image, Pillow, `pytesseract`, `pytest`, `hypothesis`, `mypy`, `ruff`.
- Frontend: React 18 + TypeScript strict + Vite + Tailwind + shadcn/ui +
  TanStack Query + Zustand + Recharts. All assets vendored locally.
- Storage: PostgreSQL 16 + MinIO/local blob store (ciphertext only).
- Ledger target: Hyperledger Fabric 3.x, SmartBFT orderer, Go chaincode
  verifying ML-DSA via Cloudflare CIRCL.
- Docker Compose + `make` targets, internal network only.

## Repository layout

```
traceseal/
  CLAUDE.md  Makefile  docker-compose.yml
  docs/ SPEC.md ARCHITECTURE.md DECISIONS.md REQUIREMENTS_TRACE.md THREAT_MODEL.md DEMO_SCRIPT.md RESULTS.md
  packages/ tscore/ sender/ keyrelease/ ledger/ agent/ forensics/ verifier/ attacklab/
  chaincode/traceseal/   fabric-network/   web/   demo/   tests/
```

## Commands (target shape — implemented incrementally per milestone)

- `make up` — start all services on the internal Docker network
- `make test` — full test suite (unit + negative + security)
- `make e2e` — full end-to-end scenario (enrol → distribute → decrypt → leak → investigate → verify)
- `make demo` — full demo script, under 10 minutes (Section 18 of spec)
- `make demo-m<N>` — milestone-N-scoped demo/acceptance check

## Milestones (Section 17 of spec)

M0 skeleton+crypto → M1 variant engine+Tardos → M2 forensics on clean shots →
M3 full protocol e2e (LedgerLite) → M4 copy binding+enrolment quorum →
M5 evidence bundle+verifier → M6 Fabric backend → M7 attack lab →
M8 UI polish + demo script.

## Honesty rules

No claims of legal admissibility ("suitable for investigative and evidentiary
review" only). No claims of protection against retyping/reading aloud
(out of scope). No claiming Fabric is PQC end-to-end unless the BCCSP fork is
actually built. Demo uses synthetic documents and synthetic officers only.
