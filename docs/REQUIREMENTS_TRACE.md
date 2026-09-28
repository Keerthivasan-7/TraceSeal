# Requirements Trace

Maps every requirement/goal ID from `docs/SPEC.md` Section 1 to the code and
tests that satisfy it. Updated at the end of every milestone.

## Security requirements

| ID | Requirement | Status | Code | Tests |
|---|---|---|---|---|
| R1 | Watermark generated at moment of decryption | Not started (M3) | — | — |
| R2 | Watermark specific to recipient + session | Not started (M3) | — | — |
| R3 | Copies visually identical, forensically distinct | **Verified for the variant engine** (M1) | `packages/sender/src/sender/{variants,assemble,quality_gate}.py` | `packages/sender/tests/*` (14/14) + `make demo-m1`: whole-page SSIM ≥ 0.98 on a real 147-position document; not yet wired into encrypted distribution (M3) |
| R4 | Decryption event bound to recipient identity | Not started (M3) | — | — |
| R5 | Decryption record signed by recipient's own key | Not started (M3) | — | — |
| R6 | NIST PQC for KEX (ML-KEM) and signatures (ML-DSA/SLH-DSA) | **Primitives verified** (M0) | `packages/tscore/src/tscore/{kem,sig}.py` | `packages/tscore/tests/{test_kem,test_sig}.py` — 42/42 pass in `docker compose run --rm tscore ...` against a real liboqs 0.16.0 build; not yet wired into any protocol |
| R7 | Immutable audit layer on ledger/DLT | Not started (M3 LedgerLite, M6 Fabric) | — | — |
| R8 | No single admin/compromised account can alter or delete audit records | Not started (M3 quorum, M4 enrolment quorum) | — | — |
| R9 | Extract watermark from a leaked copy | **Verified for clean screenshots** (M2) | `packages/forensics/src/forensics/{align,detect}.py` | `packages/forensics/tests/*` (11/11) + `make demo-m2`: real ORB/RANSAC registration + local-refinement NCC detection recovers the codeword from a rescaled simulated screenshot; photo/scan robustness is M7 |
| R10 | Look up extracted watermark against the ledger | Not started (M5) | — | — |
| R11 | Return a cryptographically verifiable record identifying the recipient | **Statistically verified, not yet cryptographic** (M2) | `packages/forensics/src/forensics/{pipeline,report}.py` | `make demo-m2`: 5/5 sessions correctly attributed, 0 innocent accusations, via `tscore.tardos` accusation; the report is explicit that it is not yet cryptographically verified (that's M5's evidence bundle + ledger proofs) |
| R12 | Fully offline and air-gapped operation | **Groundwork verified** (M0) | `docker-compose.yml` (`internal: true`) | `tests/integration/test_no_egress.py` — 3/3 pass: DNS resolution and TCP connects to two public IPs both fail from inside the network |
| R13 | No cloud KMS dependency | Consistent so far (M0) | `packages/tscore` uses only local liboqs/`cryptography` | — |
| R14 | No public blockchain dependency | Consistent so far (M0) | N/A yet — ledger is LedgerLite/Fabric, both self-hosted | — |

## Product goals

| ID | Goal | Status | Code | Tests |
|---|---|---|---|---|
| G1 | Copies bound to owner; forwarded copies denied + logged | Not started (M4) | — | — |
| G2 | Attribution survives screenshots/JPEG/crop/photo/print-scan | Not started (M7) | — | — |
| G3 | Collusion-resistant with provable false-accusation bound | **Library verified** (M1); real-document evaluation is M7 | `packages/tscore/src/tscore/tardos.py` | `packages/tscore/tests/test_tardos.py` — Monte-Carlo suite (`-m slow`) passes for majority/minority/random/interleave/all-0/all-1 pirate strategies at n=20, c0=3, eps1=1e-4; `plan_parameters` honestly degrades c0 when a document's mark-position budget can't support it (exercised for real in `make demo-m1`) |
| G4 | Standalone verifier checks evidence without trusting the server | Not started (M5) | — | — |
| G5 | No single admin can enrol a ghost identity or swap keys | Not started (M4) | — | — |

## Notes

- "Not started" means no code exists yet for that requirement, tracked
  against the milestone in `docs/SPEC.md` Section 17 where it's planned.
- R6 is split: the underlying primitives (`tscore.kem`, `tscore.sig`) exist
  and are unit-tested at M0, but no protocol step uses them yet — that
  wiring happens in M3 (decrypt session, enrolment) and M6 (ledger).
- R3/G3 are likewise split: the underlying mechanisms (variant engine,
  Tardos library) exist and are tested/simulated at M1, but nothing
  encrypts, distributes, or investigates a real document yet — that's M3
  (distribution) and M7 (real-world attack-lab evaluation of G2/G3
  together).
- R9/R11 are split the same way: real detection and accusation exist and
  are verified against clean screenshots of a known document at M2, but
  there's no vault to identify an unknown document/page against (M3+M5),
  no cryptographic evidence-chain verification (M5), and no robustness
  claim against photos, scans, or compression (M7).
