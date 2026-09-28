# Requirements Trace

Maps every requirement/goal ID from `docs/SPEC.md` Section 1 to the code and
tests that satisfy it. Updated at the end of every milestone.

## Security requirements

| ID | Requirement | Status | Code | Tests |
|---|---|---|---|---|
| R1 | Watermark generated at moment of decryption | Not started (M3) | — | — |
| R2 | Watermark specific to recipient + session | Not started (M3) | — | — |
| R3 | Copies visually identical, forensically distinct | Not started (M1) | — | — |
| R4 | Decryption event bound to recipient identity | Not started (M3) | — | — |
| R5 | Decryption record signed by recipient's own key | Not started (M3) | — | — |
| R6 | NIST PQC for KEX (ML-KEM) and signatures (ML-DSA/SLH-DSA) | **Primitives verified** (M0) | `packages/tscore/src/tscore/{kem,sig}.py` | `packages/tscore/tests/{test_kem,test_sig}.py` — 42/42 pass in `docker compose run --rm tscore ...` against a real liboqs 0.16.0 build; not yet wired into any protocol |
| R7 | Immutable audit layer on ledger/DLT | Not started (M3 LedgerLite, M6 Fabric) | — | — |
| R8 | No single admin/compromised account can alter or delete audit records | Not started (M3 quorum, M4 enrolment quorum) | — | — |
| R9 | Extract watermark from a leaked copy | Not started (M2) | — | — |
| R10 | Look up extracted watermark against the ledger | Not started (M5) | — | — |
| R11 | Return a cryptographically verifiable record identifying the recipient | Not started (M5) | — | — |
| R12 | Fully offline and air-gapped operation | **Groundwork verified** (M0) | `docker-compose.yml` (`internal: true`) | `tests/integration/test_no_egress.py` — 3/3 pass: DNS resolution and TCP connects to two public IPs both fail from inside the network |
| R13 | No cloud KMS dependency | Consistent so far (M0) | `packages/tscore` uses only local liboqs/`cryptography` | — |
| R14 | No public blockchain dependency | Consistent so far (M0) | N/A yet — ledger is LedgerLite/Fabric, both self-hosted | — |

## Product goals

| ID | Goal | Status | Code | Tests |
|---|---|---|---|---|
| G1 | Copies bound to owner; forwarded copies denied + logged | Not started (M4) | — | — |
| G2 | Attribution survives screenshots/JPEG/crop/photo/print-scan | Not started (M7) | — | — |
| G3 | Collusion-resistant with provable false-accusation bound | Not started (M1 library, M7 evaluation) | — | — |
| G4 | Standalone verifier checks evidence without trusting the server | Not started (M5) | — | — |
| G5 | No single admin can enrol a ghost identity or swap keys | Not started (M4) | — | — |

## Notes

- "Not started" means no code exists yet for that requirement, tracked
  against the milestone in `docs/SPEC.md` Section 17 where it's planned.
- R6 is split: the underlying primitives (`tscore.kem`, `tscore.sig`) exist
  and are unit-tested at M0, but no protocol step uses them yet — that
  wiring happens in M3 (decrypt session, enrolment) and M6 (ledger).
