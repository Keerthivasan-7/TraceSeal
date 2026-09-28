# Requirements Trace

Maps every requirement/goal ID from `docs/SPEC.md` Section 1 to the code and
tests that satisfy it. Updated at the end of every milestone.

## Security requirements

| ID | Requirement | Status | Code | Tests |
|---|---|---|---|---|
| R1 | Watermark generated at moment of decryption | **Verified end-to-end** (M3) | `packages/keyrelease/src/keyrelease/node.py` (`handle_decrypt_request` assigns the Tardos codeword and derives variant keys only at decrypt time, after ledger finality) | `packages/keyrelease/tests/test_integration.py` + a real 9-container `make e2e` run: 5 officers, 5 distinct sessions, each codeword assigned live |
| R2 | Watermark specific to recipient + session | **Verified end-to-end** (M3) | `keyrelease.node.handle_decrypt_request` keys the codeword/commitment to `session_id`; `tscore.release_secret.derive_variant_key` derives per-position keys from that session's codeword | Same as R1 — each of the 5 `make e2e` officers got a distinct `session_id` and its own `KeyGrant` |
| R3 | Copies visually identical, forensically distinct | **Verified end-to-end** (M3) | `packages/sender/src/sender/{variants,assemble,quality_gate,package,distribute}.py` + `packages/agent/src/agent/decrypt.py` | `packages/sender/tests/*` (21/21), `packages/agent/tests/*` (5/5) + `make demo-m1`/`make e2e`: whole-page SSIM ≥ 0.98 on a real 147-position document, now actually encrypted, distributed, and reassembled by 5 officers over real HTTP |
| R4 | Decryption event bound to recipient identity | **Verified end-to-end** (M3) | `tscore.records.DecryptRequest.recipient_cert_hash`, embedded verbatim (envelope + signature) into `DecryptRequestLedgerRecord` | `keyrelease.tests.test_integration` + `agent.tests.test_decrypt`: the finalized ledger record carries the officer's own signed request, not a coordinator-asserted claim |
| R5 | Decryption record signed by recipient's own key | **Verified end-to-end** (M3) | `agent.decrypt.build_decrypt_request` (ML-DSA-signed `DecryptRequest`); `keyrelease.node.handle_decrypt_request` calls `open_submission` to verify it before ever acting on it | Same as R4 |
| R6 | NIST PQC for KEX (ML-KEM) and signatures (ML-DSA/SLH-DSA) | **Wired into the real protocol** (M3) | `packages/tscore/src/tscore/{kem,sig}.py`, used throughout `sender`/`keyrelease`/`agent`/`ledger` for every KEM-DEM wrap and every signed record | `packages/tscore/tests/{test_kem,test_sig}.py` (42/42) plus the full M3 test/e2e pass — every package's Docker test suite exercises real ML-KEM-768/ML-DSA-65 against a real liboqs 0.16.0 build |
| R7 | Immutable audit layer on ledger/DLT | **LedgerLite verified** (M3); Fabric backend is M6 | `packages/ledger/src/ledger/{node,store,verify,service}.py` — 4-replica quorum-signed hash chain | `packages/ledger/tests/*` (19/19 in Docker): co-signing, ≥3-of-4 quorum finalization, cross-replica chain verification, tamper rejection |
| R8 | No single admin/compromised account can alter or delete audit records | **LedgerLite quorum verified** (M3); enrolment quorum (identity admission) is still M4 | `ledger.node.LedgerNode.finalize` requires ≥3-of-4 independently-verified co-signatures before any record is appended; `keyrelease.node.release_share` independently re-verifies finality (ADR-0014) | `packages/ledger/tests/test_node.py`, `packages/keyrelease/tests/test_integration.py::test_release_share_denied_without_a_finalized_decrypt_request` — the M3 acceptance-critical "grant-before-finality is impossible" test |
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
- G3's *real-document* evaluation (as opposed to the M1 library-level
  Monte-Carlo simulation) still awaits M7's attack lab, which is where
  robustness against actual adversarial distortion is measured, not just
  the clean-copy case M3 exercises.
- R9/R11 are still split: real detection and accusation exist and are
  verified against clean screenshots of a known document at M2, but
  there's no vault to identify an unknown document/page against yet (the
  M3 ledger records *which* document was registered, but `forensics`
  doesn't yet query it — that's M5), no cryptographic evidence-chain
  verification (M5), and no robustness claim against photos, scans, or
  compression (M7).
- What M3 does *not* yet cover, despite the R1–R8/R6 rows above now
  reading "verified": the enrolment ceremony itself (who's allowed to
  become an officer/node — M4), copy binding and forwarded-copy denial
  (G1, M4), and the Fabric backend behind R7/R14 (M6) — LedgerLite is a
  real, working, quorum-signed ledger, just not yet the pinned target
  backend.
