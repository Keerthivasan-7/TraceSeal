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
| R7 | Immutable audit layer on ledger/DLT | **Verified on both backends** (M3 LedgerLite; M6 Fabric) | `packages/ledger/src/ledger/{node,store,verify,service}.py` (LedgerLite: 4-replica quorum-signed hash chain); `chaincode/traceseal` + `packages/ledger/src/ledger/{fabric_client,cosigner,checkpoint,backend}.py` (Fabric: 4-org SmartBFT, `OutOf(3,...)` endorsement, chaincode-verified ML-DSA/SLH-DSA, post-hoc ML-DSA co-signing) | `packages/ledger/tests/*` (LedgerLite, 20/20 in Docker); `chaincode/traceseal/interop_test.go` (real liboqs-signed ML-DSA-65/SLH-DSA-SHA2-128s verified by CIRCL, incl. tampered-signature negative cases); `make demo-m6`: a real 4-org Fabric SmartBFT network ran the identical M3/M4 protocol scenario (enrolment, document registration, 5 officers' decrypt sessions) end-to-end via `LEDGER_BACKEND=fabric` with zero protocol-level code changes outside ledger-client construction, plus a real ≥3-of-4 ML-DSA co-signing pass and a signed SLH-DSA checkpoint export |
| R8 | No single admin/compromised account can alter or delete audit records | **Verified end-to-end, including enrolment** (M4) | `ledger.node.LedgerNode.finalize` requires ≥3-of-4 independently-verified co-signatures before any record is appended; `keyrelease.node.release_share` independently re-verifies finality (ADR-0014); `ca.enrolment.finalize_enrolment`/`finalize_revocation` require a genuine 2-of-3 admin quorum, recomputed fresh from the ledger every call (ADR-0023), before the CA acts | `packages/ledger/tests/test_node.py`, `packages/keyrelease/tests/test_integration.py::test_release_share_denied_without_a_finalized_decrypt_request` (the grant-before-finality test), `packages/ca/tests/test_enrolment.py` (below-quorum and non-admin-approval rejection) |
| R9 | Extract watermark from a leaked copy | **Verified for clean screenshots** (M2) | `packages/forensics/src/forensics/{align,detect}.py` | `packages/forensics/tests/*` (11/11) + `make demo-m2`: real ORB/RANSAC registration + local-refinement NCC detection recovers the codeword from a rescaled simulated screenshot; photo/scan robustness is M7 |
| R10 | Look up extracted watermark against the ledger | **Verified end-to-end** (M5) | `packages/forensics/src/forensics/investigation.py` (`gather_candidate_codewords` queries `DECRYPT_REQUEST_LEDGER`, resolves the coordinating node, reveals the codeword from the key-release vault, cross-checks it against the on-ledger commitment before ever trusting it) | `packages/forensics/tests/test_investigation.py` against a real in-process ledger + 5-node key-release cluster; `packages/tscore/tests/test_evidence.py`'s commitment-cross-check tampering case |
| R11 | Return a cryptographically verifiable record identifying the recipient | **Verified end-to-end, cryptographically** (M5) | `packages/tscore/src/tscore/evidence.py` (`EvidenceBundle`, `verify_evidence_bundle`); `packages/forensics/src/forensics/{investigation,report_pdf}.py` | `packages/tscore/tests/test_evidence.py` (genuine bundle + all 6 tampering cases), `packages/forensics/tests/test_investigation.py`, `packages/verifier/tests/test_main.py`, `make demo-m5`: a genuine signed `EvidenceBundle` (ML-DSA) with re-verified ledger proofs and Tardos scores; the report's mandatory limitations section states exactly what is and isn't proven (ADR-0027) |
| R12 | Fully offline and air-gapped operation | **Groundwork verified** (M0) | `docker-compose.yml` (`internal: true`) | `tests/integration/test_no_egress.py` — 3/3 pass: DNS resolution and TCP connects to two public IPs both fail from inside the network |
| R13 | No cloud KMS dependency | Consistent so far (M0) | `packages/tscore` uses only local liboqs/`cryptography` | — |
| R14 | No public blockchain dependency | **Consistent, verified on both backends** (M6) | LedgerLite is a self-hosted 4-replica hash chain; Fabric is a self-hosted, self-operated 4-org network (`fabric-network/`) with no public/permissionless chain, no cloud Fabric service, and no runtime egress (all 8 orderer/peer containers plus the gateway sit on the same `internal: true` network as everything else) | `make demo-m6` brought up the full 4-org network from locally-generated crypto material only |

## Product goals

| ID | Goal | Status | Code | Tests |
|---|---|---|---|---|
| G1 | Copies bound to owner; forwarded copies denied + logged | **Verified end-to-end** (M4) | `keyrelease.node` issues a quorum-co-signed `SealedHeader` per `KeyGrant` and independently verifies a request's `recipient_cert_hash` against the signer's real enrolled certificate before servicing it (ADR-0025); `agent.decrypt.verify_copy_binding` independently re-verifies that header's quorum and logs `OpenEventRecord`/`OpenDeniedRecord` | `packages/keyrelease/tests/test_integration.py` (SealedHeader quorum + cert-hash-mismatch rejection), `packages/agent/tests/test_decrypt.py` (forwarding detection, both the server-side and client-side paths, `OpenEventRecord` precedes `ReceiptRecord`), `agent.demo_m4`'s live forwarding demo |
| G2 | Attribution survives screenshots/JPEG/crop/photo/print-scan | Not started (M7) | — | — |
| G3 | Collusion-resistant with provable false-accusation bound | **Library verified** (M1); real-document evaluation is M7 | `packages/tscore/src/tscore/tardos.py` | `packages/tscore/tests/test_tardos.py` — Monte-Carlo suite (`-m slow`) passes for majority/minority/random/interleave/all-0/all-1 pirate strategies at n=20, c0=3, eps1=1e-4; `plan_parameters` honestly degrades c0 when a document's mark-position budget can't support it (exercised for real in `make demo-m1`) |
| G4 | Standalone verifier checks evidence without trusting the server | **Verified end-to-end** (M5) | `packages/verifier` — depends on `packages/tscore` ONLY (no `ledger`/`ca`/`forensics`/`sender` import anywhere, enforced literally by its Dockerfile never copying them in); `traceseal-verify` never makes a network call | `packages/verifier/tests/test_main.py`: genuine bundle -> exit 0/VALID; a flipped byte, a swapped `report.pdf`, and a corrupted archive -> exit 1/INVALID; `make demo-m5`'s real CLI run against a genuine and a tampered `.tsev` |
| G5 | No single admin can enrol a ghost identity or swap keys | **Verified end-to-end** (M4) | `ca.enrolment.finalize_enrolment` independently re-verifies the CSR self-signature, that its hash matches the proposal's committed `csr_hash` (rejects a swapped-CSR attack), and a genuine 2-of-3 distinct-admin quorum before issuing any certificate; `ca.seed` no longer direct-issues officer certificates at all (ADR-0020) | `packages/ca/tests/test_enrolment.py`: below-quorum rejection, non-admin-approval and duplicate-approval rejection, swapped-CSR rejection, full revocation mirror; `ca.demo_m4`'s live ceremony against a 9-container cluster |

## Notes

- "Not started" means no code exists yet for that requirement, tracked
  against the milestone in `docs/SPEC.md` Section 17 where it's planned.
- G3's *real-document* evaluation (as opposed to the M1 library-level
  Monte-Carlo simulation) still awaits M7's attack lab, which is where
  robustness against actual adversarial distortion is measured, not just
  the clean-copy case M3 exercises.
- R9 is still split from R10/R11 as of M5: real detection and accusation
  exist and are verified against clean screenshots of a known document
  (M2), and the cryptographic evidence chain (candidate codewords revealed
  from the key-release vault, cross-checked against the ledger, scored,
  and independently re-verified by a signed `EvidenceBundle`) is now
  verified end-to-end (M5) — but R9 itself still carries no robustness
  claim against photos, scans, or compression (M7), and there is still no
  automatic document/page identification against a corpus (ADR-0009's gap;
  the investigator's own external assertion of which document/page this is
  stays out-of-band until M7).
- What M4 does *not* yet cover, despite the R8/G1/G5 rows above now reading
  "verified": revoking or enrolling infrastructure identities themselves
  (ledger replicas, key-release nodes, admins) — those are still bootstrap-
  seeded directly by `ca.seed`, deliberately out of scope (ADR-0019 — the
  ceremony admits *officers*, not the system's own trust anchors); and
  certificate *expiry* (only revocation is implemented, matching what the
  spec actually asks for).
- M6 (Fabric backend, now verified — see R7/R14) does not implement the
  PQC BCCSP fork: Fabric's own internal transport (peer-to-peer gossip,
  orderer block signing) stays ECDSA, as documented in
  `docs/DECISIONS.md`'s M6 ADRs — evidentiary verification depends only on
  the chaincode-verified ML-DSA/SLH-DSA signatures and the post-hoc
  ML-DSA co-signing pass, never on Fabric's own transport-level crypto.
