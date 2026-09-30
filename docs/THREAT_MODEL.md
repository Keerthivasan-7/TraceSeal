# Threat Model

A STRIDE table covering the attack surfaces actually built and tested
across `ca`, `sender-station`, `keyrelease` (x5), `ledger` (LedgerLite /
Fabric), `recipient-agent`, `forensics`, `verifier-cli`, `attack-lab`, and
`web`/`web-api`. Every mitigation cited below points at real code and a
real test or a real live-verified demo run (Milestones M0–M8), not an
aspiration. Gaps are stated as gaps, not silently assumed away, per
`CLAUDE.md`'s non-negotiables.

## Spoofing

| Scenario | Mitigation | Evidence |
|---|---|---|
| An attacker submits a ledger record claiming to be another identity | Every submission's ML-DSA-65 signature is independently re-verified by **every** replica against the registry's own public key — never just the leader's word (`ledger.node._verify_submission`/`open_submission`) | `packages/ledger/tests`: forged-signature submissions rejected |
| An officer's agent presents another officer's decrypted copy as its own (forwarding) | The key-release quorum co-signs a `SealedHeader` binding `(doc_id, session_id)` to the *true* recipient's cert hash; the agent independently re-verifies that quorum and the binding before ever decrypting (`agent.decrypt.verify_copy_binding`); the key-release node also independently rejects a mismatched `recipient_cert_hash` server-side | Live-verified M4 and again in M8 Phase 3 (Officer Inbox's forwarding-demo control): denied, `OPEN_DENIED` logged |
| A rogue key-release node impersonates another node in the inter-node release protocol | Inter-node release-share calls are ML-DSA-signed and independently verified, same discipline as the ledger | `packages/keyrelease/tests` |
| A single admin enrols or revokes an officer without real quorum | `count_verified_approvals` is recomputed fresh from the ledger's own `ApprovalRecord`s every time — never trusts a caller-supplied count — and requires 2 of 3 *distinct* signers | Live-verified in M8: a lone admin's finalize attempt is rejected; a real 2-of-3 ceremony succeeds |

## Tampering

| Scenario | Mitigation | Evidence |
|---|---|---|
| An attacker edits one LedgerLite replica's database file directly | `LedgerClient.verify_chain()` independently recomputes each replica's hash chain; a corrupted replica flips to `internally_valid: false` with a `first_bad_height`, surfaced live on the Ledger screen — the BFT quorum (3 of 4) still finalizes new records since only one replica is compromised | Designed and unit-tested (`ledger.verify`); see `docs/DEMO_SCRIPT.md` step 8 for the manual live demonstration |
| An attacker modifies a released document's ciphertext in the blob store | AES-256-GCM's authentication tag detects any ciphertext byte flip at open time, raising `TamperError` before any plaintext is ever produced | `tscore/tests/test_aead.py` |
| An attacker tampers with an exported `.tsev` evidence bundle | The outer ML-DSA signature over the bundle's canonical CBOR envelope is independently re-verified by the standalone `traceseal-verify` CLI, which depends on `tscore` only | Live-verified in M8 Phase 4: a genuine bundle exported through the Investigate screen verified `VALID`; M5's `tamper_demo` flips one byte and the same CLI reports `INVALID` |
| A malicious/buggy evidence-bundle builder forges an inner field (e.g. an accusation score) without re-signing correctly | `verify_evidence_bundle` independently recomputes the Tardos score, cross-checks each revealed codeword/salt against the ledger's own commitment, and re-verifies every embedded ledger proof's own hash chain and quorum signatures — it never trusts a claimed field | `tscore/tests/test_evidence.py`'s six tampering cases (score, commitment, quorum signature, record hash, PDF hash, outer signature) |

## Repudiation

| Scenario | Mitigation | Evidence |
|---|---|---|
| An officer denies having opened a document | Every open produces a `DecryptRequest` (signed by the officer), a quorum-co-signed `KeyGrant`, and a finalized `Receipt` — all on the ledger, all individually attributable | Live-verified throughout M3–M8 |
| A key-release node denies having released a share or grant | `KeyGrantIssuedRecord` names every `contributing_node_id` and carries each one's own signature | `packages/keyrelease/tests` |
| An admin denies having approved an enrolment or revocation | Each `ApprovalRecord` is individually signed by that admin; quorum is counted only over distinct signer identities, so no admin's vote can be fabricated by another party | Live-verified: the Identity screen's quorum progress bar reads directly off these records |

## Information Disclosure

| Scenario | Mitigation | Evidence |
|---|---|---|
| A leaked single page reveals which recipient's copy it came from | This is the system's intended function, not a defect — decryption itself is what produces the forensic fingerprint (spec Section 2). Stated plainly in the Investigate screen's own report text, never overclaimed as more than a statistical conclusion | `forensics/report.py`'s `summary()` wording, reused verbatim in the PDF report |
| The forensic vault-reveal endpoints over-disclose a key-release node's own Shamir share | `reveal_bias_vector`/`reveal_commitment` return *only* the bias vector or the one session's codeword/salt — never the node's own share fields stored in the same database row | `packages/keyrelease/tests`: explicit assertion the response never contains share material (ADR-0026) |
| Compromise of one officer's endpoint while viewing a decrypted page | Exposes only that officer's own content under that officer's own key material — `K_B`/`S_v` never reach the recipient in a form that discloses other officers' variant keys | Architectural; residual risk (see below) |
| Inter-service traffic on the internal Docker network is plaintext HTTP | Acceptable *only* because the network is `internal: true` with runtime egress physically removed (ADR-0049) and the trust boundary is the air gap itself, not an on-path attacker inside it — stated as a residual risk below, not silently assumed safe for every deployment shape | ADR-0049; `docs/DEMO_SCRIPT.md` step 1's live egress-test |

## Denial of Service

| Scenario | Mitigation | Evidence |
|---|---|---|
| A key-release node or ledger replica goes offline or turns malicious | Shamir 3-of-5 (key release) and BFT-quorum 3-of-4 (ledger) both tolerate failures up to their threshold without losing availability or correctness | `packages/keyrelease/tests`, `packages/ledger/tests` (quorum-threshold cases) |
| Malformed input submitted to any service's API | Pydantic/canonical-CBOR schema validation rejects malformed payloads at the boundary before any protocol logic runs | FastAPI request validation throughout; `tscore.cbor.CanonicalCBORModel.from_canonical_cbor` |
| Repeated large-document uploads to `/distribute/analyze` or `/investigate/open` consume CPU (real rasterisation/alignment work) | **Not mitigated in this build** — `web-api` has no rate limiting or request-size throttling beyond nginx's `client_max_body_size`. Acceptable for a single-operator demo deployment; a real fix (per-identity rate limits) is out of scope here | Stated honestly as a residual gap, not hidden |

## Elevation of Privilege

| Scenario | Mitigation | Evidence |
|---|---|---|
| A revoked officer attempts to continue decrypting | The key-release node checks the most recent `EnrollFinalRecord`/`RevokeFinalRecord` for that officer before ever issuing a grant | Live-verified in M4: a revoked officer's next decrypt attempt is denied |
| An officer attempts to claim another officer's identity to access their copy | Blocked by both the server-side recipient-cert check (`keyrelease.node`) and the client-side `SealedHeader` check (`agent.decrypt`) independently — see Spoofing above | Live-verified M4 and M8 |
| A compromised forensics identity forges an `EvidenceBundle` accusing an innocent officer | The bundle's suspects are built only from vault-revealed codewords that are cross-checked against the ledger's own commitment before ever being trusted (`gather_candidate_codewords`), and every score is independently recomputable by the verifier — a forensics identity cannot simply assert an accusation | `tscore/tests/test_evidence.py`'s tampering cases 2, 4, 5 |

## Known operational risk (not an external attack, found live during M8)

`packages/ca/Dockerfile`'s `CMD ["python", "-m", "ca.seed"]` unconditionally
regenerates *every* identity in `demo/pki` on each container start, with no
idempotency guard. If the `ca` container ever restarts after other
services are already running and officer keystores are already sealed,
already-running `ledger-*`/`keyrelease-*` replicas keep their *old* keypair
cached in memory while `registry.json` now reflects the *new* one, and any
already-sealed keystore or already-issued `EnrollFinalRecord` becomes
orphaned against a ca-root key that no longer matches. This was hit live
(an incidental Docker Desktop restart during Phase 3/4 development) and is
documented in full, including the exact recovery steps, as ADR-0051 in
`docs/DECISIONS.md`. It is an availability/integrity-of-trust-roots risk
under operator error or infrastructure flakiness, not an externally
exploitable vulnerability — `ca` never runs as a network-reachable service.
Tracked as an open idempotency fix, not resolved under this document.

## Residual risks (architectural, stated honestly)

- **Sender + key-release collusion (framing):** framing an innocent
  recipient requires the sender *and* a threshold of key-release nodes to
  collude. Asymmetric fingerprinting, which would remove this assumption
  entirely, is out of scope for this build.
- **The analog hole:** retyping a document's content or reading it aloud
  is not attributable by this system. Out of scope; a semantic canary
  layer is future work.
- **Endpoint compromise:** if an officer's workstation is compromised
  while viewing a decrypted document (e.g. a malicious screen-scraper with
  kernel access), TraceSeal can still identify *which session* produced a
  leaked copy, but cannot prevent the capture itself.
- **Fabric's internal transport:** Hyperledger Fabric's own peer-to-peer
  transport remains classically secured (ECDSA/TLS) even after the M6
  PQC-signature work; only the application-level signatures inside ledger
  records and the block co-signatures are PQC, stated explicitly per
  `docs/SPEC.md` Section 20's honesty rules.
- **No rate limiting on `web-api`:** acceptable for this single-operator
  demo deployment; not a production-ready DoS defense (see above).
