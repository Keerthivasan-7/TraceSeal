# Architecture Decision Records

Short-form ADRs (3–6 lines each). Numbered sequentially, never renumbered or
deleted — a superseded decision gets a new entry that says so.

## ADR-0001: Distribute sealed documents as rasterised pages

**Decision:** Sealed documents are distributed as rasterised pages (300 DPI,
lossless PNG) inside the encrypted package, not as the original PDF text/
vector content.
**Why:** Removes copy-paste-able text, covers embedded images, and makes
variant regions pixel-precise for the watermark engine. Mandated explicitly
by `docs/SPEC.md` Section 9.
**Status:** Accepted (specified, not yet implemented — lands in M1).

## ADR-0002: Hand-roll GF(256) Shamir secret sharing instead of a library

**Decision:** Implement byte-wise Shamir secret sharing ourselves in
`packages/tscore/src/tscore/shamir.py`, using the same GF(2^8) field as AES
(reduction polynomial 0x11B), rather than adding a third-party dependency.
**Why:** The spec explicitly permits either approach ("implement GF(256)
byte-wise Shamir yourself ... or use a vetted library"). The algorithm is
small (~100 lines), easy to pin down with test vectors and property tests,
and avoids a new supply-chain dependency for a component central to R7/R8
(no single admin can release key material).
**Status:** Accepted, implemented in M0.

## ADR-0003: liboqs version pin and install strategy

**Decision:** Build liboqs from the exact upstream commit
`5a1a854b0dc9f2141bdc771c555ee60c37950183` (tag `0.16.0`) inside the
`tscore` Docker image, install it to `/opt/liboqs`, and point
`liboqs-python==0.16.0.1` at that build via the `OQS_INSTALL_PATH`
environment variable, rather than letting liboqs-python auto-clone-and-build
liboqs itself.
**Why:** liboqs-python versions 0.10.0–0.16.0 shipped a shell command
injection vulnerability in their automatic liboqs installation path, fixed
in 0.16.0.1. Building liboqs ourselves from a commit we pin and verify (the
Dockerfile asserts `git rev-parse HEAD` matches before proceeding) sidesteps
that code path entirely regardless of which liboqs-python version is used,
and gives us the "pinned versions and checksums" build-time guarantee the
spec requires (Section 0 rule 4) via a content-addressed git commit rather
than a hand-copied tarball hash.
**Status:** Accepted, implemented and verified in M0 — `docker compose build`
+ `docker compose run --rm tscore python -m pytest -q packages/tscore/tests`
passes 42/42 against this build, including ML-KEM-768, ML-DSA-65 and
SLH-DSA. liboqs 0.16.0 also finalised SLH-DSA naming (replacing the older,
non-standardised SPHINCS+ identifiers) as required by `docs/SPEC.md`
Section 3, but its liboqs-python mechanism string is
`SLH_DSA_PURE_SHA2_128S` (underscored, "PURE" qualifier) rather than a
hyphenated `SLH-DSA-SHA2-128s` — discovered by querying
`oqs.get_enabled_sig_mechanisms()` against the real build after an initial
wrong guess failed 4 tests; see `packages/tscore/src/tscore/sig.py`.

## ADR-0004: `tscore.schemas` ships only the generic signed envelope at M0

**Decision:** At M0, `tscore/schemas.py` defines only the generic
`SignedEnvelope{version, domain, nonce, payload}` model. Concrete
per-protocol record types (`ENROLL_PROPOSE`, `DOC_REGISTER`,
`DecryptRequest`, ledger block/record shapes, ...) are added in the
milestone that implements that protocol step, not now.
**Why:** Those record shapes aren't fully determined until the service that
produces/consumes them is designed (M3+); defining them speculatively at M0
would mean guessing at fields and re-deriving them later. The generic
envelope (canonical CBOR, versioned, domain-separated, replay-resistant via
`nonce`) is the one piece every future record actually shares, per spec
Section 3.
**Status:** Accepted, implemented in M0.

## ADR-0005: demo sample PDF is generated, not committed as a binary

**Decision:** `demo/generate_sample_pdf.py` builds the 3-page synthetic
"classified-style" sample document on demand (PyMuPDF's own text APIs),
rather than checking in a static `.pdf` file.
**Why:** Keeps the repo reproducible from source and avoids a binary blob
in git history for something that's regenerated identically every time. The
curated, presentation-quality `OPERATION_PLAN.pdf` used in the full M8 demo
script is a separate, later decision.
**Status:** Accepted, implemented in M1.

## ADR-0006: variant-A (micro-shift) rendering technique

**Decision:** Each mark position's two variant patches are produced by:
cloning the whole document, redacting just that one word on its page,
reinserting the same word (same font/size/color, extracted from the
original page) at a position shifted `±delta_px`, rendering that **whole
page** at the target DPI, then cropping the padded region back out. Mark
positions are also required to have non-overlapping padded patch regions
(`sender/positions.py`), so pasting patches independently at assembly time
is unambiguous.
**Why — two alternatives were tried and measured first, per the project's
"never fake, verify empirically" rule, rather than trusting the first
plausible-looking approach:**
1. *Translated matrix over a fixed clip on the original page* (the
   "obvious" reading of spec Section 9's "re-render from the vector page"):
   measured **zero pixel difference** — PyMuPDF sizes the output raster
   from the transformed page rectangle, so translating the whole page's
   matrix cancels out relative to a clip defined the same way. Doesn't work.
2. *Render the word alone on an isolated single-word page*, then paste/
   composite that patch back: produces a real shift, but even at **zero**
   shift it doesn't reconstruct the original exactly (measured SSIM 0.948,
   not 1.0) — an isolated page anti-aliases text slightly differently than
   the same glyph in the full page's rendering context. Pasting it as an
   opaque rectangle also silently erased legitimate neighbouring content
   (e.g. the start of the next word) that fell inside the padding margin —
   found by diffing an assembled page against each position's own recorded
   patch and seeing ~10% of a patch's pixels mismatch for reasons unrelated
   to the intended shift.
3. **The technique actually used** (redact + reinsert on a full-page
   clone): measured **SSIM 1.0, zero pixel difference** at zero shift,
   confirming it reproduces the exact rendering context; a real `±2px`
   shift then changes roughly 10-15% of a patch's pixels (measured), which
   is the quality gate's expected/legitimate baseline (see ADR-0007).
**Status:** Accepted, implemented in M1. Cost: two extra full-page renders
per mark position (one per variant bit) — fine at M1's scale; revisit if a
much larger real document makes this too slow.

## ADR-0007: quality gate is whole-page SSIM + a per-position corruption check

**Decision:** `sender/quality_gate.py` gates on (a) whole-page SSIM of each
fully-assembled variant against the original rendering (spec Section 9's
literal wording, threshold 0.98 default) plus a max-pixel-delta report, and
(b) per mark position, the fraction of that position's patch pixels that
differ between its own bit-0 and bit-1 variant, flagged if it exceeds 50%.
**Why:** Whole-page SSIM alone can't catch a single badly broken patch —
measured directly: zeroing one patch out entirely left whole-page SSIM at
0.99+, since one small patch is a tiny fraction of a mostly-blank page. The
seemingly obvious fix (SSIM computed on just each position's own small
patch crop) was tried and rejected: even a *correct*, legitimately shifted
patch scores only ~0.6-0.7 there, because SSIM's small local windows are
inherently oversensitive to a couple of pixels of edge misalignment on thin
high-contrast text strokes — not a defect, just a property of the metric on
this kind of content, confirmed by checking that the *zero-shift* case (see
ADR-0006) is pixel-perfect while the real, intended shift still tanks a
tiny-window SSIM score. The changed-pixel-fraction check is simpler, more
robust for this specific failure mode, and was calibrated against the
measured ~10-15% legitimate baseline.
**Status:** Accepted, implemented in M1.

## ADR-0008: micro-shift delta tuned to 1.5px, not the spec's 2px starting point

**Decision:** `DEFAULT_DELTA_PX = 1.5` (was 2.0).
**Why:** Spec Section 9 explicitly gives 2px at 300 DPI as a *starting*
point ("δ tunable"). Measured against the real ~150-position, 3-page M1
demo document, 2px produced whole-page SSIM 0.9799 — just under the 0.98
gate. 1.5px measured 0.9846-0.9853 (comfortable margin) while remaining a
real, non-trivial shift (per-position changed-pixel-fraction still ~8-10%,
well above the noise floor). Revisit alongside δ/ε tuning against real
attack-lab distortions in M7, where robustness-vs-imperceptibility is
actually evaluated end to end rather than just at the quality gate.
**Status:** Accepted, implemented in M1.

## ADR-0009: forensics scope at M2 is a known document, no vault/OCR/photos

**Decision:** `packages/forensics` at M2 investigates a leaked artifact
against an already-known, in-memory `DocumentVariants` (the same object
`sender` already built) and a known set of session codewords — no
document/page identification across a vault (spec Section 11 step 3, no
vault exists until M3+M5), no OCR, no perspective correction for photos
(step 2 — "clean screenshots" have no camera distortion; real photo/scan
robustness is M7's attack lab). Registration uses ORB keypoints + RANSAC
homography against the base-plus-variant-0 rendering, matching step 4.
**Why:** Building OCR-based multi-document lookup or photo-distortion
correction now would be speculative — there's no vault to search and no
distortion to correct yet. The acceptance criterion ("top-1 attribution
... clean PNG screenshots") only requires the known-document,
undistorted-capture case, which is exactly what M3's real distribution
flow and M7's attack lab will need this same core (registration +
detection + accusation) to still work under, once those exist.
**Status:** Accepted, implemented in M2.

## ADR-0010: per-position local refinement is load-bearing, not optional

**Decision:** `forensics/detect.py` doesn't crop each mark position
directly at its globally-registered location; it searches a small margin
(default 10px) around it via `cv2.matchTemplate` normalised-correlation
template matching, independently per position, and uses whichever variant
patch's *best local match* scores higher.
**Why:** Measured, not assumed — a real M2 demo trial had ORB+RANSAC global
registration with 371/561 inlier matches (a seemingly solid fit) that
still carried 5.7px/3.2px of residual translation error. That's small next
to a whole page but larger than the 1.5px shift the entire scheme depends
on detecting: a direct crop at that drifted location got only 25/49
positions right on the affected page — *worse than guessing*. The spec's
own suggested fix, local ECC refinement (Section 11 step 4), was tried
first and failed to converge on this exact case
(`cv2.findTransformECC` raised "iterations do not converge"). The
template-match search is a more numerically robust way to get the same
effect (per-region local realignment) and was verified to recover 49/49 on
the same failing case, using the *same* drifted global homography as input.
**Status:** Accepted, implemented in M2.

## ADR-0011: `ca` is a direct-issuance seed script at M3, not a quorum service

**Decision:** `packages/ca` issues certificates directly (`ca.issue.issue_certificate`,
called by a one-shot `ca.seed` script that also generates every M3 demo
identity's keypairs) rather than a live, quorum-gated enrolment service.
Every concrete signed-record payload (`Certificate`, `DocRegisterRecord`,
`DecryptRequest`, `KeyGrant`, `ReceiptRecord`, ...) is added to
`tscore.records` at M3, the milestone that first needs them, per ADR-0004's
lazy-build policy — they live in the shared `tscore` library rather than in
whichever single service happens to produce one, since each is consumed by
at least one *other* service too.
**Why:** Spec Section 4's full enrolment ceremony (`ENROLL_PROPOSE`/
`APPROVE`/`FINAL` over the ledger, M-of-N officer approvers) is explicitly
Milestone M4. M3 only needs *some* certificates to exist so the protocol
has identities to exercise; building a quorum-gated CA now and then
rebuilding it for real quorum at M4 would be speculative rework in front
of a milestone that already owns this problem.
**Status:** Accepted, implemented in M3.

## ADR-0012: LedgerLite replicas are real separate services, SQLite-backed

**Decision:** `packages/ledger` runs 4 real, separate FastAPI containers
(`ledger-0..3`, fixed leader = replica 0, "no view change" per spec's own
hedge), each with its own SQLite-backed hash-chained append-only log
(stdlib `sqlite3`, not Postgres). `/chain` and `/records/{tx_id}` only ever
expose already-finalized records — there is no "pending" state a caller
could observe, which is what makes `keyrelease`'s finality check
(ADR-0014) a structural guarantee rather than a policy one.
**Why:** The user explicitly chose "real separate services" over an
in-process simulation when asked, since the whole point of the M3
acceptance criterion is proving cross-replica, cross-service properties
that an in-process stand-in can't actually falsify. SQLite is sufficient
for LedgerLite's own job (a small per-replica append-only log with
cross-replica signature checking, spec Section 12); Postgres is still the
pinned store for general relational metadata once something needs that
(likely the M8 UI), not for the ledger's own hash chain.
**Status:** Accepted, implemented in M3 — verified with 4 real containers
on `traceseal_internal`; `ledger`'s 19-test suite (co-signing, quorum
finalization, cross-replica chain verification, tamper rejection) passes
in Docker.

## ADR-0013: the Tardos bias vector travels outside the Shamir-split secret

**Decision:** `sender.distribute.register_shares` sends every key-release
node two separate things: its own distinct Shamir share of `K_B || S_v`,
and the *same* plaintext Tardos bias vector (KEM-wrapped per node, not
secret-shared). `tscore.release_secret` documents this split explicitly.
**Why:** Discovered as an architectural bug mid-implementation, not a
design taken from the spec directly: whichever key-release node
coordinates a session needs the bias vector *before* it writes
`DECRYPT_REQUEST` to the ledger (to assign that session's codeword), but
`K_B`/`S_v` must stay gated *behind* 3-of-5 reconstruction that only
happens *after* ledger finality (commit-before-release). Bundling both
into one Shamir-split secret made these two timing requirements mutually
exclusive; separating them (same bias vector to everyone, `K_B||S_v`
properly threshold-gated) satisfies both.
**Status:** Accepted, implemented in M3.

## ADR-0014: every key-release node re-verifies finality, not just the coordinator

**Decision:** `KeyReleaseNode.release_share` independently queries the
ledger for a finalized `DECRYPT_REQUEST_LEDGER` record matching the
session before ever returning this node's share — for every node, in its
peer role, regardless of which node is coordinating that session or what
the caller claims.
**Why:** This is stronger than the spec's coordinator-centric wording, and
is what makes "grant-before-finality is impossible" (the M3 acceptance
criterion) a property that's true *by construction* rather than something
that only holds if the coordinator happens to behave. Verified directly:
`keyrelease`'s `test_release_share_denied_without_a_finalized_decrypt_request`
calls `release_share` for a session whose `DECRYPT_REQUEST` was never
submitted and asserts refusal — no Docker needed, since it's a property of
`KeyReleaseNode` itself.
**Status:** Accepted, implemented in M3.

## ADR-0015: filesystem blob store, not MinIO

**Decision:** Encrypted `.tspkg` packages and per-recipient wrapped `K_A`
blobs live under a shared Docker volume (`./demo/blob`), read/written
directly as files (`sender.package.save_package`/`load_package`), not in
MinIO.
**Why:** Spec Section 5 explicitly allows either ("MinIO or a local
filesystem blob store"); MinIO would be a heavyweight dependency with
nothing at M3 that actually needs object-store semantics (versioning,
multi-writer concurrency, HTTP object API) over a shared bind-mounted
directory.
**Status:** Accepted, implemented in M3.

## ADR-0016: `sender` and `agent` stay one-shot scripts, not persistent services

**Decision:** `sender.demo_m3` and `agent.demo_m3` are CLI entry points run
via `docker compose run`, not long-running HTTP services (unlike `ledger`
and `keyrelease`, which are real always-up containers).
**Why:** There's no UI yet to call either interactively — a sender
uploading a document and an agent serving a viewer are both M8 concerns.
Both only ever make *outbound* calls (to key-release nodes and the
ledger); a one-shot script is the honest shape for what they actually do
at M3, and matches the pattern already established for `sender.demo_m1`/
`forensics.demo_m2`.
**Status:** Accepted, implemented in M3.

## ADR-0017: `httpx.ASGITransport` is async-only; test wiring mounts `TestClient`'s transport instead

**Decision:** Every in-process test that wires multiple FastAPI apps
together through one shared `httpx.Client` (`ledger`'s and `keyrelease`'s
`build_ledger_client`/`build_keyrelease_cluster` helpers) mounts each
app's `starlette.testclient.TestClient(app)._transport`, not a bare
`httpx.ASGITransport(app=app)`.
**Why:** Measured directly against the actual installed `httpx==0.28.1` in
Docker — the *first real Docker run* of this M3 test code, since these
tests are `requires_liboqs`-marked and had only ever been collection-
checked locally before now (no liboqs on this dev machine). `ASGITransport`
in this httpx version implements only `handle_async_request`; mounting it
into a sync `httpx.Client` and calling `.post()`/`.get()` raised
`AttributeError: 'ASGITransport' object has no attribute
'handle_request'` on every affected test. `TestClient`'s own internal
transport bridges the same ASGI app synchronously via an `anyio` portal,
and is mountable the same way; swapping to it fixed all 4 previously-
failing `ledger` tests and made the equivalent `keyrelease`/`agent` helpers
work correctly the first time.
**Status:** Accepted, implemented in M3.

## ADR-0018: registry lookups raise `VerificationError`, not `KeyError`

**Decision:** `ca.registry.sig_public_key`/`kem_public_key` raise
`tscore.errors.VerificationError` for an identity_id not present in the
registry, instead of letting a raw dict-lookup `KeyError` propagate.
**Why:** Found by the same first-real-Docker-run pass as ADR-0017: a
ledger test submitting a signature from an unregistered signer expected a
clean HTTP 400 (`VerificationError` is caught and converted by
`ledger.service`'s route handlers), but got an unhandled 500 instead,
because an unknown identity leaked a raw `KeyError` past every catch
clause. Every caller of these two lookups (`ledger`, `keyrelease`) already
only catches `VerificationError` at its HTTP boundary — making the
registry raise the same typed error it already expects is the correct
fix, not adding another except-clause at each call site.
**Status:** Accepted, implemented in M3.

## ADR-0019: fixed admin identities enrol officers, not peer-officer quorum

**Decision:** A fixed set of admin identities (`ca.seed.ADMIN_IDS`, default
3, sig-only) act as the M-of-N approvers (default 2-of-3, spec Section 7.1)
for the enrolment/revocation ceremony — not the officers themselves voting
on each other.
**Why:** Officers can't approve each other's admission before any officers
exist — a bootstrap problem a peer-quorum design can't avoid without a
special-cased "genesis" set, which would just be this decision by another
name. A small fixed admin set is also what the spec's own sequence diagram
depicts (a distinct `Admin` actor proposing and approving), and matches
G5's framing: admission decisions are institutional (a unit's admins), not
something the workforce being admitted decides for itself.
**Status:** Accepted, implemented in M4.

## ADR-0020: `ca.seed` stops issuing officer certificates

**Decision:** `ca.seed.seed_all` still generates every officer's raw
ML-DSA+ML-KEM keypair (needed to build a CSR) but no longer calls
`ca.issue.issue_certificate` for them. Certificates only come from the real
ceremony (`ca.enrolment`, driven end-to-end by `ca.demo_m4` against a live
ledger).
**Why:** ADR-0011 explicitly flagged the old direct-issuance path as "the
stand-in for M4's real ledger-backed enrolment ceremony" — M4 is the
milestone that replaces it. `packages/keyrelease` and `packages/agent`'s
own test-only `seed_pki` helpers build their fixtures directly via
`ca.issue.issue_certificate` and never called `ca.seed` in the first place,
so M0–M3 test suites needed no changes on that account — they did, however,
need a `submit_enroll_final` test helper added once `keyrelease.node`
started checking a request's `recipient_cert_hash` against a real
`ENROLL_FINAL` ledger record (ADR-0025).
**Status:** Accepted, implemented in M4.

## ADR-0021: certificate/revocation status is checked by direct ledger query

**Decision:** `keyrelease.node._check_not_revoked` queries the ledger for
`REVOKE_FINAL` records naming a given cert hash, every call — no "revoked"
flag added to `ca.registry`'s untyped dict, no local cache or materialized
view anywhere.
**Why:** Spec Section 7.1 is explicit: "every service checks certificate
status against the ledger state" — not against a copy of it. This also
matches the existing `_enforce_policy` idiom exactly (it already scans
`ledger_client.query(...)` rather than trusting a local file), and at this
system's demo scale a materialized view would be speculative complexity
with no performance problem to justify it.
**Status:** Accepted, implemented in M4.

## ADR-0022: `SealedHeader` is a raw quorum-signed artifact, not a ledger record

**Decision:** `keyrelease.node` mints a fresh `SealedHeader` per `KeyGrant`
response and co-signs it directly (`sig_sign` over its own canonical CBOR —
the same attestation-signing pattern as `KeyGrantIssuedRecord.contributing
_signatures`, not a `SignedEnvelope`/`make_submission`). It travels only in
the `/decrypt-request` HTTP response body, never submitted to the ledger.
**Why:** The header exists to let the *recipient* verify, at the moment of
receipt, that a response really names them — it isn't itself part of the
audit trail (the audit trail is `OpenEventRecord`/`OpenDeniedRecord`,
logged by the agent once it has checked the header). Submitting it to the
ledger too would double the write load on every decrypt session for a
value nothing else ever needs to look up later.
**Status:** Accepted, implemented in M4.

## ADR-0023: enrolment quorum-counting trusts ledger-finalized presence, not a raw re-derived signature

**Decision:** `ca.enrolment.count_verified_approvals` recomputes the
approval count fresh from the ledger's current state every call (never
trusts a caller-supplied count), dedupes by distinct `submitter_id`, and
filters to the fixed admin allowlist — but does not itself re-verify each
approval's raw ML-DSA signature client-side.
**Why:** `ledger.wire.RecordWire` (what `/chain`/`/records` serve)
deliberately zeroes `submitter_signature` — "not exposed over /chain" — so
a byte-for-byte client-side re-verification isn't achievable through the
public wire API as it stands. This is not a shortcut: every ledger replica
already independently verified the submitter's signature at
`LedgerNode.finalize` time before the record could ever reach `/chain`
(ADR-0012/0014's trust boundary) — the exact same reasoning
`keyrelease.node.release_share` already relies on for its own finality
check. A stronger (optional) hardening would call `ledger_client
.verify_chain()` first, at the cost of extra cross-replica HTTP calls per
finalize — worth a comment, not required for M4's scope.
**Status:** Accepted, implemented in M4.

## ADR-0024: the agent's durable outbox covers only OPEN_EVENT/OPEN_DENIED

**Decision:** `agent.outbox` (fsync'd append + best-effort flush) is used
only for `OpenEventRecord`/`OpenDeniedRecord` submission, via a new
`_submit_or_queue` helper. `ReceiptRecord` submission stays a hard
synchronous `submit`+`wait_final`, exactly as before M4.
**Why:** Spec Section 7.4's offline-queueing requirement is scoped to open
events specifically ("it never opens a document without, at minimum, the
queued signed event") — it's what makes copy-binding/forwarding-detection
auditable even when the ledger is briefly unreachable. Extending the same
queueing to receipts wasn't asked for and would change M3's already-
verified "receipt finality" guarantee (a receipt tx_id `open_document`
returns today is always already finalized) into a weaker one, for a
requirement that doesn't need it.
**Status:** Accepted, implemented in M4.

## ADR-0025: `keyrelease` independently verifies a request's real certificate, not just the self-declared claim

**Decision:** `keyrelease.node.handle_decrypt_request` looks up
`submission.signer_id`'s real, currently-enrolled certificate hash (the
latest `ENROLL_FINAL` record on the ledger for that officer_id) and rejects
the request outright if it doesn't match the request's own self-declared
`recipient_cert_hash` — before any codeword assignment or ledger write.
**Why:** Found during design review, not in the spec's literal text but
required by it: spec Section 2's residual-trust statement says framing an
innocent recipient "would require the sender **and** a threshold of
Key-Release nodes to collude." Without this check, a single officer could
frame another unilaterally — sign a valid `DecryptRequest` with their own
key while self-declaring a different officer's `recipient_cert_hash` — and
the coordinator would service it (assign a codeword, write
`DECRYPT_REQUEST_LEDGER`, consume policy quota) before the agent-side
`SealedHeader` check (ADR-0022) ever ran. That's a single-actor exploit,
not a collusion scenario, contradicting the spec's own stated guarantee.
This server-side check makes the client-side `SealedHeader` check genuine
defense-in-depth (catching a compromised/malicious key-release node or
misdirected blob-store artifacts) rather than the sole line of defense.
**Status:** Accepted, implemented in M4.

## ADR-0026: forensic vault reveal lives in `keyrelease.node`; `forensics-1` is a raw, sig-only infra identity

**Decision:** No new "vault" microservice. `KeyReleaseNode` gains
`reveal_bias_vector(doc_id)` (any node that registered the doc has an
identical broadcast copy) and `reveal_commitment(session_id, doc_id)`
(only the coordinating node has it — resolved from
`DECRYPT_REQUEST_LEDGER`'s own `submitter_id`), exposed over
`/reveal-bias-vector`/`/reveal-commitment`. `reveal_bias_vector` returns
ONLY the plaintext bias vector, never the node's own Shamir share fields
in the same store row. `forensics-1` is bootstrapped by `ca.seed` exactly
like `sender-1`/`ledger-i`/`keyrelease-i` (ADR-0019's infra-identity
pattern): `with_kem=False` (vault reveal runs over plain internal HTTP,
matching every other inter-service call today) and no CA-issued
certificate.
**Why:** Spec Section 7.3 says a session's codeword+salt should be
"encrypted to the forensic vault key", but M3 never built that —
`keyrelease.store` already holds it in plaintext, locally, per node
(a stand-in acknowledged at the time). Reusing the existing 5-node trust
boundary rather than retrofitting a new encrypted-storage component adds
no new single point of compromise: the same 5 nodes already hold the
release secret shares.
**Status:** Accepted, implemented in M5.

## ADR-0027: the ledger "inclusion proof" is honestly scoped — no Merkle tree

**Decision:** `tscore.evidence.verify_record_proof` proves a ledger
record's own internal hash-chain consistency (`record_hash` recomputes
correctly from `prev_hash`/`tx_id`/`envelope_cbor`/`quorum_signer_ids`)
and genuine quorum sign-off (every quorum signature independently
re-verified, threshold enforced) — it does NOT prove the record wasn't
omitted from a longer chain never independently walked end-to-end. This
limitation is stated verbatim in every signed PDF report's mandatory
limitations section.
**Why:** LedgerLite (ADR-0012) is a flat quorum-signed hash chain, not a
Merkle/checkpoint structure. Claiming a stronger, Merkle-style
non-omission guarantee would be exactly the kind of overclaim `CLAUDE.md`'s
honesty rules forbid. A real Fabric backend (M6) could close this gap;
until then, the report says so rather than implying it.
**Status:** Accepted, implemented in M5.

## ADR-0028: new `GET /records/{tx_id}/proof` route, distinct from the redacted `/records/{tx_id}`

**Decision:** Add a second ledger route that serves the real
`submitter_signature` (already retained in `StoredRecord`, only ever
redacted at the wire-projection layer) — `/records/{tx_id}` keeps
ADR-0023's redaction unchanged for normal operational use.
**Why:** ADR-0023's redaction was justified by "operational callers trust
ledger-finalized presence, not a raw re-derived signature" — a reasonable
simplification for keyrelease's own finality checks. An evidence bundle
built for independent third-party re-verification (G4) needs the actual
signature to prove the submitter genuinely signed the record, not just
that the ledger says so. Two distinct use cases, two distinct routes,
rather than weakening ADR-0023's redaction for everyone.
**Status:** Accepted, implemented in M5.

## ADR-0029: `compute_record_hash` relocates to `tscore/chain.py`

**Decision:** Move `compute_record_hash` (pure function, zero logic
change) from `ledger/store.py` into a new `tscore/chain.py`; `ledger`
imports it from there.
**Why:** `tscore.evidence.verify_record_proof` (used by both `forensics`
and the standalone `verifier`, which must depend on `tscore` only — G4)
needs the exact same hash function `ledger` uses at write time, or the
two could silently drift apart. Kept out of `tscore/evidence.py` itself so
`ledger` doesn't pull in numpy/pydantic transitively just for one hash
function.
**Status:** Accepted, implemented in M5.

## ADR-0030: `EvidenceBundle` reuses `SignedSubmission`; `REPORT_ISSUED` is a non-circular, post-signing, verifier-ignored ledger entry

**Decision:** `EvidenceBundle` is signed via the existing
`make_submission`/`open_submission` machinery under a new
`DOMAIN_EVIDENCE_BUNDLE` — no bespoke wrapper type.
`ReportIssuedRecord{case_id, doc_id, bundle_hash, report_pdf_hash}` is
submitted to the ledger AFTER the bundle is built and signed, as a
downstream audit-trail entry only; `traceseal-verify` never queries the
ledger (G4) and therefore never checks this record.
**Why:** `ReportIssuedRecord` cannot be embedded inside the bundle it
describes — it would have to commit to the bundle's own hash, but the
bundle isn't finalized until it's signed, and its hash isn't known before
that. Found during design (not assumed away): the fix is to make it a
downstream-only entry, not to weaken the bundle's own self-containment.
**Status:** Accepted, implemented in M5.

## ADR-0031: Fabric topology — 4 orgs, each with its own orderer MSP and its own peer MSP

**Decision:** Model the 4 organisations as 4 orderer-org/peer-org pairs
(`Org<N>OrdererMSP` + `Org<N>MSP`, `N`=1..4) rather than the official
`fabric-samples` pattern of one shared `OrdererOrg` plus separate peer
orgs. Each org's `ConsenterMapping` entry uses its own orderer identity,
and each orderer's `ORDERER_GENERAL_CLUSTER_ROOTCAS`/`TLS_ROOTCAS` is a
bundle of all 4 orgs' orderer CA certs (built by
`fabric-network/scripts/generate.sh`) — a step no official sample needs,
since they all use one shared CA for the whole BFT set.
**Why:** Spec Section 12 says "4 orderers across 4 organisations" — 4
independently-controlled orgs, not 4 nodes under one org's single root of
trust. Confirmed via research that no official or community example
models this; the official BFT samples (`test-network`,
`test-network-nano-bash`) both put all 4 orderers in one `OrdererOrg`.
**Status:** Accepted, implemented in M6. Bootstrapped and verified live:
all 4 orderers joined `tschannel` via `osnadmin`, all 4 peers joined, the
`traceseal` chaincode committed with all 4 orgs' approval.

## ADR-0032: no CouchDB — a composite-key index instead

**Decision:** `chaincode/traceseal` uses the default LevelDB state
database plus a `domain~txid` composite key
(`CreateCompositeKey`/`GetStateByPartialCompositeKey`) for
`QueryRecordsByDomain`, instead of adding CouchDB per peer for rich
queries.
**Why:** The only query TraceSeal's own code ever needs is "records in
this domain" (every real caller of `ledger.client.LedgerClient.query`
already passes a `domain=` filter) — a composite-key range scan answers
that exactly, without 4 more containers and CouchDB's own startup-
ordering/health-check complexity.
**Status:** Accepted, implemented in M6.

## ADR-0033: Fabric records use a fixed `prev_hash`; `record_hash` is recomputed on co-sign

**Decision:** Every Fabric-backed record's `prev_hash` is a fixed
`GenesisHash` constant, never another record's live `record_hash` —
unlike LedgerLite, where each replica's records literally chain
prev-hash-to-record-hash. `record_hash` itself is recomputed (same
`tscore.chain.compute_record_hash` formula) each time `AddCosignature`
appends a new validator co-signer, so it always reflects the record's
CURRENT `quorum_signer_ids` — safe to mutate repeatedly here specifically
because nothing else ever references a Fabric record's `record_hash` as
some OTHER record's `prev_hash`.
**Why:** LedgerLite's prev_hash chain exists only because LedgerLite has
no other structure to lean on for tamper-evidence (ADR-0012/ADR-0027);
Fabric's own block structure already gives that. Co-signing happens
*after* the record commits (a separate transaction, `ledger.cosigner`),
so `quorum_signer_ids` genuinely isn't known at `SubmitRecord` time —
recomputing the hash on each append keeps
`tscore.evidence.verify_record_proof`'s existing hash-check semantics
("record_hash matches THIS record's own current fields") true for this
backend too, with zero changes to that M5 code.
**Status:** Accepted, implemented in M6.

## ADR-0034: `fabric-tools` built from Fabric source, not a published image

**Decision:** `fabric-network/tools.Dockerfile` compiles
`configtxgen`/`cryptogen`/`osnadmin`/`discover` from
`hyperledger/fabric`'s exact `v3.1.5` source tag (the same tag already
pinned for `fabric-orderer`/`fabric-peer`), copying `peer` itself
straight out of the already-published `fabric-peer:3.1.5` image rather
than rebuilding it too.
**Why:** Confirmed directly, not assumed: neither `fabric-tools:2.5.9`
(the newest reliably-pinned numbered tag) nor `fabric-tools:latest`
(which itself still resolves to v2.5.16) can parse a BFT `configtx.yaml`
— both panic on `"invalid keys: ConsenterMapping, SmartBFT"`. No
published `fabric-tools` image with working BFT support exists as of this
writing. `chaincode/traceseal`'s Go module dependencies are vendored in
the same Dockerfile stage (network access is allowed at build time only;
the classic Docker-based chaincode build `fabric-tools`/peers use has
none at runtime, per CLAUDE.md's zero-egress rule).
**Status:** Accepted, implemented in M6.

## ADR-0035: a Go REST gateway bridges Python to Fabric — no official Python SDK exists

**Decision:** `packages/fabric-gateway` is a small Go program (NOT a
Fabric node) wrapping the real `hyperledger/fabric-gateway` Go SDK behind
a REST API shaped exactly like `ledger.service`'s own
(`POST /submit`, `GET /records/{tx_id}`, `GET /records/{tx_id}/proof`,
`GET /chain?domain=`) — `ledger.fabric_client.FabricLedgerClient` calls
it over plain HTTP and returns the SAME `ledger.wire.RecordWire`/
`RecordProofWire` types `ledger.client.LedgerClient` already returns.
**Why:** Hyperledger only publishes official Fabric Gateway SDKs for Go,
Node, and Java — no Python SDK exists. Rather than hand-rolling a Python
gRPC client against Fabric's Gateway protobufs (a large amount of new
surface area for no real benefit), one small Go relay reuses the
battle-tested official SDK, and shaping its REST responses to match
`ledger.wire`'s existing Pydantic models makes `FabricLedgerClient` a
near-identical drop-in for `LedgerClient` (`ledger.backend.LedgerBackend`,
ADR-0031's sibling decision) rather than a parallel, divergent client
shape.
**Status:** Accepted, implemented in M6.

## ADR-0036: chaincode endorsement/lifecycle policy is `OutOf(3, ...)`, mirroring `LEDGER_QUORUM_THRESHOLD`

**Decision:** `fabric-network/configtx.yaml`'s `Application.Policies`
(`Endorsement`, `LifecycleEndorsement`) require 3-of-4 peer orgs, not a
unanimous `AND` of all 4.
**Why:** LedgerLite's own quorum is `LEDGER_QUORUM_THRESHOLD = 3` (of 4
replicas) — deliberately resilient to exactly one node being down. Using
the same threshold for Fabric keeps both backends telling the same
resilience story ("any one organisation can be offline and the system
still works"), rather than making the Fabric path strictly more fragile
(a unanimous 4-of-4 AND policy) for no corresponding security gain, since
3-of-4 already requires a majority-plus-one of independently-controlled
organisations to collude or fail together.
**Status:** Accepted, implemented in M6.

## ADR-0037: ML-DSA block co-signing is a post-hoc `AddCosignature` pass, not part of `SubmitRecord`

**Decision:** `ledger.cosigner` (one instance per validator org, run
against its own `fabric-validator-<N>` identity) polls every co-signable
domain and calls chaincode's `AddCosignature` for any record it hasn't
signed yet — a separate transaction from the original `SubmitRecord`,
not something bundled into the same call.
**Why:** The whole point of the co-signing layer (spec: "Fabric's
internal transport is still ECDSA ... evidence verification depends only
on PQC signatures") is a PQC attestation *independent* of Fabric's own
endorsement — bundling it into the same transaction as the original
submit would mean only the ORIGINAL submitter's org ever attests,
defeating the purpose. A record is "PQC-finalized" once
`len(quorum_signer_ids) >= KEY_RELEASE_QUORUM_THRESHOLD`-style 3-of-4
co-signers exist, checked by whoever reads `LedgerRecordProof` later
(`tscore.evidence.verify_record_proof`, unchanged from M5).
**Status:** Accepted, implemented in M6.

## ADR-0038: SLH-DSA checkpoint signs a queried-record manifest hash, not a running Merkle accumulator

**Decision:** `ledger.checkpoint` queries every co-signable domain,
sorts the records by `tx_id`, hashes the joined `"tx_id:record_hash"`
manifest, and signs that hash with `ca-root`'s existing SLH-DSA-SHA2-128s
key (no new checkpoint-specific identity) — writing a JSON file with the
full signed checkpoint, plus a QR PNG of a compact fingerprint
(`manifest_hash`, `record_count`, `checkpoint_authority_id`, `built_at` —
no signature) — an SLH-DSA-SHA2-128s signature is ~7.8 KB hex-encoded,
which does not fit in any QR code version (max ~2.9 KB at version 40),
confirmed directly by a real `ValueError: Invalid version` during the M6
e2e run, not assumed in advance. The QR is therefore a manual cross-check
pointer against the JSON file, not a self-contained independently
verifiable artifact — that still requires the full JSON.
**Why:** Building a genuine incremental Merkle accumulator over the
ledger's history is real, non-trivial cryptographic engineering out of
scope for this milestone's remaining time; signing a manifest over
whatever records are queryable *right now* is still a real, independently
re-verifiable SLH-DSA attestation ("as of this signature, these exact
(tx_id, record_hash) pairs existed"), just not a running commitment to
history the way a Merkle root would be. Documented honestly, same
"no Merkle tree" scoping discipline as ADR-0027 — never claimed as more
than it is. The QR PNG is a demo export (a file on disk), not an actual
printed/scanned physical workflow or an HSM/WORM device.
**Status:** Accepted, implemented in M6.

## ADR-0039: explicit anchor-peer channel updates, run once after `create-channel.sh`

**Decision:** `fabric-network/configtx.yaml`'s 4 peer-org definitions each
declare `AnchorPeers` (their own `peer0.org<N>.traceseal.local:7051`);
`fabric-network/scripts/set-anchor-peers.sh` submits one anchor-peer
channel-config-update transaction per org, run once after
`create-channel.sh`. `fabric-tools`' Dockerfile also gained `configtxlator`
(built from the same pinned Fabric source as the other tools) and `jq`
(apt, build-time only), since Fabric 3.x's `configtxgen` dropped the old
`-outputAnchorPeersUpdate` shortcut, requiring the manual fetch-config /
patch-with-jq / compute-update / submit dance instead.
**Why:** without anchor peers, each org's peer gossip network stays
island-bound — confirmed directly, not assumed: the real M6 e2e run
failed with `rpc error: ... FailedPrecondition ... no combination of
peers can be derived which satisfy the endorsement policy` on every
single `SubmitRecord`/`RegisterIdentity` call, because the Fabric
Gateway's discovery service had no cross-org layout to route the
`OutOf(3, ...)` endorsement policy (ADR-0036) across. Anchor peers are
exactly what lets Discovery bridge orgs. This has no LedgerLite
equivalent to compare against — LedgerLite's replicas never needed peer
discovery in the first place.
**Status:** Accepted, implemented in M6.

## ADR-0040: `.env` pins `LEDGER_BACKEND`/`FABRIC_GATEWAY_URL` for the whole Compose project

**Decision:** A project-root `.env` (gitignored, alongside the existing
`.env`/`.env.*` entries) sets `LEDGER_BACKEND=fabric` and
`FABRIC_GATEWAY_URL=http://fabric-gateway:8000` for the duration of M6
verification, rather than relying on exporting these as shell variables
before each `docker compose` invocation.
**Why:** `docker compose`'s `${VAR:-default}` substitution (used in
`keyrelease-N`'s `environment:` block) only sees shell-exported variables
from the SAME shell invocation that runs the command — confirmed
directly, not assumed: a later `docker compose run` for an unrelated
one-shot service (issued from a fresh shell with no exports) silently
reconciled `keyrelease-0` back to its `lite` default mid-sequence,
causing a real `recipient_cert_hash does not match ... current enrolled
certificate` failure (keyrelease-0 was querying LedgerLite, which had no
`ENROLL_FINAL` records, instead of Fabric). `.env` is read by every
`docker compose` invocation regardless of which shell process runs it,
closing that gap. This only affects Compose-level `${VAR}` substitution,
not a service's actual container environment — a one-shot service's own
container still needs `-e LEDGER_BACKEND=fabric` on its `docker compose
run` command if it reads `os.environ` directly rather than going through
a `${VAR}`-substituted `environment:` entry (as `agent`/`sender`/`ca`'s
demo scripts do); this was the cause of a second, related bug where
`agent.demo_m3`'s own receipt submission silently landed on LedgerLite
even though the same session's `DecryptRequest`/`KeyGrant` records
(written server-side by `keyrelease-0`, which does read `${VAR}`-backed
`LEDGER_BACKEND`) correctly landed on Fabric.
**Status:** Accepted, implemented in M6.

## ADR-0041: M7's attack lab evaluates variant A only; variants B/C stay unbuilt

**Decision:** `packages/attacklab` evaluates only variant A (micro-shift) —
the one variant type `sender.variants` actually implements. Variant B
(glyph micro-scale) and variant C (stroke-weight) are not built this
milestone, despite spec Section 9 framing them as "behind flags and
evaluated in the attack lab."
**Why:** Confirmed with the user before starting M7: building two new
rendering techniques (new patch-generation code, new quality-gate runs
against them, new sender tests) is materially larger scope than evaluating
the one variant type that has existed since M1 and is the only one any
other milestone's protocol code actually distributes. Spec Section 9's own
phrasing is honestly addressed by documenting the gap, not by silently
ignoring it or fabricating results for variants that don't exist.
**Status:** Accepted, implemented in M7. Deferred indefinitely (not
currently planned) rather than to a named future milestone.

## ADR-0042: bitwise collusion strategies reuse `assemble_document` directly; only patch averaging needs its own pixel-realization function

**Decision:** `attacklab.collusion`'s four bit-selection strategies
(majority, minority, random, interleave) return a pirate `BitArray`, which
`sender.assemble.assemble_document` renders into a page directly — no
separate "pixel realization" function exists for them. Only patch
averaging gets its own function, `realize_patch_averaging_pages`.
**Why:** Every session shares the exact same two physical patches per
mark position (`patch_bit0`/`patch_bit1` from
`sender.variants.build_document_variants`); sessions differ only in which
bit their own codeword selects. By construction (including the
"marking assumption" fix — see `packages/tscore/tests/test_tardos.py`), a
bit-selection strategy's pirate bit at every position always equals some
coalition member's own real bit there, so the resulting page is already
physically realizable and pixel-identical to what `assemble_document`
produces from the pirate bit array directly — inventing a wrapper that
manually looked up "which coalition member holds this bit" and pasted
their patch would have produced the exact same pixels through more code.
Patch averaging has no discrete pirate bit at all (it blends two
colluders' own patches into pixel content neither one's codeword alone
selects), so it genuinely needs its own compositing function; both share
the same underlying paste logic via `sender.assemble.paste_patches`
(extracted from `assemble_document` this milestone, no behavior change to
the existing function).
**Status:** Accepted, implemented in M7.

## ADR-0043: no page-detection/perspective-correction step for real photographed pages

**Decision:** `packages/attacklab`'s real-capture folder
(`attacklab/real/`) is evaluated through the same `forensics.pipeline.
investigate` entrypoint as every synthetic condition, with no
document-in-background contour-detection/cropping step added.
**Why:** Extends ADR-0009's original M2 scoping into M7: `forensics.align.
register`'s ORB+RANSAC homography already handles rotation, perspective,
scale, and cropping of the document's own content (confirmed — every spec
Section 15 synthetic distortion and the print-scan/screen-camera
simulations are full-frame, no added background, and register correctly),
but does not separate a photographed page from surrounding background.
Building a contour-detection step speculatively, with `attacklab/real/`
shipping empty this milestone (confirmed scope decision — no real-capture
hardware was available), would mean building and shipping code with
nothing real to validate it against. Recorded honestly in
`attacklab/real/README.md` and `docs/RESULTS.md`'s real-capture section
rather than silently worked around with an ad-hoc crop-to-frame heuristic.
**Status:** Accepted, deferred (not implemented in M7).

## ADR-0044: δ=1.5px and k=2.0 confirmed adequate by real M7 attack-lab data; no change made

**Decision:** `sender.variants.DEFAULT_DELTA_PX` (1.5, set by ADR-0008) and
`tscore.tardos.threshold`'s constant `k=2.0` are left unchanged after
reviewing `docs/RESULTS.md`'s real attack-lab numbers — ADR-0008's own
"revisit at M7" note is superseded by this decision.
**Why:** Across every mild-to-moderate synthetic condition (all 4 JPEG
qualities, both resize scales, rotation, perspective warp, blur σ ≤ 1,
noise, brightness/contrast, a 10% crop) the real per-position detection
showed **zero bit errors and 100% top-1 accuracy** at a stable ~8% baseline
erasure rate (the detector's own confidence-threshold floor, not
distortion-induced loss). Heavier conditions degrade the way an
erasure-aware scheme should: erasure rate climbs with genuine severity
(30%/50% crop: 25%/43%; blur σ=1.5: 16%; the composite screen-camera/
print-scan pipelines: 15%/10%) and top-1 accuracy drops only where the
underlying signal is genuinely gone (crop 50%: 80%; 3-of-8 interleave
collusion: 80%; 4-of-8 minority collusion: 40%) — but **zero innocent
accusations occurred across all 180 real trials**, including every one of
those degraded-accuracy conditions. Patch-averaging collusion shows
materially elevated erasure (as expected — it manufactures pixel content
neither variant patch actually has) but still zero false accusations. The
one metric that would justify raising δ (bit errors appearing under mild,
realistic conditions) never appeared; the one metric that would justify
changing `k` (innocent-accusation rate exceeding `eps1`, `tscore.tardos`'s
own `test_tardos.py` Monte-Carlo check) also never appeared. Raising either
parameter with no supporting evidence would just be guessing.
**Status:** Accepted — no change, confirmed by data (`make demo-m7`,
`docs/RESULTS.md`).
