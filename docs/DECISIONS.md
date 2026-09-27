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
**Status:** Accepted, implemented in M0. liboqs 0.16.0 also finalised
SLH-DSA naming (replacing the older, non-standardised SPHINCS+ identifiers),
so `SLH-DSA-SHA2-128s` is available under its FIPS 205 name as required by
`docs/SPEC.md` Section 3.

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
