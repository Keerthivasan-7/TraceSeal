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
