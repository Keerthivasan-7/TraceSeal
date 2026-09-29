# Real-capture folder

Drop real phone-photo or scan captures of a printed/displayed TraceSeal
document here (`.jpg`, `.jpeg`, or `.png`). `packages/attacklab`'s harness
(`python -m attacklab.demo_m7`) scans this folder and evaluates anything it
finds identically to every synthetic distortion condition — same
registration, detection, and Tardos accusation pipeline.

**Empty as of Milestone M7** — no real-capture hardware was available for
this milestone. `docs/RESULTS.md`'s real-capture section states this
plainly rather than omitting it or faking a result.

## Filename convention (optional)

A filename may encode the capture's true session and page for scoring
against ground truth, e.g.:

```
leak_S-0004_page1.jpg
```

- `S-\d+` anywhere in the filename — the session this capture actually
  came from.
- `page\d+` anywhere in the filename — which page (0-indexed) it shows.

Both are optional. A capture with neither is still registered, detected,
and accused — it just can't be scored for top-1 correctness or bit error
rate against a known answer, since there is none.

## Known limitation

There is no page-detection/perspective-correction step (spec Section 11
step 2 — finding a photographed page's quadrilateral against a background
and cropping/warping just that region out). `forensics.align.register`'s
ORB+RANSAC homography handles rotation/perspective/scale/crop of the
document's own content, but not separating the document from surrounding
background in a real photo. A capture that's already cropped tightly to
the page (no visible background) will still register correctly; a raw
phone photo with visible desk/background around the page likely won't.
See `docs/DECISIONS.md` for the ADR recording this as deferred, same
reasoning as ADR-0009's original M2 scoping.
