# Threat Model

Skeleton for now — the full STRIDE table is written in **Milestone M8**,
once every component it needs to reason about (sender, key-release, ledger,
agent, forensics, verifier) actually exists. Filling it in earlier would
mean describing mitigations for code that doesn't exist yet.

## Structure this will take (M8)

A STRIDE table (Spoofing, Tampering, Repudiation, Information disclosure,
Denial of service, Elevation of privilege), one row per attack surface
identified across `docs/SPEC.md` Sections 2–14, each with:

- the concrete attack scenario,
- the mitigation actually implemented (with a pointer to the code/test that
  enforces it),
- residual risk, if any.

## Residual risks already known from the design (spec Section 2, Section 20)

These are architectural, not implementation gaps — they'll be documented in
full at M8 but are worth stating honestly now:

- **Sender + Key-Release collusion (framing):** framing an innocent
  recipient requires the sender *and* a threshold of Key-Release nodes to
  collude. Asymmetric fingerprinting (which would remove this) is out of
  scope for this build.
- **The analog hole:** retyping the document's content or reading it aloud
  is not attributable. Out of scope; a semantic canary layer is future work.
- **Endpoint compromise:** if an officer's workstation is compromised while
  viewing a decrypted document (e.g. a malicious screen-scraper with kernel
  access), TraceSeal can still identify *which session* produced a leaked
  copy, but cannot prevent the capture itself.
- **Fabric's internal transport:** Hyperledger Fabric's own peer-to-peer
  transport remains classically secured (ECDSA/TLS) even after the M6
  PQC-signature work; only the application-level signatures inside ledger
  records and the block co-signatures are PQC. This is stated explicitly
  per the honesty rules in `docs/SPEC.md` Section 20.
