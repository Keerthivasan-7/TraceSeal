"""TraceSeal LedgerLite (spec Section 12): the `LedgerBackend` interface
plus a 4-replica ML-DSA quorum tamper-evident replicated log. Labelled
honestly per spec: "tamper-evident replicated log, not full BFT" — a
single fixed leader, no view change.
"""

__version__ = "0.1.0"
