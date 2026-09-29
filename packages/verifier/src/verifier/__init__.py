"""TraceSeal standalone verifier (spec Section 4, Section 7.5 step 5):
independently re-checks a `.tsev` evidence bundle. Depends on nothing but
`tscore` — no trust in the TraceSeal server, no network access.
"""

__version__ = "0.1.0"
