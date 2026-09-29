"""TraceSeal web UI bridge (spec Section 14, Milestone M8).

One lightweight FastAPI service calling the existing `ca`/`sender`/
`forensics`/`agent` logic directly and proxying to `ledger`'s/
`keyrelease`'s own already-real HTTP services for live state — never a
reimplementation of protocol code. See docs/DECISIONS.md for the ADR
recording why this is one bridge service rather than one new service per
package.
"""

from __future__ import annotations

__version__ = "0.1.0"
