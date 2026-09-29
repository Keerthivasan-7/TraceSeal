"""`LedgerBackend` (spec Section 12): the generic interface every ledger
implementation satisfies, so `sender`/`keyrelease`/`agent`/`ca`/`forensics`
can be pointed at either backend without their own code changing.
`ledger.client.LedgerClient` (LedgerLite, M1-M5) and
`ledger.fabric_client.FabricLedgerClient` (Fabric, M6) both satisfy this
structurally (Python's `Protocol` is duck-typed — no inheritance needed),
and in fact share the exact same `RecordWire`/`RecordProofWire` return
types (`ledger.wire`), so the two are interchangeable in practice, not
just in principle.

`build_ledger_client` is the one factory every consumer should use instead
of constructing `LedgerClient(...)` directly — selecting the backend via
an explicit `backend` argument (itself normally sourced from a
`LEDGER_BACKEND` env var at each service's own call site), defaulting to
`"lite"` everywhere so M0-M5's existing behaviour is unchanged unless a
caller opts into `"fabric"`.
"""

from __future__ import annotations

from typing import Protocol

from tscore.records import SignedSubmission

from ledger.wire import RecordProofWire, RecordWire


class LedgerBackend(Protocol):
    def submit(self, submission: SignedSubmission) -> str: ...

    def wait_final(self, tx_id: str, timeout_s: float = 10.0) -> RecordWire: ...

    def get(self, tx_id: str) -> RecordWire: ...

    def get_proof(self, tx_id: str) -> RecordProofWire: ...

    def query(self, domain: str | None = None) -> list[RecordWire]: ...


def build_ledger_client(
    backend: str = "lite",
    *,
    ledger_leader_url: str = "http://ledger-0:8000",
    replica_urls: list[str] | None = None,
    fabric_gateway_url: str = "http://fabric-gateway:8000",
) -> LedgerBackend:
    """The one place a `LedgerBackend` gets constructed. `backend` is
    `"lite"` (default, LedgerLite — every M0-M5 behaviour unchanged) or
    `"fabric"` (M6). Callers normally pass `os.environ.get("LEDGER_BACKEND",
    "lite")` rather than hardcoding either string."""
    if backend == "lite":
        from ledger.client import LedgerClient

        return LedgerClient(ledger_leader_url, replica_urls)
    if backend == "fabric":
        from ledger.fabric_client import FabricLedgerClient

        return FabricLedgerClient(fabric_gateway_url)
    raise ValueError(f"unknown LEDGER_BACKEND {backend!r} (expected 'lite' or 'fabric')")
