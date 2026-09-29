"""Cross-replica chain verification (spec Section 12: `verify_chain`
detects a direct database edit on any single replica and shows which one
diverged).

Takes already-fetched records per replica (transport-agnostic — the caller
is responsible for getting these, whether via direct `LedgerStore` access
in tests or HTTP `/chain` calls against real replicas) and checks two
independent things: each replica's own hash chain is internally
consistent, and all replicas agree with each other at every height.
"""

from __future__ import annotations

from dataclasses import dataclass

from tscore.chain import compute_record_hash

from ledger.store import GENESIS_HASH, StoredRecord


@dataclass(frozen=True)
class ReplicaChainStatus:
    replica_id: str
    height: int
    internally_valid: bool
    first_bad_height: int | None


@dataclass(frozen=True)
class ChainReport:
    replicas: list[ReplicaChainStatus]
    consensus_height: int
    diverged_replica_ids: list[str]

    @property
    def ok(self) -> bool:
        return not self.diverged_replica_ids and all(r.internally_valid for r in self.replicas)


def _recompute_chain_valid(records: list[StoredRecord]) -> tuple[bool, int | None]:
    prev_hash = GENESIS_HASH
    for record in records:
        expected = compute_record_hash(
            prev_hash, record.tx_id, record.envelope_cbor, record.quorum_signer_ids
        )
        if expected != record.record_hash or record.prev_hash != prev_hash:
            return False, record.height
        prev_hash = record.record_hash
    return True, None


def verify_chain(replica_records: dict[str, list[StoredRecord]]) -> ChainReport:
    statuses = []
    for replica_id, records in replica_records.items():
        valid, first_bad_height = _recompute_chain_valid(records)
        statuses.append(
            ReplicaChainStatus(
                replica_id=replica_id,
                height=len(records),
                internally_valid=valid,
                first_bad_height=first_bad_height,
            )
        )

    diverged: set[str] = set()
    max_height = max((len(records) for records in replica_records.values()), default=0)
    for height_idx in range(max_height):
        hashes_at_height: dict[bytes, list[str]] = {}
        for replica_id, records in replica_records.items():
            if height_idx < len(records):
                hashes_at_height.setdefault(records[height_idx].record_hash, []).append(replica_id)
        if len(hashes_at_height) > 1:
            majority_ids = max(hashes_at_height.values(), key=len)
            for ids in hashes_at_height.values():
                if ids is not majority_ids:
                    diverged.update(ids)

    consensus_height = min((len(records) for records in replica_records.values()), default=0)
    return ChainReport(
        replicas=statuses, consensus_height=consensus_height, diverged_replica_ids=sorted(diverged)
    )
