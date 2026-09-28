"""Load/save the shared public-key registry (M3 seed infrastructure — the
stand-in for the M4 ledger-backed identity registry; see the M3 plan's
scoping decisions in docs/DECISIONS.md).

Pure JSON/hex handling only — no `tscore.sig`/`tscore.kem` imports here, so
reading the registry never touches liboqs.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from tscore.errors import VerificationError

from ca.keys import Identity

RegistryEntry = dict[str, Any]
Registry = dict[str, RegistryEntry]


def build_registry_entry(
    identity: Identity,
    *,
    certificate_cbor: bytes | None = None,
    certificate_signature: bytes | None = None,
) -> RegistryEntry:
    entry = identity.public_dict()
    if certificate_cbor is not None:
        entry["certificate_cbor"] = certificate_cbor.hex()
        entry["certificate_signature"] = (certificate_signature or b"").hex()
    return entry


def save_registry(registry: Registry, path: Path) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(registry, indent=2))


def load_registry(path: Path) -> Registry:
    result: Registry = json.loads(path.read_text())
    return result


def sig_public_key(registry: Registry, identity_id: str) -> tuple[str, bytes]:
    entry = registry.get(identity_id)
    if entry is None:
        raise VerificationError(f"no such identity in the registry: {identity_id!r}")
    return entry["sig_alg"], bytes.fromhex(entry["sig_public_key"])


def kem_public_key(registry: Registry, identity_id: str) -> tuple[str, bytes]:
    entry = registry.get(identity_id)
    if entry is None:
        raise VerificationError(f"no such identity in the registry: {identity_id!r}")
    return entry["kem_alg"], bytes.fromhex(entry["kem_public_key"])
