"""Identity keypair generation and JSON persistence (M3 seed infrastructure).

Algorithm name strings are duplicated here as plain constants rather than
imported from `tscore.sig`/`tscore.kem`: those modules `import oqs` at
module level, which would make merely importing `ca.keys` (e.g. just to
load a previously-saved identity's public key, no signing involved) trip
the slow liboqs auto-install path on a host without a built liboqs — the
same reasoning as `packages/tscore/tests/conftest.py`. Actual key
generation (`generate_identity`) imports `tscore.sig`/`tscore.kem` lazily,
inside the function body, so it only pays that cost when actually invoked.
"""

from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path
from typing import Any

DEFAULT_SIG_ALG = "ML-DSA-65"
DEFAULT_KEM_ALG = "ML-KEM-768"
ROOT_SIG_ALG = "SLH_DSA_PURE_SHA2_128S"


@dataclass(frozen=True)
class Identity:
    identity_id: str
    sig_alg: str
    sig_public_key: bytes
    sig_secret_key: bytes
    kem_alg: str | None = None
    kem_public_key: bytes | None = None
    kem_secret_key: bytes | None = None

    def public_dict(self) -> dict[str, Any]:
        d: dict[str, Any] = {
            "identity_id": self.identity_id,
            "sig_alg": self.sig_alg,
            "sig_public_key": self.sig_public_key.hex(),
        }
        if self.kem_alg is not None:
            d["kem_alg"] = self.kem_alg
            d["kem_public_key"] = (self.kem_public_key or b"").hex()
        return d

    def private_dict(self) -> dict[str, Any]:
        d = self.public_dict()
        d["sig_secret_key"] = self.sig_secret_key.hex()
        if self.kem_alg is not None:
            d["kem_secret_key"] = (self.kem_secret_key or b"").hex()
        return d


def generate_identity(
    identity_id: str, *, sig_alg: str = DEFAULT_SIG_ALG, with_kem: bool = True
) -> Identity:
    from tscore.kem import generate_keypair as kem_generate_keypair
    from tscore.sig import generate_keypair as sig_generate_keypair

    sig_kp = sig_generate_keypair(sig_alg)
    if not with_kem:
        return Identity(identity_id, sig_alg, sig_kp.public_key, sig_kp.secret_key)
    kem_kp = kem_generate_keypair(DEFAULT_KEM_ALG)
    return Identity(
        identity_id,
        sig_alg,
        sig_kp.public_key,
        sig_kp.secret_key,
        DEFAULT_KEM_ALG,
        kem_kp.public_key,
        kem_kp.secret_key,
    )


def save_identity(identity: Identity, path: Path) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(identity.private_dict(), indent=2))


def load_identity(path: Path) -> Identity:
    d = json.loads(path.read_text())
    kem_alg = d.get("kem_alg")
    return Identity(
        identity_id=d["identity_id"],
        sig_alg=d["sig_alg"],
        sig_public_key=bytes.fromhex(d["sig_public_key"]),
        sig_secret_key=bytes.fromhex(d["sig_secret_key"]),
        kem_alg=kem_alg,
        kem_public_key=bytes.fromhex(d["kem_public_key"]) if kem_alg else None,
        kem_secret_key=bytes.fromhex(d["kem_secret_key"]) if kem_alg else None,
    )
