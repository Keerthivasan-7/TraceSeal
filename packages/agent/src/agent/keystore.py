"""Officer keystore: Argon2id-derived key, AES-GCM at rest (spec Section 3:
"Keystores are encrypted with Argon2id-derived keys").

M3 scoping note (docs/DECISIONS.md): key *generation* for the demo/e2e run
is done once, up front, by `ca.seed` (so the protocol has identities to
work with — the real quorum-gated enrolment ceremony is M4). This module's
job is the part that's real regardless: taking an already-generated
`Identity` and actually encrypting it at rest, and decrypting it back only
given the right passphrase — genuine Argon2id + AES-GCM, not a stand-in.
"""

from __future__ import annotations

import json
import os
from pathlib import Path

from argon2.low_level import Type, hash_secret_raw
from ca.keys import Identity
from tscore.aead import open_ as aead_open
from tscore.aead import seal as aead_seal

ARGON2_TIME_COST = 3
ARGON2_MEMORY_COST_KIB = 65536
ARGON2_PARALLELISM = 4
KEY_LEN = 32
SALT_LEN = 16


def _derive_key(passphrase: str, salt: bytes) -> bytes:
    result: bytes = hash_secret_raw(
        secret=passphrase.encode(),
        salt=salt,
        time_cost=ARGON2_TIME_COST,
        memory_cost=ARGON2_MEMORY_COST_KIB,
        parallelism=ARGON2_PARALLELISM,
        hash_len=KEY_LEN,
        type=Type.ID,
    )
    return result


def _header(identity_id: str) -> bytes:
    return f"traceseal/keystore/v1/{identity_id}".encode()


def create_keystore(identity: Identity, passphrase: str, path: Path) -> None:
    salt = os.urandom(SALT_LEN)
    key = _derive_key(passphrase, salt)
    plaintext = json.dumps(identity.private_dict()).encode()
    ciphertext = aead_seal(key, plaintext, _header(identity.identity_id))
    path.parent.mkdir(parents=True, exist_ok=True)
    data = {
        "identity_id": identity.identity_id,
        "salt": salt.hex(),
        "ciphertext": ciphertext.hex(),
    }
    path.write_text(json.dumps(data))


def unlock_keystore(path: Path, passphrase: str) -> Identity:
    """Raises `tscore.errors.TamperError` on a wrong passphrase — Argon2id
    with the stored salt derives the wrong AES key, so decryption fails
    exactly the same way a tampered ciphertext would."""
    data = json.loads(path.read_text())
    salt = bytes.fromhex(data["salt"])
    key = _derive_key(passphrase, salt)
    plaintext = aead_open(key, bytes.fromhex(data["ciphertext"]), _header(data["identity_id"]))
    fields = json.loads(plaintext)
    kem_alg = fields.get("kem_alg")
    return Identity(
        identity_id=fields["identity_id"],
        sig_alg=fields["sig_alg"],
        sig_public_key=bytes.fromhex(fields["sig_public_key"]),
        sig_secret_key=bytes.fromhex(fields["sig_secret_key"]),
        kem_alg=kem_alg,
        kem_public_key=bytes.fromhex(fields["kem_public_key"]) if kem_alg else None,
        kem_secret_key=bytes.fromhex(fields["kem_secret_key"]) if kem_alg else None,
    )
