"""`K_B || S_v` composition and Tardos bias-vector (de)serialisation
(spec Section 7.2/7.3) — shared by `sender` (splits/wraps at registration)
and `keyrelease` (reconstructs/reads at decrypt-request time), so it lives
here rather than creating a keyrelease -> sender dependency for two small
pure functions.

The bias vector is deliberately **not** bundled into the Shamir-split
secret, even though it's spec Section 2's own "document's secret bias
vector" alongside K_B/S_v: whichever key-release node ends up coordinating
a session needs it immediately, to assign a Tardos codeword *before* the
DECRYPT_REQUEST ledger write (spec Section 7.3 step 3) — but K_B/S_v must
stay gated behind a 3-of-5 reconstruction that only happens *after* ledger
finality (step 5). Bundling them would force choosing one of two wrong
options: assign codewords using a 3-of-5-reconstructed secret before
finality (breaking commit-before-release), or delay codeword assignment
until after finality (breaking the protocol's own step order, since the
commitment to a codeword has to be on the ledger by then). So every
key-release node instead gets the plaintext bias vector directly at
registration (KEM-wrapped per node for transport confidentiality, but
identical content to every node, not secret-shared) — consistent with the
threat model, where a single node knowing `p` alone doesn't let it decrypt
anything or forge an accusation; only a 3-of-5 K_B/S_v collusion does.
"""

from __future__ import annotations

import os

import numpy as np

from tscore.kdf import derive, domain_info

K_LEN = 32


def generate_document_keys() -> tuple[bytes, bytes, bytes]:
    """Fresh, random `(K_A, K_B, S_v)` — spec Section 7.2 step 2."""
    return os.urandom(K_LEN), os.urandom(K_LEN), os.urandom(K_LEN)


def combine_release_secret(k_b: bytes, s_v: bytes) -> bytes:
    """`K_B || S_v` — the one secret Shamir-split across the 5 key-release
    nodes."""
    return k_b + s_v


def split_release_secret(secret: bytes) -> tuple[bytes, bytes]:
    """Inverse of `combine_release_secret`."""
    return secret[:K_LEN], secret[K_LEN : 2 * K_LEN]


def bias_vector_to_bytes(bias_vector: np.ndarray) -> bytes:
    return np.asarray(bias_vector, dtype=np.float32).tobytes()


def bias_vector_from_bytes(data: bytes, positions_count: int) -> np.ndarray:
    bias_vector = np.frombuffer(data, dtype=np.float32)
    if len(bias_vector) != positions_count:
        raise ValueError(f"expected {positions_count} bias values, got {len(bias_vector)}")
    return bias_vector


def derive_k_base(k_a: bytes, k_b: bytes, doc_id: str) -> bytes:
    """`K_base = HKDF(K_A xor K_B)` (spec Section 7.3 step 6). Shared by
    `sender` (packaging) and `agent` (decrypting) — both must derive the
    exact same key independently."""
    xored = bytes(a ^ b for a, b in zip(k_a, k_b, strict=True))
    return derive(xored, domain_info("k-base", doc_id.encode()), length=K_LEN)


def derive_variant_key(s_v: bytes, doc_id: str, position_index: int, bit: int) -> bytes:
    """Each variant patch's own key. Shared by `sender` (encrypting both
    variants), `keyrelease` (deriving only the codeword-selected ones for
    the KeyGrant), and `agent` (decrypting the ones it was granted)."""
    info = domain_info("variant", doc_id.encode(), position_index.to_bytes(4, "big"), bytes([bit]))
    return derive(s_v, info, length=K_LEN)
