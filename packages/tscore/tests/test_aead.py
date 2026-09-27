import os

import pytest

from tscore.aead import NONCE_LEN, TamperError, open_, seal


def _key() -> bytes:
    return os.urandom(32)


def test_round_trip() -> None:
    key = _key()
    header = b"doc-id:1234|page:0"
    plaintext = b"the quick brown fox jumps over the lazy dog"
    sealed = seal(key, plaintext, header)
    assert open_(key, sealed, header) == plaintext


def test_nonce_is_96_bits_and_random_per_call() -> None:
    key = _key()
    sealed_a = seal(key, b"same plaintext", b"same header")
    sealed_b = seal(key, b"same plaintext", b"same header")
    nonce_a, nonce_b = sealed_a[:NONCE_LEN], sealed_b[:NONCE_LEN]
    assert len(nonce_a) == NONCE_LEN == 12
    assert nonce_a != nonce_b


def test_tampered_ciphertext_rejected() -> None:
    key = _key()
    header = b"h"
    sealed = bytearray(seal(key, b"secret payload", header))
    sealed[-1] ^= 0x01  # flip a bit in the GCM tag
    with pytest.raises(TamperError):
        open_(key, bytes(sealed), header)


def test_aad_mismatch_rejected() -> None:
    key = _key()
    sealed = seal(key, b"secret payload", b"header-A")
    with pytest.raises(TamperError):
        open_(key, sealed, b"header-B")


def test_wrong_key_rejected() -> None:
    sealed = seal(_key(), b"secret payload", b"h")
    with pytest.raises(TamperError):
        open_(_key(), sealed, b"h")


def test_rejects_wrong_key_length() -> None:
    with pytest.raises(ValueError, match="32 bytes"):
        seal(b"too-short-key", b"data", b"h")
