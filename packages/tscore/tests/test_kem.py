"""ML-KEM-768 KEM-DEM tests.

Imports of `tscore.kem` (and transitively `oqs`) are deliberately kept
inside each test function rather than at module level: `oqs` triggers a
slow liboqs auto-clone-and-build attempt the instant it's imported (see
conftest.py's docstring), so the module itself must stay importable even
when liboqs isn't available, letting conftest's `requires_liboqs` skip
marker take effect before that import ever happens.
"""

import pytest

pytestmark = pytest.mark.requires_liboqs


def test_round_trip() -> None:
    from tscore.kdf import domain_info
    from tscore.kem import ML_KEM_768, generate_keypair, kem_open, kem_seal

    recipient = generate_keypair(ML_KEM_768)
    header = b"doc-id:abc|recipient:officer-a"
    info = domain_info("k_a-wrap", b"doc-abc", b"officer-a")
    plaintext = b"this is K_A, thirty-two bytes!!"

    framed = kem_seal(recipient.public_key, plaintext, header=header, info=info)
    recovered = kem_open(recipient.secret_key, framed, header=header, info=info)
    assert recovered == plaintext


def test_tampered_ciphertext_rejected() -> None:
    from tscore.errors import TamperError
    from tscore.kdf import domain_info
    from tscore.kem import ML_KEM_768, generate_keypair, kem_open, kem_seal

    recipient = generate_keypair(ML_KEM_768)
    header, info = b"h", domain_info("test", b"x")
    framed = bytearray(kem_seal(recipient.public_key, b"secret", header=header, info=info))
    framed[-1] ^= 0x01  # corrupt the AEAD tag at the end of the frame
    with pytest.raises(TamperError):
        kem_open(recipient.secret_key, bytes(framed), header=header, info=info)


def test_wrong_recipient_key_rejected() -> None:
    from tscore.errors import TamperError
    from tscore.kdf import domain_info
    from tscore.kem import ML_KEM_768, generate_keypair, kem_open, kem_seal

    recipient = generate_keypair(ML_KEM_768)
    other = generate_keypair(ML_KEM_768)
    header, info = b"h", domain_info("test", b"x")
    framed = kem_seal(recipient.public_key, b"secret", header=header, info=info)
    with pytest.raises(TamperError):
        kem_open(other.secret_key, framed, header=header, info=info)
