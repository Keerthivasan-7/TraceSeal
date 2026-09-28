"""ML-DSA-65 / SLH-DSA-SHA2-128s signature tests.

See test_kem.py's module docstring for why `tscore.sig` (and transitively
`oqs`) is imported inside each test function rather than at module level.
"""

import pytest

pytestmark = pytest.mark.requires_liboqs


@pytest.mark.parametrize("alg_name", ["ML-DSA-65", "SLH_DSA_PURE_SHA2_128S"])
def test_sign_verify_round_trip(alg_name: str) -> None:
    from tscore.sig import generate_keypair, sign, verify

    kp = generate_keypair(alg_name)
    message = b"DECRYPT_REQUEST session=S-0001 doc=OPERATION_PLAN"
    signature = sign(alg_name, kp.secret_key, message)
    assert verify(alg_name, kp.public_key, message, signature)


@pytest.mark.parametrize("alg_name", ["ML-DSA-65", "SLH_DSA_PURE_SHA2_128S"])
def test_wrong_key_rejected(alg_name: str) -> None:
    from tscore.sig import generate_keypair, sign, verify

    kp = generate_keypair(alg_name)
    other = generate_keypair(alg_name)
    message = b"message"
    signature = sign(alg_name, kp.secret_key, message)
    assert not verify(alg_name, other.public_key, message, signature)


@pytest.mark.parametrize("alg_name", ["ML-DSA-65", "SLH_DSA_PURE_SHA2_128S"])
def test_tampered_message_rejected(alg_name: str) -> None:
    from tscore.sig import generate_keypair, sign, verify

    kp = generate_keypair(alg_name)
    signature = sign(alg_name, kp.secret_key, b"original message")
    assert not verify(alg_name, kp.public_key, b"tampered message!", signature)


@pytest.mark.parametrize("alg_name", ["ML-DSA-65", "SLH_DSA_PURE_SHA2_128S"])
def test_tampered_signature_rejected(alg_name: str) -> None:
    from tscore.sig import generate_keypair, sign, verify

    kp = generate_keypair(alg_name)
    message = b"message"
    signature = bytearray(sign(alg_name, kp.secret_key, message))
    signature[-1] ^= 0x01
    assert not verify(alg_name, kp.public_key, message, bytes(signature))
