import pytest
from ca.keys import Identity
from tscore.errors import TamperError

from agent.keystore import create_keystore, unlock_keystore


def _synthetic_identity() -> Identity:
    # Not real PQC keys — keystore.py only cares about encrypting/decrypting
    # whatever bytes `Identity` holds, so random bytes exercise the same
    # code path without needing liboqs.
    return Identity(
        identity_id="officer-a",
        sig_alg="ML-DSA-65",
        sig_public_key=b"\x01" * 32,
        sig_secret_key=b"\x02" * 64,
        kem_alg="ML-KEM-768",
        kem_public_key=b"\x03" * 32,
        kem_secret_key=b"\x04" * 64,
    )


def test_create_and_unlock_round_trip(tmp_path) -> None:
    identity = _synthetic_identity()
    path = tmp_path / "officer-a.keystore.json"

    create_keystore(identity, "correct horse battery staple", path)
    recovered = unlock_keystore(path, "correct horse battery staple")

    assert recovered == identity


def test_unlock_with_wrong_passphrase_fails(tmp_path) -> None:
    identity = _synthetic_identity()
    path = tmp_path / "officer-a.keystore.json"

    create_keystore(identity, "correct horse battery staple", path)
    with pytest.raises(TamperError):
        unlock_keystore(path, "wrong passphrase")


def test_keystore_without_kem_round_trips(tmp_path) -> None:
    identity = Identity(
        identity_id="ledger-0",
        sig_alg="ML-DSA-65",
        sig_public_key=b"\x05" * 32,
        sig_secret_key=b"\x06" * 64,
    )
    path = tmp_path / "ledger-0.keystore.json"

    create_keystore(identity, "another passphrase", path)
    recovered = unlock_keystore(path, "another passphrase")

    assert recovered == identity
    assert recovered.kem_alg is None
