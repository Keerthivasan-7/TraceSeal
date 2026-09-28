from ca.keys import Identity
from ca.registry import build_registry_entry, load_registry, save_registry


def _fake_identity(identity_id: str, with_kem: bool = True) -> Identity:
    if with_kem:
        return Identity(
            identity_id=identity_id,
            sig_alg="ML-DSA-65",
            sig_public_key=b"\x01" * 32,
            sig_secret_key=b"\x02" * 32,
            kem_alg="ML-KEM-768",
            kem_public_key=b"\x03" * 32,
            kem_secret_key=b"\x04" * 32,
        )
    return Identity(
        identity_id=identity_id,
        sig_alg="SLH_DSA_PURE_SHA2_128S",
        sig_public_key=b"\x01" * 32,
        sig_secret_key=b"\x02" * 32,
    )


def test_registry_entry_never_includes_secret_keys() -> None:
    entry = build_registry_entry(_fake_identity("officer-a"))
    assert "sig_secret_key" not in entry
    assert "kem_secret_key" not in entry
    assert entry["sig_public_key"] == (b"\x01" * 32).hex()


def test_registry_round_trip(tmp_path) -> None:
    registry = {
        "officer-a": build_registry_entry(_fake_identity("officer-a")),
        "ledger-0": build_registry_entry(_fake_identity("ledger-0", with_kem=False)),
    }
    path = tmp_path / "registry.json"
    save_registry(registry, path)
    restored = load_registry(path)
    assert restored == registry


def test_registry_entry_with_certificate_carries_hex_fields() -> None:
    entry = build_registry_entry(
        _fake_identity("officer-a"),
        certificate_cbor=b"\xaa\xbb",
        certificate_signature=b"\xcc\xdd",
    )
    assert entry["certificate_cbor"] == "aabb"
    assert entry["certificate_signature"] == "ccdd"
