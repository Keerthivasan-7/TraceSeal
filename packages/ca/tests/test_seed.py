import pytest

pytestmark = pytest.mark.requires_liboqs


def test_seed_all_generates_every_expected_identity(tmp_path) -> None:
    from ca.keys import load_identity
    from ca.registry import load_registry
    from ca.seed import (
        ADMIN_IDS,
        KEYRELEASE_NODES,
        LEDGER_REPLICAS,
        OFFICER_IDS,
        SENDER_ID,
        seed_all,
    )

    registry = seed_all(tmp_path)

    expected_ids = (
        {"ca-root"}
        | {f"ledger-{i}" for i in range(LEDGER_REPLICAS)}
        | {f"keyrelease-{i}" for i in range(KEYRELEASE_NODES)}
        | {SENDER_ID}
        | set(ADMIN_IDS)
        | set(OFFICER_IDS)
    )
    assert set(registry) == expected_ids

    # Officers get a real keypair (needed to build a CSR) but NO certificate
    # yet — that only comes from the real quorum ceremony (ca.enrolment).
    for officer_id in OFFICER_IDS:
        identity = load_identity(tmp_path / f"{officer_id}.json")
        entry = registry[officer_id]
        assert "certificate_cbor" not in entry
        assert entry["sig_public_key"] == identity.sig_public_key.hex()
        assert identity.kem_alg is not None  # officers do get KEM keys

    # Admins are sig-only — they never receive KEM-wrapped material.
    for admin_id in ADMIN_IDS:
        assert "kem_public_key" not in registry[admin_id]

    registry_on_disk = load_registry(tmp_path / "registry.json")
    assert registry_on_disk == registry
