import pytest

pytestmark = pytest.mark.requires_liboqs


def test_seed_all_generates_every_expected_identity(tmp_path) -> None:
    from tscore.records import Certificate

    from ca.issue import verify_certificate
    from ca.keys import load_identity
    from ca.registry import load_registry, sig_public_key
    from ca.seed import KEYRELEASE_NODES, LEDGER_REPLICAS, OFFICER_IDS, SENDER_ID, seed_all

    registry = seed_all(tmp_path)

    expected_ids = (
        {"ca-root"}
        | {f"ledger-{i}" for i in range(LEDGER_REPLICAS)}
        | {f"keyrelease-{i}" for i in range(KEYRELEASE_NODES)}
        | {SENDER_ID}
        | set(OFFICER_IDS)
    )
    assert set(registry) == expected_ids

    # Every officer's private identity file loads and its certificate
    # verifies against the seeded CA root's public key.
    ca_alg, ca_pub = sig_public_key(registry, "ca-root")
    for officer_id in OFFICER_IDS:
        identity = load_identity(tmp_path / f"{officer_id}.json")
        entry = registry[officer_id]
        cert = Certificate.from_canonical_cbor(bytes.fromhex(entry["certificate_cbor"]))
        signature = bytes.fromhex(entry["certificate_signature"])
        assert cert.subject_id == officer_id
        assert cert.ml_dsa_public_key == identity.sig_public_key
        assert verify_certificate(cert, signature, ca_alg, ca_pub)

    registry_on_disk = load_registry(tmp_path / "registry.json")
    assert registry_on_disk == registry
