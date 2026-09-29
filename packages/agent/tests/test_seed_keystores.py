from __future__ import annotations

from pathlib import Path

from ca.keys import Identity, save_identity
from ca.seed import OFFICER_IDS

from agent.keystore import unlock_keystore
from agent.seed_keystores import DEMO_PASSPHRASE, seed_keystores


def _fake_officer_identity(officer_id: str) -> Identity:
    # Not real PQC keys — seed_keystores only reads/writes JSON via
    # ca.keys/agent.keystore, no liboqs needed to exercise it.
    return Identity(
        identity_id=officer_id,
        sig_alg="ML-DSA-65",
        sig_public_key=b"\x01" * 32,
        sig_secret_key=b"\x02" * 64,
        kem_alg="ML-KEM-768",
        kem_public_key=b"\x03" * 32,
        kem_secret_key=b"\x04" * 64,
    )


def test_seed_keystores_creates_one_unlockable_keystore_per_officer(tmp_path: Path) -> None:
    pki_dir = tmp_path / "pki"
    keystore_dir = tmp_path / "keystores"
    for officer_id in OFFICER_IDS:
        save_identity(_fake_officer_identity(officer_id), pki_dir / f"{officer_id}.json")

    count = seed_keystores(pki_dir=pki_dir, keystore_dir=keystore_dir)

    assert count == len(OFFICER_IDS)
    for officer_id in OFFICER_IDS:
        recovered = unlock_keystore(keystore_dir / f"{officer_id}.keystore.json", DEMO_PASSPHRASE)
        assert recovered == _fake_officer_identity(officer_id)
