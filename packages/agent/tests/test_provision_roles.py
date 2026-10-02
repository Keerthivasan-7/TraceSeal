from __future__ import annotations

import json
import stat
from pathlib import Path

import pytest
from ca.keys import Identity, save_identity
from ca.registry import build_registry_entry, save_registry
from ca.seed import (
    ADMIN_IDS,
    FORENSICS_ID,
    KEYRELEASE_NODES,
    LEDGER_REPLICAS,
    OFFICER_IDS,
    SENDER_ID,
)
from tscore.errors import TamperError

from agent.keystore import unlock_keystore
from agent.provision_roles import WORDS, provision, purge_staging, sync_public

INFRA_IDS = [f"ledger-{i}" for i in range(LEDGER_REPLICAS)] + [
    f"keyrelease-{i}" for i in range(KEYRELEASE_NODES)
]
ALL_IDS = [*INFRA_IDS, "ca-root", SENDER_ID, FORENSICS_ID, *ADMIN_IDS, *OFFICER_IDS]


def _fake(identity_id: str) -> Identity:
    # Distinct, recognisable fake key bytes per identity — only JSON/AEAD
    # plumbing is exercised here, no liboqs needed.
    marker = identity_id.encode().ljust(16, b".")
    return Identity(
        identity_id=identity_id,
        sig_alg="ML-DSA-65",
        sig_public_key=b"P" + marker,
        sig_secret_key=b"SECRET-SIG-" + marker,
        kem_alg="ML-KEM-768",
        kem_public_key=b"K" + marker,
        kem_secret_key=b"SECRET-KEM-" + marker,
    )


@pytest.fixture
def staging(tmp_path: Path) -> Path:
    directory = tmp_path / "pki"
    registry = {}
    for identity_id in ALL_IDS:
        identity = _fake(identity_id)
        save_identity(identity, directory / f"{identity_id}.json")
        registry[identity_id] = build_registry_entry(identity)
    save_registry(registry, directory / "registry.json")
    return directory


@pytest.fixture
def roles_dir(tmp_path: Path) -> Path:
    return tmp_path / "roles"


def test_word_list_is_big_enough_and_unambiguous() -> None:
    assert len(WORDS) >= 128
    assert len(set(WORDS)) == len(WORDS)
    assert all(w.isalpha() and w.islower() for w in WORDS)


def test_each_unattended_service_gets_a_vault_with_only_its_own_identity(
    staging: Path, roles_dir: Path
) -> None:
    provision(staging, roles_dir)
    for identity_id in INFRA_IDS:
        files = sorted(p.name for p in (roles_dir / "vault" / identity_id).iterdir())
        assert files == [f"{identity_id}.json"]
    assert sorted(p.name for p in (roles_dir / "vault").iterdir()) == sorted(INFRA_IDS)


def test_each_officer_keystore_unlocks_only_with_its_own_passphrase(
    staging: Path, roles_dir: Path
) -> None:
    credentials = provision(staging, roles_dir)
    for officer_id in OFFICER_IDS:
        path = roles_dir / "keystores" / f"{officer_id}.keystore.json"
        assert unlock_keystore(path, credentials[officer_id]) == _fake(officer_id)
        other = next(o for o in OFFICER_IDS if o != officer_id)
        with pytest.raises(TamperError):
            unlock_keystore(path, credentials[other])


def test_command_keystores_share_one_operator_passphrase(staging: Path, roles_dir: Path) -> None:
    credentials = provision(staging, roles_dir)
    for identity_id in (SENDER_ID, FORENSICS_ID):
        path = roles_dir / "keystores" / f"{identity_id}.keystore.json"
        assert unlock_keystore(path, credentials["command"]) == _fake(identity_id)


def test_ca_root_and_each_admin_have_their_own_keystore_passphrase(
    staging: Path, roles_dir: Path
) -> None:
    credentials = provision(staging, roles_dir)
    root = roles_dir / "keystores" / "ca-root.keystore.json"
    assert unlock_keystore(root, credentials["authority-custodian"]) == _fake("ca-root")
    for admin_id in ADMIN_IDS:
        path = roles_dir / "keystores" / f"{admin_id}.keystore.json"
        assert unlock_keystore(path, credentials[admin_id]) == _fake(admin_id)
    with pytest.raises(TamperError):
        unlock_keystore(root, credentials["admin-1"])


def test_no_raw_private_key_exists_outside_the_vaults(staging: Path, roles_dir: Path) -> None:
    provision(staging, roles_dir)
    leaks = []
    for path in roles_dir.rglob("*"):
        if path.is_file() and "vault" not in path.relative_to(roles_dir).parts:
            if b"SECRET-" in path.read_bytes():
                leaks.append(path.relative_to(roles_dir).as_posix())
    assert leaks == []


def test_keystores_are_encrypted_not_just_wrapped(staging: Path, roles_dir: Path) -> None:
    provision(staging, roles_dir)
    for path in (roles_dir / "keystores").glob("*.keystore.json"):
        assert b"SECRET" not in path.read_bytes()
        assert b"SECRET" not in bytes.fromhex(json.loads(path.read_text())["ciphertext"])


def test_public_registry_is_published_without_private_material(
    staging: Path, roles_dir: Path
) -> None:
    provision(staging, roles_dir)
    published = (roles_dir / "public" / "registry.json").read_text()
    assert "secret" not in published.lower()
    assert "officer-a" in published


def test_credentials_file_is_private_complete_and_unique(staging: Path, roles_dir: Path) -> None:
    credentials = provision(staging, roles_dir)
    expected = {*OFFICER_IDS, *ADMIN_IDS, "command", "authority-custodian"}
    assert set(credentials) == expected
    assert len(set(credentials.values())) == len(credentials)
    for passphrase in credentials.values():
        words = passphrase.split("-")
        assert len(words) >= 4
        assert all(w in WORDS for w in words)

    path = roles_dir / "CREDENTIALS.local.txt"
    text = path.read_text()
    for principal, passphrase in credentials.items():
        assert f"{principal}: {passphrase}" in text
    assert stat.S_IMODE(path.stat().st_mode) == 0o600  # tests run on Linux in the image


def test_provisioning_twice_rotates_passphrases(staging: Path, roles_dir: Path) -> None:
    first = provision(staging, roles_dir)
    second = provision(staging, roles_dir)
    assert first != second
    path = roles_dir / "keystores" / "officer-a.keystore.json"
    with pytest.raises(TamperError):
        unlock_keystore(path, first["officer-a"])


def test_sync_public_copies_only_the_registry(staging: Path, roles_dir: Path) -> None:
    provision(staging, roles_dir)
    registry = staging / "registry.json"
    registry.write_text(registry.read_text().replace("officer-a", "officer-a-changed", 1))
    sync_public(staging, roles_dir)
    assert "officer-a-changed" in (roles_dir / "public" / "registry.json").read_text()
    assert sorted(p.name for p in (roles_dir / "public").iterdir()) == ["registry.json"]


def test_purge_staging_removes_every_private_identity_but_keeps_registry(staging: Path) -> None:
    purge_staging(staging)
    assert [p.name for p in staging.iterdir()] == ["registry.json"]
