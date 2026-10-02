"""Key-release nodes read their own private identity from VAULT_DIR, so a
node's container can be given exactly one identity file and the public
registry — not the whole PKI directory."""

import pytest

from helpers import build_ledger_client, seed_pki

pytestmark = pytest.mark.requires_liboqs


def test_node_identity_comes_from_vault_dir_registry_from_pki_dir(tmp_path) -> None:  # type: ignore[no-untyped-def]
    from keyrelease.service import create_app

    pki_dir = tmp_path / "pki"
    seed_pki(pki_dir)
    ledger_client = build_ledger_client(pki_dir, tmp_path)
    vault = tmp_path / "vault"
    vault.mkdir()
    (pki_dir / "keyrelease-0.json").replace(vault / "keyrelease-0.json")

    with pytest.raises(FileNotFoundError):
        create_app(
            node_index=0,
            pki_dir=pki_dir,
            db_path=str(tmp_path / "a.db"),
            ledger_client=ledger_client,
        )
    app = create_app(
        node_index=0,
        pki_dir=pki_dir,
        vault_dir=vault,
        db_path=str(tmp_path / "b.db"),
        ledger_client=ledger_client,
    )
    assert app.state.node is not None
