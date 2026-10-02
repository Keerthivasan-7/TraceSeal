"""Provisioning for the isolated-roles deployment (docs/superpowers/specs/
2026-10-01-role-isolation-design.md, Section 5).

`ca.seed` writes every identity's raw private key into one directory. That
is fine as an *offline ceremony staging area* but it must never be what the
running containers mount. This script distributes that material so each
container can be given exactly what it needs and nothing else:

* ``vault/<id>/<id>.json`` — raw private identity for the *unattended*
  services only (ledger replicas, key-release nodes). They cannot type a
  passphrase at boot, so they get their own file and nothing of anyone
  else's.
* ``keystores/<id>.keystore.json`` — Argon2id+AES-GCM keystores for every
  *interactive* principal. These are encrypted at rest; the matching console
  decrypts one only after a human supplies its passphrase.
* ``public/registry.json`` — the public registry (no secrets).
* ``CREDENTIALS.local.txt`` — the generated passphrases, owner-only, never
  committed.

Passphrases are demo-grade: four words from a 128-word list (28 bits), meant
to be typed on stage. Argon2id slows guessing; this is not a production
passphrase policy and is not claimed to be one.

Usage:
    python -m agent.provision_roles [provision]   # distribute + generate credentials
    python -m agent.provision_roles sync-public   # re-publish registry.json
    python -m agent.provision_roles purge-staging # drop raw private files from staging
"""

from __future__ import annotations

import argparse
import os
import secrets
import shutil
import sys
from pathlib import Path

from ca.keys import load_identity
from ca.seed import (
    ADMIN_IDS,
    FORENSICS_ID,
    KEYRELEASE_NODES,
    LEDGER_REPLICAS,
    OFFICER_IDS,
    SENDER_ID,
)

from agent.keystore import create_keystore

DEFAULT_STAGING = Path.cwd() / "demo" / "pki"
DEFAULT_ROLES_DIR = Path.cwd() / "demo" / "roles"
PASSPHRASE_WORDS = 4

WORDS: tuple[str, ...] = tuple(
    """
    amber anchor apple arrow aspen atlas badge baker basil beach birch blade bloom boat bolt
    bonus brave brick bridge brook cabin cable camel canal candle canyon cargo cedar chalk
    charm chess cider cliff cloud clover cobalt comet coral crane crest crown cyan daisy delta
    desert dock dome dune eagle ember fable falcon fern field flame flint forest fox frost
    garden gecko glade globe grain grove harbor hazel heron hill honey iris island ivory jade
    jungle kayak kite lagoon lake lantern larch lemon lily lotus lunar maple marsh meadow mesa
    mint moss nectar noble north oasis olive onyx orbit otter paddle panda pearl pine plum
    polar pond prairie quartz quill raven reef ridge river robin sage sand sierra silk slate
    solar spruce stone summit swift tiger topaz tulip valley velvet violet willow winter zephyr
    """.split()
)

_INFRA_IDS = [f"ledger-{i}" for i in range(LEDGER_REPLICAS)] + [
    f"keyrelease-{i}" for i in range(KEYRELEASE_NODES)
]
_COMMAND_IDS = [SENDER_ID, FORENSICS_ID]
CA_ROOT_ID = "ca-root"
CUSTODIAN = "authority-custodian"


def _new_passphrase(rng: secrets.SystemRandom) -> str:
    return "-".join(rng.choice(WORDS) for _ in range(PASSPHRASE_WORDS))


def _write_private(path: Path, text: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text)
    os.chmod(path, 0o600)


def provision(
    staging: Path, roles_dir: Path, *, rng: secrets.SystemRandom | None = None
) -> dict[str, str]:
    """Distribute staging material under `roles_dir` and return
    `{principal: passphrase}`. Re-running rotates every passphrase."""
    rng = rng or secrets.SystemRandom()
    credentials = {principal: _new_passphrase(rng) for principal in _principals()}

    shutil.rmtree(roles_dir / "vault", ignore_errors=True)
    shutil.rmtree(roles_dir / "keystores", ignore_errors=True)

    for identity_id in _INFRA_IDS:
        source = staging / f"{identity_id}.json"
        target = roles_dir / "vault" / identity_id / f"{identity_id}.json"
        target.parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(source, target)
        os.chmod(target, 0o600)

    keystores = roles_dir / "keystores"
    for officer_id in OFFICER_IDS:
        _make_keystore(staging, officer_id, credentials[officer_id], keystores)
    for admin_id in ADMIN_IDS:
        _make_keystore(staging, admin_id, credentials[admin_id], keystores)
    for identity_id in _COMMAND_IDS:
        _make_keystore(staging, identity_id, credentials["command"], keystores)
    _make_keystore(staging, CA_ROOT_ID, credentials[CUSTODIAN], keystores)

    sync_public(staging, roles_dir)
    for officer_id in OFFICER_IDS:
        (roles_dir / "enrol-inbox" / officer_id).mkdir(parents=True, exist_ok=True)

    lines = ["TraceSeal roles deployment — generated credentials (do not commit)", ""]
    lines += [f"{principal}: {passphrase}" for principal, passphrase in credentials.items()]
    _write_private(roles_dir / "CREDENTIALS.local.txt", "\n".join(lines) + "\n")
    return credentials


def _principals() -> list[str]:
    return [*OFFICER_IDS, *ADMIN_IDS, "command", CUSTODIAN]


def _make_keystore(staging: Path, identity_id: str, passphrase: str, keystores: Path) -> None:
    identity = load_identity(staging / f"{identity_id}.json")
    create_keystore(identity, passphrase, keystores / f"{identity_id}.keystore.json")


def sync_public(staging: Path, roles_dir: Path) -> None:
    public = roles_dir / "public"
    public.mkdir(parents=True, exist_ok=True)
    shutil.copyfile(staging / "registry.json", public / "registry.json")


def purge_staging(staging: Path) -> None:
    """Delete every raw private identity from the staging directory, keeping
    only the public registry."""
    for path in staging.glob("*.json"):
        if path.name != "registry.json":
            path.unlink()


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description=__doc__, formatter_class=argparse.RawTextHelpFormatter
    )
    parser.add_argument(
        "command",
        nargs="?",
        default="provision",
        choices=["provision", "sync-public", "purge-staging"],
    )
    parser.add_argument("--staging", type=Path, default=DEFAULT_STAGING)
    parser.add_argument("--roles-dir", type=Path, default=DEFAULT_ROLES_DIR)
    args = parser.parse_args(argv)

    if args.command == "provision":
        credentials = provision(args.staging, args.roles_dir)
        print(
            f"[PASS] provisioned {len(_INFRA_IDS)} service vaults, "
            f"{len(OFFICER_IDS) + len(ADMIN_IDS) + len(_COMMAND_IDS) + 1} keystores, "
            f"{len(credentials)} passphrases"
        )
        print(f"       credentials: {args.roles_dir / 'CREDENTIALS.local.txt'} (owner-only)")
    elif args.command == "sync-public":
        sync_public(args.staging, args.roles_dir)
        print(f"[PASS] registry republished to {args.roles_dir / 'public' / 'registry.json'}")
    else:
        purge_staging(args.staging)
        print(f"[PASS] raw private identities removed from {args.staging}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
