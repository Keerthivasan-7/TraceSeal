"""One-time M8 addition: wraps each officer's already-generated identity
into a real encrypted keystore file (spec Section 3: "Keystores are
encrypted with Argon2id-derived keys"). `agent.keystore`'s
`create_keystore`/`unlock_keystore` have been implemented and tested since
M3, but no demo script ever actually invoked them — `agent.demo_m3`/
`demo_m4` load each officer's raw identity JSON directly via
`ca.keys.load_identity`, skipping the keystore layer entirely. For the
web UI's "unlock keystore" control (spec Section 14.4) to be a real
Argon2id+AES-GCM unlock rather than theatre, this seeds one genuine
keystore per officer under a fixed, documented demo passphrase.

Usage: ``python -m agent.seed_keystores``
"""

from __future__ import annotations

import sys
from pathlib import Path

from ca.keys import load_identity
from ca.seed import OFFICER_IDS

from agent.keystore import create_keystore

# Fixed and documented here deliberately — this is a demo/pitch
# convenience for a synthetic scenario with synthetic officers (CLAUDE.md's
# honesty rules), never a stand-in for a real deployment's passphrase
# policy, which is out of this project's scope.
DEMO_PASSPHRASE = "traceseal-demo-2026"  # noqa: S105 - intentional, documented demo-only value

DEFAULT_PKI_DIR = Path.cwd() / "demo" / "pki"
DEFAULT_KEYSTORE_DIR = Path.cwd() / "demo" / "keystores"


def seed_keystores(
    pki_dir: Path = DEFAULT_PKI_DIR,
    keystore_dir: Path = DEFAULT_KEYSTORE_DIR,
    *,
    passphrase: str = DEMO_PASSPHRASE,
) -> int:
    count = 0
    for officer_id in OFFICER_IDS:
        identity = load_identity(pki_dir / f"{officer_id}.json")
        create_keystore(identity, passphrase, keystore_dir / f"{officer_id}.keystore.json")
        count += 1
    return count


def main() -> int:
    count = seed_keystores()
    print(
        f"[PASS] seeded {count} officer keystores under {DEFAULT_KEYSTORE_DIR} "
        f"(demo passphrase: {DEMO_PASSPHRASE!r})"
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())
