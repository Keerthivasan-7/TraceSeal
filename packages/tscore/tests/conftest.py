"""Auto-skip liboqs-dependent tests when the liboqs shared library isn't
actually present.

liboqs-python (`oqs`), if it can't find a built liboqs, will try to
*auto-clone-and-build* liboqs the moment it's imported (see its
``_load_liboqs``) — which is slow, needs network + a C toolchain (cmake,
ninja, a compiler), and is exactly the code path ADR-0003
(docs/DECISIONS.md) avoids in the Docker image by pre-building liboqs and
pointing ``OQS_INSTALL_PATH`` at it. So this conftest checks for the shared
library *file* directly, without ever importing ``oqs``, and skips
``requires_liboqs`` tests if it isn't there — instead of triggering that
slow auto-install path (or a confusing collection error) on a bare host.

The canonical way to run the full suite, liboqs included, is `make test`
(spec Section 17 M0 acceptance), which runs inside the pinned Docker image
where the shared library always exists.
"""

from __future__ import annotations

import ctypes.util
import os
import platform
from pathlib import Path

import pytest


def _liboqs_shared_lib_present() -> bool:
    install_dir = Path(os.environ.get("OQS_INSTALL_PATH", str(Path.home() / "_oqs")))
    system = platform.system()
    if system == "Darwin":
        candidates = [install_dir / "lib" / "liboqs.dylib"]
    elif system == "Windows":
        bin_dir = install_dir / "bin"
        candidates = [bin_dir / "oqs.dll", bin_dir / "liboqs.dll"]
    else:
        candidates = [install_dir / "lib" / "liboqs.so", install_dir / "lib64" / "liboqs.so"]
    if any(candidate.exists() for candidate in candidates):
        return True
    # Falls back to whatever the OS's own dynamic linker would find
    # (e.g. a system package) — cheap, no network, matches liboqs-python's
    # own `ctypes.util.find_library` lookup.
    return ctypes.util.find_library("oqs") is not None


_LIBOQS_AVAILABLE = _liboqs_shared_lib_present()


def pytest_collection_modifyitems(config: pytest.Config, items: list[pytest.Item]) -> None:
    if _LIBOQS_AVAILABLE:
        return
    skip_liboqs = pytest.mark.skip(
        reason="liboqs shared library not found (no OQS_INSTALL_PATH build, no system install) "
        "— run `make test` for the Docker-based, liboqs-included run"
    )
    for item in items:
        if "requires_liboqs" in item.keywords:
            item.add_marker(skip_liboqs)
