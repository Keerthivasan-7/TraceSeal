"""Constant-time comparison for MACs, hashes and tokens (spec Section 3)."""

from __future__ import annotations

import hmac


def constant_time_eq(a: bytes, b: bytes) -> bool:
    """Compare two byte strings without leaking timing information.

    Different-length inputs are also compared in constant time relative to
    the length of ``a`` via :func:`hmac.compare_digest`, and are never equal.
    """
    return hmac.compare_digest(a, b)
