"""Hand-rolled GF(256) byte-wise Shamir secret sharing (spec Section 5).

Implemented in-house rather than pulling in a third-party dependency: the
scheme is small, well-understood, and easy to pin down with test vectors
(see ADR-0002 in docs/DECISIONS.md). Arithmetic uses the same GF(2^8) field
as AES/Rijndael (reduction polynomial x^8 + x^4 + x^3 + x + 1, i.e. 0x11B).

Reconstruction below the configured threshold is well-defined but produces
an incorrect secret rather than raising an error, matching how Shamir's
scheme actually behaves: with too few points, every candidate secret is
equally consistent with the observed shares. Callers that need to detect
"not enough shares" must track share counts themselves.
"""

from __future__ import annotations

import secrets
from collections.abc import Sequence
from dataclasses import dataclass

_EXP = [0] * 512
_LOG = [0] * 256


def _xtime(x: int) -> int:
    """Multiply by the field element 2 (i.e. by x), reducing mod 0x11B."""
    x <<= 1
    if x & 0x100:
        x ^= 0x11B
    return x & 0xFF


def _init_tables() -> None:
    # 3 (not 2!) is a primitive element of GF(2^8) under the AES/Rijndael
    # reduction polynomial x^8+x^4+x^3+x+1 (0x11B): repeated multiplication
    # by 2 only cycles through a 51-element subgroup, not all 255 nonzero
    # elements, which would silently produce a broken log table.
    x = 1
    for i in range(255):
        _EXP[i] = x
        _LOG[x] = i
        x = _xtime(x) ^ x  # x * 3 = x*2 XOR x*1
    for i in range(255, 512):
        _EXP[i] = _EXP[i - 255]


_init_tables()


def gf_mul(a: int, b: int) -> int:
    if a == 0 or b == 0:
        return 0
    return _EXP[_LOG[a] + _LOG[b]]


def gf_inv(a: int) -> int:
    if a == 0:
        raise ZeroDivisionError("0 has no multiplicative inverse in GF(256)")
    return _EXP[255 - _LOG[a]]


def gf_div(a: int, b: int) -> int:
    return gf_mul(a, gf_inv(b))


@dataclass(frozen=True)
class Share:
    x: int  # 1..255
    ys: bytes


def _split_byte(secret_byte: int, n: int, k: int) -> list[int]:
    coeffs = [secret_byte] + [secrets.randbelow(256) for _ in range(k - 1)]
    ys = []
    for x in range(1, n + 1):
        y = 0
        for coeff in reversed(coeffs):
            y = gf_mul(y, x) ^ coeff
        ys.append(y)
    return ys


def _reconstruct_byte(points: Sequence[tuple[int, int]]) -> int:
    secret = 0
    for i, (xi, yi) in enumerate(points):
        num, den = 1, 1
        for j, (xj, _yj) in enumerate(points):
            if i == j:
                continue
            num = gf_mul(num, xj)
            den = gf_mul(den, xi ^ xj)
        secret ^= gf_mul(yi, gf_div(num, den))
    return secret


def split(secret: bytes, n: int, k: int) -> list[Share]:
    """Split ``secret`` into ``n`` shares, any ``k`` of which reconstruct it."""
    if not (1 <= k <= n <= 255):
        raise ValueError("require 1 <= k <= n <= 255")
    columns = [_split_byte(b, n, k) for b in secret]
    return [
        Share(x=x, ys=bytes(col[x - 1] for col in columns)) for x in range(1, n + 1)
    ]


def reconstruct(shares: Sequence[Share]) -> bytes:
    """Reconstruct a secret from ``shares``. See module docstring for the
    below-threshold behaviour."""
    if not shares:
        raise ValueError("need at least one share")
    length = len(shares[0].ys)
    if any(len(s.ys) != length for s in shares):
        raise ValueError("all shares must have the same payload length")
    xs = [s.x for s in shares]
    if len(set(xs)) != len(xs):
        raise ValueError("duplicate share x-coordinate")
    out = bytearray(length)
    for byte_idx in range(length):
        points = [(s.x, s.ys[byte_idx]) for s in shares]
        out[byte_idx] = _reconstruct_byte(points)
    return bytes(out)
