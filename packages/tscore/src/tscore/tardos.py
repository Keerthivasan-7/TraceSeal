"""Binary symmetric Tardos fingerprinting (spec Section 10).

Implements the symmetric-score variant of the Tardos traitor-tracing code
(Škorić, Katzenbeisser & Celik, "Symmetric Tardos fingerprinting codes for
arbitrary alphabet sizes", 2008), restricted to a binary alphabet, with the
arcsine bias distribution from the original Tardos (2003) scheme.

This module is deliberately shared between the sender (which only needs
``required_length``/``plan_parameters`` to size the mark-position budget)
and forensics (which will use ``accuse`` on a real leak in M5) — see
docs/SPEC.md Section 6.

The length and threshold formulas below are the standard asymptotic ones
from the literature; they are not treated as gospel. `test_tardos.py`'s
Monte-Carlo suite (`@pytest.mark.slow`) empirically checks the innocent-
accusation rate and coalition detection rate this module actually produces,
and `plan_parameters` never claims a coalition-resistance level the
document's own position budget can't support.
"""

from __future__ import annotations

import math
from dataclasses import dataclass

import numpy as np
from numpy.random import Generator

BitArray = np.ndarray  # dtype=int8, values in {0, 1}
ObservedArray = np.ndarray  # dtype=float64, values in {0.0, 1.0, nan} (nan = erasure)


def sample_bias_vector(length: int, *, cutoff: float, rng: Generator) -> np.ndarray:
    """Sample a length-``length`` bias vector ``p`` from the arcsine
    distribution restricted to ``[cutoff, 1-cutoff]``.

    ``cutoff`` must be in ``(0, 0.5)``: it keeps every position's bias away
    from 0 or 1, which is what makes both the ``0`` and ``1`` symbols
    informative at every position.
    """
    if not 0.0 < cutoff < 0.5:
        raise ValueError("cutoff must be in (0, 0.5)")
    lo = math.asin(math.sqrt(cutoff))
    hi = math.asin(math.sqrt(1.0 - cutoff))
    theta = rng.uniform(lo, hi, size=length)
    return np.sin(theta) ** 2


def assign_codeword(bias_vector: np.ndarray, rng: Generator) -> BitArray:
    """Draw one codeword: bit ``i`` is 1 with probability ``bias_vector[i]``."""
    return (rng.random(len(bias_vector)) < bias_vector).astype(np.int8)


def required_length(n: int, c0: int, eps1: float, *, margin: float = 1.2) -> int:
    """Codeword length target: ``ceil(pi^2/2 * c0^2 * ln(n/eps1)) * margin``.

    Asymptotic formula (spec Section 10); ``margin`` (default 20%) absorbs
    the gap between the asymptotic bound and finite-length behaviour, which
    is exactly what the Monte-Carlo suite checks empirically.
    """
    if n < 1:
        raise ValueError("n must be >= 1")
    if c0 < 2:
        raise ValueError("c0 must be >= 2")
    if not 0.0 < eps1 < 1.0:
        raise ValueError("eps1 must be in (0, 1)")
    base = (math.pi**2 / 2.0) * (c0**2) * math.log(n / eps1)
    return math.ceil(base * margin)


@dataclass(frozen=True)
class TardosPlan:
    length: int
    c0: int
    n: int
    eps1: float
    requested_c0: int

    @property
    def degraded(self) -> bool:
        """True if the achievable ``c0`` had to be reduced below what was requested."""
        return self.c0 < self.requested_c0


def plan_parameters(
    available_positions: int,
    n: int,
    eps1: float,
    *,
    max_c0: int = 3,
    margin: float = 1.2,
) -> TardosPlan:
    """Pick the largest ``c0 <= max_c0`` (minimum 2) whose ``required_length``
    fits in ``available_positions``, and report exactly that — never a
    ``c0`` the document can't actually support.

    Raises :class:`ValueError` if even ``c0=2`` doesn't fit; that means the
    document has too few mark positions for *any* collusion resistance at
    the requested ``n``/``eps1``, which callers must surface rather than
    silently proceed with an unfounded resistance claim.
    """
    for c0 in range(max_c0, 1, -1):
        length = required_length(n, c0, eps1, margin=margin)
        if length <= available_positions:
            return TardosPlan(length=length, c0=c0, n=n, eps1=eps1, requested_c0=max_c0)
    minimal = required_length(n, 2, eps1, margin=margin)
    raise ValueError(
        f"document has only {available_positions} mark positions; "
        f"even c0=2 needs {minimal} at n={n}, eps1={eps1}"
    )


def score(codeword_bit: int, observed_bit: float, bias: float) -> float:
    """Symmetric Tardos score contribution of one position.

    ``observed_bit`` is ``nan`` for an erasure (contributes 0). Otherwise
    the standard symmetric score (Škorić et al. 2008):

        U(1, 1, p) =  sqrt((1-p)/p)      U(0, 1, p) = -sqrt(p/(1-p))
        U(0, 0, p) =  sqrt(p/(1-p))      U(1, 0, p) = -sqrt((1-p)/p)
    """
    if math.isnan(observed_bit):
        return 0.0
    p = bias
    if observed_bit == 1.0:
        return math.sqrt((1.0 - p) / p) if codeword_bit == 1 else -math.sqrt(p / (1.0 - p))
    return math.sqrt(p / (1.0 - p)) if codeword_bit == 0 else -math.sqrt((1.0 - p) / p)


def threshold(n_observed: int, eps1: float, *, k: float = 2.0) -> float:
    """Accusation threshold ``Z``, rescaled to the number of non-erased
    positions actually observed (spec Section 10).

    ``Z = sqrt(k * n_observed * ln(1/eps1))``. ``k`` defaults to the
    standard asymptotic constant (2.0) and is exposed so it can be tuned
    against the Monte-Carlo results in `test_tardos.py` if the empirical
    false-accusation rate doesn't meet ``eps1`` at that constant.
    """
    if n_observed <= 0:
        return math.inf
    return math.sqrt(k * n_observed * math.log(1.0 / eps1))


def accuse(
    codewords: dict[str, BitArray],
    observed: ObservedArray,
    bias_vector: np.ndarray,
    eps1: float,
    *,
    k: float = 2.0,
) -> dict[str, float]:
    """Score every candidate session against the observed (possibly
    erasure-containing) pirate codeword. Returns every session's score;
    callers compare against :func:`threshold` themselves so a full
    histogram can be shown (spec Section 10)."""
    scores: dict[str, float] = {}
    for session_id, codeword in codewords.items():
        total = 0.0
        for bit, obs, bias in zip(codeword, observed, bias_vector, strict=True):
            total += score(int(bit), float(obs), float(bias))
        scores[session_id] = total
    return scores
