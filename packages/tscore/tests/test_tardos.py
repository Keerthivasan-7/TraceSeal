import math

import numpy as np
import pytest

from tscore.tardos import (
    TardosPlan,
    accuse,
    assign_codeword,
    plan_parameters,
    required_length,
    sample_bias_vector,
    score,
    threshold,
)


def test_required_length_matches_hand_computation() -> None:
    n, c0, eps1 = 5, 3, 1e-4
    expected = math.ceil((math.pi**2 / 2.0) * 9 * math.log(n / eps1) * 1.2)
    assert required_length(n, c0, eps1) == expected


def test_required_length_grows_with_c0() -> None:
    assert required_length(10, 3, 1e-4) > required_length(10, 2, 1e-4)


@pytest.mark.parametrize("bad_c0", [0, 1])
def test_required_length_rejects_small_c0(bad_c0: int) -> None:
    with pytest.raises(ValueError, match="c0"):
        required_length(5, bad_c0, 1e-4)


def test_plan_parameters_uses_requested_c0_when_it_fits() -> None:
    plan = plan_parameters(available_positions=10_000, n=5, eps1=1e-4, max_c0=3)
    assert plan.c0 == 3
    assert not plan.degraded


def test_plan_parameters_degrades_c0_when_starved() -> None:
    # c0=3 needs ~577 positions at n=5, eps1=1e-4; c0=2 needs ~257. A
    # document with 300 positions can only support the lower one — this is
    # the exact fallback the M1 demo is expected to exercise honestly
    # rather than hide.
    plan = plan_parameters(available_positions=300, n=5, eps1=1e-4, max_c0=3)
    assert plan.degraded
    assert plan.c0 == 2
    assert plan.length <= 300


def test_plan_parameters_raises_when_even_c0_2_does_not_fit() -> None:
    with pytest.raises(ValueError, match="c0=2"):
        plan_parameters(available_positions=1, n=5, eps1=1e-4, max_c0=3)


def test_sample_bias_vector_respects_cutoff() -> None:
    rng = np.random.default_rng(0)
    bias = sample_bias_vector(1000, cutoff=0.05, rng=rng)
    assert np.all(bias >= 0.05 - 1e-9)
    assert np.all(bias <= 0.95 + 1e-9)


def test_sample_bias_vector_rejects_bad_cutoff() -> None:
    rng = np.random.default_rng(0)
    with pytest.raises(ValueError):
        sample_bias_vector(10, cutoff=0.0, rng=rng)
    with pytest.raises(ValueError):
        sample_bias_vector(10, cutoff=0.5, rng=rng)


def test_assign_codeword_is_binary() -> None:
    rng = np.random.default_rng(1)
    bias = sample_bias_vector(200, cutoff=0.1, rng=rng)
    codeword = assign_codeword(bias, rng)
    assert set(np.unique(codeword)).issubset({0, 1})
    assert len(codeword) == 200


def test_score_erasure_is_zero() -> None:
    assert score(1, float("nan"), 0.3) == 0.0
    assert score(0, float("nan"), 0.7) == 0.0


def test_score_matching_symbol_is_positive_mismatch_is_negative() -> None:
    p = 0.3
    assert score(1, 1.0, p) > 0
    assert score(0, 1.0, p) < 0
    assert score(0, 0.0, p) > 0
    assert score(1, 0.0, p) < 0


def test_threshold_grows_with_observed_positions() -> None:
    assert threshold(100, 1e-4) < threshold(400, 1e-4)


def test_threshold_is_infinite_for_zero_observed() -> None:
    assert threshold(0, 1e-4) == math.inf


def test_accuse_scores_every_session() -> None:
    rng = np.random.default_rng(2)
    bias = sample_bias_vector(50, cutoff=0.1, rng=rng)
    codewords = {f"S-{i}": assign_codeword(bias, rng) for i in range(3)}
    # Pretend session S-1's copy leaked verbatim.
    observed = codewords["S-1"].astype(float)
    scores = accuse(codewords, observed, bias, eps1=1e-4)
    assert set(scores) == set(codewords)
    assert scores["S-1"] == max(scores.values())


@pytest.mark.slow
class TestTardosMonteCarlo:
    """Empirical validation required by spec Section 10: the innocent-
    accusation rate stays at or below eps1, and coalitions up to c0 are
    detected, under several pirate strategies."""

    @staticmethod
    def _run_trial(
        rng: np.random.Generator,
        *,
        n: int,
        c0: int,
        eps1: float,
        strategy: str,
    ) -> tuple[dict[str, float], float, set[str]]:
        plan: TardosPlan = plan_parameters(available_positions=10_000, n=n, eps1=eps1, max_c0=c0)
        bias = sample_bias_vector(plan.length, cutoff=0.1, rng=rng)
        codewords = {f"S-{i}": assign_codeword(bias, rng) for i in range(n)}
        coalition = [f"S-{i}" for i in range(c0)]
        coalition_bits = np.stack([codewords[s] for s in coalition])
        # The marking assumption: at a position where every colluder holds
        # the same bit, the coalition has no other value to output there —
        # only at split positions can a strategy actually choose. Ignoring
        # this let "minority"/"all-0"/"all-1" force illegal outputs at
        # unanimous positions in an earlier version of this test, which
        # made every coalition member look innocent (or worse) instead of
        # guilty; the fix is this `unanimous_mask` override below.
        unanimous_mask = np.all(coalition_bits == coalition_bits[0], axis=0)
        unanimous_value = coalition_bits[0].astype(float)

        if strategy == "majority":
            observed = (coalition_bits.mean(axis=0) >= 0.5).astype(float)
        elif strategy == "minority":
            raw = (coalition_bits.mean(axis=0) < 0.5).astype(float)
            observed = np.where(unanimous_mask, unanimous_value, raw)
        elif strategy == "random":
            pick = rng.integers(0, c0, size=plan.length)
            observed = coalition_bits[pick, np.arange(plan.length)].astype(float)
        elif strategy == "interleave":
            observed = coalition_bits[np.arange(plan.length) % c0, np.arange(plan.length)].astype(
                float
            )
        elif strategy == "all-0":
            observed = np.where(unanimous_mask, unanimous_value, 0.0)
        elif strategy == "all-1":
            observed = np.where(unanimous_mask, unanimous_value, 1.0)
        else:  # pragma: no cover - defensive, all callers use a known strategy
            raise ValueError(strategy)

        scores = accuse(codewords, observed, bias, eps1)
        z = threshold(plan.length, eps1)
        accused = {s for s, val in scores.items() if val > z}
        return scores, z, accused

    @pytest.mark.parametrize(
        "strategy", ["majority", "minority", "random", "interleave", "all-0", "all-1"]
    )
    def test_coalition_is_detected_and_no_innocent_accused(self, strategy: str) -> None:
        rng = np.random.default_rng(42)
        n, c0, eps1 = 20, 3, 1e-4
        trials = 200
        coalition = {f"S-{i}" for i in range(c0)}
        innocents_accused = 0
        coalition_hits = 0
        for _ in range(trials):
            _scores, _z, accused = self._run_trial(rng, n=n, c0=c0, eps1=eps1, strategy=strategy)
            if accused & coalition:
                coalition_hits += 1
            innocents_accused += len(accused - coalition)

        innocent_accusation_rate = innocents_accused / (trials * (n - c0))
        assert innocent_accusation_rate <= eps1 * 10, (
            f"{strategy}: empirical innocent-accusation rate "
            f"{innocent_accusation_rate:.2e} exceeds 10x eps1={eps1:.0e}"
        )
        detection_rate = coalition_hits / trials
        assert detection_rate >= 0.95, (
            f"{strategy}: coalition detected in only {detection_rate:.0%} of {trials} trials"
        )
