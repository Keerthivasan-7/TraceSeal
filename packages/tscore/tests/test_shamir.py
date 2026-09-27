import itertools

from hypothesis import given
from hypothesis import strategies as st

from tscore.shamir import Share, gf_div, gf_inv, gf_mul, reconstruct, split


def test_gf_arithmetic_basic_identities() -> None:
    for a in range(1, 256):
        assert gf_mul(a, gf_inv(a)) == 1
    assert gf_mul(0, 42) == 0
    assert gf_div(42, 42) == 1


def test_known_test_vector_3_of_5() -> None:
    secret = bytes.fromhex("deadbeef")
    shares = split(secret, n=5, k=3)
    assert len(shares) == 5
    assert {s.x for s in shares} == {1, 2, 3, 4, 5}
    for combo in itertools.combinations(shares, 3):
        assert reconstruct(list(combo)) == secret


def test_any_k_of_n_subset_reconstructs() -> None:
    secret = b"the quick brown fox"
    shares = split(secret, n=5, k=3)
    for combo in itertools.combinations(shares, 3):
        assert reconstruct(list(combo)) == secret
    for combo in itertools.combinations(shares, 4):
        assert reconstruct(list(combo)) == secret
    assert reconstruct(shares) == secret  # all 5


def test_below_threshold_does_not_recover_secret() -> None:
    secret = b"top secret key material"
    shares = split(secret, n=5, k=3)
    for combo in itertools.combinations(shares, 2):
        assert reconstruct(list(combo)) != secret


def test_duplicate_x_rejected() -> None:
    import pytest

    shares = split(b"abc", n=5, k=3)
    dup = [shares[0], shares[0], shares[1]]
    with pytest.raises(ValueError, match="duplicate"):
        reconstruct(dup)


def test_mismatched_share_lengths_rejected() -> None:
    import pytest

    a = Share(x=1, ys=b"\x00\x01")
    b = Share(x=2, ys=b"\x00")
    with pytest.raises(ValueError, match="same payload length"):
        reconstruct([a, b])


@given(
    secret=st.binary(min_size=0, max_size=64),
    n=st.integers(min_value=3, max_value=8),
)
def test_property_any_threshold_subset_reconstructs(secret: bytes, n: int) -> None:
    k = max(2, n - 2)
    shares = split(secret, n=n, k=k)
    for combo in itertools.combinations(shares, k):
        assert reconstruct(list(combo)) == secret
