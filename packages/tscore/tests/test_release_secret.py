import numpy as np
import pytest

from tscore.release_secret import (
    bias_vector_from_bytes,
    bias_vector_to_bytes,
    combine_release_secret,
    derive_k_base,
    derive_variant_key,
    generate_document_keys,
    split_release_secret,
)


def test_combine_and_split_release_secret_round_trip() -> None:
    k_b = b"\x01" * 32
    s_v = b"\x02" * 32

    secret = combine_release_secret(k_b, s_v)
    recovered_k_b, recovered_s_v = split_release_secret(secret)

    assert recovered_k_b == k_b
    assert recovered_s_v == s_v


def test_bias_vector_round_trip() -> None:
    bias = np.array([0.1, 0.25, 0.9, 0.5], dtype=np.float32)
    data = bias_vector_to_bytes(bias)
    recovered = bias_vector_from_bytes(data, positions_count=4)
    np.testing.assert_array_equal(recovered, bias)


def test_bias_vector_from_bytes_rejects_wrong_positions_count() -> None:
    data = bias_vector_to_bytes(np.array([0.1, 0.2], dtype=np.float32))
    with pytest.raises(ValueError, match="expected"):
        bias_vector_from_bytes(data, positions_count=5)


def test_generate_document_keys_are_distinct_32_byte_values() -> None:
    k_a, k_b, s_v = generate_document_keys()
    assert len({k_a, k_b, s_v}) == 3
    assert len(k_a) == len(k_b) == len(s_v) == 32


def test_derive_k_base_is_deterministic_and_xor_symmetric() -> None:
    k_a, k_b = b"\x01" * 32, b"\x02" * 32
    assert derive_k_base(k_a, k_b, "doc-1") == derive_k_base(k_a, k_b, "doc-1")
    assert derive_k_base(k_a, k_b, "doc-1") == derive_k_base(k_b, k_a, "doc-1")
    assert derive_k_base(k_a, k_b, "doc-1") != derive_k_base(k_a, k_b, "doc-2")


def test_derive_variant_key_differs_per_position_and_bit() -> None:
    s_v = b"\x03" * 32
    keys = {
        derive_variant_key(s_v, "doc-1", 0, 0),
        derive_variant_key(s_v, "doc-1", 0, 1),
        derive_variant_key(s_v, "doc-1", 1, 0),
    }
    assert len(keys) == 3
