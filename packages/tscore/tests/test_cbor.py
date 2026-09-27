from tscore.cbor import canonical_dumps, canonical_loads


def test_same_value_encodes_identically_every_time() -> None:
    obj = {"b": 2, "a": 1, "nested": {"z": 1, "y": [1, 2, 3]}}
    assert canonical_dumps(obj) == canonical_dumps(obj)


def test_key_insertion_order_does_not_affect_encoding() -> None:
    obj_1 = {"a": 1, "b": 2, "c": 3}
    obj_2 = {"c": 3, "a": 1, "b": 2}
    assert canonical_dumps(obj_1) == canonical_dumps(obj_2)


def test_round_trip() -> None:
    obj = {"version": 1, "domain": "traceseal/test/v1", "nonce": b"\x00" * 16, "n": 12345}
    assert canonical_loads(canonical_dumps(obj)) == obj


def test_decode_then_encode_is_byte_identical() -> None:
    original = canonical_dumps({"x": [1, 2, {"y": b"bytes-value"}]})
    decoded = canonical_loads(original)
    assert canonical_dumps(decoded) == original
