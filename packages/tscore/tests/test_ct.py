from tscore.ct import constant_time_eq


def test_equal_bytes() -> None:
    assert constant_time_eq(b"hello world", b"hello world")


def test_different_bytes() -> None:
    assert not constant_time_eq(b"hello world", b"hello WORLD")


def test_different_lengths() -> None:
    assert not constant_time_eq(b"short", b"a much longer string")


def test_empty_vs_empty() -> None:
    assert constant_time_eq(b"", b"")
