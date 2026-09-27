import pytest
from pydantic import ValidationError

from tscore.schemas import SignedEnvelope


def _envelope(**overrides: object) -> SignedEnvelope:
    fields: dict[str, object] = {
        "domain": "traceseal/test/v1",
        "nonce": b"\x00" * 16,
        "payload": b"payload-bytes",
    }
    fields.update(overrides)
    return SignedEnvelope.model_validate(fields)


def test_defaults_version_to_1() -> None:
    assert _envelope().version == 1


def test_canonical_cbor_round_trip() -> None:
    env = _envelope()
    restored = SignedEnvelope.from_canonical_cbor(env.to_canonical_cbor())
    assert restored == env


def test_encoding_is_deterministic() -> None:
    env = _envelope()
    assert env.to_canonical_cbor() == env.to_canonical_cbor()


def test_nonce_too_short_rejected() -> None:
    with pytest.raises(ValidationError):
        _envelope(nonce=b"short")


def test_empty_domain_rejected() -> None:
    with pytest.raises(ValidationError):
        _envelope(domain="")
