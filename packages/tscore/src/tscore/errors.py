"""Typed exception hierarchy shared across TraceSeal packages."""

from __future__ import annotations


class TraceSealError(Exception):
    """Base class for every TraceSeal-specific exception."""


class VerificationError(TraceSealError):
    """A signature, MAC, or commitment failed to verify."""


class TamperError(TraceSealError):
    """Authenticated decryption or integrity check detected tampering."""


class UnsupportedAlgorithmError(TraceSealError):
    """The requested algorithm name is not enabled by the local liboqs build."""
