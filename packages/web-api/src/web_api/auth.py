"""Per-identity session authentication primitives.

Login's credential is the keystore passphrase (an Argon2id+AES-GCM unlock —
see `web_api.routes.session`); this module only owns what happens *after* a
successful unlock: the in-memory session table, brute-force lockout, and a
small security-event ring buffer. Nothing here touches disk, and nothing
here is cryptography — tokens are `secrets.token_urlsafe(32)` and are
looked up by their SHA-256, so the live table never holds a usable token.
"""

from __future__ import annotations

import hashlib
import hmac
import secrets
import time
from collections import deque
from collections.abc import Callable
from dataclasses import dataclass, field
from datetime import UTC, datetime

from web_api.config import Settings

Clock = Callable[[], float]

LOCKOUT_FREE_ATTEMPTS = 5
LOCKOUT_BASE_DELAY_S = 30.0
LOCKOUT_CAP_S = 300.0
EVENT_LOG_SIZE = 200


def cookie_name(settings: Settings) -> str:
    """Per-identity so two consoles in one browser profile never clobber each
    other's cookie even if a deployment ever served them from one origin."""
    return f"ts_session_{settings.identity_id or settings.role}"


@dataclass
class Session:
    token_hash: str
    principal_id: str
    identity_ids: list[str]
    created_at: float
    last_seen: float


def _hash_token(token: str) -> str:
    return hashlib.sha256(token.encode()).hexdigest()


class SessionManager:
    def __init__(
        self,
        idle_timeout_s: float = 300.0,
        abs_timeout_s: float = 1800.0,
        clock: Clock = time.monotonic,
    ) -> None:
        self._idle = idle_timeout_s
        self._abs = abs_timeout_s
        self._clock = clock
        self._sessions: dict[str, Session] = {}
        self._expired: list[Session] = []

    def create(self, principal_id: str, identity_ids: list[str]) -> tuple[str, Session]:
        """Returns `(raw_token, session)`. The raw token exists only in the
        caller's hands (to set the cookie); the table keeps its hash."""
        token = secrets.token_urlsafe(32)
        now = self._clock()
        token_hash = _hash_token(token)
        session = Session(token_hash, principal_id, list(identity_ids), now, now)
        self._sessions[token_hash] = session
        return token, session

    def _collect_expired(self) -> None:
        now = self._clock()
        for token_hash, session in list(self._sessions.items()):
            if now - session.last_seen > self._idle or now - session.created_at > self._abs:
                del self._sessions[token_hash]
                self._expired.append(session)

    def validate(self, token: str | None, *, touch: bool = True) -> Session | None:
        """`touch=False` is for status polling (`GET /session`): it must report
        the countdown without being the thing that keeps the session alive."""
        if not token:
            return None
        self._collect_expired()
        presented = _hash_token(token)
        session = self._sessions.get(presented)
        if session is None or not hmac.compare_digest(presented, session.token_hash):
            return None
        if touch:
            session.last_seen = self._clock()
        return session

    def sweep(self) -> list[Session]:
        """Sessions that expired since the last sweep — the caller must wipe
        their unlocked identities and any decrypted pages."""
        self._collect_expired()
        expired, self._expired = self._expired, []
        return expired

    def revoke(self, session: Session) -> None:
        self._sessions.pop(session.token_hash, None)

    def revoke_all(self) -> list[Session]:
        revoked = list(self._sessions.values())
        self._sessions.clear()
        return revoked

    def time_left(self, session: Session) -> tuple[float, float]:
        now = self._clock()
        idle_left = max(0.0, self._idle - (now - session.last_seen))
        abs_left = max(0.0, self._abs - (now - session.created_at))
        return idle_left, abs_left


class LockoutTracker:
    """Exponential backoff after repeated failed unlocks. Applies to the
    correct passphrase too while the window is open, otherwise a patient
    attacker could ignore the delay."""

    def __init__(self, clock: Clock = time.monotonic) -> None:
        self._clock = clock
        self._failures = 0
        self._locked_until = 0.0

    def retry_after(self) -> float:
        return max(0.0, self._locked_until - self._clock())

    def record_failure(self) -> None:
        self._failures += 1
        if self._failures >= LOCKOUT_FREE_ATTEMPTS:
            exponent = min(self._failures - LOCKOUT_FREE_ATTEMPTS, 10)
            delay = min(LOCKOUT_BASE_DELAY_S * (2**exponent), LOCKOUT_CAP_S)
            self._locked_until = self._clock() + delay

    def record_success(self) -> None:
        self._failures = 0
        self._locked_until = 0.0


@dataclass
class EventLog:
    maxlen: int = EVENT_LOG_SIZE
    _events: deque[dict[str, object]] = field(init=False)

    def __post_init__(self) -> None:
        self._events = deque(maxlen=self.maxlen)

    def add(self, kind: str, detail: str) -> None:
        self._events.append(
            {"at": datetime.now(UTC).isoformat(timespec="seconds"), "kind": kind, "detail": detail}
        )

    def recent(self) -> list[dict[str, object]]:
        return list(reversed(self._events))
