"""Unit tests for the session/lockout/event primitives (web_api.auth) — no
FastAPI app, no crypto; time is an injected fake clock so expiry and
lockout windows are exact rather than slept through."""

from __future__ import annotations

from web_api.auth import EventLog, LockoutTracker, SessionManager, cookie_name
from web_api.config import Settings


class FakeClock:
    def __init__(self) -> None:
        self.now = 1000.0

    def __call__(self) -> float:
        return self.now

    def advance(self, seconds: float) -> None:
        self.now += seconds


def _manager(clock: FakeClock) -> SessionManager:
    return SessionManager(idle_timeout_s=300, abs_timeout_s=1800, clock=clock)


def test_tokens_are_long_unique_and_not_stored_raw() -> None:
    manager = _manager(FakeClock())
    token_a, session_a = manager.create("officer-a", ["officer-a"])
    token_b, _ = manager.create("officer-a", ["officer-a"])
    assert token_a != token_b
    assert len(token_a) >= 43  # token_urlsafe(32) is 43 chars of base64
    assert token_a not in vars(session_a).values()


def test_validate_returns_session_then_none_after_idle_timeout() -> None:
    clock = FakeClock()
    manager = _manager(clock)
    token, _ = manager.create("officer-a", ["officer-a"])
    clock.advance(299)
    assert manager.validate(token) is not None
    clock.advance(299)  # activity above reset the idle clock
    assert manager.validate(token) is not None
    clock.advance(301)
    assert manager.validate(token) is None


def test_absolute_timeout_applies_even_when_continuously_active() -> None:
    clock = FakeClock()
    manager = _manager(clock)
    token, _ = manager.create("officer-a", ["officer-a"])
    for _ in range(6):
        clock.advance(290)  # always inside the 300 s idle window...
        assert manager.validate(token) is not None  # ...up to 1740 s elapsed
    clock.advance(290)  # 2030 s elapsed: past the 1800 s absolute cap
    assert manager.validate(token) is None


def test_validate_rejects_missing_and_garbage_tokens() -> None:
    manager = _manager(FakeClock())
    manager.create("officer-a", ["officer-a"])
    assert manager.validate(None) is None
    assert manager.validate("") is None
    assert manager.validate("not-a-real-token") is None


def test_sweep_reports_each_expired_session_exactly_once() -> None:
    clock = FakeClock()
    manager = _manager(clock)
    manager.create("officer-a", ["officer-a"])
    assert manager.sweep() == []
    clock.advance(301)
    expired = manager.sweep()
    assert [s.principal_id for s in expired] == ["officer-a"]
    assert manager.sweep() == []


def test_revoke_all_returns_and_removes_sessions() -> None:
    manager = _manager(FakeClock())
    token, _ = manager.create("officer-a", ["officer-a"])
    revoked = manager.revoke_all()
    assert len(revoked) == 1
    assert manager.validate(token) is None


def test_time_left_counts_down() -> None:
    clock = FakeClock()
    manager = _manager(clock)
    token, session = manager.create("officer-a", ["officer-a"])
    clock.advance(100)
    session = manager.validate(token)  # type: ignore[assignment]
    idle_left, abs_left = manager.time_left(session)
    assert round(idle_left) == 300
    assert round(abs_left) == 1700


def test_lockout_backoff_doubles_caps_and_resets() -> None:
    clock = FakeClock()
    lockout = LockoutTracker(clock=clock)
    for _ in range(4):
        lockout.record_failure()
        assert lockout.retry_after() == 0
    lockout.record_failure()
    assert lockout.retry_after() == 30
    clock.advance(31)
    assert lockout.retry_after() == 0
    lockout.record_failure()
    assert lockout.retry_after() == 60
    for _ in range(10):
        clock.advance(400)
        lockout.record_failure()
    assert lockout.retry_after() == 300
    lockout.record_success()
    assert lockout.retry_after() == 0
    lockout.record_failure()
    assert lockout.retry_after() == 0  # counter really reset


def test_event_log_keeps_newest_200_newest_first() -> None:
    log = EventLog(maxlen=200)
    for i in range(250):
        log.add("login_failed", f"attempt {i}")
    recent = log.recent()
    assert len(recent) == 200
    assert recent[0]["detail"] == "attempt 249"
    assert recent[-1]["detail"] == "attempt 50"
    assert {"at", "kind", "detail"} <= recent[0].keys()


def test_cookie_name_is_per_identity_or_role(settings: Settings) -> None:
    officer = Settings(**{**settings.__dict__, "role": "officer", "identity_id": "officer-a"})
    command = Settings(**{**settings.__dict__, "role": "command", "identity_id": None})
    assert cookie_name(officer) == "ts_session_officer-a"
    assert cookie_name(command) == "ts_session_command"


def test_settings_auth_defaults_by_role(settings: Settings) -> None:
    def with_role(role: str) -> Settings:
        return Settings(
            **{
                **settings.__dict__,
                "role": role,
                "identity_id": "officer-a" if role == "officer" else None,
                "auth_required_override": None,
            }
        )

    assert with_role("all").auth_enabled is False
    assert with_role("ops").auth_enabled is False
    assert with_role("officer").auth_enabled is True
    assert with_role("command").auth_enabled is True
    assert with_role("authority").auth_enabled is True
