"""Where a route gets a signing identity from.

In the isolated roles an identity exists only because a person unlocked its
keystore in the current session — no raw private-key file is mounted at
all. Role `all` (the original combined console) keeps loading the raw file
so every existing flow and test is untouched.
"""

from __future__ import annotations

from ca.keys import Identity, load_identity
from fastapi import HTTPException

from web_api.config import Settings
from web_api.state import AppState


def resolve_identity(settings: Settings, app_state: AppState, identity_id: str) -> Identity:
    unlocked = app_state.unlocked.get(identity_id)
    if unlocked is not None:
        return unlocked
    if settings.role == "all":
        return load_identity(settings.identity_dir / f"{identity_id}.json")
    raise HTTPException(status_code=401, detail=f"{identity_id!r} is not unlocked — log in first")
