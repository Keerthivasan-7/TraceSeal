"""In-memory application state — everything here is intentionally
ephemeral (lost on restart) and never persisted to disk beyond what the
underlying `ca`/`sender`/`agent`/`forensics` calls already write to the
ledger/blob store themselves. Officer identities and decrypted pages in
particular must never touch disk here (spec: in-memory-only assembly) —
see `web_api.routes.officers`.

Grows incrementally as each phase's routes need it; this is deliberately
minimal for the Phase 1 skeleton.
"""

from __future__ import annotations

from dataclasses import dataclass, field

from ca.keys import Identity


@dataclass
class AppState:
    # officer_id -> unlocked Identity (Officer Inbox/Viewer, Phase 3).
    officer_sessions: dict[str, Identity] = field(default_factory=dict)
