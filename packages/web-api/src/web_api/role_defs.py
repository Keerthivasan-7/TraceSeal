"""Static per-role facts shared by the session routes and router assembly.
Kept free of router imports so `routes.session` can use it without a cycle.
"""

from __future__ import annotations

from ca.seed import FORENSICS_ID, SENDER_ID

# What the UI is allowed to show per role. The server is still the
# enforcement point (routers outside a role are simply not mounted); this
# list only stops the UI offering screens whose API will 404.
ROLE_SCREENS: dict[str, list[str]] = {
    "all": [
        "command",
        "identity",
        "distribute",
        "inbox",
        "monitor",
        "investigate",
        "ledger",
        "attacklab",
    ],
    "command": ["command", "distribute", "monitor", "investigate", "ledger", "attacklab"],
    "officer": ["inbox"],
    "authority": ["identity", "ledger"],
    "ops": ["command", "monitor", "ledger"],
}

# Whose keystores a successful login unlocks, for roles without a fixed
# `identity_id`. `command` is one operator holding both document-owner
# identities (the patch library Investigate needs lives in that process).
FIXED_PRINCIPALS: dict[str, list[str]] = {
    "command": [SENDER_ID, FORENSICS_ID],
    "authority": ["ca-root"],
}
