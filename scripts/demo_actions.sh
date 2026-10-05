#!/usr/bin/env bash
# One-line stage actions for the isolated-roles demo (docs/JUDGE_DEMO_SCRIPT_ROLES_9MIN.md).
#
#   bash scripts/demo_actions.sh kill-node       stop key-release node 3 (decryption must still work)
#   bash scripts/demo_actions.sh kill-quorum     stop nodes 1-3 as well (decryption must be REFUSED)
#   bash scripts/demo_actions.sh restore-nodes   start every key-release node again
#   bash scripts/demo_actions.sh tamper-ledger   an "insider" edits ledger-2's stored history on disk
#   bash scripts/demo_actions.sh start-officer-c start officer-c's workstation (it is NOT enrolled yet)
#   bash scripts/demo_actions.sh status          which ledger/key-release containers are up
#
# `tamper-ledger` really edits replica 2's SQLite file; the only undo is a full
# reset (`bash scripts/roles.sh provision`), which you do after the demo anyway.
set -euo pipefail
cd "$(dirname "$0")/.."
export MSYS_NO_PATHCONV=1
DC="docker compose -f docker-compose.yml -f docker-compose.roles.yml"

case "${1:-}" in
  kill-node)
    $DC stop keyrelease-3 >/dev/null 2>&1
    echo "[done] keyrelease-3 is DOWN — 4 of 5 key-release nodes remain (threshold is 3)"
    ;;
  kill-quorum)
    $DC stop keyrelease-1 keyrelease-2 keyrelease-3 >/dev/null 2>&1
    echo "[done] keyrelease-1, -2, -3 are DOWN — only 2 of 5 remain, below the threshold of 3"
    ;;
  restore-nodes)
    $DC start keyrelease-1 keyrelease-2 keyrelease-3 >/dev/null 2>&1
    echo "[done] all five key-release nodes are up again"
    ;;
  tamper-ledger)
    $DC stop ledger-2 >/dev/null 2>&1
    $DC run --rm -T --no-deps --entrypoint python ledger-2 -c "
import sqlite3
conn = sqlite3.connect('/data/ledger-2.db')
conn.execute('UPDATE records SET record_hash = randomblob(32) WHERE height = 1')
conn.commit()
print('[done] ledger-2: stored hash at height 1 overwritten on disk')
" 2>&1 | grep '^\[done\]'
    $DC start ledger-2 >/dev/null 2>&1
    echo "[done] ledger-2 restarted — now look at the Ledger screen on the Operations console"
    ;;
  start-officer-c)
    $DC --profile officers-extra up -d --no-build agent-officer-c >/dev/null 2>&1
    echo "[done] officer-c workstation is UP at http://officer-c.localhost:8080 — not enrolled yet"
    ;;
  status)
    docker ps --format '{{.Names}}\t{{.Status}}' | grep -E "ledger|keyrelease" | sort
    ;;
  *)
    echo "usage: $0 {kill-node|kill-quorum|restore-nodes|tamper-ledger|start-officer-c|status}" >&2
    exit 2
    ;;
esac
