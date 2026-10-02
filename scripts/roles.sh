#!/usr/bin/env bash
# Isolated-roles deployment driver (docs/superpowers/specs/2026-10-01-role-isolation-design.md).
#
#   scripts/roles.sh provision   reset state, seed PKI, distribute keys, enrol officers a-c
#   scripts/roles.sh up          build + start the consoles (after `provision`)
#   scripts/roles.sh down        stop everything
#   scripts/roles.sh status      show containers and console URLs
#
# Runs under Git Bash on Windows as well as Linux/macOS (the Makefile targets
# `roles-provision`, `roles-up`, `roles-down` just call this).
set -euo pipefail
cd "$(dirname "$0")/.."
# Git Bash would otherwise rewrite /app/... style arguments into Windows paths.
export MSYS_NO_PATHCONV=1

ROLES="docker compose -f docker-compose.yml -f docker-compose.roles.yml"
BASE="docker compose"
INFRA="ledger-0 ledger-1 ledger-2 ledger-3 keyrelease-0 keyrelease-1 keyrelease-2 keyrelease-3 keyrelease-4"
CONSOLES="agent-officer-a agent-officer-b agent-officer-c console-command console-authority console-ops web"
ENROLLED_OFFICERS="officer-a officer-b officer-c"

wait_healthy() {
  local service="$1"
  for _ in $(seq 1 60); do
    if $ROLES exec -T "$service" python -c \
      "import httpx; httpx.get('http://localhost:8000/health', timeout=2).raise_for_status()" \
      >/dev/null 2>&1; then
      return 0
    fi
    sleep 1
  done
  echo "[FAIL] $service did not become healthy" >&2
  return 1
}

provision() {
  echo "== build images that carry the role-isolation code (web-api, ledger, key-release)"
  $ROLES build web-api ledger-0 keyrelease-0

  echo "== stop any running deployment"
  $ROLES --profile combined --profile officers-extra down --remove-orphans

  echo "== reset demo state (ledger data, blobs, PKI staging, roles material)"
  rm -rf demo/pki demo/blob demo/data demo/roles demo/agent-state demo/checkpoints demo/out
  mkdir -p demo/pki demo/blob demo/data demo/out demo/roles

  echo "== seed PKI into the offline staging directory"
  $BASE run --rm ca

  echo "== distribute keys: service vaults, principal keystores, public registry"
  $BASE run --rm --no-deps --entrypoint python web-api -m agent.provision_roles

  echo "== start ledger + key-release on their narrowed mounts"
  # shellcheck disable=SC2086
  $ROLES up -d $INFRA
  for service in ledger-0 ledger-1 ledger-2 ledger-3 keyrelease-0 keyrelease-1 \
                 keyrelease-2 keyrelease-3 keyrelease-4; do
    wait_healthy "$service"
  done

  echo "== enrol officers through the 2-of-3 admin quorum ceremony (offline CA area)"
  for officer in $ENROLLED_OFFICERS; do
    $BASE run --rm ca python -c "
import sys
from pathlib import Path
from ca.demo_m4 import enrol_officer
sys.exit(0 if enrol_officer('$officer', pki_dir=Path('/app/demo/pki'),
                            ledger_leader_url='http://ledger-0:8000') else 1)
"
  done

  echo "== publish the registry; remove raw private keys from staging"
  $BASE run --rm --no-deps --entrypoint python web-api -m agent.provision_roles sync-public
  $BASE run --rm --no-deps --entrypoint python web-api -m agent.provision_roles purge-staging

  echo
  echo "[PASS] provisioned. Passphrases: demo/roles/CREDENTIALS.local.txt (owner-only, gitignored)."
  echo "       Next: scripts/roles.sh up"
}

up() {
  [ -f demo/roles/public/registry.json ] || { echo "run 'scripts/roles.sh provision' first" >&2; exit 1; }
  echo "== build images (web-api is profile-gated in the overlay, so build it explicitly)"
  $ROLES build web-api web
  echo "== start ledger + key-release (idempotent) and consoles"
  # shellcheck disable=SC2086
  $ROLES up -d $INFRA $CONSOLES
  for service in ledger-0 ledger-1 ledger-2 ledger-3 keyrelease-0 keyrelease-1                  keyrelease-2 keyrelease-3 keyrelease-4; do
    wait_healthy "$service"
  done
  status
}

down() {
  $ROLES --profile combined --profile officers-extra down --remove-orphans
}

status() {
  $ROLES ps --format 'table {{.Name}}\t{{.Status}}'
  cat <<URLS

Consoles (one browser origin each — open them side by side):
  http://command.localhost:8080     document owner: release + investigate
  http://officer-a.localhost:8080   officer A workstation
  http://officer-b.localhost:8080   officer B workstation
  http://officer-c.localhost:8080   officer C workstation
  http://authority.localhost:8080   enrolment authority
  http://ops.localhost:8080         operations view (read-only)
  http://localhost:8080             console launcher
URLS
}

case "${1:-}" in
  provision) provision ;;
  up) up ;;
  down) down ;;
  status) status ;;
  *) echo "usage: $0 {provision|up|down|status}" >&2; exit 2 ;;
esac
