#!/usr/bin/env bash
# One-time post-create-channel step: without anchor peers, each org's peer
# gossip stays island-bound and the Fabric Gateway's discovery service can't
# build any cross-org endorsement layout for the OutOf(3, ...) policy
# (confirmed by a real M6 e2e failure: "no combination of peers can be
# derived which satisfy the endorsement policy"). Fabric 3.x's configtxgen
# dropped `-outputAnchorPeersUpdate` (a system-channel-era shortcut), so
# this does the modern manual channel-config-update dance instead: fetch
# the current config, patch in AnchorPeers with jq, compute the delta with
# configtxlator, wrap it in a signed envelope, submit. Run inside the
# `fabric-tools` container, after create-channel.sh:
#   docker compose run --rm fabric-tools bash scripts/set-anchor-peers.sh
set -euo pipefail
cd "$(dirname "$0")/.."

CA_FILE="$(pwd)/crypto-config/cluster-cas/bundle.pem"
ORDERER_ADDR="orderer.org1.traceseal.local:7050"
WORKDIR="channel-artifacts/anchors"
mkdir -p "$WORKDIR"

peer_env() {
  local n="$1"
  export FABRIC_CFG_PATH="$(pwd)/peercfg"
  export CORE_PEER_TLS_ENABLED=true
  export CORE_PEER_LOCALMSPID="Org${n}MSP"
  export CORE_PEER_TLS_ROOTCERT_FILE="$(pwd)/crypto-config/peerOrganizations/org${n}.traceseal.local/peers/peer0.org${n}.traceseal.local/tls/ca.crt"
  export CORE_PEER_MSPCONFIGPATH="$(pwd)/crypto-config/peerOrganizations/org${n}.traceseal.local/users/Admin@org${n}.traceseal.local/msp"
  export CORE_PEER_ADDRESS="peer0.org${n}.traceseal.local:7051"
}

set_anchor_peer() {
  local n="$1"
  local msp="Org${n}MSP"
  local host="peer0.org${n}.traceseal.local"
  local port=7051
  local d="${WORKDIR}/org${n}"
  mkdir -p "$d"

  peer_env "$n"

  peer channel fetch config "${d}/config_block.pb" \
    -o "$ORDERER_ADDR" --tls --cafile "$CA_FILE" -c tschannel

  configtxlator proto_decode --input "${d}/config_block.pb" --type common.Block \
    | jq .data.data[0].payload.data.config > "${d}/config.json"

  jq --arg host "$host" --argjson port "$port" \
    '.channel_group.groups.Application.groups.'"$msp"'.values.AnchorPeers = {
        "mod_policy": "Admins",
        "value": {"anchor_peers": [{"host": $host, "port": $port}]},
        "version": "0"
      }' "${d}/config.json" > "${d}/modified_config.json"

  configtxlator proto_encode --input "${d}/config.json" --type common.Config --output "${d}/config.pb"
  configtxlator proto_encode --input "${d}/modified_config.json" --type common.Config --output "${d}/modified_config.pb"
  configtxlator compute_update --channel_id tschannel \
    --original "${d}/config.pb" --updated "${d}/modified_config.pb" --output "${d}/config_update.pb"

  configtxlator proto_decode --input "${d}/config_update.pb" --type common.ConfigUpdate \
    | jq . > "${d}/config_update.json"

  jq -n --slurpfile update "${d}/config_update.json" \
    '{"payload":{"header":{"channel_header":{"channel_id":"tschannel","type":2}},"data":{"config_update":$update[0]}}}' \
    > "${d}/config_update_in_envelope.json"

  configtxlator proto_encode --input "${d}/config_update_in_envelope.json" --type common.Envelope \
    --output "${d}/config_update_in_envelope.pb"

  peer channel update -f "${d}/config_update_in_envelope.pb" -c tschannel \
    -o "$ORDERER_ADDR" --tls --cafile "$CA_FILE"

  echo "[PASS] org${n} anchor peer set: ${host}:${port}"
}

for n in 1 2 3 4; do set_anchor_peer "$n"; done

echo "[PASS] anchor peers set for all 4 orgs"
