#!/usr/bin/env bash
# Joins all 4 orderers (via each one's own osnadmin channel-participation
# API — Fabric 3.x has no system channel, so there is no genesis-block
# startup step; membership is established per-channel, per-orderer, here)
# and all 4 peers to `tschannel`, using the genesis block `generate.sh`
# already produced. Run inside the `fabric-tools` container, after
# generate.sh and after the orderer/peer containers are up:
#   docker compose run --rm fabric-tools bash scripts/create-channel.sh
set -euo pipefail
cd "$(dirname "$0")/.."

CA_FILE="$(pwd)/crypto-config/cluster-cas/bundle.pem"
BLOCK="$(pwd)/channel-artifacts/tschannel.block"

join_orderer() {
  local n="$1"
  local cert_dir="crypto-config/ordererOrganizations/org${n}.traceseal.local/orderers/orderer.org${n}.traceseal.local/tls"
  osnadmin channel join \
    --channelID tschannel \
    --config-block "$BLOCK" \
    -o "orderer.org${n}.traceseal.local:7053" \
    --ca-file "$CA_FILE" \
    --client-cert "$(pwd)/${cert_dir}/server.crt" \
    --client-key "$(pwd)/${cert_dir}/server.key"
  echo "[PASS] orderer org${n} joined tschannel"
}

join_peer() {
  local n="$1"
  export FABRIC_CFG_PATH="$(pwd)/peercfg"
  export CORE_PEER_TLS_ENABLED=true
  export CORE_PEER_LOCALMSPID="Org${n}MSP"
  export CORE_PEER_TLS_ROOTCERT_FILE="$(pwd)/crypto-config/peerOrganizations/org${n}.traceseal.local/peers/peer0.org${n}.traceseal.local/tls/ca.crt"
  export CORE_PEER_MSPCONFIGPATH="$(pwd)/crypto-config/peerOrganizations/org${n}.traceseal.local/users/Admin@org${n}.traceseal.local/msp"
  export CORE_PEER_ADDRESS="peer0.org${n}.traceseal.local:7051"
  peer channel join -b "$BLOCK"
  echo "[PASS] peer0.org${n} joined tschannel"
}

for n in 1 2 3 4; do join_orderer "$n"; done
for n in 1 2 3 4; do join_peer "$n"; done

echo "[PASS] tschannel is live: 4 BFT orderers + 4 peers all joined"
