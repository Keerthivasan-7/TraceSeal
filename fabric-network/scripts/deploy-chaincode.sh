#!/usr/bin/env bash
# Packages, installs (on all 4 orgs' peers), approves (all 4 orgs), and
# commits the `traceseal` chaincode on `tschannel` — spec Section 12's Go
# chaincode. Assumes `chaincode/traceseal` already has its `vendor/`
# directory populated (`go mod vendor` — the classic Fabric Docker-based
# chaincode build has no network access, so dependencies must be vendored
# ahead of time). Run inside the `fabric-tools` container, after
# create-channel.sh:
#   docker compose run --rm fabric-tools bash scripts/deploy-chaincode.sh
set -euo pipefail
cd "$(dirname "$0")/.."

CC_NAME=traceseal
CC_VERSION="1.0"
CC_SEQUENCE="1"
CC_SRC=/chaincode/traceseal
PKG=chaincode-artifacts/traceseal.tar.gz
CA_FILE="$(pwd)/crypto-config/cluster-cas/bundle.pem"

mkdir -p chaincode-artifacts

peer_env() {
  local n="$1"
  export FABRIC_CFG_PATH="$(pwd)/peercfg"
  export CORE_PEER_TLS_ENABLED=true
  export CORE_PEER_LOCALMSPID="Org${n}MSP"
  export CORE_PEER_TLS_ROOTCERT_FILE="$(pwd)/crypto-config/peerOrganizations/org${n}.traceseal.local/peers/peer0.org${n}.traceseal.local/tls/ca.crt"
  export CORE_PEER_MSPCONFIGPATH="$(pwd)/crypto-config/peerOrganizations/org${n}.traceseal.local/users/Admin@org${n}.traceseal.local/msp"
  export CORE_PEER_ADDRESS="peer0.org${n}.traceseal.local:7051"
}

echo "== packaging chaincode =="
peer_env 1
peer lifecycle chaincode package "$PKG" \
  --path "$CC_SRC" --lang golang --label "${CC_NAME}_${CC_VERSION}"

PACKAGE_ID=$(peer lifecycle chaincode calculatepackageid "$PKG")
echo "PACKAGE_ID=$PACKAGE_ID"

echo "== installing on all 4 orgs' peers =="
for n in 1 2 3 4; do
  peer_env "$n"
  peer lifecycle chaincode install "$PKG"
  echo "[PASS] installed on org${n}"
done

echo "== approving for all 4 orgs =="
for n in 1 2 3 4; do
  peer_env "$n"
  peer lifecycle chaincode approveformyorg \
    -o orderer.org1.traceseal.local:7050 --tls --cafile "$CA_FILE" \
    --channelID tschannel --name "$CC_NAME" --version "$CC_VERSION" \
    --package-id "$PACKAGE_ID" --sequence "$CC_SEQUENCE"
  echo "[PASS] approved by org${n}"
done

echo "== checking commit readiness =="
peer_env 1
peer lifecycle chaincode checkcommitreadiness \
  --channelID tschannel --name "$CC_NAME" --version "$CC_VERSION" \
  --sequence "$CC_SEQUENCE" --output json

echo "== committing =="
peer lifecycle chaincode commit \
  -o orderer.org1.traceseal.local:7050 --tls --cafile "$CA_FILE" \
  --channelID tschannel --name "$CC_NAME" --version "$CC_VERSION" --sequence "$CC_SEQUENCE" \
  --peerAddresses peer0.org1.traceseal.local:7051 --tlsRootCertFiles "$(pwd)/crypto-config/peerOrganizations/org1.traceseal.local/peers/peer0.org1.traceseal.local/tls/ca.crt" \
  --peerAddresses peer0.org2.traceseal.local:7051 --tlsRootCertFiles "$(pwd)/crypto-config/peerOrganizations/org2.traceseal.local/peers/peer0.org2.traceseal.local/tls/ca.crt" \
  --peerAddresses peer0.org3.traceseal.local:7051 --tlsRootCertFiles "$(pwd)/crypto-config/peerOrganizations/org3.traceseal.local/peers/peer0.org3.traceseal.local/tls/ca.crt" \
  --peerAddresses peer0.org4.traceseal.local:7051 --tlsRootCertFiles "$(pwd)/crypto-config/peerOrganizations/org4.traceseal.local/peers/peer0.org4.traceseal.local/tls/ca.crt"

peer_env 1
peer lifecycle chaincode querycommitted --channelID tschannel --name "$CC_NAME"

echo "[PASS] traceseal chaincode committed on tschannel"
