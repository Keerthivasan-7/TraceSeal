#!/usr/bin/env bash
# Generates crypto material (cryptogen) for the 4-org Fabric network, builds
# the combined ordering-service TLS root CA bundle every orderer needs to
# validate the OTHER 3 orderers' BFT cluster connections (see
# docs/DECISIONS.md ADR-0031 — each org has its own orderer CA here, unlike
# the single-shared-OrdererOrg reference samples, so this bundle step has
# no upstream precedent to copy), and produces the channel genesis block
# via configtxgen. Run inside the `fabric-tools` container:
#   docker compose run --rm fabric-tools bash scripts/generate.sh
set -euo pipefail
cd "$(dirname "$0")/.."

rm -rf crypto-config channel-artifacts
cryptogen generate --config=crypto-config.yaml --output=crypto-config

mkdir -p crypto-config/cluster-cas
cat \
  crypto-config/ordererOrganizations/org1.traceseal.local/msp/tlscacerts/*.pem \
  crypto-config/ordererOrganizations/org2.traceseal.local/msp/tlscacerts/*.pem \
  crypto-config/ordererOrganizations/org3.traceseal.local/msp/tlscacerts/*.pem \
  crypto-config/ordererOrganizations/org4.traceseal.local/msp/tlscacerts/*.pem \
  > crypto-config/cluster-cas/bundle.pem

mkdir -p channel-artifacts
export FABRIC_CFG_PATH="$(pwd)"
configtxgen -profile TraceSealChannel -outputBlock ./channel-artifacts/tschannel.block -channelID tschannel

echo "[PASS] crypto material generated, cluster CA bundle built, tschannel.block written"
