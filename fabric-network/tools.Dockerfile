# syntax=docker/dockerfile:1.7
#
# No published `hyperledger/fabric-tools` image actually contains a
# BFT-aware `configtxgen` — confirmed directly, not assumed: both
# `fabric-tools:2.5.9` (the last reliably-pinned numbered tag) AND
# `fabric-tools:latest` (the only other pullable tag, per Docker Hub)
# panic on "invalid keys: ConsenterMapping, SmartBFT" — `latest` itself
# still resolves to v2.5.16's configtxgen, which predates BFT channel
# config support. See docs/DECISIONS.md ADR-0031.
#
# Fix: build `configtxgen`/`cryptogen`/`osnadmin` from the exact same
# `hyperledger/fabric` source tag as the pinned `fabric-orderer`/
# `fabric-peer` images (v3.1.5), so every tool speaks the identical
# config/wire version. `peer` itself is NOT rebuilt — it's copied
# straight out of the already-pinned, already-published
# `hyperledger/fabric-peer:3.1.5` image, since that one already builds
# the real thing.

FROM golang:1.23-bookworm AS builder

# Fabric v3.1.5's go.mod pins a newer Go than this base image ships;
# GOTOOLCHAIN=auto lets the go command fetch and use exactly the
# toolchain go.mod asks for rather than guessing a base image tag here.
ENV GOTOOLCHAIN=auto

ARG FABRIC_VERSION=v3.1.5

RUN apt-get update && apt-get install -y --no-install-recommends git \
    && rm -rf /var/lib/apt/lists/*

RUN git clone --branch "${FABRIC_VERSION}" --depth 1 \
        https://github.com/hyperledger/fabric.git /src/fabric
WORKDIR /src/fabric
RUN actual="$(git describe --tags --exact-match)" && \
    if [ "${actual}" != "${FABRIC_VERSION}" ]; then \
        echo "fabric tag mismatch: expected ${FABRIC_VERSION}, got ${actual}" >&2; \
        exit 1; \
    fi
RUN go build -o /out/configtxgen ./cmd/configtxgen && \
    go build -o /out/cryptogen ./cmd/cryptogen && \
    go build -o /out/osnadmin ./cmd/osnadmin && \
    go build -o /out/discover ./cmd/discover && \
    go build -o /out/configtxlator ./cmd/configtxlator

FROM hyperledger/fabric-peer:3.1.5 AS peer-binary

# Vendors the chaincode's Go module dependencies HERE, at build time
# (network access allowed, per CLAUDE.md's "build-time downloads only
# inside Dockerfiles" rule) — the classic Fabric Docker-based chaincode
# build (`CORE_VM_ENDPOINT`, ccenv) has no network access at package/
# install time, so a go-modules chaincode must ship its dependencies
# vendored. Baking the vendored copy into this image (rather than a host
# bind mount) means `fabric-tools` never needs a manual
# `go mod vendor` step run by hand before deploy-chaincode.sh.
FROM golang:1.26-bookworm AS chaincode-vendor

ENV GOTOOLCHAIN=local

COPY chaincode/traceseal /chaincode-src
WORKDIR /chaincode-src
RUN go mod vendor

# `peer lifecycle chaincode package` for a golang-modules chaincode shells
# out to `go` itself to normalize/introspect the module — needs a real Go
# toolchain in the runtime image, not just the builder stage above. Pinned
# directly to the exact toolchain chaincode/traceseal/go.mod resolved to
# (1.26.7) and GOTOOLCHAIN=local, deliberately NOT `auto`: this image runs
# on the `internal: true` network with zero runtime egress (CLAUDE.md's
# non-negotiable #2) — confirmed directly, `go`'s own toolchain
# auto-fetch failed exactly as it should on that network. Fetching a
# newer/older toolchain only ever happens here, at build time.
FROM golang:1.26-bookworm

ENV GOTOOLCHAIN=local

# jq: patches channel config JSON for the manual anchor-peer channel-update
# flow (configtxgen's `-outputAnchorPeersUpdate` shortcut no longer exists
# in Fabric 3.x). Installed at build time only, per CLAUDE.md's zero-runtime-
# egress rule.
RUN apt-get update && apt-get install -y --no-install-recommends jq \
    && rm -rf /var/lib/apt/lists/*

COPY --from=builder /out/configtxgen /out/cryptogen /out/osnadmin /out/discover /out/configtxlator /usr/local/bin/
COPY --from=peer-binary /usr/local/bin/peer /usr/local/bin/peer
COPY --from=chaincode-vendor /chaincode-src /chaincode/traceseal

WORKDIR /fabric-network
CMD ["sleep", "infinity"]
