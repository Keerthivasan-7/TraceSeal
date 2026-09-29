# syntax=docker/dockerfile:1.7
#
# fabric-gateway: a thin REST facade over the real `hyperledger/fabric-
# gateway` Go SDK (no official Python SDK exists) — NOT a Fabric node
# itself. See main.go's docstring.

FROM golang:1.26-bookworm AS builder

ENV GOTOOLCHAIN=auto

WORKDIR /src
COPY packages/fabric-gateway/go.mod packages/fabric-gateway/go.sum ./
COPY packages/fabric-gateway/main.go ./
RUN go mod tidy && go build -o /out/fabric-gateway .

FROM debian:bookworm-slim

RUN apt-get update && apt-get install -y --no-install-recommends ca-certificates \
    && rm -rf /var/lib/apt/lists/*

COPY --from=builder /out/fabric-gateway /usr/local/bin/fabric-gateway

CMD ["fabric-gateway"]
