# syntax=docker/dockerfile:1.7
#
# M2 scope was registration + per-position detection + Tardos accusation
# against a known document, no crypto needed at all. Starting M5,
# `forensics.investigation`/`report_pdf` do real ML-DSA signing/
# verification to build and self-check a signed evidence bundle, so this
# image now needs a real liboqs build too — same pinned-commit approach as
# packages/ca/Dockerfile (see that file's comment and docs/DECISIONS.md
# ADR-0003 for why). It also needs `ledger`/`ca` to reach the live cluster
# and load the registry when building a bundle. `ledger` is installed WITH
# its full dependencies (not --no-deps): `packages/forensics/tests/helpers.py`
# wires a real 4-replica ledger cluster in-process via `ledger.service`'s
# FastAPI apps, the exact same reason `packages/ca/Dockerfile` does the
# same for `ca`'s own test suite.

FROM python:3.12-slim AS liboqs-builder

ARG LIBOQS_COMMIT=5a1a854b0dc9f2141bdc771c555ee60c37950183

RUN apt-get update && apt-get install -y --no-install-recommends \
        git cmake ninja-build build-essential libssl-dev \
    && rm -rf /var/lib/apt/lists/*

RUN git clone https://github.com/open-quantum-safe/liboqs.git /src/liboqs && \
    cd /src/liboqs && \
    git checkout "${LIBOQS_COMMIT}" && \
    actual="$(git rev-parse HEAD)" && \
    if [ "${actual}" != "${LIBOQS_COMMIT}" ]; then \
        echo "liboqs commit pin mismatch: expected ${LIBOQS_COMMIT}, got ${actual}" >&2; \
        exit 1; \
    fi && \
    cmake -GNinja -B build \
        -DCMAKE_INSTALL_PREFIX=/opt/liboqs \
        -DBUILD_SHARED_LIBS=ON \
        -DOQS_BUILD_ONLY_LIB=ON \
        -DCMAKE_BUILD_TYPE=Release \
        . && \
    ninja -C build && \
    ninja -C build install

FROM python:3.12-slim

COPY --from=liboqs-builder /opt/liboqs /opt/liboqs
ENV OQS_INSTALL_PATH=/opt/liboqs
ENV LD_LIBRARY_PATH=/opt/liboqs/lib

WORKDIR /app
COPY packages/tscore/pyproject.toml packages/tscore/pyproject.toml
COPY packages/tscore/src packages/tscore/src
COPY packages/ledger/pyproject.toml packages/ledger/pyproject.toml
COPY packages/ledger/src packages/ledger/src
COPY packages/ca/pyproject.toml packages/ca/pyproject.toml
COPY packages/ca/src packages/ca/src
COPY packages/sender/pyproject.toml packages/sender/pyproject.toml
COPY packages/sender/src packages/sender/src
COPY packages/keyrelease/pyproject.toml packages/keyrelease/pyproject.toml
COPY packages/keyrelease/src packages/keyrelease/src
COPY packages/agent/pyproject.toml packages/agent/pyproject.toml
COPY packages/agent/src packages/agent/src
COPY packages/forensics/pyproject.toml packages/forensics/pyproject.toml
COPY packages/forensics/src packages/forensics/src
COPY packages/forensics/tests packages/forensics/tests

# `agent` is --no-deps: `forensics.demo_m5` only calls `agent.decrypt.open_document`,
# which never touches `agent.keystore` (the only consumer of agent's own
# argon2-cffi dependency), so there's no reason to install it here.
RUN pip install --no-cache-dir "./packages/tscore" && \
    pip install --no-cache-dir "./packages/ledger" && \
    pip install --no-cache-dir --no-deps "./packages/ca" "./packages/keyrelease" "./packages/agent" && \
    pip install --no-cache-dir "./packages/sender" && \
    pip install --no-cache-dir "./packages/forensics[dev]"

CMD ["python", "-m", "pytest", "-q", "packages/forensics/tests"]
