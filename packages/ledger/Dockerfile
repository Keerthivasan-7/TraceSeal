# syntax=docker/dockerfile:1.7
#
# LedgerLite replica (spec Section 12). Same liboqs-builder pattern as
# packages/tscore/Dockerfile — see that file's docstring and
# docs/DECISIONS.md ADR-0003 for the pinned commit and CVE-avoidance
# rationale. `REPLICA_INDEX` (0..3) selects this container's identity,
# keypair, and SQLite file at runtime (see `ledger.main`).

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
COPY packages/ca/pyproject.toml packages/ca/pyproject.toml
COPY packages/ca/src packages/ca/src
COPY packages/ledger/pyproject.toml packages/ledger/pyproject.toml
COPY packages/ledger/src packages/ledger/src
COPY packages/ledger/tests packages/ledger/tests

RUN pip install --no-cache-dir "./packages/tscore" && \
    pip install --no-cache-dir --no-deps "./packages/ca" && \
    pip install --no-cache-dir "./packages/ledger[dev]"

EXPOSE 8000
CMD ["python", "-m", "ledger.main"]
