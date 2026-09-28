# syntax=docker/dockerfile:1.7
#
# Offline root CA (M3 scope: seed script only, no live service — see
# docs/DECISIONS.md ADR-0011). Same liboqs-builder pattern as
# packages/tscore/Dockerfile. Run once per demo/e2e cycle:
#   docker compose run --rm ca python -m ca.seed /pki
# writing every identity + the shared public registry to the `pki` volume
# that ledger/keyrelease/sender/agent all mount read-only (sender/agent
# also need their own identity's private key, so they mount it read-write
# in practice — see docker-compose.yml).

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
COPY packages/ca/tests packages/ca/tests

RUN pip install --no-cache-dir "./packages/tscore" && \
    pip install --no-cache-dir "./packages/ca[dev]"

CMD ["python", "-m", "ca.seed", "/pki"]
