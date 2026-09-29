# syntax=docker/dockerfile:1.7
#
# Standalone verifier — spec Section 4 states three times that this
# package depends on tscore ONLY. Enforced literally here, not just by
# convention: this Dockerfile copies in `packages/tscore` and
# `packages/verifier` and nothing else — no `ledger`, `ca`, `forensics`,
# `sender`, or `keyrelease`. Same liboqs-builder pattern as
# packages/ca/Dockerfile.
#   docker compose run --rm verifier traceseal-verify demo/out/m5/case.tsev

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
COPY packages/verifier/pyproject.toml packages/verifier/pyproject.toml
COPY packages/verifier/src packages/verifier/src
COPY packages/verifier/tests packages/verifier/tests

RUN pip install --no-cache-dir "./packages/tscore" && \
    pip install --no-cache-dir "./packages/verifier[dev]"

CMD ["python", "-m", "pytest", "-q", "packages/verifier/tests"]
