# syntax=docker/dockerfile:1.7
#
# The M8 UI bridge (spec Section 14/17): one lightweight FastAPI service
# that calls ca.enrolment/sender.distribute/forensics.investigation/
# agent.decrypt directly (all of which do real ML-DSA/ML-KEM operations),
# and proxies to ledger's/keyrelease's own already-real HTTP services for
# live state — never a reimplementation of protocol code (docs/DECISIONS.md
# ADR: web-api bridge pattern). Same liboqs-builder pattern as
# packages/forensics/Dockerfile. Needs `attacklab` too (Attack Lab screen's
# results reader and "quick run" trigger), installed --no-deps since its
# own numpy/opencv/Pillow/pymupdf pins are already satisfied transitively
# by sender/forensics here.

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
COPY packages/keyrelease/pyproject.toml packages/keyrelease/pyproject.toml
COPY packages/keyrelease/src packages/keyrelease/src
COPY packages/sender/pyproject.toml packages/sender/pyproject.toml
COPY packages/sender/src packages/sender/src
COPY packages/forensics/pyproject.toml packages/forensics/pyproject.toml
COPY packages/forensics/src packages/forensics/src
COPY packages/agent/pyproject.toml packages/agent/pyproject.toml
COPY packages/agent/src packages/agent/src
COPY packages/attacklab/pyproject.toml packages/attacklab/pyproject.toml
COPY packages/attacklab/src packages/attacklab/src
COPY packages/web-api/pyproject.toml packages/web-api/pyproject.toml
COPY packages/web-api/src packages/web-api/src
COPY packages/web-api/tests packages/web-api/tests

RUN pip install --no-cache-dir "./packages/tscore" && \
    pip install --no-cache-dir --no-deps "./packages/ca" && \
    pip install --no-cache-dir "./packages/ledger" "./packages/keyrelease" && \
    pip install --no-cache-dir --no-deps "./packages/sender" "./packages/forensics" "./packages/agent" "./packages/attacklab" && \
    pip install --no-cache-dir "./packages/web-api[dev]"

EXPOSE 8000
CMD ["python", "-m", "web_api.main"]
