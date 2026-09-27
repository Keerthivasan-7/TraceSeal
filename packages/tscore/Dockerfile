# syntax=docker/dockerfile:1.7
#
# Builds liboqs from a pinned upstream commit (verified against the exact
# SHA below, not just a mutable tag), installs it system-wide, then installs
# tscore against that build via OQS_INSTALL_PATH so liboqs-python's own
# automatic-clone-and-build code path (CVE-affected pre-0.16.0.1, see
# docs/DECISIONS.md ADR-0003) never runs.
#
# Version pins (docs/DECISIONS.md ADR-0003):
#   liboqs        tag 0.16.0    commit 5a1a854b0dc9f2141bdc771c555ee60c37950183
#   liboqs-python tag 0.16.0.1  (pinned exactly in pyproject.toml)

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
COPY packages/tscore/tests packages/tscore/tests
COPY tests/integration tests/integration

RUN pip install --no-cache-dir "./packages/tscore[dev]"

# Default: tscore's own unit tests. The M0 no-egress proof is run separately
# via `docker compose run --rm tscore python -m pytest -q tests/integration`
# (see Makefile), since it deliberately targets the network, not the code.
CMD ["python", "-m", "pytest", "-q", "packages/tscore/tests"]
