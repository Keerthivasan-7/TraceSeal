# syntax=docker/dockerfile:1.7
#
# M1 scope only: variant engine + quality gate + the M1 demo script. No
# crypto/liboqs here (that's tscore's own image) — this installs tscore
# itself only for the pure-Python tscore.tardos module the M1 demo needs.

FROM python:3.12-slim

WORKDIR /app
COPY packages/tscore/pyproject.toml packages/tscore/pyproject.toml
COPY packages/tscore/src packages/tscore/src
COPY packages/sender/pyproject.toml packages/sender/pyproject.toml
COPY packages/sender/src packages/sender/src
COPY packages/sender/tests packages/sender/tests
COPY demo/generate_sample_pdf.py demo/generate_sample_pdf.py

# tscore installed without its liboqs-python/cryptography/argon2-cffi/cbor2
# dependencies: sender only ever imports tscore.tardos (pure Python +
# numpy), and pulling in liboqs-python here would mean building liboqs in
# this image too for no benefit. See docs/DECISIONS.md.
RUN pip install --no-cache-dir --no-deps ./packages/tscore && \
    pip install --no-cache-dir "./packages/sender[dev]"

CMD ["python", "-m", "pytest", "-q", "packages/sender/tests"]
