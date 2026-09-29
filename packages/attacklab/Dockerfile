# syntax=docker/dockerfile:1.7
#
# The attack lab never touches liboqs/PQC (it never imports tscore.kem or
# tscore.sig — only tscore.tardos, which is pure numpy/math) and never
# touches the live protocol stack (no ledger/ca/keyrelease/agent) — it
# renders variant pages and distorts/colludes them entirely in-process via
# sender's rendering functions and forensics's registration/detection/
# accusation pipeline, exactly the same "no live cluster needed" property
# packages/verifier's Dockerfile enforces for a different reason. No
# liboqs-builder stage: tscore's own pyproject.toml still lists
# liboqs-python as a hard dependency (installing tscore always pulls in the
# pure-Python `oqs` wheel), but liboqs-python only tries to load the actual
# C shared library when a Signature/KeyEncapsulation object is
# instantiated — which nothing in this image's code path ever does.

FROM python:3.12-slim

# git: `attacklab.harness.git_commit` shells out to it to stamp
# docs/RESULTS.md's header with a real commit (spec Section 15) — not
# present in python:3.12-slim by default, confirmed directly (a real run
# silently fell back to "unknown" before this was added).
RUN apt-get update && apt-get install -y --no-install-recommends git \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app
COPY packages/tscore/pyproject.toml packages/tscore/pyproject.toml
COPY packages/tscore/src packages/tscore/src
COPY packages/sender/pyproject.toml packages/sender/pyproject.toml
COPY packages/sender/src packages/sender/src
COPY packages/forensics/pyproject.toml packages/forensics/pyproject.toml
COPY packages/forensics/src packages/forensics/src
COPY packages/attacklab/pyproject.toml packages/attacklab/pyproject.toml
COPY packages/attacklab/src packages/attacklab/src
COPY packages/attacklab/tests packages/attacklab/tests

RUN pip install --no-cache-dir "./packages/tscore" && \
    pip install --no-cache-dir --no-deps "./packages/sender" && \
    pip install --no-cache-dir --no-deps "./packages/forensics" && \
    pip install --no-cache-dir "./packages/attacklab[dev]"

CMD ["python", "-m", "pytest", "-q", "packages/attacklab/tests"]
