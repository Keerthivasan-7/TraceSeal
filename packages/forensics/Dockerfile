# syntax=docker/dockerfile:1.7
#
# M2 scope only: registration + per-position detection + Tardos accusation
# against a known document. No crypto/liboqs here — tscore is installed
# without its crypto extras (only tscore.tardos, pure Python + numpy, is
# used); sender is installed with its full dependencies since forensics'
# demo/tests reuse sender's actual document-building pipeline
# (sample_doc/positions/variants/assemble), not just its data types.

FROM python:3.12-slim

WORKDIR /app
COPY packages/tscore/pyproject.toml packages/tscore/pyproject.toml
COPY packages/tscore/src packages/tscore/src
COPY packages/sender/pyproject.toml packages/sender/pyproject.toml
COPY packages/sender/src packages/sender/src
COPY packages/forensics/pyproject.toml packages/forensics/pyproject.toml
COPY packages/forensics/src packages/forensics/src
COPY packages/forensics/tests packages/forensics/tests

RUN pip install --no-cache-dir --no-deps ./packages/tscore && \
    pip install --no-cache-dir ./packages/sender && \
    pip install --no-cache-dir "./packages/forensics[dev]"

CMD ["python", "-m", "pytest", "-q", "packages/forensics/tests"]
