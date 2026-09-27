.PHONY: up down test test-unit test-egress lint demo-m0

COMPOSE := docker compose

## Bring up all containers on the internal-only network (M0: just tscore).
up:
	$(COMPOSE) up -d --build

down:
	$(COMPOSE) down

## Full M0 test set: crypto unit tests + the no-egress proof.
test: test-unit test-egress

## packages/tscore's own pytest suite (KEM-DEM, signatures, Shamir, HKDF,
## canonical CBOR, AES-GCM — see docs/SPEC.md Section 16).
test-unit:
	$(COMPOSE) run --rm tscore python -m pytest -q packages/tscore/tests

## Proves the `internal: true` network actually blocks egress
## (docs/SPEC.md Section 17, M0 acceptance criterion).
test-egress:
	$(COMPOSE) run --rm tscore python -m pytest -q tests/integration

lint:
	$(COMPOSE) run --rm tscore sh -c "ruff check packages/tscore/src packages/tscore/tests && cd packages/tscore && mypy"

## Milestone-scoped acceptance check. There is no UI yet, so this is the
## honest M0 stand-in for the later UI-driven `make demo-m<N>` targets.
demo-m0:
	@echo "== TraceSeal M0 acceptance =="
	@$(MAKE) test-unit && echo "[PASS] crypto unit tests" || (echo "[FAIL] crypto unit tests" && exit 1)
	@$(MAKE) test-egress && echo "[PASS] egress blocked on the internal network" || (echo "[FAIL] egress blocked" && exit 1)
	@echo ""
	@echo "M0 complete: repo skeleton, tscore crypto core, Compose, docs skeleton."
	@echo "Not yet implemented (see docs/SPEC.md Section 17): variant/watermark"
	@echo "engine, Tardos, sender/keyrelease/ledger/agent/forensics/verifier"
	@echo "services, Fabric backend, attack lab, web UI."
