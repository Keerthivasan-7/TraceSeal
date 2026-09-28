.PHONY: up down test test-unit test-egress test-sender test-forensics test-tardos-sim lint demo-m0 demo-m1 demo-m2

COMPOSE := docker compose

## Bring up all containers on the internal-only network.
up:
	$(COMPOSE) up -d --build

down:
	$(COMPOSE) down

## Full fast test set: crypto unit tests, the no-egress proof, sender and
## forensics unit tests. Excludes the slow Tardos Monte-Carlo suite (see
## test-tardos-sim).
test: test-unit test-egress test-sender test-forensics

## packages/tscore's own pytest suite (KEM-DEM, signatures, Shamir, HKDF,
## canonical CBOR, AES-GCM, Tardos — see docs/SPEC.md Section 16). The slow
## Monte-Carlo suite is excluded here; see test-tardos-sim.
test-unit:
	$(COMPOSE) run --rm tscore python -m pytest -q -m "not slow" packages/tscore/tests

## The Tardos Monte-Carlo suite (spec Section 10): empirical innocent-
## accusation rate and coalition-detection rate under all required pirate
## strategies. Slower, so it's separate from test-unit and run explicitly
## by demo-m1.
test-tardos-sim:
	$(COMPOSE) run --rm tscore python -m pytest -q -m slow packages/tscore/tests/test_tardos.py

## Proves the `internal: true` network actually blocks egress
## (docs/SPEC.md Section 17, M0 acceptance criterion).
test-egress:
	$(COMPOSE) run --rm tscore python -m pytest -q tests/integration

## packages/sender's own pytest suite: mark-position selection, variant
## rendering, assembly, and the quality gate.
test-sender:
	$(COMPOSE) run --rm sender python -m pytest -q packages/sender/tests

## packages/forensics's own pytest suite: registration, per-position
## detection, Tardos accusation, and the report's honesty checks.
test-forensics:
	$(COMPOSE) run --rm forensics python -m pytest -q packages/forensics/tests

lint:
	$(COMPOSE) run --rm tscore sh -c "ruff check packages/tscore/src packages/tscore/tests && cd packages/tscore && mypy"
	$(COMPOSE) run --rm sender sh -c "ruff check packages/sender/src packages/sender/tests && cd packages/sender && mypy"
	$(COMPOSE) run --rm forensics sh -c "ruff check packages/forensics/src packages/forensics/tests && cd packages/forensics && mypy"

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

## Milestone M1 acceptance: variant engine + quality gate + Tardos.
## "A 3-page sample PDF produces 5 assembled copies; the quality gate
## passes; the Tardos simulation meets its bounds" (docs/SPEC.md Section 17).
demo-m1:
	@echo "== TraceSeal M1 acceptance =="
	@$(MAKE) test-sender && echo "[PASS] sender unit tests" || (echo "[FAIL] sender unit tests" && exit 1)
	@$(MAKE) test-tardos-sim && echo "[PASS] Tardos Monte-Carlo bounds" || (echo "[FAIL] Tardos Monte-Carlo bounds" && exit 1)
	@$(COMPOSE) run --rm sender python -m sender.demo_m1
	@echo ""
	@echo "M1 complete: variant/watermark engine (micro-shift), quality gate,"
	@echo "Tardos fingerprinting library. Assembled demo copies are under"
	@echo "demo/out/m1/. Not yet implemented: encryption/packaging, ledger,"
	@echo "protocol services, forensics, UI (see docs/SPEC.md Section 17)."

## Milestone M2 acceptance: forensics on clean screenshots.
## "Top-1 attribution across 5 sessions from clean PNG screenshots is
## 100%, with 0 innocent accusations" (docs/SPEC.md Section 17).
demo-m2:
	@echo "== TraceSeal M2 acceptance =="
	@$(MAKE) test-forensics && echo "[PASS] forensics unit tests" || (echo "[FAIL] forensics unit tests" && exit 1)
	@$(COMPOSE) run --rm forensics python -m forensics.demo_m2
	@echo ""
	@echo "M2 complete: ORB/RANSAC + local-refinement registration,"
	@echo "per-position NCC detection, Tardos accusation, honest reporting."
	@echo "Simulated leaked screenshots are under demo/out/m2/. Not yet"
	@echo "implemented: OCR/vault document lookup, photo/scan robustness,"
	@echo "evidence bundle signing, encryption/ledger (see docs/SPEC.md"
	@echo "Section 17)."
