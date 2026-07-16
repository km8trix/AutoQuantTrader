SHELL := /bin/bash
.DEFAULT_GOAL := help

UV ?= uv
PNPM ?= pnpm
COMPOSE ?= docker compose -f infra/compose/compose.yaml

.PHONY: help bootstrap dev dev-detached db down logs ps api web worker trader migrate \
	check backend-check frontend-check architecture-check test compose-check \
	api-contracts api-contracts-check admission-evaluate market-data-probe \
	sharadar-sfp-capture tiingo-eod-profile-inspect tiingo-eod-capture

help: ## List developer commands.
	@awk 'BEGIN {FS = ":.*## "; printf "AutoQuantTrader developer commands:\n\n"} /^[a-zA-Z0-9_-]+:.*## / {printf "  %-20s %s\n", $$1, $$2}' $(MAKEFILE_LIST)

bootstrap: ## Install locked Python and browser dependencies.
	$(UV) sync --all-groups --locked
	$(PNPM) --dir apps/web install --frozen-lockfile

dev: ## Run the local stack plus one-shot worker/trader stub diagnostics.
	$(COMPOSE) up --build

dev-detached: ## Run the local stack and stub diagnostics in the background.
	$(COMPOSE) up --build --detach

db: ## Start only local PostgreSQL.
	$(COMPOSE) up --detach postgres

down: ## Stop the local stack without deleting data volumes.
	$(COMPOSE) down

logs: ## Follow logs from the local stack.
	$(COMPOSE) logs --follow

ps: ## Show local service health and status.
	$(COMPOSE) ps

api: ## Run the API on the host with reload enabled.
	$(UV) run uvicorn apps.api.main:app --host 127.0.0.1 --port 8000 --reload

web: ## Run the browser application on the host.
	$(PNPM) --dir apps/web dev --host 127.0.0.1

worker: ## Ingest and evaluate the synthetic Phase 1B point-in-time fixture once.
	$(UV) run autoquant-worker --once

admission-evaluate: ## Evaluate SPECIFICATION and EVIDENCE JSON; succeeds only if admitted.
	$(UV) run python scripts/evaluate_market_data_admission.py --specification "$(SPECIFICATION)" --evidence "$(EVIDENCE)"

market-data-probe: ## Read-only candidate access check; requires DATE=YYYY-MM-DD.
	@test -n "$(DATE)" || (echo "DATE=YYYY-MM-DD is required" >&2; exit 2)
	$(UV) run --no-env-file python scripts/probe_market_data_access.py \
		--env-file .env --date "$(DATE)" --symbol "$(if $(SYMBOL),$(SYMBOL),SPY)"

sharadar-sfp-capture: ## Archive SFP after reviewed storage authorization.
	@test -n "$(START_DATE)" || (echo "START_DATE=YYYY-MM-DD is required" >&2; exit 2)
	@test -n "$(AUTHORIZATION)" || (echo "AUTHORIZATION=path/to/reviewed.json is required" >&2; exit 2)
	$(UV) run --no-env-file python scripts/capture_sharadar_sfp.py --env-file .env \
		--authorization-file "$(AUTHORIZATION)" --start-date "$(START_DATE)" \
		--end-date "$(if $(END_DATE),$(END_DATE),$(START_DATE))"

tiingo-eod-capture: ## Archive Tiingo EOD after reviewed profile and storage authorization.
	@test -n "$(START_DATE)" || (echo "START_DATE=YYYY-MM-DD is required" >&2; exit 2)
	@test -n "$(PROFILE)" || (echo "PROFILE=path/to/reviewed.json is required" >&2; exit 2)
	@test -n "$(AUTHORIZATION)" || (echo "AUTHORIZATION=path/to/reviewed.json is required" >&2; exit 2)
	$(UV) run --no-env-file python scripts/capture_tiingo_eod.py --env-file .env \
		--profile-file "$(PROFILE)" --authorization-file "$(AUTHORIZATION)" \
		--start-date "$(START_DATE)" \
		--end-date "$(if $(END_DATE),$(END_DATE),$(START_DATE))"

tiingo-eod-profile-inspect: ## Validate a Tiingo profile and print its normalized digest.
	@test -n "$(PROFILE)" || (echo "PROFILE=path/to/reviewed.json is required" >&2; exit 2)
	$(UV) run --no-env-file python scripts/inspect_tiingo_eod_profile.py \
		--profile-file "$(PROFILE)"

trader: ## Run the local Phase 0 trader stub diagnostic once.
	$(UV) run autoquant-trader --once

migrate: ## Upgrade the configured database to the latest schema.
	$(UV) run alembic upgrade head

check: backend-check test frontend-check architecture-check api-contracts-check compose-check ## Run all quality checks and tests.

backend-check: ## Check Python formatting, lint, and types.
	$(UV) run ruff format --check .
	$(UV) run ruff check .
	$(UV) run mypy apps packages

frontend-check: ## Check browser lint, types, tests, and production build.
	$(PNPM) --dir apps/web lint
	$(PNPM) --dir apps/web typecheck
	$(PNPM) --dir apps/web test --run
	$(PNPM) --dir apps/web build

architecture-check: ## Enforce dependency direction between packages and apps.
	$(UV) run python scripts/check_architecture.py

api-contracts: ## Regenerate the checked-in OpenAPI document and browser wire types.
	$(UV) run python scripts/generate_api_contracts.py

api-contracts-check: ## Fail if the checked-in API contract artifacts are stale.
	$(UV) run python scripts/generate_api_contracts.py --check

test: ## Run backend tests.
	$(UV) run pytest

compose-check: ## Validate the Docker Compose model without starting services.
	$(COMPOSE) config --quiet
