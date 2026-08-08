SHELL := /bin/bash
.DEFAULT_GOAL := help

UV ?= uv
PNPM ?= pnpm
COMPOSE ?= docker compose -f infra/compose/compose.yaml
override TRUSTED_TIME_PYTHON := $(UV) run --isolated --offline --locked --no-env-file \
	python -I -B -X pycache_prefix=/dev/null
TRUSTED_TIME_IMAGE_ADMISSION_ARTIFACT ?= $(CURDIR)/artifacts/trusted-time/image-admission.json
TRUSTED_TIME_QUALIFICATION_ARTIFACT_DIR ?= $(CURDIR)/artifacts/trusted-time
TRUSTED_TIME_UNENROLLED_ADMISSION_ARTIFACT_DIR ?= $(CURDIR)/artifacts/trusted-time

.PHONY: help bootstrap dev dev-detached db down logs ps api web worker trader migrate \
	check backend-check frontend-check architecture-check test compose-check \
	api-contracts api-contracts-check admission-evaluate market-data-probe \
	sharadar-sfp-capture tiingo-eod-profile-inspect tiingo-eod-capture tiingo-eod-verify \
	tiingo-eod-lineage tiingo-eod-fields-qualify tiingo-eod-identity-qualify \
	tiingo-eod-semantics-qualify no-exposure-smoke-verify trusted-time-compose-check \
	trusted-time-images trusted-time-readmit-images trusted-time-start trusted-time-admit-unenrolled \
	trusted-time-enroll-first trusted-time-recover-first-enrollment \
	trusted-time-runtime-diagnostic trusted-time-inspect trusted-time-stop

help: ## List developer commands.
	@awk 'BEGIN {FS = ":.*## "; printf "AutoQuantTrader developer commands:\n\n"} /^[a-zA-Z0-9_-]+:.*## / {printf "  %-20s %s\n", $$1, $$2}' $(MAKEFILE_LIST)

bootstrap: ## Install locked Python and browser dependencies.
	$(UV) sync --all-groups --locked
	$(PNPM) --dir apps/web install --frozen-lockfile

dev: ## Run the local stack, continuous fixture worker, and trader diagnostic.
	$(COMPOSE) up --build

dev-detached: ## Run the local stack, fixture worker, and trader diagnostic in the background.
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

worker: ## Ingest the Phase 1 fixture and process at most one Phase 2 backtest.
	$(UV) run autoquant-worker --once

no-exposure-smoke-verify: ## Verify the checked-in no-exposure strategy bytes and manifest.
	$(UV) run --offline --frozen --no-sync --no-env-file python -B \
		scripts/verify_no_exposure_smoke_strategy.py

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

tiingo-eod-capture: ## Archive Tiingo EOD after reviewed profile, rights, and calendar approval.
	@test -n "$(START_DATE)" || (echo "START_DATE=YYYY-MM-DD is required" >&2; exit 2)
	@test -n "$(PROFILE)" || (echo "PROFILE=path/to/reviewed.json is required" >&2; exit 2)
	@test -n "$(AUTHORIZATION)" || (echo "AUTHORIZATION=path/to/reviewed.json is required" >&2; exit 2)
	@test -n "$(CALENDAR)" || (echo "CALENDAR=path/to/reviewed.json is required" >&2; exit 2)
	$(UV) run --no-env-file python scripts/capture_tiingo_eod.py --env-file .env \
		--profile-file "$(PROFILE)" --authorization-file "$(AUTHORIZATION)" \
		--calendar-file "$(CALENDAR)" $(foreach symbol,$(SYMBOLS),--symbol "$(symbol)") \
		--start-date "$(START_DATE)" \
		--end-date "$(if $(END_DATE),$(END_DATE),$(START_DATE))"

tiingo-eod-verify: ## Verify one final Tiingo EOD capture entirely offline.
	@test -n "$(CAPTURE)" || (echo "CAPTURE=final-capture-name is required" >&2; exit 2)
	@test -n "$(PROFILE)" || (echo "PROFILE=path/to/reviewed.json is required" >&2; exit 2)
	@test -n "$(AUTHORIZATION)" || (echo "AUTHORIZATION=path/to/reviewed.json is required" >&2; exit 2)
	@test -n "$(CALENDAR)" || (echo "CALENDAR=path/to/reviewed.json is required" >&2; exit 2)
	$(UV) run --offline --frozen --no-sync --no-env-file python -B \
		scripts/verify_tiingo_eod_capture.py \
		--capture-name "$(CAPTURE)" --profile-file "$(PROFILE)" \
		--authorization-file "$(AUTHORIZATION)" --calendar-file "$(CALENDAR)"

tiingo-eod-identity-qualify: ## Prove identity/lifecycle contract consistency offline.
	@test -n "$(CAPTURE)" || (echo "CAPTURE=final-capture-name is required" >&2; exit 2)
	@test -n "$(PROFILE)" || (echo "PROFILE=path/to/reviewed.json is required" >&2; exit 2)
	@test -n "$(AUTHORIZATION)" || (echo "AUTHORIZATION=path/to/reviewed.json is required" >&2; exit 2)
	@test -n "$(CALENDAR)" || (echo "CALENDAR=path/to/reviewed.json is required" >&2; exit 2)
	@test -n "$(IDENTITY_LIFECYCLE)" || (echo "IDENTITY_LIFECYCLE=path/to/artifact.json is required" >&2; exit 2)
	$(UV) run --offline --frozen --no-sync --no-env-file python -B \
		scripts/qualify_tiingo_eod_identity_lifecycle.py \
		--capture-name "$(CAPTURE)" --profile-file "$(PROFILE)" \
		--authorization-file "$(AUTHORIZATION)" --calendar-file "$(CALENDAR)" \
		--identity-lifecycle-file "$(IDENTITY_LIFECYCLE)"

tiingo-eod-semantics-qualify: ## Prove market-semantics/action-candidate consistency offline.
	@test -n "$(CAPTURE)" || (echo "CAPTURE=final-capture-name is required" >&2; exit 2)
	@test -n "$(PROFILE)" || (echo "PROFILE=path/to/reviewed.json is required" >&2; exit 2)
	@test -n "$(AUTHORIZATION)" || (echo "AUTHORIZATION=path/to/reviewed.json is required" >&2; exit 2)
	@test -n "$(CALENDAR)" || (echo "CALENDAR=path/to/reviewed.json is required" >&2; exit 2)
	@test -n "$(IDENTITY_LIFECYCLE)" || (echo "IDENTITY_LIFECYCLE=path/to/artifact.json is required" >&2; exit 2)
	@test -n "$(MARKET_SEMANTICS)" || (echo "MARKET_SEMANTICS=path/to/artifact.json is required" >&2; exit 2)
	$(UV) run --offline --frozen --no-sync --no-env-file python -B \
		scripts/qualify_tiingo_eod_market_semantics.py \
		--capture-name "$(CAPTURE)" --profile-file "$(PROFILE)" \
		--authorization-file "$(AUTHORIZATION)" --calendar-file "$(CALENDAR)" \
		--identity-lifecycle-file "$(IDENTITY_LIFECYCLE)" \
		--market-semantics-file "$(MARKET_SEMANTICS)"

tiingo-eod-lineage: ## Derive research-only local lineage from two or more final captures.
	@test -n "$(CAPTURES)" || (echo "CAPTURES='capture-name ...' is required" >&2; exit 2)
	@test -n "$(PROFILE)" || (echo "PROFILE=path/to/reviewed.json is required" >&2; exit 2)
	@test -n "$(AUTHORIZATION)" || (echo "AUTHORIZATION=path/to/reviewed.json is required" >&2; exit 2)
	@test -n "$(CALENDAR)" || (echo "CALENDAR=path/to/reviewed.json is required" >&2; exit 2)
	$(UV) run --offline --frozen --no-sync --no-env-file python -B \
		scripts/derive_tiingo_eod_lineage.py \
		$(foreach capture,$(CAPTURES),--capture-name "$(capture)") \
		--profile-file "$(PROFILE)" --authorization-file "$(AUTHORIZATION)" \
		--calendar-file "$(CALENDAR)"

tiingo-eod-fields-qualify: ## Prove value-free field routing for one verified Tiingo capture.
	@test -n "$(CAPTURE)" || (echo "CAPTURE=final-capture-name is required" >&2; exit 2)
	@test -n "$(PROFILE)" || (echo "PROFILE=path/to/reviewed.json is required" >&2; exit 2)
	@test -n "$(AUTHORIZATION)" || (echo "AUTHORIZATION=path/to/reviewed.json is required" >&2; exit 2)
	@test -n "$(CALENDAR)" || (echo "CALENDAR=path/to/reviewed.json is required" >&2; exit 2)
	$(UV) run --offline --frozen --no-sync --no-env-file python -B \
		scripts/qualify_tiingo_eod_retained_fields.py \
		--capture-name "$(CAPTURE)" --profile-file "$(PROFILE)" \
		--authorization-file "$(AUTHORIZATION)" --calendar-file "$(CALENDAR)"

tiingo-eod-profile-inspect: ## Validate a Tiingo profile and print its normalized digest.
	@test -n "$(PROFILE)" || (echo "PROFILE=path/to/reviewed.json is required" >&2; exit 2)
	$(UV) run --offline --frozen --no-sync --no-env-file python -B \
		scripts/inspect_tiingo_eod_profile.py \
		--profile-file "$(PROFILE)"

trader: ## Verify the paper smoke profile and report fail-closed readiness once.
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
	$(PNPM) --dir apps/web bundle:test
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
	$(TRUSTED_TIME_PYTHON) \
		scripts/verify_trusted_time_compose.py

trusted-time-compose-check: ## Verify the isolated evidence-only Compose contract.
	$(TRUSTED_TIME_PYTHON) \
		scripts/verify_trusted_time_compose.py

trusted-time-images: ## Build and admit the local Chrony/source supervisor images.
	$(TRUSTED_TIME_PYTHON) \
		scripts/verify_trusted_time_images.py --build \
		--artifact "$(TRUSTED_TIME_IMAGE_ADMISSION_ARTIFACT)"

trusted-time-readmit-images: ## Freshly admit an exact existing immutable image pair without rebuilding.
	@test -n "$(TRUSTED_TIME_EXISTING_SOURCE_IMAGE_ID)" || (echo "TRUSTED_TIME_EXISTING_SOURCE_IMAGE_ID is required" >&2; exit 2)
	@test -n "$(TRUSTED_TIME_EXISTING_SUPERVISOR_IMAGE_ID)" || (echo "TRUSTED_TIME_EXISTING_SUPERVISOR_IMAGE_ID is required" >&2; exit 2)
	$(TRUSTED_TIME_PYTHON) \
		scripts/verify_trusted_time_images.py --admit-existing \
		--artifact "$(TRUSTED_TIME_IMAGE_ADMISSION_ARTIFACT)" \
		"$(TRUSTED_TIME_EXISTING_SOURCE_IMAGE_ID)" \
		"$(TRUSTED_TIME_EXISTING_SUPERVISOR_IMAGE_ID)"

trusted-time-start: ## Start approved trusted-time images with an exact-four launch env.
	@test -n "$(TRUSTED_TIME_LAUNCH_ENV_FILE)" || (echo "TRUSTED_TIME_LAUNCH_ENV_FILE=path/to/dedicated-owner-only.env is required" >&2; exit 2)
	@test -n "$(TRUSTED_TIME_APPROVED_GIT_REVISION)" || (echo "TRUSTED_TIME_APPROVED_GIT_REVISION is required" >&2; exit 2)
	@test -n "$(TRUSTED_TIME_APPROVED_IMAGE_ADMISSION_SHA256)" || (echo "TRUSTED_TIME_APPROVED_IMAGE_ADMISSION_SHA256 is required" >&2; exit 2)
	@test -n "$(TRUSTED_TIME_APPROVED_SOURCE_IMAGE_ID)" || (echo "TRUSTED_TIME_APPROVED_SOURCE_IMAGE_ID is required" >&2; exit 2)
	@test -n "$(TRUSTED_TIME_APPROVED_SUPERVISOR_IMAGE_ID)" || (echo "TRUSTED_TIME_APPROVED_SUPERVISOR_IMAGE_ID is required" >&2; exit 2)
	$(TRUSTED_TIME_PYTHON) \
		scripts/start_trusted_time_supervisor.py \
		--env-file "$(TRUSTED_TIME_LAUNCH_ENV_FILE)" \
		--image-admission-artifact "$(TRUSTED_TIME_IMAGE_ADMISSION_ARTIFACT)" \
		--approved-git-revision "$(TRUSTED_TIME_APPROVED_GIT_REVISION)" \
		--approved-image-admission-sha256 "$(TRUSTED_TIME_APPROVED_IMAGE_ADMISSION_SHA256)" \
		--approved-source-image-id "$(TRUSTED_TIME_APPROVED_SOURCE_IMAGE_ID)" \
		--approved-supervisor-image-id "$(TRUSTED_TIME_APPROVED_SUPERVISOR_IMAGE_ID)"

trusted-time-admit-unenrolled: ## Observe an approved fail-closed startup expectation, then tear down.
	@test -n "$(TRUSTED_TIME_LAUNCH_ENV_FILE)" || (echo "TRUSTED_TIME_LAUNCH_ENV_FILE=path/to/dedicated-owner-only.env is required" >&2; exit 2)
	@test -n "$(TRUSTED_TIME_APPROVED_GIT_REVISION)" || (echo "TRUSTED_TIME_APPROVED_GIT_REVISION is required" >&2; exit 2)
	@test -n "$(TRUSTED_TIME_APPROVED_IMAGE_ADMISSION_SHA256)" || (echo "TRUSTED_TIME_APPROVED_IMAGE_ADMISSION_SHA256 is required" >&2; exit 2)
	@test -n "$(TRUSTED_TIME_APPROVED_SOURCE_IMAGE_ID)" || (echo "TRUSTED_TIME_APPROVED_SOURCE_IMAGE_ID is required" >&2; exit 2)
	@test -n "$(TRUSTED_TIME_APPROVED_SUPERVISOR_IMAGE_ID)" || (echo "TRUSTED_TIME_APPROVED_SUPERVISOR_IMAGE_ID is required" >&2; exit 2)
	$(TRUSTED_TIME_PYTHON) \
		scripts/start_trusted_time_supervisor.py \
		--env-file "$(TRUSTED_TIME_LAUNCH_ENV_FILE)" \
		--image-admission-artifact "$(TRUSTED_TIME_IMAGE_ADMISSION_ARTIFACT)" \
		--artifact-dir "$(TRUSTED_TIME_UNENROLLED_ADMISSION_ARTIFACT_DIR)" \
		--approved-git-revision "$(TRUSTED_TIME_APPROVED_GIT_REVISION)" \
		--approved-image-admission-sha256 "$(TRUSTED_TIME_APPROVED_IMAGE_ADMISSION_SHA256)" \
		--approved-source-image-id "$(TRUSTED_TIME_APPROVED_SOURCE_IMAGE_ID)" \
		--approved-supervisor-image-id "$(TRUSTED_TIME_APPROVED_SUPERVISOR_IMAGE_ID)" \
		--expect-unenrolled-fail-closed

trusted-time-enroll-first: ## Consume one exact approval for a fresh sequence-one enrollment.
	@test -n "$(TRUSTED_TIME_LAUNCH_ENV_FILE)" || (echo "TRUSTED_TIME_LAUNCH_ENV_FILE=path/to/dedicated-owner-only.env is required" >&2; exit 2)
	@test -n "$(TRUSTED_TIME_FIRST_ENROLLMENT_OPERATION_ID)" || (echo "TRUSTED_TIME_FIRST_ENROLLMENT_OPERATION_ID is required" >&2; exit 2)
	@test -n "$(TRUSTED_TIME_APPROVED_GIT_REVISION)" || (echo "TRUSTED_TIME_APPROVED_GIT_REVISION is required" >&2; exit 2)
	@test -n "$(TRUSTED_TIME_APPROVED_IMAGE_ADMISSION_SHA256)" || (echo "TRUSTED_TIME_APPROVED_IMAGE_ADMISSION_SHA256 is required" >&2; exit 2)
	@test -n "$(TRUSTED_TIME_APPROVED_SOURCE_IMAGE_ID)" || (echo "TRUSTED_TIME_APPROVED_SOURCE_IMAGE_ID is required" >&2; exit 2)
	@test -n "$(TRUSTED_TIME_APPROVED_SUPERVISOR_IMAGE_ID)" || (echo "TRUSTED_TIME_APPROVED_SUPERVISOR_IMAGE_ID is required" >&2; exit 2)
	@test -n "$(TRUSTED_TIME_APPROVED_UNENROLLED_ADMISSION_SHA256)" || (echo "TRUSTED_TIME_APPROVED_UNENROLLED_ADMISSION_SHA256 is required" >&2; exit 2)
	@test -n "$(TRUSTED_TIME_APPROVED_ANCHOR_AUTHORITY_SHA256)" || (echo "TRUSTED_TIME_APPROVED_ANCHOR_AUTHORITY_SHA256 is required" >&2; exit 2)
	@test -n "$(TRUSTED_TIME_APPROVED_DEPLOYMENT_IDENTITY_SHA256)" || (echo "TRUSTED_TIME_APPROVED_DEPLOYMENT_IDENTITY_SHA256 is required" >&2; exit 2)
	@test -n "$(TRUSTED_TIME_APPROVED_RUNTIME_DATABASE_IDENTITY_SHA256)" || (echo "TRUSTED_TIME_APPROVED_RUNTIME_DATABASE_IDENTITY_SHA256 is required" >&2; exit 2)
	@test -n "$(TRUSTED_TIME_APPROVED_ANCHOR_PROJECT_IDENTITY_SHA256)" || (echo "TRUSTED_TIME_APPROVED_ANCHOR_PROJECT_IDENTITY_SHA256 is required" >&2; exit 2)
	@test -n "$(TRUSTED_TIME_APPROVED_SOURCE_AUTHORITY_SHA256)" || (echo "TRUSTED_TIME_APPROVED_SOURCE_AUTHORITY_SHA256 is required" >&2; exit 2)
	@test -n "$(TRUSTED_TIME_APPROVED_SIGNING_PUBLIC_KEY_SHA256)" || (echo "TRUSTED_TIME_APPROVED_SIGNING_PUBLIC_KEY_SHA256 is required" >&2; exit 2)
	@test -n "$(TRUSTED_TIME_APPROVED_HOST_IDENTITY_SHA256)" || (echo "TRUSTED_TIME_APPROVED_HOST_IDENTITY_SHA256 is required" >&2; exit 2)
	@test -n "$(TRUSTED_TIME_APPROVED_PRINCIPAL_IDENTITY_SHA256)" || (echo "TRUSTED_TIME_APPROVED_PRINCIPAL_IDENTITY_SHA256 is required" >&2; exit 2)
	@test -n "$(TRUSTED_TIME_APPROVED_BUCKET_IDENTITY_SHA256)" || (echo "TRUSTED_TIME_APPROVED_BUCKET_IDENTITY_SHA256 is required" >&2; exit 2)
	$(TRUSTED_TIME_PYTHON) \
		scripts/enroll_trusted_time_head_anchor.py \
		--env-file "$(TRUSTED_TIME_LAUNCH_ENV_FILE)" \
		--image-admission-artifact "$(TRUSTED_TIME_IMAGE_ADMISSION_ARTIFACT)" \
		--artifact-dir "$(TRUSTED_TIME_UNENROLLED_ADMISSION_ARTIFACT_DIR)" \
		--operation-id "$(TRUSTED_TIME_FIRST_ENROLLMENT_OPERATION_ID)" \
		--approved-git-revision "$(TRUSTED_TIME_APPROVED_GIT_REVISION)" \
		--approved-image-admission-sha256 "$(TRUSTED_TIME_APPROVED_IMAGE_ADMISSION_SHA256)" \
		--approved-source-image-id "$(TRUSTED_TIME_APPROVED_SOURCE_IMAGE_ID)" \
		--approved-supervisor-image-id "$(TRUSTED_TIME_APPROVED_SUPERVISOR_IMAGE_ID)" \
		--unenrolled-admission-sha256 "$(TRUSTED_TIME_APPROVED_UNENROLLED_ADMISSION_SHA256)" \
		--anchor-authority-sha256 "$(TRUSTED_TIME_APPROVED_ANCHOR_AUTHORITY_SHA256)" \
		--deployment-identity-sha256 "$(TRUSTED_TIME_APPROVED_DEPLOYMENT_IDENTITY_SHA256)" \
		--runtime-database-identity-sha256 "$(TRUSTED_TIME_APPROVED_RUNTIME_DATABASE_IDENTITY_SHA256)" \
		--anchor-project-identity-sha256 "$(TRUSTED_TIME_APPROVED_ANCHOR_PROJECT_IDENTITY_SHA256)" \
		--source-authority-sha256 "$(TRUSTED_TIME_APPROVED_SOURCE_AUTHORITY_SHA256)" \
		--signing-public-key-sha256 "$(TRUSTED_TIME_APPROVED_SIGNING_PUBLIC_KEY_SHA256)" \
		--host-identity-sha256 "$(TRUSTED_TIME_APPROVED_HOST_IDENTITY_SHA256)" \
		--principal-identity-sha256 "$(TRUSTED_TIME_APPROVED_PRINCIPAL_IDENTITY_SHA256)" \
		--bucket-identity-sha256 "$(TRUSTED_TIME_APPROVED_BUCKET_IDENTITY_SHA256)"

trusted-time-recover-first-enrollment: ## Consume a separate approval for sequence-one recovery.
	@test -n "$(TRUSTED_TIME_LAUNCH_ENV_FILE)" || (echo "TRUSTED_TIME_LAUNCH_ENV_FILE=path/to/dedicated-owner-only.env is required" >&2; exit 2)
	@test -n "$(TRUSTED_TIME_FIRST_ENROLLMENT_OPERATION_ID)" || (echo "TRUSTED_TIME_FIRST_ENROLLMENT_OPERATION_ID is required" >&2; exit 2)
	@test -n "$(TRUSTED_TIME_PRIOR_NEW_OPERATION_ID)" || (echo "TRUSTED_TIME_PRIOR_NEW_OPERATION_ID is required" >&2; exit 2)
	@test -n "$(TRUSTED_TIME_PRIOR_NEW_CLAIM_SHA256)" || (echo "TRUSTED_TIME_PRIOR_NEW_CLAIM_SHA256 is required" >&2; exit 2)
	@test -n "$(TRUSTED_TIME_APPROVED_GIT_REVISION)" || (echo "TRUSTED_TIME_APPROVED_GIT_REVISION is required" >&2; exit 2)
	@test -n "$(TRUSTED_TIME_APPROVED_IMAGE_ADMISSION_SHA256)" || (echo "TRUSTED_TIME_APPROVED_IMAGE_ADMISSION_SHA256 is required" >&2; exit 2)
	@test -n "$(TRUSTED_TIME_APPROVED_SOURCE_IMAGE_ID)" || (echo "TRUSTED_TIME_APPROVED_SOURCE_IMAGE_ID is required" >&2; exit 2)
	@test -n "$(TRUSTED_TIME_APPROVED_SUPERVISOR_IMAGE_ID)" || (echo "TRUSTED_TIME_APPROVED_SUPERVISOR_IMAGE_ID is required" >&2; exit 2)
	@test -n "$(TRUSTED_TIME_APPROVED_UNENROLLED_ADMISSION_SHA256)" || (echo "TRUSTED_TIME_APPROVED_UNENROLLED_ADMISSION_SHA256 is required" >&2; exit 2)
	@test -n "$(TRUSTED_TIME_APPROVED_ANCHOR_AUTHORITY_SHA256)" || (echo "TRUSTED_TIME_APPROVED_ANCHOR_AUTHORITY_SHA256 is required" >&2; exit 2)
	@test -n "$(TRUSTED_TIME_APPROVED_DEPLOYMENT_IDENTITY_SHA256)" || (echo "TRUSTED_TIME_APPROVED_DEPLOYMENT_IDENTITY_SHA256 is required" >&2; exit 2)
	@test -n "$(TRUSTED_TIME_APPROVED_RUNTIME_DATABASE_IDENTITY_SHA256)" || (echo "TRUSTED_TIME_APPROVED_RUNTIME_DATABASE_IDENTITY_SHA256 is required" >&2; exit 2)
	@test -n "$(TRUSTED_TIME_APPROVED_ANCHOR_PROJECT_IDENTITY_SHA256)" || (echo "TRUSTED_TIME_APPROVED_ANCHOR_PROJECT_IDENTITY_SHA256 is required" >&2; exit 2)
	@test -n "$(TRUSTED_TIME_APPROVED_SOURCE_AUTHORITY_SHA256)" || (echo "TRUSTED_TIME_APPROVED_SOURCE_AUTHORITY_SHA256 is required" >&2; exit 2)
	@test -n "$(TRUSTED_TIME_APPROVED_SIGNING_PUBLIC_KEY_SHA256)" || (echo "TRUSTED_TIME_APPROVED_SIGNING_PUBLIC_KEY_SHA256 is required" >&2; exit 2)
	@test -n "$(TRUSTED_TIME_APPROVED_HOST_IDENTITY_SHA256)" || (echo "TRUSTED_TIME_APPROVED_HOST_IDENTITY_SHA256 is required" >&2; exit 2)
	@test -n "$(TRUSTED_TIME_APPROVED_PRINCIPAL_IDENTITY_SHA256)" || (echo "TRUSTED_TIME_APPROVED_PRINCIPAL_IDENTITY_SHA256 is required" >&2; exit 2)
	@test -n "$(TRUSTED_TIME_APPROVED_BUCKET_IDENTITY_SHA256)" || (echo "TRUSTED_TIME_APPROVED_BUCKET_IDENTITY_SHA256 is required" >&2; exit 2)
	$(TRUSTED_TIME_PYTHON) \
		scripts/enroll_trusted_time_head_anchor.py \
		--env-file "$(TRUSTED_TIME_LAUNCH_ENV_FILE)" \
		--image-admission-artifact "$(TRUSTED_TIME_IMAGE_ADMISSION_ARTIFACT)" \
		--artifact-dir "$(TRUSTED_TIME_UNENROLLED_ADMISSION_ARTIFACT_DIR)" \
		--operation-id "$(TRUSTED_TIME_FIRST_ENROLLMENT_OPERATION_ID)" \
		--prior-new-operation-id "$(TRUSTED_TIME_PRIOR_NEW_OPERATION_ID)" \
		--prior-new-claim-sha256 "$(TRUSTED_TIME_PRIOR_NEW_CLAIM_SHA256)" \
		--approved-git-revision "$(TRUSTED_TIME_APPROVED_GIT_REVISION)" \
		--approved-image-admission-sha256 "$(TRUSTED_TIME_APPROVED_IMAGE_ADMISSION_SHA256)" \
		--approved-source-image-id "$(TRUSTED_TIME_APPROVED_SOURCE_IMAGE_ID)" \
		--approved-supervisor-image-id "$(TRUSTED_TIME_APPROVED_SUPERVISOR_IMAGE_ID)" \
		--unenrolled-admission-sha256 "$(TRUSTED_TIME_APPROVED_UNENROLLED_ADMISSION_SHA256)" \
		--anchor-authority-sha256 "$(TRUSTED_TIME_APPROVED_ANCHOR_AUTHORITY_SHA256)" \
		--deployment-identity-sha256 "$(TRUSTED_TIME_APPROVED_DEPLOYMENT_IDENTITY_SHA256)" \
		--runtime-database-identity-sha256 "$(TRUSTED_TIME_APPROVED_RUNTIME_DATABASE_IDENTITY_SHA256)" \
		--anchor-project-identity-sha256 "$(TRUSTED_TIME_APPROVED_ANCHOR_PROJECT_IDENTITY_SHA256)" \
		--source-authority-sha256 "$(TRUSTED_TIME_APPROVED_SOURCE_AUTHORITY_SHA256)" \
		--signing-public-key-sha256 "$(TRUSTED_TIME_APPROVED_SIGNING_PUBLIC_KEY_SHA256)" \
		--host-identity-sha256 "$(TRUSTED_TIME_APPROVED_HOST_IDENTITY_SHA256)" \
		--principal-identity-sha256 "$(TRUSTED_TIME_APPROVED_PRINCIPAL_IDENTITY_SHA256)" \
		--bucket-identity-sha256 "$(TRUSTED_TIME_APPROVED_BUCKET_IDENTITY_SHA256)" \
		--recover-pending

trusted-time-runtime-diagnostic: ## Run the bounded read-only trusted-time runtime diagnostic.
	@test -n "$(TRUSTED_TIME_LAUNCH_ENV_FILE)" || (echo "TRUSTED_TIME_LAUNCH_ENV_FILE=path/to/dedicated-owner-only.env is required" >&2; exit 2)
	@$(TRUSTED_TIME_PYTHON) \
		scripts/diagnose_trusted_time_runtime.py \
		--env-file "$(TRUSTED_TIME_LAUNCH_ENV_FILE)"

trusted-time-inspect: ## Inspect the running trusted-time qualification window.
	@test -n "$(TRUSTED_TIME_INSPECT_ENV_FILE)" || (echo "TRUSTED_TIME_INSPECT_ENV_FILE=path/to/database-only-owner-only.env is required" >&2; exit 2)
	$(TRUSTED_TIME_PYTHON) \
		scripts/inspect_trusted_time_qualification.py \
		--env-file "$(TRUSTED_TIME_INSPECT_ENV_FILE)" \
		--image-admission-artifact "$(TRUSTED_TIME_IMAGE_ADMISSION_ARTIFACT)" \
		--artifact-dir "$(TRUSTED_TIME_QUALIFICATION_ARTIFACT_DIR)"

trusted-time-stop: ## Fail closed until an approval-bound frozen shutdown path is implemented.
	@echo "trusted-time-stop is approval-blocked: no frozen approved shutdown path is implemented" >&2
	@exit 2
