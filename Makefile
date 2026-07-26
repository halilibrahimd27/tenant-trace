.DEFAULT_GOAL := help
.PHONY: help install verify lint format types test property metrics \
        fixtures-up fixtures-down reports demo site release-check clean

UV ?= uv

help:  ## Show this help
	@grep -E '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) \
		| awk 'BEGIN {FS = ":.*?## "}; {printf "  \033[36m%-16s\033[0m %s\n", $$1, $$2}'

install:  ## Sync dev + fixture dependencies
	$(UV) sync --extra dev --extra fixtures

## ---------------------------------------------------------------- gate
# Hermetic on purpose: every target below runs without Docker, Redis, or a
# network. The fixture apps are driven in-process over ASGI (ADR-0004).
verify: lint types test metrics  ## THE GATE — must be green to finish a milestone
	@echo "✅ verify passed"

lint:  ## ruff + black --check
	$(UV) run ruff check src tests fixtures seeders
	$(UV) run black --check src tests fixtures seeders

format:  ## Apply black + ruff --fix
	$(UV) run black src tests fixtures seeders
	$(UV) run ruff check --fix src tests fixtures seeders

types:  ## mypy --strict
	$(UV) run mypy src

test:  ## pytest with the coverage gate (>=85%)
	$(UV) run pytest --cov=tenanttrace --cov-report=term-missing --cov-fail-under=85

property:  ## Hypothesis property tests only
	$(UV) run pytest -m property -v

metrics:  ## Precision/recall against fixtures/labels.yaml (recall >= 90%)
	$(UV) run tenanttrace metrics --labels fixtures/labels.yaml --min-recall 0.90

## ------------------------------------------------------------ fixtures
# Containers are for demoing over real sockets. The gate does not need them.
# The compose file lives at the repository root — it is the whole product's
# one-command demo, not a fixtures-only detail. These targets pointed at
# fixtures/docker-compose.yml, which has not existed since it moved.
fixtures-up:  ## Boot vulnerable_app + safe_app + Redis in Docker
	docker compose up -d --wait vulnerable-app safe-app redis
	@echo "vulnerable_app → http://127.0.0.1:8001   safe_app → http://127.0.0.1:8002"

fixtures-down:  ## Tear the fixtures down
	docker compose down -v

reports:  ## Copy the containerised demo's reports out onto the host
	docker compose cp report:/reports ./reports
	@echo "→ ./reports (also served at http://127.0.0.1:8088)"

## ---------------------------------------------------------------- demo
demo:  ## Probe both fixture apps in-process and write HTML reports
	$(UV) run tenanttrace demo

## ---------------------------------------------------------------- site
site:  ## Serve the GitHub Pages landing page locally
	@echo "→ http://127.0.0.1:8088"
	@cd docs/site && python3 -m http.server 8088

## ------------------------------------------------------------- release
release-check:  ## Pre-flight before tagging a release
	@echo "── secrets in history ──"
	@# Two deliberate scoping choices, both learned the hard way:
	@#  1. Match *seeded* canary values (tt-canary-<label>-<hex>), not the bare
	@#     `tt-canary-` prefix — that prefix appears throughout the docs by
	@#     design, and matching it would fail this check permanently.
	@#  2. Exclude tests/, whose canaries are obviously-synthetic published
	@#     constants (…0123456789abcdef). A canary that actually leaked would
	@#     be in a run artifact or a config file, and those are checked below.
	@! git log -p --all -- . ':(exclude)tests/' \
		| grep -nE '(sk-ant-[A-Za-z0-9_-]{10,}|ghp_[A-Za-z0-9]{20,}|github_pat_[A-Za-z0-9_]{20,}|Bearer [A-Za-z0-9._-]{20,}|tt-canary-[A-Za-z0-9]+-[0-9a-f]{8,})' \
		|| (echo "❌ possible secret or seeded canary in git history"; exit 1)
	@echo "── gitignore rules actually match (no trailing-comment traps) ──"
	@for p in tenanttrace.toml .tenanttrace/run.json reports/x.html; do \
		git check-ignore -q "$$p" || { echo "❌ .gitignore does not ignore $$p"; exit 1; }; done
	@echo "── required files ──"
	@for f in LICENSE SECURITY.md THREAT_MODEL.md CONTRIBUTING.md README.md; do \
		test -f $$f || { echo "❌ missing $$f"; exit 1; }; done
	@echo "── ignored files not tracked ──"
	@! git ls-files | grep -E '^(tenanttrace\.toml|\.tenanttrace/|.*\.har)$$' \
		|| (echo "❌ a gitignored target file is tracked"; exit 1)
	@$(MAKE) verify
	@echo "✅ release-check passed"

clean:
	rm -rf .pytest_cache .mypy_cache .ruff_cache .coverage htmlcov .tenanttrace
	find . -type d -name __pycache__ -prune -exec rm -rf {} +
