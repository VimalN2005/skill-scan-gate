.PHONY: install lint format test check build demo docker clean

PY ?= uv run

install:
	uv venv
	uv pip install -e ".[dev]"

lint:
	$(PY) ruff check .
	$(PY) ruff format --check .

format:
	$(PY) ruff format .
	$(PY) ruff check --fix .

test:
	$(PY) pytest -q

check: lint test

build:
	rm -rf dist
	uv build

# Scan the planted fixture (exit 1 expected) and the clean fixture (exit 0 expected).
demo:
	$(PY) skill-scan-gate scan tests/fixtures/fixture-planted; test $$? -eq 1
	$(PY) skill-scan-gate scan tests/fixtures/fixture-clean --fail-on low

docker:
	docker build -t skill-scan-gate:dev .
	docker run --rm skill-scan-gate:dev --help

clean:
	rm -rf dist build .pytest_cache .ruff_cache *.sarif
	find . -name __pycache__ -type d -prune -exec rm -rf {} +
