PY ?= .venv/bin/python

.PHONY: install test lint demo fixtures
install:
	$(PY) -m pip install -e ".[dev]"
test:
	$(PY) -m pytest -q
lint:
	.venv/bin/ruff check .
fixtures:
	$(PY) scripts/build_fixtures.py
demo:
	.venv/bin/loadpath scan examples/demo_app --receipts examples/demo_app/receipts.json
