.PHONY: install dev test lint clean

install:
	uv pip install -e .

dev:
	uv pip install -e ".[dev,all]"

test:
	uv run pytest agentgate/tests/ -v --tb=short

test-timing:
	uv run pytest agentgate/tests/test_timing.py -v

lint:
	uv run ruff check agentgate/
	uv run ruff format --check agentgate/

format:
	uv run ruff format agentgate/
	uv run ruff check --fix agentgate/

clean:
	find . -type d -name __pycache__ -exec rm -rf {} + 2>/dev/null || true
	find . -type d -name .pytest_cache -exec rm -rf {} + 2>/dev/null || true
	find . -type f -name "*.pyc" -delete 2>/dev/null || true
	rm -rf dist/ build/ *.egg-info/
