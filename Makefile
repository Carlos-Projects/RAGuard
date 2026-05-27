.PHONY: install test lint format typecheck clean build

install:
	pip install -e ".[dev]"

test:
	python3 -m pytest tests/ -v --cov=raguard --cov-report=term-missing

lint:
	python3 -m ruff check src/ tests/

format:
	python3 -m ruff format src/ tests/

typecheck:
	python3 -m mypy src/raguard/

clean:
	rm -rf dist/ build/ *.egg-info/ .pytest_cache/ .ruff_cache/ .mypy_cache/ .coverage htmlcov/

build: clean
	python3 -m build
