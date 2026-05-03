.PHONY: install test lint run

install:
	pip install -e ".[dev]"

test:
	pytest -v

lint:
	ruff check . && ruff format --check .

run:
	@echo "not implemented yet"
