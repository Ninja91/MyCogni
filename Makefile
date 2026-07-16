.PHONY: bootstrap check format lock test

bootstrap:
	uv sync --all-groups --frozen

lock:
	uv lock --check

format:
	uv run ruff format .
	uv run ruff check --fix .

check:
	uv lock --check
	uv run ruff format --check .
	uv run ruff check .
	uv run mypy
	uv run lint-imports
	uv run pytest

test:
	uv run pytest
