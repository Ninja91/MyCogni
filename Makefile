UV_VERSION := 0.9.26
PYTHON_VERSION := 3.12.12
export UV_BUILD_CONSTRAINT := build-constraints.txt

.PHONY: bootstrap check format lock lock-update test verify-toolchain

verify-toolchain:
	@test "$$(uv --version | awk '{print $$2}')" = "$(UV_VERSION)" || { \
		echo "Expected uv $(UV_VERSION); found $$(uv --version)"; exit 1; \
	}
	@test "$$(cat .python-version)" = "$(PYTHON_VERSION)" || { \
		echo "Expected .python-version $(PYTHON_VERSION)"; exit 1; \
	}

bootstrap: verify-toolchain
	uv sync --all-groups --all-packages --frozen --python $(PYTHON_VERSION)

lock: verify-toolchain
	uv lock --check

lock-update: verify-toolchain
	uv lock --upgrade

format: verify-toolchain
	uv run --all-packages --frozen --python $(PYTHON_VERSION) ruff format .
	uv run --all-packages --frozen --python $(PYTHON_VERSION) ruff check --fix .

check: verify-toolchain
	uv lock --check
	uv run --all-packages --frozen --python $(PYTHON_VERSION) ruff format --check .
	uv run --all-packages --frozen --python $(PYTHON_VERSION) ruff check .
	uv run --all-packages --frozen --python $(PYTHON_VERSION) mypy -p mycogni -p connector_protocol
	uv run --all-packages --frozen --python $(PYTHON_VERSION) lint-imports
	uv run --all-packages --frozen --python $(PYTHON_VERSION) pytest tests packages/mycogni-connector-sdk/tests

test: verify-toolchain
	uv run --all-packages --frozen --python $(PYTHON_VERSION) pytest tests packages/mycogni-connector-sdk/tests
