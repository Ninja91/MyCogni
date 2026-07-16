UV_VERSION := 0.9.26
PYTHON_VERSION := 3.12.12
PYTHON_COMPAT_VERSION := 3.13.11
export UV_BUILD_CONSTRAINT := build-constraints.txt

.PHONY: bootstrap check check-python-313 format lock lock-update test verify-toolchain

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
	uv run --all-packages --frozen --python $(PYTHON_VERSION) mypy -p mycogni -p connector_protocol -p simulator
	uv run --all-packages --frozen --python $(PYTHON_VERSION) lint-imports
	uv run --all-packages --frozen --python $(PYTHON_VERSION) pytest tests packages/mycogni-connector-sdk/tests
	uv run --all-packages --frozen --python $(PYTHON_VERSION) python scripts/ci/safety_guard.py
	uv run --all-packages --frozen --python $(PYTHON_VERSION) python scripts/ci/claim_guard.py
	uv run --all-packages --frozen --python $(PYTHON_VERSION) python scripts/ci/threat_catalog_guard.py
	uv run --all-packages --frozen --python $(PYTHON_VERSION) python -m scripts.ci.governance_guard

check-python-313: verify-toolchain
	uv sync --all-groups --all-packages --frozen --python $(PYTHON_COMPAT_VERSION)
	uv run --all-packages --frozen --python $(PYTHON_COMPAT_VERSION) ruff check .
	uv run --all-packages --frozen --python $(PYTHON_COMPAT_VERSION) lint-imports
	uv run --all-packages --frozen --python $(PYTHON_COMPAT_VERSION) pytest tests packages/mycogni-connector-sdk/tests
	uv run --all-packages --frozen --python $(PYTHON_COMPAT_VERSION) python scripts/ci/safety_guard.py
	uv run --all-packages --frozen --python $(PYTHON_COMPAT_VERSION) python scripts/ci/claim_guard.py
	uv run --all-packages --frozen --python $(PYTHON_COMPAT_VERSION) python scripts/ci/threat_catalog_guard.py
	uv run --all-packages --frozen --python $(PYTHON_COMPAT_VERSION) python -m scripts.ci.governance_guard

test: verify-toolchain
	uv run --all-packages --frozen --python $(PYTHON_VERSION) pytest tests packages/mycogni-connector-sdk/tests
