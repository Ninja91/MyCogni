FROM ghcr.io/astral-sh/uv@sha256:9a23023be68b2ed09750ae636228e903a54a05ea56ed03a934d00fe9fbeded4b AS uv

FROM docker.io/library/python@sha256:593bd06efe90efa80dc4eee3948be7c0fde4134606dd40d8dd8dbcade98e669c AS build

COPY --from=uv /uv /uvx /bin/

ENV UV_COMPILE_BYTECODE=1 \
    UV_LINK_MODE=copy \
    UV_NO_DEV=1 \
    UV_PYTHON_DOWNLOADS=never \
    UV_PROJECT_ENVIRONMENT=/opt/mycogni/.venv

WORKDIR /build

COPY pyproject.toml uv.lock build-constraints.txt README.md LICENSE NOTICE ./
COPY packages/mycogni-connector-sdk ./packages/mycogni-connector-sdk
COPY src ./src

RUN uv sync --frozen --no-dev --no-editable --package mycogni \
    && /opt/mycogni/.venv/bin/python -c "import importlib.util; assert importlib.util.find_spec('connector_protocol') is None" \
    && /opt/mycogni/.venv/bin/python -c "from pathlib import Path; expected = '#!/opt/mycogni/.venv/bin/python'; assert all((Path('/opt/mycogni/.venv/bin') / name).read_text().splitlines()[0] == expected for name in ('uvicorn', 'alembic'))" \
    && /opt/mycogni/.venv/bin/uvicorn --version \
    && /opt/mycogni/.venv/bin/alembic --version \
    && rm -rf /root/.cache/uv \
    && chown -R 0:0 /opt/mycogni \
    && chmod -R a-w /opt/mycogni

FROM docker.io/library/python@sha256:593bd06efe90efa80dc4eee3948be7c0fde4134606dd40d8dd8dbcade98e669c AS runtime

ARG BUILD_CREATED="1970-01-01T00:00:00Z"
ARG VERSION="0.0.0"
ARG VCS_REF="unknown"

LABEL org.opencontainers.image.created="${BUILD_CREATED}" \
      org.opencontainers.image.description="MyCogni local-first trusted core skeleton" \
      org.opencontainers.image.licenses="Apache-2.0" \
      org.opencontainers.image.revision="${VCS_REF}" \
      org.opencontainers.image.source="https://github.com/Ninja91/MyCogni" \
      org.opencontainers.image.title="MyCogni" \
      org.opencontainers.image.version="${VERSION}"

ENV HOME=/tmp/mycogni \
    PATH=/opt/mycogni/.venv/bin:/usr/local/bin:/usr/bin:/bin \
    PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    TMPDIR=/tmp/mycogni

RUN install -d -o 0 -g 0 -m 0555 /opt/mycogni \
    && install -d -o 65532 -g 65532 -m 0700 /var/lib/mycogni /tmp/mycogni

COPY --from=build /opt/mycogni/.venv /opt/mycogni/.venv

WORKDIR /var/lib/mycogni
USER 65532:65532

# PF-002 is a packaging skeleton only. A later entrypoint work package replaces
# this console-script and import smoke with the role-aware server/worker/scheduler CLI.
CMD ["/bin/sh", "-c", "/opt/mycogni/.venv/bin/uvicorn --version && /opt/mycogni/.venv/bin/alembic --version && /opt/mycogni/.venv/bin/python -c \"import mycogni; print('MyCogni PF-002 import smoke passed')\""]
