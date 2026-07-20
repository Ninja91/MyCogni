"""Isolated, no-site bootstrap for the synthetic runner mailbox probe."""

from __future__ import annotations

import sys
from pathlib import Path

_ROOT = Path("/opt/mycogni-runner")
_SITE_PACKAGES = _ROOT / ".venv/lib/python3.12/site-packages"


def _expected_initial_path() -> tuple[str, str, str]:
    version = f"python{sys.version_info.major}.{sys.version_info.minor}"
    library = Path(sys.base_prefix) / "lib"
    return (
        str(library / f"python{sys.version_info.major}{sys.version_info.minor}.zip"),
        str(library / version),
        str(library / version / "lib-dynload"),
    )


def _sealed_path(
    initial: list[str], *, isolated: int, no_site: int, site_loaded: bool
) -> list[str]:
    if isolated != 1 or no_site != 1 or site_loaded:
        raise RuntimeError("runner Python must start isolated with site disabled")
    if tuple(initial) != _expected_initial_path():
        raise RuntimeError("runner Python started with an unexpected import path")
    return [*initial, str(_SITE_PACKAGES), str(_ROOT)]


def _activate() -> None:
    if not _ROOT.is_dir() or not _SITE_PACKAGES.is_dir():
        raise RuntimeError("runner sealed import roots are absent")
    sys.path[:] = _sealed_path(
        sys.path,
        isolated=sys.flags.isolated,
        no_site=sys.flags.no_site,
        site_loaded="site" in sys.modules,
    )


def main() -> None:
    _activate()
    from mycogni_runner_mailbox_runtime.container_probe import main as probe_main

    probe_main()


if __name__ == "__main__":
    main()
