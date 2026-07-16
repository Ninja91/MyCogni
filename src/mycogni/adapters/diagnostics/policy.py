"""Deny-by-default settings for diagnostic surfaces with unsafe auto-capture."""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass, field
from types import MappingProxyType
from typing import Literal


@dataclass(frozen=True, slots=True)
class UnsafeCaptureDefaults:
    """Non-overridable V1 defaults for automatic diagnostic capture.

    A future adapter may introduce a separately reviewed, typed safe event. It
    must not flip one of these flags to capture raw framework or transport data.
    """

    uvicorn_access_log: Literal[False] = field(default=False, init=False)
    uvicorn_default_log_config: Literal[False] = field(default=False, init=False)
    proxy_access_log: Literal[False] = field(default=False, init=False)
    proxy_error_detail: Literal[False] = field(default=False, init=False)
    browser_console_log: Literal[False] = field(default=False, init=False)
    browser_network_log: Literal[False] = field(default=False, init=False)
    browser_page_log: Literal[False] = field(default=False, init=False)
    mail_protocol_log: Literal[False] = field(default=False, init=False)
    remote_exporter: Literal[False] = field(default=False, init=False)


def uvicorn_safe_options() -> Mapping[str, object]:
    """Return options that disable Uvicorn's automatic access/default logs."""
    return MappingProxyType(
        {
            "access_log": False,
            "log_config": None,
            "use_colors": False,
        }
    )
