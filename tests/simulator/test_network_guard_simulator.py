"""Marked local-HTTP policy mutations that never contact a live origin."""

from __future__ import annotations

import os
import socket

import httpx
import pytest

from scripts.ci import network_guard


def _url(scheme: str, authority: str, path: str = "/") -> str:
    return scheme + "://" + authority + path


@pytest.mark.simulator_loopback
@pytest.mark.parametrize(
    "url",
    [
        _url("https", "127.0.0.1:43123"),
        _url("ftp", "127.0.0.1:43123"),
        "file:///synthetic",
        _url("http", "localhost:43123"),
        _url("http", "127.0.0.2:43123"),
        _url("http", "2130706433:43123"),
        _url("http", "0x7f000001:43123"),
        _url("http", "[::1]:43123"),
        _url("http", "[::ffff:127.0.0.1]:43123"),
        _url("http", "synthetic@127.0.0.1:43123"),
        _url("http", "%31%32%37.0.0.1:43123"),
        _url("http", "127.0.0.1"),
        _url("http", "127.0.0.1:0"),
        _url("http", "127.0.0.1:65536"),
    ],
)
def test_noncanonical_local_http_urls_fail_before_transport(url: str) -> None:
    with pytest.raises(network_guard.NetworkDenied) as raised:
        network_guard.parse_local_http_url(url)
    assert raised.value.reason in {
        network_guard.DenialReason.SCHEME_FORBIDDEN,
        network_guard.DenialReason.URL_INVALID,
        network_guard.DenialReason.PORT_INVALID,
    }
    assert url not in str(raised.value)


@pytest.mark.simulator_loopback
@pytest.mark.parametrize(
    ("family", "address"),
    [
        (socket.AF_INET, ("127.0.0.2", 43123)),
        (socket.AF_INET, ("0.0.0.0", 43123)),
        (socket.AF_INET6, ("::1", 43123, 0, 0)),
        (socket.AF_INET6, ("::ffff:127.0.0.1", 43123, 0, 0)),
        (socket.AF_UNIX, "/tmp/synthetic.sock"),
    ],
)
def test_ip_family_alias_and_unix_socket_escapes_fail(family: int, address: object) -> None:
    with pytest.raises(network_guard.NetworkDenied):
        network_guard.authorize_socket_address(family, address)


@pytest.mark.simulator_loopback
def test_external_redirect_is_denied_before_second_transport() -> None:
    calls: list[str] = []

    def transport(request: httpx.Request) -> httpx.Response:
        calls.append(str(request.url))
        return httpx.Response(
            302,
            headers={"location": _url("http", "outside.test", "/synthetic-query")},
            request=request,
        )

    with (
        httpx.Client(transport=httpx.MockTransport(transport), follow_redirects=True) as client,
        pytest.raises(network_guard.NetworkDenied) as raised,
    ):
        client.get(_url("http", "127.0.0.1:43123", "/start"))
    assert calls == [_url("http", "127.0.0.1:43123", "/start")]
    assert "outside.test" not in str(raised.value)
    assert "synthetic-query" not in str(raised.value)


@pytest.mark.simulator_loopback
def test_valid_local_http_policy_is_exact() -> None:
    parsed = network_guard.parse_local_http_url(
        _url("http", "127.0.0.1:43123", "/v1/synthetic?case=opaque")
    )
    assert parsed.scheme == "http"
    assert parsed.hostname == "127.0.0.1"
    assert parsed.port == 43123


@pytest.mark.simulator_loopback
@pytest.mark.parametrize("name", ["HTTP_PROXY", "https_proxy", "No_PrOxY", "ALL_PROXY"])
def test_proxy_environment_names_are_case_insensitive_and_forbidden(
    monkeypatch: pytest.MonkeyPatch, name: str
) -> None:
    monkeypatch.setitem(
        os.environ,
        name,
        _url("http", "127.0.0.1:43123", "/synthetic-proxy"),
    )
    with pytest.raises(network_guard.NetworkDenied) as raised:
        network_guard.authorize_socket_address(socket.AF_INET, ("127.0.0.1", 43123))
    assert raised.value.category is network_guard.DenialCategory.PROXY
    assert raised.value.reason is network_guard.DenialReason.PROXY_FORBIDDEN
    assert "synthetic-proxy" not in str(raised.value)
