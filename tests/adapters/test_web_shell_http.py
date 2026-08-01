"""HTTP and browser-facing security evidence for UX-001."""

from __future__ import annotations

import asyncio
import re
from collections.abc import Mapping
from dataclasses import dataclass
from http.cookies import SimpleCookie
from urllib.parse import urlencode

from mycogni.bootstrap.web_shell import build_synthetic_web_shell

CSRF = re.compile(r'name="csrf_token" value="([^"]+)"')


@dataclass(frozen=True, slots=True)
class ASGIResponse:
    status_code: int
    headers: Mapping[str, str]
    body: bytes
    set_cookies: tuple[str, ...]

    @property
    def text(self) -> str:
        return self.body.decode("utf-8")


class ASGIClient:
    """In-process HTTP harness; it never opens a socket or invokes a proxy."""

    def __init__(self, app: object) -> None:
        self._app = app
        self._cookies: dict[str, str] = {}

    def request(
        self,
        method: str,
        path: str,
        *,
        data: Mapping[str, str] | None = None,
        host: str = "127.0.0.1",
        origin: str | None = None,
        omit_content_length: bool = False,
        content_length: str | None = None,
    ) -> ASGIResponse:
        body = urlencode(data or {}).encode("utf-8")
        raw_headers = [(b"host", host.encode("ascii"))]
        if self._cookies:
            raw_headers.append(
                (
                    b"cookie",
                    "; ".join(f"{key}={value}" for key, value in self._cookies.items()).encode(
                        "ascii"
                    ),
                )
            )
        if data is not None:
            raw_headers.append((b"content-type", b"application/x-www-form-urlencoded"))
            if not omit_content_length:
                raw_headers.append(
                    (
                        b"content-length",
                        (content_length or str(len(body))).encode("ascii"),
                    )
                )
        if origin is not None:
            raw_headers.append((b"origin", origin.encode("ascii")))
        messages: list[dict[str, object]] = []
        received = False

        async def receive() -> dict[str, object]:
            nonlocal received
            if received:
                return {"type": "http.disconnect"}
            received = True
            return {"type": "http.request", "body": body, "more_body": False}

        async def send(message: dict[str, object]) -> None:
            messages.append(message)

        scope = {
            "type": "http",
            "asgi": {"version": "3.0", "spec_version": "2.3"},
            "http_version": "1.1",
            "method": method,
            "scheme": "http",
            "path": path,
            "raw_path": path.encode("ascii"),
            "query_string": b"",
            "headers": raw_headers,
            "client": ("127.0.0.1", 43123),
            "server": ("127.0.0.1", 80),
            "root_path": "",
        }
        asyncio.run(self._app(scope, receive, send))  # type: ignore[operator]
        start = next(message for message in messages if message["type"] == "http.response.start")
        response_headers = {
            key.decode("latin-1"): value.decode("latin-1")
            for key, value in start["headers"]  # type: ignore[index]
            if key.lower() != b"set-cookie"
        }
        set_cookies: list[str] = []
        for message in messages:
            if message["type"] != "http.response.start":
                continue
            for key, value in message["headers"]:  # type: ignore[index]
                if key.lower() != b"set-cookie":
                    continue
                raw_cookie = value.decode("latin-1")
                set_cookies.append(raw_cookie)
                cookie = SimpleCookie()
                cookie.load(raw_cookie)
                for morsel in cookie.values():
                    self._cookies[morsel.key] = morsel.value
        return ASGIResponse(
            status_code=int(start["status"]),  # type: ignore[arg-type]
            headers=response_headers,
            body=b"".join(
                message["body"]  # type: ignore[misc]
                for message in messages
                if message["type"] == "http.response.body"
            ),
            set_cookies=tuple(set_cookies),
        )


def _csrf(body: str) -> str:
    match = CSRF.search(body)
    assert match is not None
    return match.group(1)


def test_synthetic_login_logout_and_headers() -> None:
    bundle = build_synthetic_web_shell(allowed_hosts=("testserver",))
    client = ASGIClient(bundle.app)
    landing = client.request("GET", "/", host="testserver")
    assert landing.status_code == 200
    assert "real personal data" in landing.text
    assert landing.headers["content-security-policy"].endswith("frame-ancestors 'none'")
    assert landing.headers["x-frame-options"] == "DENY"
    assert landing.headers["cache-control"] == "no-store"

    login = client.request("GET", "/login", host="testserver")
    assert login.status_code == 200
    csrf = _csrf(login.text)
    submitted = client.request(
        "POST",
        "/login",
        data={"csrf_token": csrf, "operator_code": bundle.bootstrap_code},
        host="testserver",
        origin="http://testserver",
    )
    assert submitted.status_code == 303
    assert submitted.headers["location"] == "/app"
    assert any("mycogni_session=" in value for value in submitted.set_cookies)
    session_cookie = next(value for value in submitted.set_cookies if "mycogni_session=" in value)
    assert "HttpOnly" in session_cookie
    assert "SameSite=strict" in session_cookie
    assert "Secure" not in session_cookie

    dashboard = client.request("GET", "/app", host="testserver")
    assert dashboard.status_code == 200
    assert "AUTHENTICATED SYNTHETIC SHELL" in dashboard.text
    assert bundle.bootstrap_code not in dashboard.text
    logout = client.request(
        "POST",
        "/logout",
        data={"csrf_token": _csrf(dashboard.text)},
        host="testserver",
        origin="http://testserver",
    )
    assert logout.status_code == 303
    assert client.request("GET", "/app", host="testserver").status_code == 303


def test_host_origin_and_csrf_guards_fail_closed() -> None:
    bundle = build_synthetic_web_shell(allowed_hosts=("testserver",))
    client = ASGIClient(bundle.app)
    assert client.request("GET", "/", host="attacker.invalid").status_code == 400
    login = client.request("GET", "/login", host="testserver")
    csrf = _csrf(login.text)
    missing_origin = client.request(
        "POST",
        "/login",
        data={"csrf_token": csrf, "operator_code": bundle.bootstrap_code},
        host="testserver",
    )
    assert missing_origin.status_code == 403
    wrong_csrf = client.request(
        "POST",
        "/login",
        data={"csrf_token": "wrong", "operator_code": bundle.bootstrap_code},
        host="testserver",
        origin="http://testserver",
    )
    assert wrong_csrf.status_code == 401
    assert "not accepted" in wrong_csrf.text


def test_secure_cookie_profile_sets_secure_attribute() -> None:
    bundle = build_synthetic_web_shell(allowed_hosts=("testserver",), secure_cookies=True)
    response = ASGIClient(bundle.app).request("GET", "/login", host="testserver")
    assert response.status_code == 200
    assert any("Secure" in value for value in response.set_cookies)


def test_unexpected_handler_error_keeps_security_headers_and_redacts_body() -> None:
    bundle = build_synthetic_web_shell(allowed_hosts=("testserver",))

    async def explode() -> None:
        raise RuntimeError("synthetic-secret-error")

    bundle.app.add_api_route("/explode", explode, methods=["GET"])
    response = ASGIClient(bundle.app).request("GET", "/explode", host="testserver")
    assert response.status_code == 500
    assert response.headers["cache-control"] == "no-store"
    assert response.headers["x-content-type-options"] == "nosniff"
    assert "synthetic-secret-error" not in response.text


def test_form_size_and_field_limits_fail_closed() -> None:
    bundle = build_synthetic_web_shell(allowed_hosts=("testserver",))
    client = ASGIClient(bundle.app)
    login = client.request("GET", "/login", host="testserver")
    csrf = _csrf(login.text)
    oversized = client.request(
        "POST",
        "/login",
        data={"csrf_token": csrf, "operator_code": "x" * 20_000},
        host="testserver",
        origin="http://testserver",
    )
    assert oversized.status_code == 401
    assert "internal" not in oversized.text.lower()

    unknown_length = client.request(
        "POST",
        "/login",
        data={"csrf_token": csrf, "operator_code": "x" * 20_000},
        host="testserver",
        origin="http://testserver",
        omit_content_length=True,
    )
    assert unknown_length.status_code == 401
    malformed_length = client.request(
        "POST",
        "/login",
        data={"csrf_token": csrf, "operator_code": "x"},
        host="testserver",
        origin="http://testserver",
        content_length="not-a-number",
    )
    assert malformed_length.status_code == 401
    negative_length = client.request(
        "POST",
        "/login",
        data={"csrf_token": csrf, "operator_code": "x"},
        host="testserver",
        origin="http://testserver",
        content_length="-1",
    )
    assert negative_length.status_code == 401
    too_many_fields = {"csrf_token": csrf, "operator_code": "x"}
    too_many_fields.update({f"extra-{index}": "x" for index in range(31)})
    field_overflow = client.request(
        "POST",
        "/login",
        data=too_many_fields,
        host="testserver",
        origin="http://testserver",
    )
    assert field_overflow.status_code == 401
