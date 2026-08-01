"""FastAPI adapter for the UX-001 synthetic authenticated shell."""

from __future__ import annotations

import html
from collections.abc import Awaitable, Callable, Iterable
from urllib.parse import parse_qs

from fastapi import FastAPI, HTTPException, Request
from fastapi.responses import HTMLResponse, JSONResponse, RedirectResponse, Response
from starlette.requests import ClientDisconnect
from starlette.responses import PlainTextResponse

from mycogni.application.web_shell import AuthenticatedShellView, SyntheticWebShell

DEFAULT_ALLOWED_HOSTS = frozenset({"127.0.0.1", "localhost"})
SESSION_COOKIE = "mycogni_session"
LOGIN_COOKIE = "mycogni_login_challenge"
MAX_FORM_BYTES = 16_384
MAX_FORM_FIELDS = 32
MAX_FORM_FIELD_CHARS = 256

SECURITY_HEADERS = {
    "Content-Security-Policy": (
        "default-src 'none'; style-src 'unsafe-inline'; form-action 'self'; "
        "base-uri 'none'; frame-ancestors 'none'"
    ),
    "X-Content-Type-Options": "nosniff",
    "X-Frame-Options": "DENY",
    "Referrer-Policy": "no-referrer",
    "Permissions-Policy": "camera=(), geolocation=(), microphone=()",
    "Cache-Control": "no-store",
}


def create_synthetic_web_app(
    shell: SyntheticWebShell,
    *,
    allowed_hosts: Iterable[str] = DEFAULT_ALLOWED_HOSTS,
    secure_cookies: bool = False,
) -> FastAPI:
    """Create a no-script, local-only synthetic web surface.

    ``secure_cookies`` is false only for the loopback HTTP developer profile.
    A TLS deployment must set it to true.  This adapter intentionally exposes
    no OpenAPI/docs route and accepts only form-encoded synthetic credentials.
    """

    if type(shell) is not SyntheticWebShell:
        raise TypeError("synthetic web app requires the exact shell service")
    hosts = frozenset(_normalize_host(value) for value in allowed_hosts)
    if not hosts or "" in hosts:
        raise ValueError("synthetic web app requires at least one non-empty allowed host")
    app = FastAPI(docs_url=None, redoc_url=None, openapi_url=None)

    @app.middleware("http")
    async def security_headers(
        request: Request, call_next: Callable[[Request], Awaitable[Response]]
    ) -> Response:
        try:
            response = await call_next(request)
        except Exception:
            # Keep the fail-closed response inside this middleware so even an
            # unexpected handler error receives the no-store/security policy.
            response = PlainTextResponse("request failed", status_code=500)
        for name, value in SECURITY_HEADERS.items():
            response.headers[name] = value
        return response

    @app.get("/", response_class=HTMLResponse)
    async def landing(request: Request) -> HTMLResponse:
        _require_host(request, hosts)
        return HTMLResponse(_landing_page())

    @app.get("/login", response_class=HTMLResponse)
    async def login_form(request: Request) -> HTMLResponse:
        _require_host(request, hosts)
        start = shell.begin_login()
        response = HTMLResponse(_login_page(start.csrf_token))
        _set_cookie(
            response,
            LOGIN_COOKIE,
            start.challenge_cookie,
            secure=secure_cookies,
            max_age=300,
        )
        return response

    @app.post("/login", response_class=HTMLResponse)
    async def login_submit(request: Request) -> Response:
        _require_host(request, hosts, state_changing=True)
        values = await _form_values(request)
        result = shell.authenticate_login(
            challenge_cookie=request.cookies.get(LOGIN_COOKIE),
            csrf_token=values.get("csrf_token", ""),
            operator_code=values.get("operator_code", ""),
        )
        if result.session_cookie is None or result.csrf_token is None:
            start = shell.begin_login()
            failure_response = HTMLResponse(
                _login_page(
                    start.csrf_token,
                    error="The synthetic code or form was not accepted. Start a new login attempt.",
                ),
                status_code=401,
            )
            _set_cookie(
                failure_response,
                LOGIN_COOKIE,
                start.challenge_cookie,
                secure=secure_cookies,
                max_age=300,
            )
            return failure_response
        response: Response = RedirectResponse("/app", status_code=303)
        _set_cookie(
            response,
            SESSION_COOKIE,
            result.session_cookie,
            secure=secure_cookies,
        )
        response.delete_cookie(LOGIN_COOKIE, path="/")
        return response

    @app.get("/app", response_class=HTMLResponse)
    async def dashboard(request: Request) -> Response:
        _require_host(request, hosts)
        view = shell.view(request.cookies.get(SESSION_COOKIE))
        if view is None:
            return _login_redirect()
        return HTMLResponse(_dashboard_page(view))

    @app.post("/logout")
    async def logout(request: Request) -> Response:
        _require_host(request, hosts, state_changing=True)
        values = await _form_values(request)
        if not shell.logout(
            session_cookie=request.cookies.get(SESSION_COOKIE),
            csrf_token=values.get("csrf_token", ""),
        ):
            raise HTTPException(status_code=403, detail="request denied")
        response = RedirectResponse("/login", status_code=303)
        response.delete_cookie(SESSION_COOKIE, path="/")
        return response

    @app.get("/healthz")
    async def health(request: Request) -> JSONResponse:
        _require_host(request, hosts)
        return JSONResponse(
            {
                "profile": "developer_preview_synthetic_only",
                "authenticated_shell": "synthetic_only",
                "active_sessions": shell.active_session_count(),
                "real_pii": "not accepted",
                "external_actions": "unavailable",
            }
        )

    return app


async def _form_values(request: Request) -> dict[str, str]:
    content_type = request.headers.get("content-type", "").split(";", 1)[0].strip().lower()
    if content_type != "application/x-www-form-urlencoded":
        return {}
    declared_length = request.headers.get("content-length")
    if declared_length is not None:
        try:
            parsed_length = int(declared_length)
            if parsed_length < 0 or parsed_length > MAX_FORM_BYTES:
                return {}
        except ValueError:
            return {}
    chunks = bytearray()
    try:
        async for chunk in request.stream():
            if len(chunks) + len(chunk) > MAX_FORM_BYTES:
                return {}
            chunks.extend(chunk)
        body = bytes(chunks).decode("utf-8")
    except (ClientDisconnect, UnicodeError):
        return {}
    try:
        parsed = parse_qs(
            body,
            keep_blank_values=True,
            strict_parsing=False,
            max_num_fields=MAX_FORM_FIELDS,
        )
    except ValueError:
        return {}
    if any(
        len(key) > MAX_FORM_FIELD_CHARS
        or any(len(value) > MAX_FORM_FIELD_CHARS for value in values)
        for key, values in parsed.items()
    ):
        return {}
    return {key: values[0] for key, values in parsed.items() if values}


def _require_host(
    request: Request, allowed_hosts: frozenset[str], *, state_changing: bool = False
) -> None:
    hostname = request.url.hostname
    if hostname is None or _normalize_host(hostname) not in allowed_hosts:
        raise HTTPException(status_code=400, detail="host not allowed")
    if state_changing:
        host_header = request.headers.get("host")
        origin = request.headers.get("origin")
        if not host_header or not origin or origin != f"{request.url.scheme}://{host_header}":
            raise HTTPException(status_code=403, detail="origin not allowed")


def _normalize_host(value: str) -> str:
    if type(value) is not str:
        raise TypeError("allowed host must be text")
    return value.strip().lower().rstrip(".")


def _set_cookie(
    response: Response,
    name: str,
    value: str,
    *,
    secure: bool,
    max_age: int | None = None,
) -> None:
    response.set_cookie(
        name,
        value,
        max_age=max_age,
        httponly=True,
        secure=secure,
        samesite="strict",
        path="/",
    )


def _login_redirect() -> RedirectResponse:
    response = RedirectResponse("/login", status_code=303)
    response.delete_cookie(SESSION_COOKIE, path="/")
    return response


def _landing_page() -> str:
    return """<!doctype html>
<html lang="en">
<head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>MyCogni synthetic shell</title></head>
<body>
<main>
<p>MYCOGNI · DEVELOPER PREVIEW</p>
<h1>Private control-plane shell</h1>
<p>This is a synthetic-only authenticated walkthrough. It accepts no real personal data,
contacts no broker, sends no mail, and cannot submit a removal request.</p>
<p><a href="/login">Start the local synthetic login</a></p>
<p><a href="/healthz">View non-secret health</a></p>
</main>
</body></html>"""


def _login_page(csrf_token: str, *, error: str | None = None) -> str:
    safe_token = html.escape(csrf_token, quote=True)
    error_html = f'<p role="alert">{html.escape(error)}</p>' if error else ""
    return f"""<!doctype html>
<html lang="en">
<head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>MyCogni synthetic login</title></head>
<body>
<main>
<p>MYCOGNI · SYNTHETIC ONLY</p>
<h1>Authenticate the local walkthrough</h1>
{error_html}
<p>Use the one-time synthetic operator code printed by the local developer command.
Never paste a real credential or personal data here.</p>
<form method="post" action="/login" autocomplete="off">
<input type="hidden" name="csrf_token" value="{safe_token}">
<label for="operator-code">Synthetic operator code</label>
<input id="operator-code" name="operator_code" type="password" inputmode="text"
       autocomplete="off" required>
<button type="submit">Continue</button>
</form>
<p><a href="/">Back to the safety boundary</a></p>
</main>
</body></html>"""


def _dashboard_page(view: AuthenticatedShellView) -> str:
    safe_token = html.escape(view.csrf_token, quote=True)
    return f"""<!doctype html>
<html lang="en">
<head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>MyCogni synthetic dashboard</title></head>
<body>
<main>
<p>MYCOGNI · AUTHENTICATED SYNTHETIC SHELL</p>
<h1>Nothing leaves this preview</h1>
<p>Actor: {html.escape(view.actor_label)}</p>
<p>Profile: {html.escape(view.profile_label)}</p>
<ul>
<li>real personal data: not accepted</li>
<li>broker observations: unavailable</li>
<li>mail/browser actions: unavailable</li>
<li>removal outcome: not applicable</li>
</ul>
<form method="post" action="/logout">
<input type="hidden" name="csrf_token" value="{safe_token}">
<button type="submit">Sign out</button>
</form>
</main>
</body></html>"""
