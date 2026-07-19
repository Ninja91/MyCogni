"""Fail-closed, process-local network guard for the pytest harness.

This is a language-level safety belt, not an operating-system sandbox.  The
only runtime capability it grants is TCP over IPv4 to numeric ``127.0.0.1``
from the currently executing, explicitly marked simulator test.
"""

from __future__ import annotations

import asyncio
import contextvars
import hashlib
import http.client
import os
import socket
import ssl
import urllib.request
from dataclasses import dataclass
from enum import StrEnum
from typing import Any, Final
from urllib.parse import SplitResult, urlsplit

LOOPBACK: Final = "127.0.0.1"
PROXY_ENV_NAMES: Final = frozenset(
    {
        "all_proxy",
        "http_proxy",
        "https_proxy",
        "no_proxy",
    }
)


class DenialCategory(StrEnum):
    DNS = "dns"
    SOCKET = "socket"
    TLS = "tls"
    PROXY = "proxy"
    URL = "url"
    POLICY = "policy"


class DenialReason(StrEnum):
    AUTHORITY_REVOKED = "authority_revoked"
    CAPABILITY_ABSENT = "capability_absent"
    DESCRIPTOR_FORBIDDEN = "descriptor_forbidden"
    DNS_FORBIDDEN = "dns_forbidden"
    FAMILY_FORBIDDEN = "family_forbidden"
    LOOPBACK_REQUIRED = "loopback_required"
    PORT_INVALID = "port_invalid"
    PROXY_FORBIDDEN = "proxy_forbidden"
    SCHEME_FORBIDDEN = "scheme_forbidden"
    SOCKET_TYPE_FORBIDDEN = "socket_type_forbidden"
    TLS_FORBIDDEN = "tls_forbidden"
    URL_INVALID = "url_invalid"


@dataclass(slots=True)
class _AuthorityLease:
    opaque_test_id: str
    simulator_loopback: bool
    active: bool = True


@dataclass(frozen=True, slots=True)
class AuthorityHandle:
    token: contextvars.Token[_AuthorityLease | None]
    lease: _AuthorityLease


_CONTEXT: contextvars.ContextVar[_AuthorityLease | None] = contextvars.ContextVar(
    "mycogni_network_test_context", default=None
)


class NetworkDenied(RuntimeError):
    """A finite, input-free network denial safe for local diagnostics."""

    __slots__ = ("category", "reason", "opaque_test_id")

    def __init__(self, category: DenialCategory, reason: DenialReason) -> None:
        context = _CONTEXT.get()
        test_id = "nt_unscoped" if context is None else context.opaque_test_id
        self.category = category
        self.reason = reason
        self.opaque_test_id = test_id
        super().__init__(
            f"network_denied category={category.value} reason={reason.value} test={test_id}"
        )


def opaque_test_id(nodeid: str) -> str:
    """Return a stable identifier without retaining the pytest node ID."""

    digest = hashlib.sha256(nodeid.encode("utf-8", errors="strict")).hexdigest()[:16]
    return f"nt_{digest}"


def activate_test(nodeid: str, *, simulator_loopback: bool) -> AuthorityHandle:
    lease = _AuthorityLease(opaque_test_id(nodeid), simulator_loopback)
    return AuthorityHandle(_CONTEXT.set(lease), lease)


def deactivate_test(handle: AuthorityHandle) -> None:
    revoke_test(handle)
    _CONTEXT.reset(handle.token)


def revoke_test(handle: AuthorityHandle) -> None:
    handle.lease.active = False


def _deny(category: DenialCategory, reason: DenialReason) -> None:
    raise NetworkDenied(category, reason)


def _require_capability() -> _AuthorityLease:
    lease = _CONTEXT.get()
    if lease is None or not lease.simulator_loopback:
        _deny(DenialCategory.POLICY, DenialReason.CAPABILITY_ABSENT)
    if not lease.active:
        _deny(DenialCategory.POLICY, DenialReason.AUTHORITY_REVOKED)
    return lease


def _proxy_configured() -> bool:
    return any(
        name.lower() in PROXY_ENV_NAMES and bool(value) for name, value in os.environ.items()
    )


def _require_no_proxy() -> None:
    if _proxy_configured():
        _deny(DenialCategory.PROXY, DenialReason.PROXY_FORBIDDEN)


def _port(value: object, *, allow_zero: bool) -> int:
    if isinstance(value, bool) or not isinstance(value, int):
        _deny(DenialCategory.SOCKET, DenialReason.PORT_INVALID)
    minimum = 0 if allow_zero else 1
    if not minimum <= value <= 65_535:
        _deny(DenialCategory.SOCKET, DenialReason.PORT_INVALID)
    return value


def _ipv4_address(address: object, *, allow_zero_port: bool) -> tuple[str, int]:
    if not isinstance(address, tuple) or len(address) != 2 or not isinstance(address[0], str):
        _deny(DenialCategory.SOCKET, DenialReason.FAMILY_FORBIDDEN)
    host = address[0]
    port = _port(address[1], allow_zero=allow_zero_port)
    if host != LOOPBACK:
        _deny(DenialCategory.SOCKET, DenialReason.LOOPBACK_REQUIRED)
    return host, port


def authorize_socket_address(
    family: int, address: object, *, allow_zero_port: bool = False
) -> tuple[str, int]:
    _require_capability()
    _require_no_proxy()
    if family != socket.AF_INET:
        _deny(DenialCategory.SOCKET, DenialReason.FAMILY_FORBIDDEN)
    return _ipv4_address(address, allow_zero_port=allow_zero_port)


def parse_local_http_url(value: object) -> SplitResult:
    _require_capability()
    _require_no_proxy()
    if not isinstance(value, str):
        _deny(DenialCategory.URL, DenialReason.URL_INVALID)
    try:
        parsed = urlsplit(value)
        port = parsed.port
    except (TypeError, UnicodeError, ValueError):
        _deny(DenialCategory.URL, DenialReason.URL_INVALID)
    if parsed.scheme != "http":
        _deny(DenialCategory.URL, DenialReason.SCHEME_FORBIDDEN)
    if (
        parsed.hostname != LOOPBACK
        or parsed.username is not None
        or parsed.password is not None
        or parsed.fragment
        or port is None
    ):
        _deny(DenialCategory.URL, DenialReason.URL_INVALID)
    _port(port, allow_zero=False)
    return parsed


_ORIGINAL_SOCKET = socket.socket
_ORIGINAL_SOCKET_TYPE = socket.SocketType
_ORIGINAL_SOCKETPAIR = socket.socketpair
_ORIGINAL_FROMFD = getattr(socket, "fromfd", None)
_ORIGINAL_FROMSHARE = getattr(socket, "fromshare", None)
_ORIGINAL_DUP = getattr(socket, "dup", None)
_ORIGINAL_CREATE_CONNECTION = socket.create_connection
_ORIGINAL_GETADDRINFO = socket.getaddrinfo
_ORIGINAL_GETHOSTBYNAME = socket.gethostbyname
_ORIGINAL_GETHOSTBYNAME_EX = socket.gethostbyname_ex
_ORIGINAL_GETHOSTBYADDR = socket.gethostbyaddr
_ORIGINAL_GETNAMEINFO = socket.getnameinfo
_ORIGINAL_ASYNCIO_OPEN_CONNECTION = asyncio.open_connection
_ORIGINAL_SSL_WRAP_SOCKET = ssl.SSLContext.wrap_socket
_ORIGINAL_SSL_WRAP_BIO = ssl.SSLContext.wrap_bio
_ORIGINAL_URLOPEN = urllib.request.urlopen
_ORIGINAL_OPENER_OPEN = urllib.request.OpenerDirector.open
_ORIGINAL_PROXY_HANDLER_INIT = urllib.request.ProxyHandler.__init__
_ORIGINAL_HTTP_CONNECT = http.client.HTTPConnection.connect


@dataclass(frozen=True, slots=True)
class _DescriptorGrant:
    lease: _AuthorityLease | None = None
    anonymous_pair: bool = False


_ADOPT_DESCRIPTOR: contextvars.ContextVar[_DescriptorGrant | None] = contextvars.ContextVar(
    "mycogni_guarded_descriptor_adoption", default=None
)


def guarded_getaddrinfo(*args: object, **kwargs: object) -> list[Any]:
    _deny(DenialCategory.DNS, DenialReason.DNS_FORBIDDEN)


def guarded_gethostbyname(*args: object, **kwargs: object) -> str:
    _deny(DenialCategory.DNS, DenialReason.DNS_FORBIDDEN)


def guarded_gethostbyname_ex(*args: object, **kwargs: object) -> tuple[str, list[str], list[str]]:
    _deny(DenialCategory.DNS, DenialReason.DNS_FORBIDDEN)


def guarded_gethostbyaddr(*args: object, **kwargs: object) -> tuple[str, list[str], list[str]]:
    _deny(DenialCategory.DNS, DenialReason.DNS_FORBIDDEN)


def guarded_getnameinfo(*args: object, **kwargs: object) -> tuple[str, str]:
    _deny(DenialCategory.DNS, DenialReason.DNS_FORBIDDEN)


class GuardedSocket(_ORIGINAL_SOCKET):
    """Socket whose address-bearing operations are policy checked first."""

    def __init__(self, *args: Any, **kwargs: Any) -> None:
        fileno = kwargs.get("fileno")
        if fileno is None and len(args) >= 4:
            fileno = args[3]
        grant = _ADOPT_DESCRIPTOR.get()
        if fileno is not None and grant is None:
            _deny(DenialCategory.SOCKET, DenialReason.DESCRIPTOR_FORBIDDEN)
        super().__init__(*args, **kwargs)
        self._mycogni_lease = None if grant is None else grant.lease
        self._mycogni_anonymous_pair = bool(grant and grant.anonymous_pair)

    def _require_descriptor(self) -> None:
        if self._mycogni_anonymous_pair:
            return
        lease = self._mycogni_lease
        if lease is None:
            _deny(DenialCategory.SOCKET, DenialReason.DESCRIPTOR_FORBIDDEN)
        if not lease.active:
            _deny(DenialCategory.POLICY, DenialReason.AUTHORITY_REVOKED)

    def _require_tcp_ipv4(self) -> None:
        if self.family != socket.AF_INET:
            _deny(DenialCategory.SOCKET, DenialReason.FAMILY_FORBIDDEN)
        if self.type & 0xF != socket.SOCK_STREAM:
            _deny(DenialCategory.SOCKET, DenialReason.SOCKET_TYPE_FORBIDDEN)

    def _attach_current_lease(self) -> _AuthorityLease:
        lease = _require_capability()
        self._mycogni_lease = lease
        return lease

    def connect(self, address: object) -> None:
        self._require_tcp_ipv4()
        authorize_socket_address(self.family, address)
        self._attach_current_lease()
        return super().connect(address)  # type: ignore[arg-type, no-any-return]

    def connect_ex(self, address: object) -> int:
        self._require_tcp_ipv4()
        authorize_socket_address(self.family, address)
        self._attach_current_lease()
        return super().connect_ex(address)  # type: ignore[arg-type, no-any-return]

    def bind(self, address: object) -> None:
        self._require_tcp_ipv4()
        authorize_socket_address(self.family, address, allow_zero_port=True)
        self._attach_current_lease()
        return super().bind(address)  # type: ignore[arg-type, no-any-return]

    def listen(self, backlog: int = 0) -> None:
        self._require_descriptor()
        self._require_tcp_ipv4()
        _ipv4_address(self.getsockname(), allow_zero_port=True)
        return super().listen(backlog)

    def accept(self) -> tuple[GuardedSocket, Any]:
        self._require_descriptor()
        self._require_tcp_ipv4()
        descriptor, address = self._accept()
        try:
            _ipv4_address(address, allow_zero_port=False)
            grant = _DescriptorGrant(lease=self._mycogni_lease)
            token = _ADOPT_DESCRIPTOR.set(grant)
            try:
                accepted = GuardedSocket(
                    self.family,
                    self.type,
                    self.proto,
                    fileno=descriptor,
                )
            finally:
                _ADOPT_DESCRIPTOR.reset(token)
        except BaseException:
            _ORIGINAL_SOCKET(fileno=descriptor).close()
            raise
        accepted.settimeout(self.gettimeout())
        return accepted, address

    def send(self, data: Any, *args: Any) -> int:
        self._require_descriptor()
        return super().send(data, *args)

    def sendall(self, data: Any, *args: Any) -> None:
        self._require_descriptor()
        return super().sendall(data, *args)

    def recv(self, bufsize: int, *args: Any) -> bytes:
        self._require_descriptor()
        return super().recv(bufsize, *args)

    def recv_into(self, buffer: Any, *args: Any) -> int:
        self._require_descriptor()
        return super().recv_into(buffer, *args)

    def recvfrom(self, bufsize: int, *args: Any) -> Any:
        self._require_descriptor()
        return super().recvfrom(bufsize, *args)

    def recvmsg(self, *args: Any, **kwargs: Any) -> Any:
        self._require_descriptor()
        return super().recvmsg(*args, **kwargs)

    def shutdown(self, how: int) -> None:
        self._require_descriptor()
        return super().shutdown(how)

    def sendfile(self, file: Any, *args: Any, **kwargs: Any) -> int:
        self._require_descriptor()
        return super().sendfile(file, *args, **kwargs)

    def sendto(self, data: Any, *args: Any) -> int:
        _deny(DenialCategory.SOCKET, DenialReason.SOCKET_TYPE_FORBIDDEN)

    def sendmsg(self, *args: Any, **kwargs: Any) -> int:
        _deny(DenialCategory.SOCKET, DenialReason.FAMILY_FORBIDDEN)

    def dup(self) -> GuardedSocket:
        _deny(DenialCategory.SOCKET, DenialReason.DESCRIPTOR_FORBIDDEN)

    def detach(self) -> int:
        _deny(DenialCategory.SOCKET, DenialReason.DESCRIPTOR_FORBIDDEN)


def guarded_socketpair(*args: Any, **kwargs: Any) -> tuple[socket.socket, socket.socket]:
    token = _ADOPT_DESCRIPTOR.set(_DescriptorGrant(anonymous_pair=True))
    try:
        left, right = _ORIGINAL_SOCKETPAIR(*args, **kwargs)
    finally:
        _ADOPT_DESCRIPTOR.reset(token)
    if not isinstance(left, GuardedSocket) or not isinstance(right, GuardedSocket):
        left.close()
        right.close()
        raise RuntimeError("network guard socketpair wrapping failure")
    return left, right


def guarded_fromfd(*args: Any, **kwargs: Any) -> socket.socket:
    _deny(DenialCategory.SOCKET, DenialReason.DESCRIPTOR_FORBIDDEN)


def guarded_fromshare(*args: Any, **kwargs: Any) -> socket.socket:
    _deny(DenialCategory.SOCKET, DenialReason.DESCRIPTOR_FORBIDDEN)


def guarded_dup(*args: Any, **kwargs: Any) -> int:
    _deny(DenialCategory.SOCKET, DenialReason.DESCRIPTOR_FORBIDDEN)


def guarded_create_connection(
    address: object,
    timeout: object = socket._GLOBAL_DEFAULT_TIMEOUT,
    source_address: object | None = None,
    *,
    all_errors: bool = False,
) -> socket.socket:
    _require_capability()
    _require_no_proxy()
    destination = _ipv4_address(address, allow_zero_port=False)
    if source_address is not None:
        _ipv4_address(source_address, allow_zero_port=True)
    failures: list[OSError] = []
    candidate = GuardedSocket(socket.AF_INET, socket.SOCK_STREAM)
    try:
        if timeout is not socket._GLOBAL_DEFAULT_TIMEOUT:
            candidate.settimeout(timeout)  # type: ignore[arg-type]
        if source_address is not None:
            candidate.bind(source_address)
        candidate.connect(destination)
        return candidate
    except OSError as error:
        failures.append(error)
        candidate.close()
    if all_errors:
        raise ExceptionGroup("loopback connection failed", failures)
    raise failures[-1]


async def guarded_asyncio_open_connection(
    host: object | None = None,
    port: object | None = None,
    *args: object,
    **kwargs: object,
) -> tuple[asyncio.StreamReader, asyncio.StreamWriter]:
    if kwargs.get("ssl") not in (None, False):
        _deny(DenialCategory.TLS, DenialReason.TLS_FORBIDDEN)
    if kwargs.get("server_hostname") is not None:
        _deny(DenialCategory.TLS, DenialReason.TLS_FORBIDDEN)
    if host is None and "sock" in kwargs:
        _deny(DenialCategory.SOCKET, DenialReason.FAMILY_FORBIDDEN)
    destination = authorize_socket_address(socket.AF_INET, (host, port))
    candidate = GuardedSocket(socket.AF_INET, socket.SOCK_STREAM)
    candidate.setblocking(False)
    try:
        await asyncio.get_running_loop().sock_connect(candidate, destination)
        return await _ORIGINAL_ASYNCIO_OPEN_CONNECTION(
            *args,
            sock=candidate,
            **kwargs,  # type: ignore[arg-type]
        )
    except BaseException:
        candidate.close()
        raise


def guarded_ssl_wrap_socket(self: ssl.SSLContext, *args: object, **kwargs: object) -> Any:
    _deny(DenialCategory.TLS, DenialReason.TLS_FORBIDDEN)


def guarded_ssl_wrap_bio(self: ssl.SSLContext, *args: object, **kwargs: object) -> Any:
    _deny(DenialCategory.TLS, DenialReason.TLS_FORBIDDEN)


def _request_url(value: object) -> str:
    if isinstance(value, urllib.request.Request):
        return value.full_url
    if isinstance(value, str):
        return value
    _deny(DenialCategory.URL, DenialReason.URL_INVALID)


def guarded_urlopen(url: object, *args: object, **kwargs: object) -> Any:
    parse_local_http_url(_request_url(url))
    return _ORIGINAL_URLOPEN(url, *args, **kwargs)


def guarded_opener_open(
    self: urllib.request.OpenerDirector, fullurl: object, *args: object, **kwargs: object
) -> Any:
    parse_local_http_url(_request_url(fullurl))
    return _ORIGINAL_OPENER_OPEN(self, fullurl, *args, **kwargs)


def guarded_proxy_handler_init(
    self: urllib.request.ProxyHandler, proxies: object | None = None
) -> None:
    if proxies:
        _deny(DenialCategory.PROXY, DenialReason.PROXY_FORBIDDEN)
    _ORIGINAL_PROXY_HANDLER_INIT(self, {})


def guarded_http_connect(self: http.client.HTTPConnection) -> None:
    authorize_socket_address(socket.AF_INET, (self.host, self.port))
    return _ORIGINAL_HTTP_CONNECT(self)


_HTTPX_PATCHES: list[tuple[type[Any], str, Any]] = []
_HTTPX_EXPECTED: list[tuple[type[Any], str, Any]] = []
_INSTALLED = False
_SCRUBBED_PROXY_ENV: dict[str, str] = {}


def _install_httpx_guards() -> None:
    try:
        import httpx
    except ImportError:
        return

    def guard_init(original: Any) -> Any:
        def wrapped(self: object, *args: object, **kwargs: object) -> None:
            if kwargs.get("proxy") is not None or kwargs.get("mounts"):
                _deny(DenialCategory.PROXY, DenialReason.PROXY_FORBIDDEN)
            original(self, *args, **kwargs)

        return wrapped

    def guard_send(original: Any) -> Any:
        def wrapped(self: object, request: object, *args: object, **kwargs: object) -> Any:
            parse_local_http_url(str(getattr(request, "url", "")))
            return original(self, request, *args, **kwargs)

        return wrapped

    async def async_send(
        original: Any, self: object, request: object, *args: object, **kwargs: object
    ) -> Any:
        parse_local_http_url(str(getattr(request, "url", "")))
        return await original(self, request, *args, **kwargs)

    def guard_async_send(original: Any) -> Any:
        async def wrapped(self: object, request: object, *args: object, **kwargs: object) -> Any:
            return await async_send(original, self, request, *args, **kwargs)

        return wrapped

    patches = (
        (httpx.Client, "__init__", guard_init(httpx.Client.__init__)),
        (httpx.AsyncClient, "__init__", guard_init(httpx.AsyncClient.__init__)),
        (httpx.Client, "_send_single_request", guard_send(httpx.Client._send_single_request)),
        (
            httpx.AsyncClient,
            "_send_single_request",
            guard_async_send(httpx.AsyncClient._send_single_request),
        ),
    )
    for owner, name, replacement in patches:
        _HTTPX_PATCHES.append((owner, name, getattr(owner, name)))
        _HTTPX_EXPECTED.append((owner, name, replacement))
        setattr(owner, name, replacement)


def scrub_proxy_environment() -> None:
    for name in tuple(os.environ):
        if name.lower() in PROXY_ENV_NAMES:
            _SCRUBBED_PROXY_ENV[name] = os.environ.pop(name)


def install() -> None:
    global _INSTALLED
    if _INSTALLED:
        raise RuntimeError("network guard already installed")
    scrub_proxy_environment()
    socket.socket = GuardedSocket
    socket.SocketType = GuardedSocket
    socket.socketpair = guarded_socketpair
    if _ORIGINAL_FROMFD is not None:
        socket.fromfd = guarded_fromfd
    if _ORIGINAL_FROMSHARE is not None:
        socket.fromshare = guarded_fromshare
    if _ORIGINAL_DUP is not None:
        socket.dup = guarded_dup
    socket.create_connection = guarded_create_connection
    socket.getaddrinfo = guarded_getaddrinfo
    socket.gethostbyname = guarded_gethostbyname
    socket.gethostbyname_ex = guarded_gethostbyname_ex
    socket.gethostbyaddr = guarded_gethostbyaddr
    socket.getnameinfo = guarded_getnameinfo
    asyncio.open_connection = guarded_asyncio_open_connection
    ssl.SSLContext.wrap_socket = guarded_ssl_wrap_socket
    ssl.SSLContext.wrap_bio = guarded_ssl_wrap_bio
    urllib.request.urlopen = guarded_urlopen
    urllib.request.OpenerDirector.open = guarded_opener_open
    urllib.request.ProxyHandler.__init__ = guarded_proxy_handler_init
    http.client.HTTPConnection.connect = guarded_http_connect
    _install_httpx_guards()
    _INSTALLED = True


def integrity_bindings() -> tuple[tuple[object, str, object], ...]:
    """Return every monkey-patched binding covered by the integrity check."""

    expected = (
        (socket, "socket", GuardedSocket),
        (socket, "SocketType", GuardedSocket),
        (socket, "socketpair", guarded_socketpair),
        (socket, "create_connection", guarded_create_connection),
        (socket, "getaddrinfo", guarded_getaddrinfo),
        (socket, "gethostbyname", guarded_gethostbyname),
        (socket, "gethostbyname_ex", guarded_gethostbyname_ex),
        (socket, "gethostbyaddr", guarded_gethostbyaddr),
        (socket, "getnameinfo", guarded_getnameinfo),
        (asyncio, "open_connection", guarded_asyncio_open_connection),
        (ssl.SSLContext, "wrap_socket", guarded_ssl_wrap_socket),
        (ssl.SSLContext, "wrap_bio", guarded_ssl_wrap_bio),
        (urllib.request, "urlopen", guarded_urlopen),
        (urllib.request.OpenerDirector, "open", guarded_opener_open),
        (urllib.request.ProxyHandler, "__init__", guarded_proxy_handler_init),
        (http.client.HTTPConnection, "connect", guarded_http_connect),
    )
    optional = []
    if _ORIGINAL_FROMFD is not None:
        optional.append((socket, "fromfd", guarded_fromfd))
    if _ORIGINAL_FROMSHARE is not None:
        optional.append((socket, "fromshare", guarded_fromshare))
    if _ORIGINAL_DUP is not None:
        optional.append((socket, "dup", guarded_dup))
    return (*expected, *optional, *_HTTPX_EXPECTED)


def assert_installed() -> None:
    if not _INSTALLED or any(
        getattr(owner, name) is not value for owner, name, value in integrity_bindings()
    ):
        raise RuntimeError("network guard integrity failure")


def uninstall() -> None:
    global _INSTALLED
    if not _INSTALLED:
        return
    integrity_error: RuntimeError | None = None
    try:
        assert_installed()
    except RuntimeError as error:
        integrity_error = error
    finally:
        socket.socket = _ORIGINAL_SOCKET
        socket.SocketType = _ORIGINAL_SOCKET_TYPE
        socket.socketpair = _ORIGINAL_SOCKETPAIR
        if _ORIGINAL_FROMFD is not None:
            socket.fromfd = _ORIGINAL_FROMFD
        if _ORIGINAL_FROMSHARE is not None:
            socket.fromshare = _ORIGINAL_FROMSHARE
        if _ORIGINAL_DUP is not None:
            socket.dup = _ORIGINAL_DUP
        socket.create_connection = _ORIGINAL_CREATE_CONNECTION
        socket.getaddrinfo = _ORIGINAL_GETADDRINFO
        socket.gethostbyname = _ORIGINAL_GETHOSTBYNAME
        socket.gethostbyname_ex = _ORIGINAL_GETHOSTBYNAME_EX
        socket.gethostbyaddr = _ORIGINAL_GETHOSTBYADDR
        socket.getnameinfo = _ORIGINAL_GETNAMEINFO
        asyncio.open_connection = _ORIGINAL_ASYNCIO_OPEN_CONNECTION
        ssl.SSLContext.wrap_socket = _ORIGINAL_SSL_WRAP_SOCKET
        ssl.SSLContext.wrap_bio = _ORIGINAL_SSL_WRAP_BIO
        urllib.request.urlopen = _ORIGINAL_URLOPEN
        urllib.request.OpenerDirector.open = _ORIGINAL_OPENER_OPEN
        urllib.request.ProxyHandler.__init__ = _ORIGINAL_PROXY_HANDLER_INIT
        http.client.HTTPConnection.connect = _ORIGINAL_HTTP_CONNECT
        for owner, name, original in reversed(_HTTPX_PATCHES):
            setattr(owner, name, original)
        _HTTPX_PATCHES.clear()
        _HTTPX_EXPECTED.clear()
        os.environ.update(_SCRUBBED_PROXY_ENV)
        _SCRUBBED_PROXY_ENV.clear()
        _INSTALLED = False
    if integrity_error is not None:
        raise integrity_error
