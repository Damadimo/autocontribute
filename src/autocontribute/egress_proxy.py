"""An allowlisting HTTP forward proxy for the networked setup container (DESIGN §5.2).

Setup runs repository install scripts with network access. Its container sits on an internal
Docker network whose only way out is this proxy, which runs in a container of its own that is
also attached to the default bridge. It opens CONNECT tunnels to port 443 and forwards plain
GET and HEAD requests to port 80 (Debian's package mirrors), and only for allowlisted host names.
IP literals and names that resolve only to non-public addresses are refused, so setup reaches
neither the Docker host and its VM nor a cloud metadata service.

The setup runner hands this file's source to ``python3 -c`` in a pinned python:3.12-alpine
image, so it uses nothing but the standard library of Python 3.12.
"""

from __future__ import annotations

import argparse
import asyncio
import base64
import ipaddress
import os
import socket
from collections.abc import Iterable, Mapping, Sequence
from contextlib import suppress
from dataclasses import dataclass
from typing import Final
from urllib.parse import SplitResult, unquote, urlsplit

LISTEN_PORT: Final = 3128
READY_MESSAGE: Final = "egress proxy listening"
_MAX_HEAD_BYTES: Final = 16_384
_MAX_HEADERS: Final = 100
_HEAD_TIMEOUT_SECONDS: Final = 30.0
_CONNECT_TIMEOUT_SECONDS: Final = 15.0
# A tunnel or download with no bytes in either direction for this long is closed.
_IDLE_TIMEOUT_SECONDS: Final = 120.0
_IDLE_CHECK_SECONDS: Final = 5.0
_CHUNK_BYTES: Final = 65_536
_DEFAULT_MAX_CONNECTIONS: Final = 64
_MAX_LOGGED_CHARACTERS: Final = 300
_TUNNEL_PORT: Final = 443
_PLAIN_HTTP_PORT: Final = 80
_HOP_BY_HOP_HEADERS: Final = frozenset(
    {
        "connection",
        "keep-alive",
        "proxy-authenticate",
        "proxy-authorization",
        "proxy-connection",
        "te",
        "trailer",
        "transfer-encoding",
        "upgrade",
    }
)
_REASONS: Final = {
    400: "Bad Request",
    403: "Forbidden",
    405: "Method Not Allowed",
    431: "Request Header Fields Too Large",
    502: "Bad Gateway",
    503: "Service Unavailable",
    504: "Gateway Timeout",
}


class ProxyRefusal(Exception):
    """A request the proxy answers with an error status instead of forwarding."""

    def __init__(self, status: int, reason: str) -> None:
        super().__init__(reason)
        self.status = status
        self.reason = reason


@dataclass(frozen=True, slots=True)
class Upstream:
    """The operator's own proxy, through which every forwarded request leaves."""

    host: str
    port: int
    authorization: str | None

    @classmethod
    def from_environment(cls, environment: Mapping[str, str], name: str) -> Upstream | None:
        """Read ``NAME`` or ``name`` (for example HTTPS_PROXY); only http:// proxies work."""

        url = environment.get(name) or environment.get(name.lower())
        if not url:
            return None
        parsed = urlsplit(url if "://" in url else f"http://{url}")
        if parsed.scheme != "http" or not parsed.hostname:
            raise ValueError(f"{name} must be an http:// proxy URL")
        authorization = None
        if parsed.username is not None:
            credentials = f"{unquote(parsed.username)}:{unquote(parsed.password or '')}"
            authorization = "Basic " + base64.b64encode(credentials.encode()).decode("ascii")
        return cls(parsed.hostname, parsed.port or 8080, authorization)

    def header(self) -> str:
        if self.authorization is None:
            return ""
        return f"Proxy-Authorization: {self.authorization}\r\n"


class EgressProxy:
    """Forward allowlisted requests directly or through the operator's proxy."""

    def __init__(
        self,
        allowed_hosts: Iterable[str],
        *,
        max_connections: int = _DEFAULT_MAX_CONNECTIONS,
        https_upstream: Upstream | None = None,
        http_upstream: Upstream | None = None,
    ) -> None:
        self.allowed_hosts = frozenset(host.rstrip(".").lower() for host in allowed_hosts)
        self.max_connections = max_connections
        self.https_upstream = https_upstream
        self.http_upstream = http_upstream
        self._active = 0

    async def start(self, host: str, port: int) -> asyncio.Server:
        return await asyncio.start_server(self._serve, host, port, limit=_MAX_HEAD_BYTES)

    async def _serve(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
        if self._active >= self.max_connections:
            # Reading the request first lets the client see the answer instead of a reset.
            with suppress(ProxyRefusal, OSError, asyncio.IncompleteReadError, TimeoutError):
                await _read_request(reader)
            await _respond(writer, 503, "too many connections")
            writer.close()
            return
        self._active += 1
        try:
            await self._handle(reader, writer)
        except ProxyRefusal as refusal:
            await _respond(writer, refusal.status, refusal.reason)
        except (OSError, asyncio.IncompleteReadError, TimeoutError):
            pass
        finally:
            self._active -= 1
            writer.close()
            with suppress(OSError):
                await writer.wait_closed()

    async def _handle(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
        method, target, headers = await _read_request(reader)
        try:
            server_reader, server_writer = await self._connect(method, target, headers)
        except ProxyRefusal as refusal:
            _log("deny", method, target, refusal.reason)
            raise
        _log("allow", method, target, "")
        try:
            if method == "CONNECT":
                writer.write(b"HTTP/1.1 200 Connection established\r\n\r\n")
                await writer.drain()
            # A GET or HEAD sends nothing after its head. Relaying what follows would let a
            # second request reach the operator's proxy without the allowlist check.
            await _relay(reader, writer, server_reader, server_writer, upload=method == "CONNECT")
        finally:
            server_writer.close()

    async def _connect(
        self, method: str, target: str, headers: Sequence[tuple[str, str]]
    ) -> tuple[asyncio.StreamReader, asyncio.StreamWriter]:
        if method == "CONNECT":
            host, port = _authority(target)
            name = self._allowed_name(method, host, port, _TUNNEL_PORT)
            return await self._open_tunnel(name, port)
        if method in {"GET", "HEAD"}:
            url = _absolute_http_url(target)
            name = self._allowed_name(method, url.hostname or "", _port(url), _PLAIN_HTTP_PORT)
            if any(header in {"content-length", "transfer-encoding"} for header, _ in headers):
                raise ProxyRefusal(400, "GET and HEAD requests cannot carry a body")
            path = (url.path or "/") + (f"?{url.query}" if url.query else "")
            return await self._open_plain(method, name, path, headers)
        raise ProxyRefusal(405, "only CONNECT, GET and HEAD are forwarded")

    def _allowed_name(self, method: str, host: str, port: int, allowed_port: int) -> str:
        """Return the allowlisted host name a request may reach, or refuse the request."""

        name = host.rstrip(".").lower()
        if _is_ip_literal(name):
            raise ProxyRefusal(403, "IP addresses are refused; use a host name")
        if name not in self.allowed_hosts:
            raise ProxyRefusal(403, "the host is not on the setup allowlist")
        if port != allowed_port:
            raise ProxyRefusal(403, f"{method} is allowed to port {allowed_port} only")
        return name

    async def _open_tunnel(
        self, host: str, port: int
    ) -> tuple[asyncio.StreamReader, asyncio.StreamWriter]:
        upstream = self.https_upstream
        if upstream is None:
            return await _open_public(host, port)
        reader, writer = await _open(upstream.host, upstream.port)
        writer.write(
            (
                f"CONNECT {host}:{port} HTTP/1.1\r\nHost: {host}:{port}\r\n{upstream.header()}\r\n"
            ).encode("latin-1")
        )
        await writer.drain()
        try:
            response = await asyncio.wait_for(reader.readuntil(b"\r\n\r\n"), _HEAD_TIMEOUT_SECONDS)
        except (asyncio.IncompleteReadError, asyncio.LimitOverrunError, TimeoutError) as exc:
            writer.close()
            raise ProxyRefusal(502, "the upstream proxy did not answer the tunnel request") from exc
        status = response.split(b"\r\n", 1)[0].split(b" ")
        if len(status) < 2 or status[1] != b"200":
            writer.close()
            raise ProxyRefusal(502, "the upstream proxy refused the tunnel")
        return reader, writer

    async def _open_plain(
        self, method: str, host: str, path: str, headers: Sequence[tuple[str, str]]
    ) -> tuple[asyncio.StreamReader, asyncio.StreamWriter]:
        upstream = self.http_upstream
        if upstream is None:
            reader, writer = await _open_public(host, _PLAIN_HTTP_PORT)
            request_target = path
        else:
            reader, writer = await _open(upstream.host, upstream.port)
            request_target = f"http://{host}{path}"
        forwarded = "".join(
            f"{name}: {value}\r\n"
            for name, value in headers
            if name not in _HOP_BY_HOP_HEADERS and name != "host"
        )
        writer.write(
            (
                f"{method} {request_target} HTTP/1.1\r\nHost: {host}\r\n{forwarded}"
                f"{'' if upstream is None else upstream.header()}Connection: close\r\n\r\n"
            ).encode("latin-1")
        )
        await writer.drain()
        return reader, writer


async def _read_request(
    reader: asyncio.StreamReader,
) -> tuple[str, str, list[tuple[str, str]]]:
    try:
        head = await asyncio.wait_for(reader.readuntil(b"\r\n\r\n"), _HEAD_TIMEOUT_SECONDS)
    except asyncio.LimitOverrunError as exc:
        raise ProxyRefusal(431, "the request head is too large") from exc
    lines = head.decode("latin-1").split("\r\n")
    if any(character in line for line in lines for character in "\r\n\0"):
        # A bare line break would let one header smuggle another into the forwarded request.
        raise ProxyRefusal(400, "control characters in the request head")
    parts = lines[0].split(" ")
    if len(parts) != 3 or not parts[2].startswith("HTTP/1."):
        raise ProxyRefusal(400, "malformed request line")
    fields = [line for line in lines[1:] if line]
    if len(fields) > _MAX_HEADERS:
        raise ProxyRefusal(431, "too many request headers")
    headers: list[tuple[str, str]] = []
    for field in fields:
        name, separator, value = field.partition(":")
        if not separator or not name or name != name.strip():
            raise ProxyRefusal(400, "malformed request header")
        headers.append((name.lower(), value.strip()))
    return parts[0], parts[1], headers


def _authority(target: str) -> tuple[str, int]:
    parsed = urlsplit(f"//{target}")
    if not parsed.hostname or parsed.path or parsed.query or parsed.username:
        raise ProxyRefusal(400, "CONNECT needs a host:port target")
    port = _port(parsed)
    return parsed.hostname, port


def _absolute_http_url(target: str) -> SplitResult:
    url = urlsplit(target)
    if url.scheme.lower() != "http" or not url.hostname or url.username is not None:
        raise ProxyRefusal(400, "plain requests need an absolute http:// URL")
    return url


def _port(url: SplitResult) -> int:
    try:
        port = url.port
    except ValueError as exc:
        raise ProxyRefusal(400, "invalid port") from exc
    if port is None:
        if url.scheme:
            return _PLAIN_HTTP_PORT
        raise ProxyRefusal(400, "CONNECT needs a host:port target")
    return port


def _is_ip_literal(host: str) -> bool:
    try:
        ipaddress.ip_address(host.strip("[]").split("%", 1)[0])
    except ValueError:
        return False
    return True


async def _open_public(host: str, port: int) -> tuple[asyncio.StreamReader, asyncio.StreamWriter]:
    """Connect to a public address of ``host``; a private answer cannot reach the host network."""

    loop = asyncio.get_running_loop()
    try:
        answers = await asyncio.wait_for(
            loop.getaddrinfo(host, port, type=socket.SOCK_STREAM), _CONNECT_TIMEOUT_SECONDS
        )
    except (OSError, TimeoutError) as exc:
        raise ProxyRefusal(502, f"could not resolve {host}") from exc
    addresses = [str(answer[4][0]) for answer in answers]
    public = [
        address
        for address in dict.fromkeys(addresses)
        if ipaddress.ip_address(address.split("%", 1)[0]).is_global
    ]
    if not public:
        raise ProxyRefusal(403, f"{host} resolves only to non-public addresses")
    failure: Exception | None = None
    for address in public:
        try:
            return await _open(address, port)
        except ProxyRefusal as refusal:
            failure = refusal
    raise ProxyRefusal(502, f"could not connect to {host}") from failure


async def _open(host: str, port: int) -> tuple[asyncio.StreamReader, asyncio.StreamWriter]:
    try:
        return await asyncio.wait_for(
            asyncio.open_connection(host, port, limit=_MAX_HEAD_BYTES), _CONNECT_TIMEOUT_SECONDS
        )
    except TimeoutError as exc:
        raise ProxyRefusal(504, f"connecting to {host}:{port} timed out") from exc
    except OSError as exc:
        raise ProxyRefusal(502, f"could not connect to {host}:{port}") from exc


async def _relay(
    client_reader: asyncio.StreamReader,
    client_writer: asyncio.StreamWriter,
    server_reader: asyncio.StreamReader,
    server_writer: asyncio.StreamWriter,
    *,
    upload: bool,
) -> None:
    """Copy the server's bytes to the client, and the client's to the server when ``upload``.

    Stops when every direction finishes or nothing moves for a while.
    """

    loop = asyncio.get_running_loop()
    last_activity = loop.time()

    async def pump(source: asyncio.StreamReader, sink: asyncio.StreamWriter) -> None:
        nonlocal last_activity
        try:
            while data := await source.read(_CHUNK_BYTES):
                last_activity = loop.time()
                sink.write(data)
                await sink.drain()
        finally:
            # A half-close keeps the other direction open, as HTTP clients expect.
            if sink.can_write_eof():
                with suppress(OSError, RuntimeError):
                    sink.write_eof()

    tasks = {asyncio.create_task(pump(server_reader, client_writer))}
    if upload:
        tasks.add(asyncio.create_task(pump(client_reader, server_writer)))
    pending = tasks
    while pending:
        _, pending = await asyncio.wait(pending, timeout=_IDLE_CHECK_SECONDS)
        if pending and loop.time() - last_activity > _IDLE_TIMEOUT_SECONDS:
            for task in pending:
                task.cancel()
            break
    await asyncio.gather(*tasks, return_exceptions=True)


async def _respond(writer: asyncio.StreamWriter, status: int, reason: str) -> None:
    body = f"{reason}\n".encode()
    writer.write(
        (
            f"HTTP/1.1 {status} {_REASONS.get(status, 'Error')}\r\n"
            f"Content-Type: text/plain\r\nContent-Length: {len(body)}\r\n"
            "Connection: close\r\n\r\n"
        ).encode("latin-1")
        + body
    )
    with suppress(OSError):
        await writer.drain()


def _log(decision: str, method: str, target: str, reason: str) -> None:
    # The target comes from repository code, so it is made printable and short.
    shown = "".join(c if c.isprintable() else "?" for c in target)[:_MAX_LOGGED_CHARACTERS]
    print(f"{decision} {method} {shown}{f': {reason}' if reason else ''}", flush=True)


async def _serve_forever(proxy: EgressProxy) -> None:
    server = await proxy.start("0.0.0.0", LISTEN_PORT)
    print(READY_MESSAGE, flush=True)
    async with server:
        await server.serve_forever()


def main(argv: Sequence[str] | None = None) -> None:
    parser = argparse.ArgumentParser(prog="egress-proxy")
    parser.add_argument("--allow", action="append", default=[], metavar="HOST")
    arguments = parser.parse_args(argv)
    proxy = EgressProxy(
        arguments.allow,
        https_upstream=Upstream.from_environment(os.environ, "HTTPS_PROXY"),
        http_upstream=Upstream.from_environment(os.environ, "HTTP_PROXY"),
    )
    asyncio.run(_serve_forever(proxy))


if __name__ == "__main__":
    main()
