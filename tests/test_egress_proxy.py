from __future__ import annotations

import asyncio
import base64
from collections.abc import Awaitable, Callable

import pytest

from autocontribute.egress_proxy import EgressProxy, Upstream

_UPSTREAM_AUTHORIZATION = "Basic " + base64.b64encode(b"operator:s3cret").decode()


class _FakeUpstream:
    """An operator proxy that records request heads, tunnels by echoing, and answers GETs."""

    def __init__(self) -> None:
        self.heads: list[str] = []

    async def handle(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
        head = (await reader.readuntil(b"\r\n\r\n")).decode("latin-1")
        self.heads.append(head)
        if head.startswith("CONNECT "):
            writer.write(b"HTTP/1.1 200 Connection established\r\n\r\n")
            while data := await reader.read(1024):
                writer.write(data.upper())
                await writer.drain()
        else:
            writer.write(b"HTTP/1.1 200 OK\r\nContent-Length: 5\r\nConnection: close\r\n\r\nhello")
            await writer.drain()
        writer.close()


async def _exchange(port: int, request: bytes, *, then: bytes = b"") -> bytes:
    reader, writer = await asyncio.open_connection("127.0.0.1", port)
    writer.write(request)
    await writer.drain()
    response = await reader.readuntil(b"\r\n\r\n")
    if then:
        writer.write(then)
        await writer.drain()
        writer.write_eof()
    response += await asyncio.wait_for(reader.read(), 5)
    writer.close()
    return response


def _run(
    scenario: Callable[[int, _FakeUpstream], Awaitable[None]],
    *,
    allowed: tuple[str, ...] = ("pypi.org", "deb.debian.org"),
    upstream: bool = True,
    max_connections: int = 8,
) -> _FakeUpstream:
    fake = _FakeUpstream()

    async def main() -> None:
        upstream_server = await asyncio.start_server(fake.handle, "127.0.0.1", 0)
        upstream_port = upstream_server.sockets[0].getsockname()[1]
        operator = Upstream("127.0.0.1", upstream_port, _UPSTREAM_AUTHORIZATION)
        proxy = EgressProxy(
            allowed,
            max_connections=max_connections,
            https_upstream=operator if upstream else None,
            http_upstream=operator if upstream else None,
        )
        server = await proxy.start("127.0.0.1", 0)
        try:
            await scenario(server.sockets[0].getsockname()[1], fake)
        finally:
            server.close()
            upstream_server.close()

    asyncio.run(main())
    return fake


def test_allowlisted_tunnel_reaches_port_443_through_the_operator_proxy() -> None:
    async def scenario(port: int, _fake: _FakeUpstream) -> None:
        response = await _exchange(
            port,
            b"CONNECT PyPI.org.:443 HTTP/1.1\r\nHost: pypi.org:443\r\n\r\n",
            then=b"client hello",
        )
        assert response.startswith(b"HTTP/1.1 200 Connection established\r\n\r\n")
        assert response.endswith(b"CLIENT HELLO")

    fake = _run(scenario)

    assert fake.heads == [
        "CONNECT pypi.org:443 HTTP/1.1\r\nHost: pypi.org:443\r\n"
        f"Proxy-Authorization: {_UPSTREAM_AUTHORIZATION}\r\n\r\n"
    ]


@pytest.mark.parametrize(
    ("request_line", "reason"),
    [
        ("CONNECT evil.example:443", b"not on the setup allowlist"),
        ("CONNECT pypi.org.evil.example:443", b"not on the setup allowlist"),
        ("CONNECT 192.168.5.2:443", b"IP addresses are refused"),
        ("CONNECT [::1]:443", b"IP addresses are refused"),
        ("CONNECT 169.254.169.254:443", b"IP addresses are refused"),
        ("CONNECT pypi.org:22", b"allowed to port 443 only"),
        ("CONNECT pypi.org:80", b"allowed to port 443 only"),
        ("GET http://169.254.169.254/latest/meta-data/", b"IP addresses are refused"),
        ("GET http://evil.example/", b"not on the setup allowlist"),
        ("GET http://deb.debian.org:8080/", b"allowed to port 80 only"),
    ],
)
def test_proxy_refuses_hosts_addresses_and_ports_off_the_allowlist(
    request_line: str, reason: bytes
) -> None:
    async def scenario(port: int, _fake: _FakeUpstream) -> None:
        response = await _exchange(port, f"{request_line} HTTP/1.1\r\n\r\n".encode())
        assert response.startswith(b"HTTP/1.1 403 Forbidden\r\n")
        assert reason in response

    fake = _run(scenario)

    assert fake.heads == []


def test_plain_get_is_forwarded_without_hop_by_hop_headers() -> None:
    async def scenario(port: int, _fake: _FakeUpstream) -> None:
        response = await _exchange(
            port,
            b"GET http://deb.debian.org/debian/dists/bookworm/InRelease HTTP/1.1\r\n"
            b"Host: deb.debian.org\r\nProxy-Authorization: Basic Y2xpZW50\r\n"
            b"Proxy-Connection: keep-alive\r\nUser-Agent: apt\r\n\r\n",
        )
        assert response.endswith(b"\r\n\r\nhello")

    fake = _run(scenario)

    assert fake.heads == [
        "GET http://deb.debian.org/debian/dists/bookworm/InRelease HTTP/1.1\r\n"
        "Host: deb.debian.org\r\nuser-agent: apt\r\n"
        f"Proxy-Authorization: {_UPSTREAM_AUTHORIZATION}\r\nConnection: close\r\n\r\n"
    ]


@pytest.mark.parametrize(
    ("head", "status"),
    [
        (b"POST http://deb.debian.org/ HTTP/1.1\r\nContent-Length: 0\r\n\r\n", b"405"),
        (b"GET https://pypi.org/simple/ HTTP/1.1\r\n\r\n", b"400"),
        (b"GET /simple/ HTTP/1.1\r\nHost: pypi.org\r\n\r\n", b"400"),
        (b"GET http://deb.debian.org/ HTTP/1.1\r\nContent-Length: 4\r\n\r\nbody", b"400"),
        (b"CONNECT pypi.org HTTP/1.1\r\n\r\n", b"400"),
        (b"CONNECT pypi.org:443\r\n\r\n", b"400"),
        (b"CONNECT pypi.org:443 HTTP/1.1\r\nno-colon\r\n\r\n", b"400"),
        (b"GET http://deb.debian.org/ HTTP/1.1\r\nX-A: 1\nHost: evil\r\n\r\n", b"400"),
        (b"GET http://deb.debian.org/ HTTP/1.1\r\n" + b"X-A: 1\r\n" * 101 + b"\r\n", b"431"),
        (b"GET http://deb.debian.org/ HTTP/1.1\r\nX-A: " + b"a" * 20_000 + b"\r\n\r\n", b"431"),
    ],
)
def test_proxy_rejects_unsupported_or_malformed_requests(head: bytes, status: bytes) -> None:
    async def scenario(port: int, _fake: _FakeUpstream) -> None:
        response = await _exchange(port, head)
        assert response.startswith(b"HTTP/1.1 " + status)

    fake = _run(scenario)

    assert fake.heads == []


def test_direct_connections_refuse_names_that_resolve_to_private_addresses() -> None:
    async def scenario(port: int, _fake: _FakeUpstream) -> None:
        response = await _exchange(port, b"CONNECT localhost:443 HTTP/1.1\r\n\r\n")
        assert response.startswith(b"HTTP/1.1 403 Forbidden\r\n")
        assert b"resolves only to non-public addresses" in response

    _run(scenario, allowed=("localhost",), upstream=False)


def test_proxy_caps_concurrent_connections() -> None:
    async def scenario(port: int, _fake: _FakeUpstream) -> None:
        reader, writer = await asyncio.open_connection("127.0.0.1", port)
        writer.write(b"CONNECT pypi.org:443 HTTP/1.1\r\n\r\n")
        await writer.drain()
        await reader.readuntil(b"\r\n\r\n")
        response = await _exchange(port, b"CONNECT pypi.org:443 HTTP/1.1\r\n\r\n")
        assert response.startswith(b"HTTP/1.1 503 Service Unavailable\r\n")
        writer.close()

    _run(scenario, max_connections=1)


def test_upstream_proxy_is_read_from_either_case_with_its_credentials() -> None:
    upstream = Upstream.from_environment(
        {"https_proxy": "http://op%40corp:p%3Ass@proxy.corp:3129"}, "HTTPS_PROXY"
    )

    assert upstream == Upstream(
        "proxy.corp", 3129, "Basic " + base64.b64encode(b"op@corp:p:ss").decode()
    )
    assert Upstream.from_environment({"HTTP_PROXY": "proxy.corp"}, "HTTP_PROXY") == Upstream(
        "proxy.corp", 8080, None
    )
    assert Upstream.from_environment({"HTTPS_PROXY": ""}, "HTTPS_PROXY") is None
    with pytest.raises(ValueError, match="http:// proxy URL"):
        Upstream.from_environment({"HTTPS_PROXY": "https://proxy.corp"}, "HTTPS_PROXY")
