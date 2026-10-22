from __future__ import annotations

import pytest

import autocontribute.host_environment as host_environment


def test_proxy_environment_returns_only_the_operator_proxy_and_ca_settings(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    proxies = {
        "ALL_PROXY": "socks5://proxy.example.test:1080",
        "GIT_SSL_CAINFO": "/operator/git-ca.pem",
        "GIT_SSL_CAPATH": "/operator/git-certs",
        "HTTPS_PROXY": "http://user:pass@proxy.example.test:3128",
        "HTTP_PROXY": "http://proxy.example.test:3128",
        "NO_PROXY": "localhost,127.0.0.1",
        "REQUESTS_CA_BUNDLE": "/operator/requests-ca.pem",
        "SSL_CERT_DIR": "/operator/certs",
        "SSL_CERT_FILE": "/operator/ca.pem",
        "all_proxy": "socks5://lower.example.test:1080",
        "http_proxy": "http://lower.example.test:3128",
        "https_proxy": "http://lower.example.test:3128",
        "no_proxy": "",
    }
    unrelated = {
        "FTP_PROXY": "http://ftp-proxy.example.test:3128",
        "GIT_PROXY_COMMAND": "/attacker/proxy",
        "HOME": "/home/operator",
        "OPENAI_API_KEY": "model-secret",
        "PATH": "/usr/bin:/bin",
    }
    monkeypatch.setattr(host_environment.os, "environ", {**proxies, **unrelated})

    assert host_environment.proxy_environment() == proxies


def test_proxy_environment_is_empty_without_operator_settings(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(host_environment.os, "environ", {"PATH": "/usr/bin:/bin"})

    assert host_environment.proxy_environment() == {}
