"""Proof that the `internal: true` Docker network actually blocks egress
(spec Section 17, M0 acceptance criterion).

This test is meaningless on a normal host with internet access — it must be
run *inside* a container attached only to the `traceseal_internal` network
(see docker-compose.yml and `make test`), where every attempt below is
expected to fail or time out.
"""

from __future__ import annotations

import socket

import pytest

_CONNECT_TIMEOUT_S = 3.0


def _tcp_connect_should_fail(host: str, port: int) -> None:
    with pytest.raises(OSError):
        with socket.create_connection((host, port), timeout=_CONNECT_TIMEOUT_S):
            pass  # pragma: no cover - reaching this means egress leaked through


def test_dns_resolution_fails() -> None:
    with pytest.raises(OSError):
        socket.getaddrinfo("example.com", 443)


def test_tcp_connect_to_public_ip_fails() -> None:
    # 1.1.1.1 (Cloudflare public DNS) chosen so this doesn't depend on our
    # own DNS resolution also being blocked (tested separately above).
    _tcp_connect_should_fail("1.1.1.1", 443)


def test_tcp_connect_to_second_public_ip_fails() -> None:
    # A second, unrelated provider (Google public DNS) so a single
    # provider-specific outage can't produce a false pass.
    _tcp_connect_should_fail("8.8.8.8", 443)
