"""Tiny HTTP client for talking to the isolated consoles through the real nginx
edge (host header picks the console). Standard library only; shared by
`demo_isolation.py` and `roles_e2e.py`."""

from __future__ import annotations

import json
import urllib.error
import urllib.request
import uuid
from http.client import HTTPMessage

EDGE = "http://127.0.0.1:8080"


def request(
    host: str,
    method: str,
    path: str,
    cookie: str | None = None,
    body: object | None = None,
    *,
    fields: dict[str, str] | None = None,
    files: dict[str, tuple[str, bytes]] | None = None,
    timeout: int = 300,
) -> tuple[int, HTTPMessage, bytes]:
    """JSON body via `body`, or multipart via `fields`/`files` (name -> (filename, bytes))."""
    headers = {"Host": f"{host}.localhost"}
    data: bytes | None = None
    if files is not None or fields is not None:
        boundary = uuid.uuid4().hex
        chunks: list[bytes] = []
        for name, value in (fields or {}).items():
            chunks.append(
                f'--{boundary}\r\nContent-Disposition: form-data; name="{name}"\r\n\r\n{value}\r\n'.encode()
            )
        for name, (filename, content) in (files or {}).items():
            chunks.append(
                f'--{boundary}\r\nContent-Disposition: form-data; name="{name}"; '
                f'filename="{filename}"\r\nContent-Type: application/octet-stream\r\n\r\n'.encode()
                + content
                + b"\r\n"
            )
        chunks.append(f"--{boundary}--\r\n".encode())
        data = b"".join(chunks)
        headers["Content-Type"] = f"multipart/form-data; boundary={boundary}"
    elif body is not None:
        data = json.dumps(body).encode()
        headers["Content-Type"] = "application/json"
    if cookie:
        headers["Cookie"] = cookie
    req = urllib.request.Request(f"{EDGE}/api{path}", data=data, headers=headers, method=method)
    try:
        with urllib.request.urlopen(req, timeout=timeout) as response:  # noqa: S310 - fixed loopback edge
            return response.status, response.headers, response.read()
    except urllib.error.HTTPError as err:
        return err.code, err.headers, err.read()


def login(host: str, passphrase: str) -> str | None:
    """Returns the session cookie (`name=value`) or None if login failed."""
    status, headers, _ = request(host, "POST", "/session/login", body={"passphrase": passphrase})
    cookie = headers.get("Set-Cookie", "")
    return cookie.split(";")[0] if status == 200 and cookie else None


def credentials(path: str) -> dict[str, str]:
    from pathlib import Path

    file = Path(path)
    if not file.exists():
        return {}
    pairs = (line.split(": ", 1) for line in file.read_text().splitlines() if ": " in line)
    return {name: value for name, value in pairs}
