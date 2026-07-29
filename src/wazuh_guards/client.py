"""Unix-socket client for the warm scan daemon.

Extracted so all hooks share one implementation of the wire protocol. Three
copies of this is how field-name drift starts.
"""

import json
import os
import socket

SOCKET_PATH = os.environ.get(
    "WAZUH_GUARDS_SOCKET",
    os.environ.get(
        "CLAUDE_GUARDRAIL_SOCKET",
        f"/run/user/{os.getuid()}/wazuh-guards.sock",
    ),
)
CONNECT_TIMEOUT = float(os.environ.get("WAZUH_GUARDS_TIMEOUT", "5"))


def request(payload: dict, socket_path: str | None = None, timeout: float | None = None) -> dict:
    """Send one request, read one JSON reply. Raises OSError when the daemon is
    unavailable -- callers fall back to an in-process regex scan."""
    path = socket_path or SOCKET_PATH
    s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    s.settimeout(timeout if timeout is not None else CONNECT_TIMEOUT)
    try:
        s.connect(path)
        s.sendall((json.dumps(payload) + "\n").encode())
        s.shutdown(socket.SHUT_WR)
        chunks = []
        while True:
            chunk = s.recv(65536)
            if not chunk:
                break
            chunks.append(chunk)
        return json.loads(b"".join(chunks).decode("utf-8", "replace"))
    finally:
        s.close()


def scan(text: str, **kw) -> dict:
    return request({"op": "scan", "text": text}, **kw)


def ping(**kw) -> dict:
    return request({"op": "ping"}, **kw)


def status(**kw) -> dict:
    return request({"op": "status"}, **kw)
