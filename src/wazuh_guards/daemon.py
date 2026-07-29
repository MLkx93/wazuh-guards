"""Persistent scan daemon.

Presidio costs ~12s to load its spaCy pipeline. Paying that per prompt would
make the hook unusable, so the model is loaded once here and scans are served
over a Unix domain socket in milliseconds. Warm path is ~0.23s end to end.

The socket is mode 0600 in the user's runtime dir: prompts are sensitive by
definition and must not be readable by other local users.

WAZUH IS NEVER IN THE ENFORCEMENT PATH. Patterns are fetched at startup and on
a background timer, never during a scan. If the manager is unreachable the
daemon starts anyway on cached or bundled patterns and logs the degradation.
A scan never waits on the network.
"""

import json
import os
import socket
import socketserver
import sys
import threading
import time

from . import scanner
from .ruleset import load

SOCKET_PATH = os.environ.get(
    "WAZUH_GUARDS_SOCKET",
    os.environ.get(
        "CLAUDE_GUARDRAIL_SOCKET",
        f"/run/user/{os.getuid()}/wazuh-guards.sock",
    ),
)
IDLE_TIMEOUT = int(os.environ.get("WAZUH_GUARDS_IDLE_TIMEOUT", "0"))  # 0 = never exit
# Pattern refresh cadence. Well under the 300 req/min limit at any sane value.
REFRESH_INTERVAL = int(os.environ.get("WAZUH_GUARDS_REFRESH_INTERVAL", "3600"))

_last_used = time.time()


def _log(message: str) -> None:
    print(message, file=sys.stderr, flush=True)


def _build_fetcher():
    """Resolve the Wazuh fetcher, tolerating a missing/broken wazuh module.
    A guardrail that will not start because its SIEM client failed to import
    has the failure mode backwards."""
    try:
        from .wazuh.api import pattern_fetcher

        return pattern_fetcher()
    except Exception as exc:  # noqa: BLE001
        _log(f"WARNING wazuh client unavailable: {type(exc).__name__}: {exc}")
        return None


def refresh_patterns() -> None:
    """Load patterns and install them. Never raises: load() degrades internally
    and the active ruleset is only replaced on success."""
    ruleset, notes = load(fetcher=_build_fetcher())
    for note in notes:
        _log(note)
    scanner.set_ruleset(ruleset)


def _refresh_loop() -> None:
    while True:
        time.sleep(REFRESH_INTERVAL)
        try:
            refresh_patterns()
        except Exception as exc:  # noqa: BLE001
            # Keep serving on the ruleset we already have.
            _log(f"WARNING pattern refresh failed: {type(exc).__name__}: {exc}")


class Handler(socketserver.BaseRequestHandler):
    def handle(self):
        global _last_used
        _last_used = time.time()
        try:
            chunks = []
            while True:
                data = self.request.recv(65536)
                if not data:
                    break
                chunks.append(data)
                if b"\n" in data:
                    break
            raw = b"".join(chunks).strip()
            if not raw:
                return
            req = json.loads(raw.decode("utf-8", "replace"))
            op = req.get("op")

            if op == "ping":
                self.request.sendall(b'{"ok":true}\n')
                return

            if op == "status":
                rs = scanner.get_ruleset()
                self.request.sendall((json.dumps({
                    "ok": True,
                    "rules": len(rs),
                    "pattern_version": rs.version,
                    "pattern_sha": rs.sha256,
                    "pattern_source": rs.source,
                    "presidio_error": scanner.presidio_error(),
                }) + "\n").encode())
                return

            result = scanner.scan(req.get("text", ""))
            self.request.sendall((json.dumps(result) + "\n").encode())
        except Exception as exc:  # noqa: BLE001
            err = json.dumps({"error": f"{type(exc).__name__}: {exc}"})
            try:
                self.request.sendall((err + "\n").encode())
            except OSError:
                pass


class Server(socketserver.ThreadingUnixStreamServer):
    daemon_threads = True
    allow_reuse_address = True


def _idle_reaper(server):
    while True:
        time.sleep(30)
        if IDLE_TIMEOUT and time.time() - _last_used > IDLE_TIMEOUT:
            server.shutdown()
            return


def main():
    # A stale socket from a killed daemon would block bind(); clear it, but only
    # if nothing is actually listening.
    if os.path.exists(SOCKET_PATH):
        probe = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        try:
            probe.connect(SOCKET_PATH)
            _log(f"daemon already running at {SOCKET_PATH}")
            return 1
        except OSError:
            os.unlink(SOCKET_PATH)
        finally:
            probe.close()

    os.makedirs(os.path.dirname(SOCKET_PATH), exist_ok=True)

    # Patterns first: a scan must never find an unloaded ruleset.
    refresh_patterns()

    # Warm the model before accepting connections so the first real prompt does
    # not eat the cold-start cost.
    scanner.scan("warmup", use_presidio=True)

    server = Server(SOCKET_PATH, Handler)
    os.chmod(SOCKET_PATH, 0o600)

    if IDLE_TIMEOUT:
        threading.Thread(target=_idle_reaper, args=(server,), daemon=True).start()
    if REFRESH_INTERVAL > 0:
        threading.Thread(target=_refresh_loop, daemon=True).start()

    rs = scanner.get_ruleset()
    _log(
        f"guardrail daemon listening on {SOCKET_PATH} "
        f"({len(rs)} rules, source={rs.source}, version={rs.version})"
    )
    if scanner.presidio_error():
        _log(f"WARNING presidio unavailable: {scanner.presidio_error()}")

    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        server.server_close()
        if os.path.exists(SOCKET_PATH):
            os.unlink(SOCKET_PATH)
    return 0


if __name__ == "__main__":
    sys.exit(main())
