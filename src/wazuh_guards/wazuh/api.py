"""Read-only Wazuh manager client: fetch the pattern file, nothing else.

This module is NEVER in the enforcement path. It is called at daemon startup
and on a refresh timer. If every function here raises, the guardrail still
blocks prompts and still redacts output -- ruleset.load() falls through to the
cache and then to bundled defaults.

Three constraints the API imposes, each learned the hard way:

1. `raw=true` is MANDATORY on the file fetch. Without it the response falls
   through to `_rcl2json()` and comes back mangled -- valid JSON in the
   envelope, garbage in the content.

2. Re-auth on 401 ONLY. JWTs last 900s and there are no API keys.
   `max_login_attempts` is 50 per 300s, so a client that authenticates per
   request will IP-block itself, and the block looks exactly like the manager
   being down.

3. GET-only. There is no PUT/POST for group files -- updating patterns means
   editing the file on the manager over SSH. Accepted deliberately so Wazuh
   stays the single management plane.

Credentials come from the environment, never from a file in the repo.
"""

import json
import os
import ssl
import time
import urllib.error
import urllib.parse
import urllib.request
from base64 import b64encode

DEFAULT_TIMEOUT = float(os.environ.get("WAZUH_API_TIMEOUT", "10"))
# JWTs are valid 900s; renew early so a scan-time refresh never races expiry.
TOKEN_TTL = int(os.environ.get("WAZUH_API_TOKEN_TTL", "780"))


class WazuhError(RuntimeError):
    """Any failure talking to the manager. Callers degrade, never crash."""


class WazuhClient:
    """Minimal urllib client. Deliberately dependency-free: the daemon must be
    installable without `requests` on a locked-down host."""

    def __init__(
        self,
        base_url: str | None = None,
        user: str | None = None,
        password: str | None = None,
        verify_tls: bool | None = None,
        timeout: float = DEFAULT_TIMEOUT,
    ):
        self.base_url = (base_url or os.environ.get("WAZUH_API_URL", "")).rstrip("/")
        self.user = user or os.environ.get("WAZUH_API_USER", "")
        self.password = password or os.environ.get("WAZUH_API_PASSWORD", "")
        if verify_tls is None:
            # wazuh-docker ships a self-signed cert by default. Opting out is a
            # deliberate, explicit act -- not the default.
            verify_tls = os.environ.get("WAZUH_API_VERIFY_TLS", "true").lower() not in (
                "false", "0", "no",
            )
        self.verify_tls = verify_tls
        self.timeout = timeout

        self._token: str | None = None
        self._token_at: float = 0.0

    @property
    def configured(self) -> bool:
        return bool(self.base_url and self.user and self.password)

    def _ssl_context(self):
        if self.verify_tls:
            return ssl.create_default_context()
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        return ctx

    def _request(self, path: str, headers: dict, method: str = "GET") -> tuple[int, bytes]:
        url = f"{self.base_url}{path}"
        req = urllib.request.Request(url, headers=headers, method=method)
        try:
            with urllib.request.urlopen(
                req, timeout=self.timeout, context=self._ssl_context()
            ) as resp:
                return resp.status, resp.read()
        except urllib.error.HTTPError as exc:
            return exc.code, exc.read()
        except urllib.error.URLError as exc:
            raise WazuhError(f"cannot reach {self.base_url}: {exc.reason}") from exc
        except (TimeoutError, OSError) as exc:
            raise WazuhError(f"transport error to {self.base_url}: {exc}") from exc

    def authenticate(self) -> str:
        """POST /security/user/authenticate with basic auth -> JWT."""
        if not self.configured:
            raise WazuhError(
                "wazuh not configured (set WAZUH_API_URL, WAZUH_API_USER, "
                "WAZUH_API_PASSWORD)"
            )
        basic = b64encode(f"{self.user}:{self.password}".encode()).decode()
        status, body = self._request(
            "/security/user/authenticate",
            {"Authorization": f"Basic {basic}"},
            method="POST",
        )
        if status == 401:
            raise WazuhError("authentication rejected (401): check credentials")
        if status != 200:
            raise WazuhError(f"authentication failed: HTTP {status}")
        try:
            token = json.loads(body)["data"]["token"]
        except (ValueError, KeyError, TypeError) as exc:
            raise WazuhError(f"unexpected auth response shape: {exc}") from exc
        self._token = token
        self._token_at = time.monotonic()
        return token

    def _token_valid(self) -> bool:
        return bool(self._token) and (time.monotonic() - self._token_at) < TOKEN_TTL

    def get(self, path: str) -> bytes:
        """GET with a cached token, re-authenticating at most ONCE on 401.

        The single retry is the whole point: it recovers from an expired token
        without ever looping, which is what would trip max_login_attempts.
        """
        if not self._token_valid():
            self.authenticate()

        status, body = self._request(path, {"Authorization": f"Bearer {self._token}"})
        if status == 401:
            # Token rejected despite our TTL -- manager restarted, or clocks
            # differ. Re-auth exactly once; a second 401 is a real failure.
            self.authenticate()
            status, body = self._request(
                path, {"Authorization": f"Bearer {self._token}"}
            )
            if status == 401:
                raise WazuhError(
                    "still 401 after re-authentication - not retrying "
                    "(max_login_attempts is 50/300s; a retry loop self-blocks)"
                )
        if status == 429:
            raise WazuhError("rate limited by manager (300 req/min) - backing off")
        if status != 200:
            raise WazuhError(f"GET {path} failed: HTTP {status}")
        return body

    def fetch_group_file(self, group: str, filename: str) -> str:
        """GET /groups/{group}/files/{file}?raw=true

        raw=true is mandatory. Without it the manager runs the response through
        _rcl2json() and returns mangled content that still parses as JSON.
        """
        path = (
            f"/groups/{urllib.parse.quote(group)}"
            f"/files/{urllib.parse.quote(filename)}?raw=true"
        )
        return self.get(path).decode("utf-8")


def pattern_fetcher(
    group: str | None = None,
    filename: str | None = None,
    client: WazuhClient | None = None,
):
    """Build the callable ruleset.load() expects.

    Returns None when Wazuh is not configured, so the daemon skips the fetch
    entirely rather than logging a failure every refresh on a standalone host.
    """
    group = group or os.environ.get("WAZUH_GUARDS_GROUP", "guardrail")
    filename = filename or os.environ.get("WAZUH_GUARDS_PATTERN_FILE", "patterns.json")
    client = client or WazuhClient()
    if not client.configured:
        return None

    def fetch() -> str:
        return client.fetch_group_file(group, filename)

    return fetch
