"""Wazuh client: the three constraints the API imposes.

No network. Every test stubs _request, because the behaviors that matter here
are about WHEN we call the API, not what it returns -- and the worst failure
(a re-auth loop that IP-blocks the host) is invisible to a test that mocks at
a higher level.
"""

import json

import pytest

from wazuh_guards.wazuh.api import WazuhClient, WazuhError, pattern_fetcher

TOKEN_BODY = json.dumps({"data": {"token": "jwt-abc"}}).encode()


def _client(**kw):
    kw.setdefault("base_url", "https://wazuh.test:55000")
    kw.setdefault("user", "wazuh")
    kw.setdefault("password", "secret")
    return WazuhClient(**kw)


class Recorder:
    """Stub for _request that records every call."""

    def __init__(self, responses):
        self.responses = list(responses)
        self.calls = []

    def __call__(self, path, headers, method="GET"):
        self.calls.append((method, path, headers))
        if not self.responses:
            raise AssertionError(f"unexpected extra request: {method} {path}")
        return self.responses.pop(0)

    @property
    def auth_count(self):
        return sum(1 for m, p, _ in self.calls if p.endswith("/authenticate"))


# --- constraint 1: raw=true is mandatory ----------------------------------

def test_fetch_uses_raw_true(monkeypatch):
    rec = Recorder([(200, TOKEN_BODY), (200, b'{"version":"1","rules":[]}')])
    c = _client()
    monkeypatch.setattr(c, "_request", rec)
    c.fetch_group_file("guardrail", "patterns.json")

    get_path = rec.calls[-1][1]
    assert "raw=true" in get_path, "without raw=true the manager mangles the content"
    assert get_path.startswith("/groups/guardrail/files/patterns.json")


def test_group_and_filename_are_url_quoted(monkeypatch):
    rec = Recorder([(200, TOKEN_BODY), (200, b"{}")])
    c = _client()
    monkeypatch.setattr(c, "_request", rec)
    c.fetch_group_file("my group", "pat terns.json")
    assert "my%20group" in rec.calls[-1][1]


# --- constraint 2: re-auth on 401 ONLY ------------------------------------

def test_token_is_cached_across_requests(monkeypatch):
    rec = Recorder([(200, TOKEN_BODY), (200, b"a"), (200, b"b"), (200, b"c")])
    c = _client()
    monkeypatch.setattr(c, "_request", rec)
    for _ in range(3):
        c.get("/x")
    assert rec.auth_count == 1, "authenticated more than once for a valid token"


def test_401_triggers_exactly_one_reauth(monkeypatch):
    rec = Recorder([
        (200, TOKEN_BODY),   # initial auth
        (401, b""),          # token rejected
        (200, TOKEN_BODY),   # re-auth
        (200, b"ok"),        # retry succeeds
    ])
    c = _client()
    monkeypatch.setattr(c, "_request", rec)
    assert c.get("/x") == b"ok"
    assert rec.auth_count == 2


def test_second_401_raises_instead_of_looping(monkeypatch):
    """The guard against IP-blocking ourselves: max_login_attempts is 50/300s,
    and a retry loop looks identical to the manager being down."""
    rec = Recorder([
        (200, TOKEN_BODY),
        (401, b""),
        (200, TOKEN_BODY),
        (401, b""),
    ])
    c = _client()
    monkeypatch.setattr(c, "_request", rec)
    with pytest.raises(WazuhError, match="not retrying"):
        c.get("/x")
    assert rec.auth_count == 2, "a third auth attempt would start the loop"


def test_non_401_errors_do_not_reauth(monkeypatch):
    rec = Recorder([(200, TOKEN_BODY), (500, b"")])
    c = _client()
    monkeypatch.setattr(c, "_request", rec)
    with pytest.raises(WazuhError, match="HTTP 500"):
        c.get("/x")
    assert rec.auth_count == 1


def test_rate_limit_is_reported_distinctly(monkeypatch):
    rec = Recorder([(200, TOKEN_BODY), (429, b"")])
    c = _client()
    monkeypatch.setattr(c, "_request", rec)
    with pytest.raises(WazuhError, match="rate limited"):
        c.get("/x")


def test_expired_token_reauths_before_the_request(monkeypatch):
    rec = Recorder([(200, TOKEN_BODY), (200, b"x"), (200, TOKEN_BODY), (200, b"y")])
    c = _client()
    monkeypatch.setattr(c, "_request", rec)
    c.get("/a")
    c._token_at -= 10_000  # simulate TTL expiry
    c.get("/b")
    assert rec.auth_count == 2


def test_bad_credentials_reported_clearly(monkeypatch):
    rec = Recorder([(401, b"")])
    c = _client()
    monkeypatch.setattr(c, "_request", rec)
    with pytest.raises(WazuhError, match="check credentials"):
        c.authenticate()


def test_malformed_auth_response_is_an_error(monkeypatch):
    rec = Recorder([(200, b'{"data": {}}')])
    c = _client()
    monkeypatch.setattr(c, "_request", rec)
    with pytest.raises(WazuhError, match="unexpected auth response"):
        c.authenticate()


# --- configuration --------------------------------------------------------

def test_unconfigured_client_yields_no_fetcher(monkeypatch):
    """A standalone host must not log a fetch failure every refresh."""
    for var in ("WAZUH_API_URL", "WAZUH_API_USER", "WAZUH_API_PASSWORD"):
        monkeypatch.delenv(var, raising=False)
    assert pattern_fetcher() is None


def test_configured_client_yields_a_fetcher(monkeypatch):
    monkeypatch.setenv("WAZUH_API_URL", "https://wazuh.test:55000")
    monkeypatch.setenv("WAZUH_API_USER", "wazuh")
    monkeypatch.setenv("WAZUH_API_PASSWORD", "secret")
    assert callable(pattern_fetcher())


def test_unconfigured_authenticate_names_the_missing_vars():
    c = WazuhClient(base_url="", user="", password="")
    with pytest.raises(WazuhError, match="WAZUH_API_URL"):
        c.authenticate()


def test_tls_verification_is_on_by_default(monkeypatch):
    monkeypatch.delenv("WAZUH_API_VERIFY_TLS", raising=False)
    assert _client().verify_tls is True


def test_tls_verification_opt_out_is_explicit(monkeypatch):
    monkeypatch.setenv("WAZUH_API_VERIFY_TLS", "false")
    assert WazuhClient(base_url="x", user="u", password="p").verify_tls is False


def test_unreachable_manager_raises_wazuh_error(monkeypatch):
    import urllib.error

    c = _client()

    def boom(*a, **k):
        raise urllib.error.URLError("connection refused")

    monkeypatch.setattr("urllib.request.urlopen", boom)
    with pytest.raises(WazuhError, match="cannot reach"):
        c.authenticate()
