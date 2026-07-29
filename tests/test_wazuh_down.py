"""The non-negotiable: Wazuh down must not mean guardrail down.

The SIEM is never in the enforcement path. Patterns are fetched at daemon
startup and cached; a scan never touches the network. These tests assert that
property directly rather than trusting the call graph, because the regression
-- a fetch that sneaks into the request path -- is invisible until the manager
goes down in production.
"""

import json
import time

import pytest

from wazuh_guards import audit, scanner
from wazuh_guards.hooks import post_tool_use, pre_tool_use, prompt_submit
from wazuh_guards.ruleset import load_bundled

from corpus import REGEX_ONLY_BLOCK_CASES

SECRET = "AKIAIOSFODNN7EXAMPLE"


@pytest.fixture(autouse=True)
def bundled_rules():
    scanner.set_ruleset(load_bundled())


@pytest.fixture
def no_network(monkeypatch):
    """Make any socket/urllib use raise. If enforcement touches the network,
    these tests fail loudly instead of hanging in production."""
    def forbidden(*a, **k):
        raise AssertionError("enforcement path attempted a network call")

    monkeypatch.setattr("urllib.request.urlopen", forbidden)
    monkeypatch.setattr("socket.create_connection", forbidden)
    return monkeypatch


def test_prompt_blocking_works_with_no_network(no_network):
    for label, text in REGEX_ONLY_BLOCK_CASES:
        result = scanner.scan(text, use_presidio=False)
        assert result["action"] == "block", label


def test_redaction_works_with_no_network(no_network):
    out, findings, changed = post_tool_use.redact_tool_response(
        {"file": {"content": f'KEY = "{SECRET}"'}})
    assert changed
    assert SECRET not in json.dumps(out)


def test_path_denial_works_with_no_network(no_network):
    deny, _, _ = pre_tool_use.evaluate(
        {"tool_name": "Read", "tool_input": {"file_path": "/app/.env"}})
    assert deny


def test_audit_write_failure_does_not_break_the_hook(monkeypatch, tmp_path):
    """A full disk or unwritable log must not stop enforcement."""
    monkeypatch.setattr(audit, "LOG_PATH", "/proc/nonexistent/guardrail.json")
    event = audit.audit_event(hook="PostToolUse", action="output_redacted", findings=[])
    assert event["guardrail"]["action"] == "output_redacted"  # returned, not raised


def test_enforcement_is_fast_without_a_daemon(no_network):
    """No hidden network timeout in the scan path. Regex-only over a realistic
    file should be milliseconds, not seconds."""
    content = ("some ordinary source line\n" * 5000) + f'KEY = "{SECRET}"\n'
    start = time.monotonic()
    out, _, changed = post_tool_use.redact_tool_response({"stdout": content})
    elapsed = time.monotonic() - start
    assert changed
    assert elapsed < 2.0, f"redaction took {elapsed:.2f}s - something is blocking"


def test_daemon_startup_survives_an_unreachable_manager(monkeypatch, tmp_path):
    """Startup must not abort when the manager is down; it degrades to cache
    or bundled and says so."""
    from wazuh_guards import daemon
    from wazuh_guards import ruleset as rs_mod

    monkeypatch.setattr(rs_mod, "CACHE_PATH", str(tmp_path / "absent.json"))
    monkeypatch.setattr(rs_mod, "CACHE_DIR", str(tmp_path))
    monkeypatch.setattr(
        daemon, "_build_fetcher",
        lambda: (lambda: (_ for _ in ()).throw(OSError("connection refused"))))

    daemon.refresh_patterns()
    rs = scanner.get_ruleset()
    assert len(rs) > 0
    assert rs.source == "bundled"


def test_refresh_failure_keeps_the_previous_ruleset(monkeypatch, tmp_path):
    """A manager that goes down mid-session must not empty the live ruleset."""
    from wazuh_guards import daemon
    from wazuh_guards import ruleset as rs_mod

    good = load_bundled()
    scanner.set_ruleset(good)
    monkeypatch.setattr(rs_mod, "CACHE_PATH", str(tmp_path / "absent.json"))
    monkeypatch.setattr(rs_mod, "CACHE_DIR", str(tmp_path))
    monkeypatch.setattr(
        daemon, "_build_fetcher",
        lambda: (lambda: (_ for _ in ()).throw(OSError("gone"))))

    daemon.refresh_patterns()
    assert len(scanner.get_ruleset()) == len(good)
    assert scanner.scan(f"key {SECRET}", use_presidio=False)["action"] == "block"


def test_unconfigured_wazuh_is_not_an_error(monkeypatch, tmp_path):
    """A standalone host with no manager configured runs on bundled patterns
    without logging a failure every refresh."""
    from wazuh_guards import daemon
    from wazuh_guards import ruleset as rs_mod

    for var in ("WAZUH_API_URL", "WAZUH_API_USER", "WAZUH_API_PASSWORD"):
        monkeypatch.delenv(var, raising=False)
    monkeypatch.setattr(rs_mod, "CACHE_PATH", str(tmp_path / "absent.json"))
    monkeypatch.setattr(rs_mod, "CACHE_DIR", str(tmp_path))

    assert daemon._build_fetcher() is None
    daemon.refresh_patterns()
    assert scanner.get_ruleset().source == "bundled"
