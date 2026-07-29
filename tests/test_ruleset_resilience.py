"""A bad pattern push must not disarm the guardrail.

The threat here is not malice, it is a typo on the manager at 2am. Every one of
these payloads is something a human could plausibly save, and every one must
leave the previous ruleset in force rather than partially applying.
"""

import json

import pytest

from wazuh_guards import ruleset as rs_mod
from wazuh_guards.ruleset import PatternError, Ruleset, load, load_bundled, parse

GOOD = json.dumps(
    {
        "version": "2026.07.29",
        "rules": [
            {"name": "AWS Access Key ID", "severity": "high",
             "pattern": r"\b(?:AKIA|ASIA)[0-9A-Z]{16}\b"},
        ],
    }
)


def test_bundled_ruleset_is_valid_and_non_empty():
    bundled = load_bundled()
    assert len(bundled) >= 20
    assert bundled.source == "bundled"
    assert bundled.version


def test_parse_accepts_a_good_payload():
    parsed = parse(GOOD, source="wazuh")
    assert len(parsed) == 1
    assert parsed.rules[0].name == "AWS Access Key ID"
    assert parsed.sha256


@pytest.mark.parametrize(
    "label,payload",
    [
        ("not_json", "{ this is not json"),
        ("top_level_list", "[]"),
        ("missing_version", json.dumps({"rules": [{"name": "a", "severity": "high", "pattern": "x"}]})),
        ("empty_version", json.dumps({"version": "  ", "rules": [{"name": "a", "severity": "high", "pattern": "x"}]})),
        ("rules_not_list", json.dumps({"version": "1", "rules": {}})),
        ("rules_empty", json.dumps({"version": "1", "rules": []})),
        ("rule_not_object", json.dumps({"version": "1", "rules": ["AKIA"]})),
        ("missing_name", json.dumps({"version": "1", "rules": [{"severity": "high", "pattern": "x"}]})),
        ("duplicate_name", json.dumps({"version": "1", "rules": [
            {"name": "dup", "severity": "high", "pattern": "a"},
            {"name": "dup", "severity": "high", "pattern": "b"}]})),
        ("bad_severity", json.dumps({"version": "1", "rules": [{"name": "a", "severity": "critical", "pattern": "x"}]})),
        ("missing_pattern", json.dumps({"version": "1", "rules": [{"name": "a", "severity": "high"}]})),
        ("uncompilable_regex", json.dumps({"version": "1", "rules": [{"name": "a", "severity": "high", "pattern": "([unclosed"}]})),
        ("empty_string_match", json.dumps({"version": "1", "rules": [{"name": "a", "severity": "high", "pattern": "x*"}]})),
        ("unknown_validator", json.dumps({"version": "1", "rules": [{"name": "a", "severity": "high", "pattern": "x", "validator": "lhun"}]})),
    ],
    ids=lambda v: v if isinstance(v, str) else "",
)
def test_malformed_payloads_are_rejected(label, payload):
    with pytest.raises(PatternError):
        parse(payload, source="wazuh")


def test_one_bad_rule_rejects_the_whole_set():
    """All-or-nothing. A partial accept would silently delete the AWS rule while
    keeping the rest -- the failure most likely to go unnoticed."""
    payload = json.dumps({
        "version": "1",
        "rules": [
            {"name": "good", "severity": "high", "pattern": r"\bAKIA[0-9A-Z]{16}\b"},
            {"name": "bad", "severity": "high", "pattern": "([unclosed"},
        ],
    })
    with pytest.raises(PatternError):
        parse(payload, source="wazuh")


def test_bad_push_falls_back_to_cache_not_empty(tmp_path, monkeypatch):
    cache = tmp_path / "patterns.json"
    cache.write_text(GOOD)
    monkeypatch.setattr(rs_mod, "CACHE_PATH", str(cache))
    monkeypatch.setattr(rs_mod, "CACHE_DIR", str(tmp_path))

    def bad_fetch():
        return json.dumps({"version": "2", "rules": [{"name": "a", "severity": "high", "pattern": "([bad"}]})

    result, notes = load(fetcher=bad_fetch)
    assert result.source == "cache"
    assert len(result) == 1
    assert any("rejected pattern push" in n for n in notes)


def test_fetch_failure_falls_back_to_cache(tmp_path, monkeypatch):
    cache = tmp_path / "patterns.json"
    cache.write_text(GOOD)
    monkeypatch.setattr(rs_mod, "CACHE_PATH", str(cache))
    monkeypatch.setattr(rs_mod, "CACHE_DIR", str(tmp_path))

    def dead_wazuh():
        raise OSError("connection refused")

    result, notes = load(fetcher=dead_wazuh)
    assert result.source == "cache"
    assert any("wazuh fetch failed" in n for n in notes)


def test_no_cache_and_no_wazuh_falls_back_to_bundled(tmp_path, monkeypatch):
    monkeypatch.setattr(rs_mod, "CACHE_PATH", str(tmp_path / "absent.json"))
    monkeypatch.setattr(rs_mod, "CACHE_DIR", str(tmp_path))

    result, notes = load(fetcher=lambda: (_ for _ in ()).throw(OSError("down")))
    assert result.source == "bundled"
    assert len(result) >= 20
    assert any("bundled defaults" in n for n in notes)


def test_corrupt_cache_falls_through_to_bundled(tmp_path, monkeypatch):
    cache = tmp_path / "patterns.json"
    cache.write_text("{ truncated")
    monkeypatch.setattr(rs_mod, "CACHE_PATH", str(cache))
    monkeypatch.setattr(rs_mod, "CACHE_DIR", str(tmp_path))

    result, _ = load(fetcher=None)
    assert result.source == "bundled"


def test_load_never_returns_an_empty_ruleset(tmp_path, monkeypatch):
    """The invariant the whole module exists to protect."""
    monkeypatch.setattr(rs_mod, "CACHE_PATH", str(tmp_path / "absent.json"))
    monkeypatch.setattr(rs_mod, "CACHE_DIR", str(tmp_path))
    for fetcher in (None,
                    lambda: "",
                    lambda: "{}",
                    lambda: json.dumps({"version": "1", "rules": []}),
                    lambda: (_ for _ in ()).throw(RuntimeError("boom"))):
        result, _ = load(fetcher=fetcher)
        assert len(result) > 0


def test_good_push_is_cached_for_next_cold_start(tmp_path, monkeypatch):
    cache = tmp_path / "patterns.json"
    monkeypatch.setattr(rs_mod, "CACHE_PATH", str(cache))
    monkeypatch.setattr(rs_mod, "CACHE_DIR", str(tmp_path))

    result, notes = load(fetcher=lambda: GOOD)
    assert result.source == "wazuh"
    assert cache.read_text() == GOOD
    assert any("cached patterns" in n for n in notes)


def test_unwritable_cache_does_not_break_loading(tmp_path, monkeypatch):
    """A read-only cache dir is an operational annoyance, not an outage."""
    monkeypatch.setattr(rs_mod, "CACHE_DIR", "/proc/nonexistent")
    monkeypatch.setattr(rs_mod, "CACHE_PATH", "/proc/nonexistent/patterns.json")

    result, notes = load(fetcher=lambda: GOOD)
    assert result.source == "wazuh"
    assert any("could not write cache" in n for n in notes)


def test_ruleset_sha_changes_when_patterns_change():
    """Drift detection keys on this: same bytes -> same sha, on every host."""
    a = parse(GOOD, source="wazuh")
    b = parse(GOOD, source="cache")
    assert a.sha256 == b.sha256

    modified = json.dumps({
        "version": "2026.07.30",
        "rules": [{"name": "AWS Access Key ID", "severity": "high",
                   "pattern": r"\b(?:AKIA|ASIA)[0-9A-Z]{16}\b"}],
    })
    assert parse(modified, source="wazuh").sha256 != a.sha256
