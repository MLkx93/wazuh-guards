"""Audit events: the contract Wazuh rules are written against.

The central constraint: Wazuh's JSON decoder flattens arrays to
`findings.0.rule`, `findings.1.rule`, ... A rule matching `findings.0.severity`
MISSES a high-severity finding at index 1. So every field a rule keys on must
be a scalar aggregated across ALL findings -- that is what these tests pin.
"""

import json

import pytest

from wazuh_guards.audit import audit_event, build_event

HIGH = {"rule": "AWS Access Key ID", "severity": "high",
        "detector": "regex", "sample": "AKIA****LE"}
LOW = {"rule": "Person", "severity": "low",
       "detector": "presidio", "sample": "Sa****en"}


def _guardrail(**kw):
    return build_event(**kw)["guardrail"]


def test_event_is_namespaced_under_guardrail():
    event = build_event(hook="UserPromptSubmit", action="block")
    assert set(event) == {"guardrail"}


def test_high_finding_at_index_1_still_sets_has_high():
    """THE regression this file exists for. A low finding first, a high second:
    a rule reading findings.0.severity would see 'low' and miss the credential."""
    g = _guardrail(hook="UserPromptSubmit", action="block", findings=[LOW, HIGH])
    assert g["has_high"] is True
    assert g["max_severity"] == "high"
    assert g["finding_count"] == 2


def test_aggregated_fields_are_scalars_not_arrays():
    g = _guardrail(hook="PostToolUse", action="output_redacted", findings=[HIGH, LOW])
    for key in ("action", "max_severity", "has_high", "finding_count",
                "rules", "hook", "tool", "target", "pattern_version",
                "pattern_sha", "host", "session_id"):
        assert not isinstance(g[key], (list, dict)), f"{key} must be a scalar"


def test_rules_field_lists_every_rule_in_one_string():
    g = _guardrail(hook="PostToolUse", action="output_redacted", findings=[HIGH, LOW])
    assert "AWS Access Key ID" in g["rules"]
    assert "Person" in g["rules"]


def test_no_findings_produces_a_clean_zero_state():
    g = _guardrail(hook="UserPromptSubmit", action="allow")
    assert g["finding_count"] == 0
    assert g["has_high"] is False
    assert g["max_severity"] == "none"
    assert g["rules"] == ""


def test_scanner_findings_and_dicts_are_both_accepted():
    """Hooks pass Finding objects; the prompt hook passes dicts from the daemon."""
    from wazuh_guards.scanner import Finding

    obj = Finding(rule="AWS Access Key ID", severity="high",
                  detector="regex", sample="AKIA****LE")
    assert _guardrail(hook="x", action="y", findings=[obj])["has_high"] is True
    assert _guardrail(hook="x", action="y", findings=[HIGH])["has_high"] is True


def test_samples_are_redacted_and_bounded():
    many = [dict(HIGH, sample="A" * 100) for _ in range(20)]
    g = _guardrail(hook="PostToolUse", action="output_redacted", findings=many)
    assert len(g["samples"]) <= 512


def test_target_is_bounded():
    g = _guardrail(hook="PreToolUse", action="read_denied", target="/x" * 500)
    assert len(g["target"]) <= 256


def test_required_correlation_fields_are_present():
    """Rules 100210/100211 correlate on session_id and target."""
    g = _guardrail(hook="PostToolUse", action="output_redacted",
                   session_id="sess-1", target="/app/.env", tool="Read")
    assert g["session_id"] == "sess-1"
    assert g["target"] == "/app/.env"
    assert g["tool"] == "Read"


def test_drift_fields_are_present():
    """The drift rule keys on pattern_sha and host."""
    g = _guardrail(hook="UserPromptSubmit", action="allow",
                   pattern_version="2026.07.29", pattern_sha="a" * 64)
    assert g["pattern_version"] == "2026.07.29"
    assert g["pattern_sha"] == "a" * 64
    assert g["host"]


def test_timestamp_is_iso_with_offset():
    g = _guardrail(hook="x", action="y")
    assert "T" in g["timestamp"]
    assert g["timestamp"][-6] in "+-", "no UTC offset - Wazuh cannot order events"


def test_event_is_one_json_line(tmp_path, monkeypatch):
    """<localfile> with log_format json reads one object per line."""
    from wazuh_guards import audit

    log = tmp_path / "guardrail.json"
    monkeypatch.setattr(audit, "LOG_PATH", str(log))
    audit.audit_event(hook="PostToolUse", action="output_redacted", findings=[HIGH])
    audit.audit_event(hook="UserPromptSubmit", action="block", findings=[HIGH, LOW])

    lines = log.read_text().strip().splitlines()
    assert len(lines) == 2
    for line in lines:
        assert json.loads(line)["guardrail"]


def test_rotation_bounds_the_log(tmp_path, monkeypatch):
    from wazuh_guards import audit

    log = tmp_path / "guardrail.json"
    monkeypatch.setattr(audit, "LOG_PATH", str(log))
    monkeypatch.setattr(audit, "MAX_BYTES", 500)
    for _ in range(20):
        audit.audit_event(hook="PostToolUse", action="output_redacted", findings=[HIGH])
    assert log.stat().st_size < 2000
    assert (tmp_path / "guardrail.json.1").exists()


def test_write_failure_is_swallowed(monkeypatch):
    """Auditing must never break the tool path."""
    from wazuh_guards import audit

    monkeypatch.setattr(audit, "LOG_PATH", "/proc/nonexistent/x.json")
    assert audit.audit_event(hook="x", action="y")["guardrail"]["action"] == "y"
