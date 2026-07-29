"""UserPromptSubmit verdict formatting and the daemon-down fallback."""

import json

import pytest

from wazuh_guards import scanner
from wazuh_guards.hooks import prompt_submit as hook
from wazuh_guards.ruleset import load_bundled

from corpus import REGEX_ONLY_BLOCK_CASES


@pytest.fixture(autouse=True)
def bundled_rules():
    scanner.set_ruleset(load_bundled())


def _verdict(text):
    return scanner.scan(text, use_presidio=False)


def test_block_response_shape():
    response = hook.build_response(_verdict("key AKIAIOSFODNN7EXAMPLE"))
    assert response["decision"] == "block"
    assert "AWS Access Key ID" in response["reason"]
    assert "🛡" in response["systemMessage"]


def test_block_reason_never_contains_the_raw_secret():
    response = hook.build_response(_verdict("key AKIAIOSFODNN7EXAMPLE"))
    assert "AKIAIOSFODNN7EXAMPLE" not in json.dumps(response)


def test_warn_response_does_not_block_and_says_it_did_not_redact():
    """UserPromptSubmit cannot rewrite the prompt. The notice must not imply
    otherwise."""
    result = {"findings": [{"rule": "Person", "severity": "low",
                            "detector": "presidio", "sample": "Sa****en"}],
              "action": "warn"}
    response = hook.build_response(result)
    assert "decision" not in response
    assert "NOT REDACTED" in response["systemMessage"]
    hso = response["hookSpecificOutput"]
    assert hso["hookEventName"] == "UserPromptSubmit"
    assert "additionalContext" in hso
    assert "updatedInput" not in hso  # does not exist for this hook


def test_clean_prompt_yields_no_response():
    assert hook.build_response(_verdict("what is the capital of France")) is None


def test_block_lists_low_severity_findings_separately():
    result = {
        "findings": [
            {"rule": "AWS Access Key ID", "severity": "high",
             "detector": "regex", "sample": "AKIA****LE"},
            {"rule": "Person", "severity": "low",
             "detector": "presidio", "sample": "Sa****en"},
        ],
        "action": "block",
    }
    response = hook.build_response(result)
    assert "Also present" in response["reason"]
    assert response["systemMessage"].endswith("1 policy violation(s) detected.")


# --- daemon-down fallback -------------------------------------------------

@pytest.mark.parametrize("label,text", REGEX_ONLY_BLOCK_CASES, ids=lambda v: v)
def test_fallback_still_blocks_every_credential(label, text):
    """The non-negotiable: daemon down must not mean credentials get through."""
    result = hook._via_fallback(text)
    assert result["action"] == "block", f"{label} passed with the daemon down"
    assert result["degraded"]


def test_fallback_is_announced_in_the_block_reason():
    response = hook.build_response(hook._via_fallback("key AKIAIOSFODNN7EXAMPLE"))
    assert "daemon unavailable" in response["reason"]


def test_daemon_down_falls_back_end_to_end(monkeypatch, capsys, tmp_path):
    monkeypatch.setenv("WAZUH_GUARDS_LOG", str(tmp_path / "g.json"))

    def refused(*a, **k):
        raise OSError("connection refused")

    monkeypatch.setattr(hook.client, "scan", refused)
    monkeypatch.setattr("sys.stdin", _stdin(json.dumps(
        {"prompt": "key AKIAIOSFODNN7EXAMPLE", "session_id": "s1"})))
    with pytest.raises(SystemExit) as exc:
        hook.main()
    assert exc.value.code == 0
    assert json.loads(capsys.readouterr().out)["decision"] == "block"


def test_scanner_crash_fails_open_loudly(monkeypatch, capsys):
    monkeypatch.setattr(hook.client, "scan",
                        lambda *a, **k: (_ for _ in ()).throw(OSError("down")))
    monkeypatch.setattr(hook, "_via_fallback",
                        lambda t: (_ for _ in ()).throw(RuntimeError("boom")))
    monkeypatch.setattr("sys.stdin", _stdin(json.dumps({"prompt": "hello"})))
    with pytest.raises(SystemExit) as exc:
        hook.main()
    assert exc.value.code == 0
    emitted = json.loads(capsys.readouterr().out)
    assert "NOT scanned" in emitted["systemMessage"]


def test_empty_prompt_exits_quietly(monkeypatch, capsys):
    monkeypatch.setattr("sys.stdin", _stdin(json.dumps({"prompt": "   "})))
    with pytest.raises(SystemExit):
        hook.main()
    assert capsys.readouterr().out == ""


def test_unparseable_stdin_does_not_block(monkeypatch, capsys):
    monkeypatch.setattr("sys.stdin", _stdin("{ not json"))
    with pytest.raises(SystemExit) as exc:
        hook.main()
    assert exc.value.code == 0
    assert capsys.readouterr().out == ""


class _stdin:
    def __init__(self, text):
        self._text = text

    def read(self):
        return self._text
