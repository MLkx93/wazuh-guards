"""PostToolUse redaction, against the REAL stdin shapes.

Every payload here mirrors what Claude Code actually sends, not what the docs
describe. The distinction is the entire point: a redactor reading `tool_output`
/ `.text` produces valid-looking output while passing every secret through.

These are unit tests. They are necessary and NOT sufficient -- see
test_canary.py for the end-to-end proof.
"""

import json

import pytest

from wazuh_guards import scanner
from wazuh_guards.hooks import post_tool_use as hook
from wazuh_guards.ruleset import load_bundled

from corpus import REDACTABLE_FILE, REDACTABLE_KEPT, REDACTABLE_SECRETS

SECRET = "AKIAIOSFODNN7EXAMPLE"


@pytest.fixture(autouse=True)
def bundled_rules():
    scanner.set_ruleset(load_bundled())


# --- the real shapes ------------------------------------------------------

def test_read_shape_uses_file_content_not_text():
    """Read content lives at tool_response.file.content. A redactor reading
    `.text` here silently passes the secret through."""
    response = {"type": "text", "file": {
        "filePath": "/app/config.py", "content": REDACTABLE_FILE,
        "numLines": 6, "startLine": 1, "totalLines": 6}}
    out, findings, changed = hook.redact_tool_response(response)
    assert changed
    assert SECRET not in json.dumps(out)
    assert "[REDACTED:AWS Access Key ID]" in out["file"]["content"]
    # Untouched siblings survive: redaction must not eat metadata.
    assert out["file"]["filePath"] == "/app/config.py"
    assert out["file"]["numLines"] == 6


def test_bash_shape_uses_stdout_and_stderr():
    response = {"stdout": f"AWS_ACCESS_KEY_ID={SECRET}\n",
                "stderr": "warning: postgres://admin:hunter2pass@db:5432/app\n",
                "interrupted": False, "isImage": False}
    out, findings, changed = hook.redact_tool_response(response)
    assert changed
    blob = json.dumps(out)
    assert SECRET not in blob
    assert "hunter2pass" not in blob
    assert "[REDACTED:" in out["stdout"]
    assert "[REDACTED:" in out["stderr"]


def test_cached_reread_has_no_content_and_is_left_alone():
    """A cached re-read is {'type': 'file_unchanged'} with no content. It must
    not crash the hook and must not be rewritten."""
    response = {"type": "file_unchanged"}
    out, findings, changed = hook.redact_tool_response(response)
    assert changed is False
    assert findings == []
    assert out == response


def test_bare_string_response_is_redacted():
    out, findings, changed = hook.redact_tool_response(f"key is {SECRET}")
    assert changed
    assert SECRET not in out


@pytest.mark.parametrize("response", [None, 42, [], ["a", "b"], True])
def test_unknown_response_types_are_passed_through(response):
    out, findings, changed = hook.redact_tool_response(response)
    assert changed is False
    assert out == response


# --- what must and must not be redacted -----------------------------------

def test_only_high_severity_is_redacted():
    """Redacting every PERSON would mangle author names in source."""
    response = {"file": {"content": REDACTABLE_FILE}}
    out, _, _ = hook.redact_tool_response(response)
    content = out["file"]["content"]
    for secret in REDACTABLE_SECRETS:
        assert secret not in content
    for kept in REDACTABLE_KEPT:
        assert kept in content


def test_clean_output_produces_no_updated_output():
    """Emitting updatedToolOutput unconditionally would rewrite every tool
    result in the session."""
    response = {"file": {"content": "def main():\n    return 0\n"}}
    payload, findings = hook.build_response(response)
    assert payload is None
    assert findings == []


def test_response_envelope_shape_is_exact():
    response = {"file": {"content": f"key={SECRET}"}}
    payload, findings = hook.build_response(response)
    assert set(payload) == {"hookSpecificOutput", "systemMessage"}
    hso = payload["hookSpecificOutput"]
    assert hso["hookEventName"] == "PostToolUse"
    assert "updatedToolOutput" in hso
    assert "tool_output" not in hso  # the documented-but-wrong key
    assert findings


def test_original_response_is_not_mutated():
    original = {"file": {"content": f"key={SECRET}"}}
    snapshot = json.loads(json.dumps(original))
    hook.redact_tool_response(original)
    assert original == snapshot


def test_multiple_secrets_in_one_output_all_redacted():
    content = "\n".join([
        f"aws={SECRET}",
        "gh=ghp_016C7f4b8A2d9E3f5B7c1D0a6E8b4F2c0A9d3B",
        "db=postgres://admin:hunter2pass@db:5432/app",
    ])
    out, findings, changed = hook.redact_tool_response({"stdout": content})
    assert changed
    blob = json.dumps(out)
    for secret in (SECRET, "ghp_016C7f4b8A2d9E3f5B7c1D0a6E8b4F2c0A9d3B", "hunter2pass"):
        assert secret not in blob
    assert len(findings) >= 3


def test_adjacent_secrets_do_not_corrupt_each_other():
    """Right-to-left replacement keeps earlier spans valid."""
    content = f"{SECRET} AKIAJKLMNOPQRSTUVWXY"
    out, _, changed = hook.redact_tool_response({"stdout": content})
    assert changed
    assert out["stdout"].count("[REDACTED:AWS Access Key ID]") == 2
    assert "AKIA" not in out["stdout"].replace("[REDACTED:AWS Access Key ID]", "")


def test_large_output_is_handled_without_presidio(monkeypatch):
    """PostToolUse fires on every tool call, a 50MB Read included. Presidio must
    never be reached on this path."""
    def explode(*a, **k):
        raise AssertionError("Presidio was invoked on the PostToolUse path")

    monkeypatch.setattr(scanner, "_scan_presidio", explode)
    big = ("filler line that is entirely benign\n" * 20000) + f"key={SECRET}\n"
    out, findings, changed = hook.redact_tool_response({"stdout": big})
    assert changed
    assert SECRET not in out["stdout"]


# --- error policy ---------------------------------------------------------

def test_redaction_failure_is_loud(monkeypatch, capsys):
    """Failing open here means an unredacted secret in context. It must be
    announced, not swallowed."""
    def boom(*a, **k):
        raise RuntimeError("scanner exploded")

    monkeypatch.setattr(hook, "build_response", boom)
    monkeypatch.setattr(
        "sys.stdin",
        _stdin(json.dumps({"tool_name": "Read", "tool_response": {"file": {"content": "x"}}})),
    )
    with pytest.raises(SystemExit) as exc:
        hook.main()
    assert exc.value.code == 0  # never break the tool path
    emitted = json.loads(capsys.readouterr().out)
    assert "NOT redacted" in emitted["systemMessage"]
    assert "⚠" in emitted["systemMessage"]


def test_unparseable_stdin_is_announced(monkeypatch, capsys):
    monkeypatch.setattr("sys.stdin", _stdin("{ not json"))
    with pytest.raises(SystemExit):
        hook.main()
    emitted = json.loads(capsys.readouterr().out)
    assert "NOT scanned" in emitted["systemMessage"]


def test_missing_tool_response_exits_quietly(monkeypatch, capsys):
    monkeypatch.setattr("sys.stdin", _stdin(json.dumps({"tool_name": "Read"})))
    with pytest.raises(SystemExit):
        hook.main()
    assert capsys.readouterr().out == ""


class _stdin:
    def __init__(self, text):
        self._text = text

    def read(self):
        return self._text
