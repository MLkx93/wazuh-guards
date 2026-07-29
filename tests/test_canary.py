"""Canary: end-to-end proof that redaction is real, not cosmetic.

The failure this exists to catch: a redactor pointed at the wrong field emits a
structurally valid response, the hook looks like it works, and every secret
passes through untouched. Unit tests pass in that state. Only tracing a unique
token from a real file through the real hook process catches it.

Method:
  1. Plant a token that exists nowhere else in the repo or on the machine.
  2. Build the tool_response Claude Code actually sends for that read.
  3. Run the hook as a SUBPROCESS -- real stdin, real stdout, no in-process
     shortcuts that could mask an import-time or entry-point bug.
  4. Assert the token appears in ZERO bytes of what the model would receive.
  5. Assert it appears in ZERO bytes of the audit log the SIEM ingests.

Run for both Read and Bash: the field paths differ, and one working does not
imply the other.
"""

import json
import os
import re
import subprocess
import sys
import uuid

import pytest

pytestmark = pytest.mark.canary

REPO_SRC = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "src")


def _canary() -> str:
    """A token no rule matches on its own, sized to sit inside a credential that
    does. If the value survives anywhere, redaction did not happen.

    The AWS rule is `AKIA[0-9A-Z]{16}` with \\b anchors, so the canary must be
    exactly 16 chars of [0-9A-Z] -- `AKIA` + canary is then a complete match
    with nothing appended. Getting this wrong produces a canary that no rule
    fires on, and the test fails "closed" (hook emits nothing) rather than
    silently passing.
    """
    token = f"ZZQQ{uuid.uuid4().hex[:12].upper()}"
    assert len(token) == 16 and token.isalnum() and token.upper() == token
    return token


def _aws_secret(canary: str) -> str:
    """Embed the canary in a credential the bundled AWS rule matches exactly."""
    secret = f"AKIA{canary}"
    assert re.fullmatch(r"(?:AKIA|ASIA|ABIA|ACCA)[0-9A-Z]{16}", secret), secret
    return secret


def _run_hook(payload: dict, log_path: str) -> tuple[int, str, str]:
    env = dict(os.environ)
    env["PYTHONPATH"] = REPO_SRC + os.pathsep + env.get("PYTHONPATH", "")
    env["WAZUH_GUARDS_LOG"] = log_path
    proc = subprocess.run(
        [sys.executable, "-m", "wazuh_guards.hooks.post_tool_use"],
        input=json.dumps(payload),
        capture_output=True,
        text=True,
        env=env,
        timeout=60,
    )
    return proc.returncode, proc.stdout, proc.stderr


def test_canary_read_is_redacted_end_to_end(tmp_path):
    canary = _canary()
    secret = _aws_secret(canary)

    target = tmp_path / "config.py"
    target.write_text(f'AWS_ACCESS_KEY_ID = "{secret}"\nDEBUG = True\n')
    log = str(tmp_path / "guardrail.json")

    payload = {
        "hook_event_name": "PostToolUse",
        "tool_name": "Read",
        "tool_input": {"file_path": str(target)},
        "tool_response": {
            "type": "text",
            "file": {
                "filePath": str(target),
                "content": target.read_text(),
                "numLines": 2,
                "startLine": 1,
                "totalLines": 2,
            },
        },
    }

    code, stdout, stderr = _run_hook(payload, log)
    assert code == 0, stderr
    assert stdout.strip(), "hook emitted nothing - the secret would reach the model verbatim"

    emitted = json.loads(stdout)
    hso = emitted["hookSpecificOutput"]
    assert hso["hookEventName"] == "PostToolUse"

    updated = hso["updatedToolOutput"]
    # What the model actually receives.
    assert canary not in json.dumps(updated)
    assert secret not in json.dumps(updated)
    assert "[REDACTED:AWS Access Key ID]" in updated["file"]["content"]
    # Non-secret content is preserved.
    assert "DEBUG = True" in updated["file"]["content"]

    # The whole emitted payload, systemMessage included.
    assert canary not in stdout


def test_canary_bash_is_redacted_end_to_end(tmp_path):
    """Bash uses .stdout/.stderr, a different path from Read. Verified
    separately because one working does not imply the other."""
    canary = _canary()
    secret = _aws_secret(canary)
    log = str(tmp_path / "guardrail.json")

    payload = {
        "hook_event_name": "PostToolUse",
        "tool_name": "Bash",
        "tool_input": {"command": "cat .env"},
        "tool_response": {
            "stdout": f"AWS_ACCESS_KEY_ID={secret}\nAWS_REGION=eu-west-1\n",
            "stderr": f"debug: using {secret}\n",
            "interrupted": False,
            "isImage": False,
        },
    }

    code, stdout, stderr = _run_hook(payload, log)
    assert code == 0, stderr
    assert stdout.strip(), "hook emitted nothing - the secret would reach the model verbatim"

    updated = json.loads(stdout)["hookSpecificOutput"]["updatedToolOutput"]
    assert canary not in json.dumps(updated)
    assert "[REDACTED:" in updated["stdout"]
    assert "[REDACTED:" in updated["stderr"]
    assert "AWS_REGION=eu-west-1" in updated["stdout"]
    assert canary not in stdout


def test_canary_never_reaches_the_audit_log(tmp_path):
    """The SIEM pipeline must not re-leak what was just redacted.
    Mirrors `grep -c <canary> guardrail.json` == 0 from the verification plan."""
    canary = _canary()
    secret = _aws_secret(canary)
    log = tmp_path / "guardrail.json"

    payload = {
        "hook_event_name": "PostToolUse",
        "tool_name": "Bash",
        "tool_input": {"command": "cat .env"},
        "tool_response": {"stdout": f"key={secret}\n", "stderr": ""},
    }

    code, stdout, stderr = _run_hook(payload, str(log))
    assert code == 0, stderr

    assert log.exists(), "no audit event written - the SIEM would see nothing"
    raw = log.read_text()
    assert canary not in raw, "CANARY LEAKED INTO THE AUDIT LOG"
    assert secret not in raw

    event = json.loads(raw.strip().splitlines()[-1])["guardrail"]
    assert event["action"] == "output_redacted"
    assert event["has_high"] is True
    assert "AWS Access Key ID" in event["rules"]
    # Redacted sample only, and it must not reconstruct the secret.
    assert canary not in event["samples"]


def test_canary_survives_a_cached_reread(tmp_path):
    """A cached re-read carries no content. The hook must stay silent rather
    than emit an empty updatedToolOutput that would blank the tool result."""
    log = str(tmp_path / "guardrail.json")
    payload = {
        "hook_event_name": "PostToolUse",
        "tool_name": "Read",
        "tool_input": {"file_path": "/app/config.py"},
        "tool_response": {"type": "file_unchanged"},
    }
    code, stdout, stderr = _run_hook(payload, log)
    assert code == 0, stderr
    assert stdout.strip() == "", "hook rewrote a contentless response"


def test_hook_runs_without_optional_dependencies(tmp_path):
    """The PostToolUse path must work under a bare interpreter: no presidio, no
    requests. If an import creeps in, redaction breaks exactly when the daemon
    is already down."""
    canary = _canary()
    secret = _aws_secret(canary)
    log = str(tmp_path / "guardrail.json")

    env = dict(os.environ)
    env["PYTHONPATH"] = REPO_SRC
    env["WAZUH_GUARDS_LOG"] = log
    blocker = (
        "import sys\n"
        "class Block:\n"
        "    def find_module(self, name, path=None):\n"
        "        if name.split('.')[0] in ('presidio_analyzer', 'spacy', 'requests'):\n"
        "            raise ImportError(f'{name} blocked by test')\n"
        "        return None\n"
        "sys.meta_path.insert(0, Block())\n"
        "from wazuh_guards.hooks.post_tool_use import main\n"
        "main()\n"
    )
    payload = {
        "tool_name": "Bash",
        "tool_input": {"command": "env"},
        "tool_response": {"stdout": f"key={secret}\n"},
    }
    proc = subprocess.run(
        [sys.executable, "-c", blocker],
        input=json.dumps(payload),
        capture_output=True, text=True, env=env, timeout=60,
    )
    assert proc.returncode == 0, proc.stderr
    assert canary not in proc.stdout
    assert "[REDACTED:" in proc.stdout
