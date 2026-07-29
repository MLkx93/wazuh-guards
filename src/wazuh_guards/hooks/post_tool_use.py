"""PostToolUse hook: redact high-severity secrets from tool output.

This is the hook that matters most. UserPromptSubmit only sees what the user
types -- roughly 1% of what enters context. Reading one .env puts more
credentials in front of the model than a user would type in a week.

THE DOCUMENTED FIELD NAMES ARE WRONG. Verified empirically against a live
Claude Code install:

    stdin key      is `tool_response`         NOT `tool_output`
    Read content   is `tool_response.file.content`   NOT `.text`
    Bash content   is `tool_response.stdout` / `.stderr`
    cached re-read is {'type': 'file_unchanged'} with no content at all

A redactor targeting the wrong field FAILS OPEN SILENTLY: it emits a valid
response, the hook appears to work, and every secret passes through. Unit tests
pass in that state. Only the canary test (tests/test_canary.py) catches it, so
do not change the extractors below without running it.

Output shape:
    {"hookSpecificOutput": {"hookEventName": "PostToolUse",
                            "updatedToolOutput": <modified tool_response>}}

Error policy is INVERTED relative to the prompt hook. There, failing open costs
one unscanned prompt. Here it means an unredacted secret in context, silently.
So any failure in the redaction path is announced loudly rather than swallowed.

Regex only -- no Presidio. This fires on every tool call with the full output on
stdin, a 50MB Read included, where a 12s NLP pass would be unusable.
"""

import json
import sys

from .. import scanner
from ..audit import audit_event


def _redact_field(container: dict, key: str, findings: list) -> bool:
    """Redact one string field in place. Returns True if it changed."""
    value = container.get(key)
    if not isinstance(value, str) or not value:
        return False
    cleaned, hits = scanner.redact_text(value)
    if not hits:
        return False
    container[key] = cleaned
    findings.extend(hits)
    return True


def redact_tool_response(tool_response):
    """Walk the known content shapes and redact each one.

    Returns (redacted_response, findings, changed). The response is copied
    rather than mutated so a caller holding the original is unaffected.
    """
    findings: list = []

    # Bash and some MCP tools return a bare string.
    if isinstance(tool_response, str):
        cleaned, hits = scanner.redact_text(tool_response)
        return cleaned, hits, bool(hits)

    if not isinstance(tool_response, dict):
        # Nothing we know how to read. Not an error -- many tools return
        # structured non-text results -- but nothing to redact either.
        return tool_response, [], False

    out = json.loads(json.dumps(tool_response))  # deep copy, JSON-safe by construction
    changed = False

    # Read: {"file": {"content": "...", "filePath": "...", ...}}
    file_obj = out.get("file")
    if isinstance(file_obj, dict):
        changed |= _redact_field(file_obj, "content", findings)

    # Bash: {"stdout": "...", "stderr": "...", ...}
    for key in ("stdout", "stderr"):
        changed |= _redact_field(out, key, findings)

    # Grep/Glob and several MCP tools surface content at the top level.
    for key in ("content", "output", "text", "result"):
        changed |= _redact_field(out, key, findings)

    return out, findings, changed


def build_response(tool_response):
    """Produce the hook's stdout payload, or None when nothing changed.

    Emitting updatedToolOutput unconditionally would rewrite every tool result
    in the session even when no secret was present; returning None leaves the
    original untouched.
    """
    redacted, findings, changed = redact_tool_response(tool_response)
    if not changed:
        return None, findings
    return (
        {
            "hookSpecificOutput": {
                "hookEventName": "PostToolUse",
                "updatedToolOutput": redacted,
            },
            "systemMessage": (
                f"🛡 Redacted {len(findings)} secret(s) from tool output: "
                + ", ".join(sorted({f.rule for f in findings}))
            ),
        },
        findings,
    )


def main():
    try:
        payload = json.load(sys.stdin)
    except Exception:  # noqa: BLE001
        # Unparseable stdin: we cannot redact what we cannot read. Say so --
        # staying quiet here is indistinguishable from "nothing to redact".
        print(json.dumps({
            "systemMessage": "⚠ Guardrail: unreadable PostToolUse payload; "
                             "tool output was NOT scanned for secrets."
        }))
        sys.exit(0)

    tool_response = payload.get("tool_response")
    if tool_response is None:
        sys.exit(0)

    tool_name = payload.get("tool_name", "")
    target = _tool_target(payload)

    try:
        response, findings = build_response(tool_response)
    except Exception as exc:  # noqa: BLE001
        # Loud by design: a silent failure here leaves the secret in context.
        print(json.dumps({
            "systemMessage": (
                f"⚠ GUARDRAIL REDACTION FAILED ({type(exc).__name__}: {exc}). "
                f"Output of {tool_name or 'tool'} was NOT redacted and may "
                f"contain secrets."
            )
        }))
        audit_event(
            hook="PostToolUse", action="error", findings=[],
            tool=tool_name, target=target, error=f"{type(exc).__name__}: {exc}",
        )
        sys.exit(0)

    if response is None:
        sys.exit(0)

    audit_event(
        hook="PostToolUse", action="output_redacted", findings=findings,
        tool=tool_name, target=target,
    )
    print(json.dumps(response))
    sys.exit(0)


def _tool_target(payload: dict) -> str:
    """Best-effort identifier of what the tool acted on, for correlation.
    Wazuh rule 100211 keys on this to spot a file that leaks repeatedly."""
    ti = payload.get("tool_input")
    if not isinstance(ti, dict):
        return ""
    for key in ("file_path", "path", "notebook_path", "command", "pattern"):
        value = ti.get(key)
        if isinstance(value, str) and value:
            return value[:256]
    return ""


if __name__ == "__main__":
    main()
