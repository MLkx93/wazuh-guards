"""UserPromptSubmit hook: block prompts containing secrets, warn on PII.

Latency strategy:
  1. Try the warm daemon over a Unix socket (regex + Presidio).
  2. If the daemon is down, fall back to an in-process regex-only scan. That
     path is ~10ms and still catches every credential rule.

Fail-closed on detection, fail-open on infrastructure error: if the scanner
itself crashes we allow the prompt but surface a loud warning, because
silently dropping a user's prompts is its own kind of outage. Detections
themselves always block.

WHY LOW SEVERITY WARNS RATHER THAN REDACTS: a UserPromptSubmit hook CANNOT
rewrite the prompt. `updatedInput` is PreToolUse/PermissionRequest only; at
prompt submission a hook may allow, block, or APPEND context. Anything we
appended as "[REDACTED]" would sit next to the untouched original -- leaking
the value while implying it was protected. Real redaction happens at
PostToolUse, on tool output.

There is no per-prompt bypass. Note this is not an enforcement boundary: files
under ~/.claude/ are user-writable, so anyone able to set an env var could
equally unregister the hook. Hardening that requires a root-owned install plus
managed settings.
"""

import json
import socket
import sys

from .. import client
from ..audit import audit_event
from ..patterns import SEVERITY_ACTION


def _via_fallback(text: str) -> dict:
    from .. import scanner

    result = scanner.scan(text, use_presidio=False)
    result["degraded"] = "daemon unavailable - regex-only scan (no NLP PII detection)"
    return result


def _format(findings) -> str:
    return "\n".join(
        f"  • {f['rule']} ({f['detector']}): {f['sample']}" for f in findings
    )


def build_response(result: dict) -> dict | None:
    """Turn a scan verdict into the hook's stdout payload, or None to allow.
    Pure function -- tested without a daemon or a subprocess."""
    findings = result.get("findings") or []
    if not findings:
        return None

    action = result.get("action", "block")

    notes = []
    if result.get("degraded"):
        notes.append(result["degraded"])
    if result.get("presidio_error"):
        notes.append(f"presidio: {result['presidio_error']}")
    suffix = ("\n\n" + "\n".join(notes)) if notes else ""

    if action == "block":
        # A blocking prompt may also carry low-severity findings; list the
        # blocking ones first so the reason for rejection is unambiguous.
        blocking = [f for f in findings if SEVERITY_ACTION.get(f["severity"]) == "block"]
        other = [f for f in findings if SEVERITY_ACTION.get(f["severity"]) != "block"]
        detail = _format(blocking)
        if other:
            detail += "\n\nAlso present (would not block on their own):\n" + _format(other)
        return {
            "decision": "block",
            "reason": (
                f"Prompt blocked by input policy — sensitive data detected:\n{detail}\n\n"
                f"Remove or redact the values above and resend.{suffix}"
            ),
            "systemMessage": (
                f"🛡 Prompt blocked: {len(blocking)} policy violation(s) detected."
            ),
        }

    if action == "warn":
        # The prompt proceeds unchanged. The notice names each value so it is
        # obvious WHAT was exposed -- "personal data detected" alone reads as
        # though something was hidden.
        counts: dict[str, int] = {}
        for f in findings:
            counts[f["rule"]] = counts.get(f["rule"], 0) + 1
        summary = ", ".join(f"{k} x{v}" for k, v in sorted(counts.items()))
        listing = "\n".join(f"    • {f['rule']}: {f['sample']}" for f in findings)
        return {
            "systemMessage": (
                f"⚠ NOT REDACTED — {len(findings)} personal value(s) sent to the "
                f"model as typed:\n{listing}\n"
                f"    (policy: low severity = warn. Set low -> \"block\" in "
                f"patterns.py to stop these.)"
            ),
            "hookSpecificOutput": {
                "hookEventName": "UserPromptSubmit",
                "additionalContext": (
                    "[input-policy] This prompt contains personal data "
                    f"({summary}). Treat it as sensitive: do not repeat these "
                    "values unnecessarily, and do not write them to files, "
                    "logs, or outbound requests."
                ),
            },
        }

    return None


def main():
    try:
        payload = json.load(sys.stdin)
    except Exception:  # noqa: BLE001
        sys.exit(0)  # unparseable input: not our call to block

    prompt = payload.get("prompt", "") or ""
    if not prompt.strip():
        sys.exit(0)

    mode = "daemon"
    try:
        result = client.scan(prompt)
    except (OSError, socket.timeout, json.JSONDecodeError):
        mode = "fallback"
        try:
            result = _via_fallback(prompt)
        except Exception as exc:  # noqa: BLE001
            print(json.dumps({
                "systemMessage": f"⚠ Guardrail scanner failed ({type(exc).__name__}); "
                                 "prompt was NOT scanned."
            }))
            sys.exit(0)

    if result.get("error"):
        print(json.dumps({"systemMessage": f"⚠ Guardrail error: {result['error']}"}))
        sys.exit(0)

    findings = result.get("findings") or []
    audit_event(
        hook="UserPromptSubmit",
        action=result.get("action", "allow"),
        findings=findings,
        mode=mode,
        session_id=payload.get("session_id", ""),
        pattern_version=result.get("pattern_version", ""),
        pattern_sha=result.get("pattern_sha", ""),
        extra={"prompt_chars": len(prompt)},
    )

    response = build_response(result)
    if response is not None:
        print(json.dumps(response))
    sys.exit(0)


if __name__ == "__main__":
    main()
