"""Verdict sink: local ndjson that Wazuh ingests via <localfile>.

Two hard rules.

1. Auditing must never break the tool path. Every failure mode here is caught
   and dropped. A full disk is not a reason to stop a user's work.

2. AGGREGATED SCALARS, NOT ARRAYS. Wazuh's JSON decoder flattens arrays to
   `findings.0.rule`, `findings.1.rule`, ... so a rule matching
   `findings.0.severity` MISSES a high-severity finding sitting at index 1.
   Every field a Wazuh rule keys on is therefore a single scalar under
   `guardrail.*`, computed across all findings.

Redacted samples only. Never raw prompt text, never an unredacted value -- the
alert pipeline is not a place to re-leak what was just blocked.
"""

import datetime
import json
import os
import socket

DEFAULT_LOG = os.path.join(
    os.environ.get("XDG_STATE_HOME", os.path.expanduser("~/.local/state")),
    "wazuh-guards",
    "guardrail.json",
)
LOG_PATH = os.environ.get("WAZUH_GUARDS_LOG", DEFAULT_LOG)

# Bound the ndjson so an unattended host cannot fill its disk. Wazuh tails the
# file, so rotation is a plain rename the agent follows.
MAX_BYTES = int(os.environ.get("WAZUH_GUARDS_LOG_MAX_BYTES", str(32 * 1024 * 1024)))

_SEVERITY_RANK = {"low": 0, "high": 1}


def _host() -> str:
    try:
        return socket.gethostname()
    except OSError:
        return "unknown"


def _finding_fields(findings) -> dict:
    """Collapse a finding list into the scalars Wazuh rules match on."""
    normalized = []
    for f in findings:
        if isinstance(f, dict):
            normalized.append((f.get("rule", ""), f.get("severity", "low"),
                               f.get("detector", ""), f.get("sample", "")))
        else:  # scanner.Finding
            normalized.append((f.rule, f.severity, f.detector, f.sample))

    if not normalized:
        return {
            "finding_count": 0,
            "max_severity": "none",
            "has_high": False,
            "rules": "",
            "detectors": "",
            "samples": "",
        }

    max_sev = max(normalized, key=lambda n: _SEVERITY_RANK.get(n[1], 0))[1]
    rules = sorted({n[0] for n in normalized if n[0]})
    detectors = sorted({n[2] for n in normalized if n[2]})
    return {
        "finding_count": len(normalized),
        "max_severity": max_sev,
        "has_high": any(n[1] == "high" for n in normalized),
        # Comma-joined so a Wazuh rule can regex the whole set in one field
        # instead of walking indices that may not exist.
        "rules": ", ".join(rules),
        "detectors": ", ".join(detectors),
        "samples": ", ".join(n[3] for n in normalized if n[3])[:512],
    }


def build_event(
    *,
    hook: str,
    action: str,
    findings=(),
    tool: str = "",
    target: str = "",
    mode: str = "",
    pattern_version: str = "",
    pattern_sha: str = "",
    session_id: str = "",
    error: str = "",
    extra: dict | None = None,
) -> dict:
    """Assemble one guardrail event. Pure function -- tested directly."""
    event = {
        "timestamp": datetime.datetime.now().astimezone().isoformat(timespec="seconds"),
        "action": action,
        "hook": hook,
        "tool": tool,
        "target": target[:256],
        "mode": mode,
        "host": _host(),
        "session_id": session_id or os.environ.get("CLAUDE_SESSION_ID", ""),
        "cwd": os.environ.get("CLAUDE_PROJECT_DIR", ""),
        "pattern_version": pattern_version,
        "pattern_sha": pattern_sha,
    }
    event.update(_finding_fields(findings))
    if error:
        event["error"] = error[:512]
    if extra:
        event.update(extra)
    return {"guardrail": event}


def _rotate_if_needed(path: str) -> None:
    try:
        if os.path.getsize(path) >= MAX_BYTES:
            os.replace(path, f"{path}.1")
    except OSError:
        pass


def audit_event(**kwargs) -> dict:
    """Build and append one event. Returns the event so callers can assert on
    it; write failures are swallowed by design."""
    event = build_event(**kwargs)
    try:
        os.makedirs(os.path.dirname(LOG_PATH), exist_ok=True)
        _rotate_if_needed(LOG_PATH)
        with open(LOG_PATH, "a", encoding="utf-8") as fh:
            fh.write(json.dumps(event) + "\n")
    except OSError:
        pass  # auditing must never break the tool path
    except Exception:  # noqa: BLE001
        pass
    return event
