"""PreToolUse hook: deny reads of files whose whole purpose is holding secrets.

This is prevention where PostToolUse is mitigation. Redaction is good, but the
secret still transits the hook process and depends on a rule matching its
shape. A .env full of unrecognized vendor tokens redacts to nothing useful.
Refusing the read is the stronger guarantee, and cheap: these paths are almost
never what someone legitimately needs in context.

Scope is deliberately narrow -- protected paths only, not "files that look
sensitive". A hook that denies too much gets disabled, and a disabled hook
protects nothing.

Bash is checked too, because `cat .env` reaches the same content by another
route. That check is best-effort pattern matching on the command string, not a
shell parser; it raises the bar without claiming to be airtight. PostToolUse
redaction is the backstop for whatever slips through.

Output shape:
    {"hookSpecificOutput": {"hookEventName": "PreToolUse",
                            "permissionDecision": "deny",
                            "permissionDecisionReason": "..."}}
"""

import fnmatch
import json
import os
import re
import sys

from ..audit import audit_event

# Filename patterns that are secret stores by definition. Matched against the
# basename, case-insensitively.
PROTECTED_NAMES = (
    ".env",
    ".env.*",
    "*.pem",
    "*.key",
    "*.p12",
    "*.pfx",
    "*.jks",
    "*.keystore",
    "id_rsa",
    "id_dsa",
    "id_ecdsa",
    "id_ed25519",
    "*.ppk",
    ".netrc",
    ".pgpass",
    ".htpasswd",
    "credentials",
    "credentials.json",
    "service-account*.json",
    "*.kdbx",
    "shadow",
    "secring.gpg",
)

# Directory segments whose contents are credential material wholesale.
PROTECTED_DIRS = (
    ".ssh",
    ".gnupg",
    ".aws",
    ".kube",
    ".docker",
)

# Names that LOOK protected but are routinely needed and hold no secrets.
# Without these, the hook blocks ordinary work and gets turned off.
ALLOWED_NAMES = (
    ".env.example",
    ".env.sample",
    ".env.template",
    ".env.dist",
    ".env.test",
    "env.example",
)

# Bash commands that would read a protected path. Best-effort, not a parser.
_READERS = r"(?:cat|bat|less|more|head|tail|strings|xxd|od|nl|cp|rsync|scp|base64|openssl)"
BASH_READ_PATTERNS = tuple(
    re.compile(p, re.IGNORECASE)
    for p in (
        # A reader command naming a protected file
        rf"\b{_READERS}\b[^|;&]*?(?:^|[\s/'\"])(\.env(?:\.[A-Za-z0-9_-]+)?)(?:[\s'\"]|$)",
        rf"\b{_READERS}\b[^|;&]*?\.(?:pem|key|p12|pfx|jks|kdbx|ppk)\b",
        rf"\b{_READERS}\b[^|;&]*?(?:\.ssh|\.gnupg|\.aws|\.kube)/",
        rf"\b{_READERS}\b[^|;&]*?\bid_(?:rsa|dsa|ecdsa|ed25519)\b",
        # No \b before the leading dot: "/" and "." are both non-word chars, so
        # there is no boundary between them in "~/.netrc".
        rf"\b{_READERS}\b[^|;&]*?(?:^|[\s/'\"])\.(?:netrc|pgpass|htpasswd)\b",
        # Whole-directory dumps of credential stores
        r"\b(?:tar|zip|find)\b[^|;&]*?(?:\.ssh|\.gnupg|\.aws)\b",
    )
)

# Tools that read file content. Write/Edit are excluded: blocking a write to
# .env stops legitimate setup work and leaks nothing into context.
READ_TOOLS = {"Read", "NotebookRead"}
CONTENT_TOOLS = READ_TOOLS | {"Bash", "Grep", "Glob"}


def is_protected_path(path: str) -> tuple[bool, str]:
    """Return (protected, reason). Reason is empty when not protected."""
    if not path:
        return False, ""
    normalized = os.path.normpath(path.strip().strip("'\""))
    basename = os.path.basename(normalized).lower()

    if basename in ALLOWED_NAMES:
        return False, ""
    # An example file in any casing/suffix arrangement is still an example.
    if basename.startswith(".env.") and basename.split(".")[-1] in {
        "example", "sample", "template", "dist"
    }:
        return False, ""

    segments = {s.lower() for s in normalized.split(os.sep) if s}
    for protected_dir in PROTECTED_DIRS:
        if protected_dir in segments:
            return True, f"{protected_dir}/ holds credential material"

    for pattern in PROTECTED_NAMES:
        if fnmatch.fnmatch(basename, pattern):
            return True, f"{basename} matches protected pattern '{pattern}'"

    return False, ""


def check_bash_command(command: str) -> tuple[bool, str]:
    if not command:
        return False, ""
    for pattern in BASH_READ_PATTERNS:
        m = pattern.search(command)
        if m:
            return True, f"command reads a protected path: {m.group(0)[:120]}"
    return False, ""


def evaluate(payload: dict) -> tuple[bool, str, str]:
    """Return (deny, reason, target)."""
    tool = payload.get("tool_name", "")
    if tool not in CONTENT_TOOLS:
        return False, "", ""

    tool_input = payload.get("tool_input")
    if not isinstance(tool_input, dict):
        return False, "", ""

    if tool == "Bash":
        command = tool_input.get("command", "")
        denied, reason = check_bash_command(command)
        return denied, reason, command[:256] if denied else ""

    for key in ("file_path", "path", "notebook_path"):
        value = tool_input.get(key)
        if isinstance(value, str) and value:
            denied, reason = is_protected_path(value)
            if denied:
                return True, reason, value[:256]

    # Grep/Glob take a search path; denying the *pattern* would be noise, but a
    # glob rooted inside .ssh is a credential sweep.
    if tool in ("Grep", "Glob"):
        for key in ("path", "glob"):
            value = tool_input.get(key)
            if isinstance(value, str) and value:
                denied, reason = is_protected_path(value)
                if denied:
                    return True, reason, value[:256]

    return False, "", ""


def build_response(reason: str) -> dict:
    return {
        "hookSpecificOutput": {
            "hookEventName": "PreToolUse",
            "permissionDecision": "deny",
            "permissionDecisionReason": (
                f"Blocked by input policy: {reason}. Reading this file would put "
                f"credentials directly into model context. If you need a value "
                f"from it, reference it by variable name instead."
            ),
        }
    }


def main():
    try:
        payload = json.load(sys.stdin)
    except Exception:  # noqa: BLE001
        sys.exit(0)  # unparseable input: not our call to deny

    try:
        deny, reason, target = evaluate(payload)
    except Exception as exc:  # noqa: BLE001
        # Fail open with a warning: a crashing path check must not wedge every
        # tool call. PostToolUse still redacts whatever this would have stopped.
        print(json.dumps({
            "systemMessage": f"⚠ Guardrail path check failed ({type(exc).__name__}); "
                             f"tool call was NOT checked against protected paths."
        }))
        sys.exit(0)

    if not deny:
        sys.exit(0)

    audit_event(
        hook="PreToolUse",
        action="read_denied",
        tool=payload.get("tool_name", ""),
        target=target,
        extra={"reason": reason[:256]},
    )
    print(json.dumps(build_response(reason)))
    sys.exit(0)


if __name__ == "__main__":
    main()
