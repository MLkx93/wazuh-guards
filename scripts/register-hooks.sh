#!/usr/bin/env bash
# Register (or remove) the guardrail hooks in ~/.claude/settings.json.
#
# Separate from install.sh on purpose: installing the software and arming it
# against your live Claude Code sessions are different decisions, and this one
# should be trivially reversible.
#
#   register-hooks.sh            register
#   register-hooks.sh --remove   remove
#   register-hooks.sh --dry-run  print the resulting settings, change nothing
set -euo pipefail

SETTINGS="${CLAUDE_SETTINGS:-$HOME/.claude/settings.json}"
PREFIX="${WAZUH_GUARDS_PREFIX:-$HOME/.local/share/wazuh-guards}"
PYTHON="$PREFIX/venv/bin/python"

MODE=register
case "${1:-}" in
  --remove)  MODE=remove ;;
  --dry-run) MODE=dry-run ;;
  "")        ;;
  *) echo "usage: $0 [--remove|--dry-run]" >&2; exit 1 ;;
esac

[[ -x "$PYTHON" ]] || { echo "error: $PYTHON not found - run scripts/install.sh first" >&2; exit 1; }

"$PYTHON" - "$SETTINGS" "$PYTHON" "$MODE" <<'PY'
import json, os, shutil, sys

settings_path, python_bin, mode = sys.argv[1], sys.argv[2], sys.argv[3]

# Matcher filters keep PostToolUse off tools that return no readable content.
# The hook is cheap but fires on EVERY tool call, so narrowing it is free
# latency. Read/Bash are the paths that actually carry file content.
HOOKS = {
    "UserPromptSubmit": [
        {"hooks": [{"type": "command",
                    "command": f"{python_bin} -m wazuh_guards.hooks.prompt_submit"}]}
    ],
    "PreToolUse": [
        {"matcher": "Read|NotebookRead|Bash|Grep|Glob",
         "hooks": [{"type": "command",
                    "command": f"{python_bin} -m wazuh_guards.hooks.pre_tool_use"}]}
    ],
    "PostToolUse": [
        {"matcher": "Read|NotebookRead|Bash|Grep",
         "hooks": [{"type": "command",
                    "command": f"{python_bin} -m wazuh_guards.hooks.post_tool_use"}]}
    ],
}

MARKER = "wazuh_guards.hooks"

if os.path.exists(settings_path):
    with open(settings_path) as fh:
        settings = json.load(fh)
else:
    settings = {}
    os.makedirs(os.path.dirname(settings_path), exist_ok=True)

hooks = settings.setdefault("hooks", {})

def strip_ours(event_list):
    """Drop only entries whose command mentions our module, so hooks belonging
    to other tools survive untouched."""
    out = []
    for entry in event_list:
        remaining = [h for h in entry.get("hooks", [])
                     if MARKER not in h.get("command", "")]
        if remaining:
            out.append({**entry, "hooks": remaining})
    return out

for event in list(hooks):
    hooks[event] = strip_ours(hooks[event])
    if not hooks[event]:
        del hooks[event]

if mode != "remove":
    for event, entries in HOOKS.items():
        hooks.setdefault(event, []).extend(entries)

if not hooks:
    settings.pop("hooks", None)

if mode == "dry-run":
    print(json.dumps(settings, indent=2))
    sys.exit(0)

if os.path.exists(settings_path):
    backup = settings_path + ".bak"
    shutil.copy2(settings_path, backup)
    print(f"backed up {settings_path} -> {backup}")

tmp = settings_path + ".tmp"
with open(tmp, "w") as fh:
    json.dump(settings, fh, indent=2)
    fh.write("\n")
os.replace(tmp, settings_path)

if mode == "remove":
    print(f"removed guardrail hooks from {settings_path}")
else:
    print(f"registered guardrail hooks in {settings_path}:")
    for event in HOOKS:
        print(f"  {event}")
    print("\nRestart Claude Code for the change to take effect.")
PY
