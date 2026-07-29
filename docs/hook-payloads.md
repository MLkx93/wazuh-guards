# Hook payload shapes

Field names verified empirically against a live Claude Code install. **Several
documented names are wrong**, and getting them wrong fails open silently — the
hook emits a valid response, appears to work, and passes every secret through.

## PostToolUse

| | Documented | **Actual** |
|---|---|---|
| stdin key | `tool_output` | **`tool_response`** |
| Read content | `.text` | **`.file.content`** |
| Bash content | `.text` | **`.stdout` / `.stderr`** |
| Cached re-read | — | `{"type": "file_unchanged"}`, no content |

### Read

```json
{
  "hook_event_name": "PostToolUse",
  "tool_name": "Read",
  "tool_input": {"file_path": "/app/config.py"},
  "tool_response": {
    "type": "text",
    "file": {
      "filePath": "/app/config.py",
      "content": "...",
      "numLines": 42,
      "startLine": 1,
      "totalLines": 42
    }
  }
}
```

### Bash

```json
{
  "tool_name": "Bash",
  "tool_input": {"command": "cat .env"},
  "tool_response": {
    "stdout": "...",
    "stderr": "...",
    "interrupted": false,
    "isImage": false
  }
}
```

### Cached re-read

A second Read of an unchanged file carries no content at all:

```json
{"tool_name": "Read", "tool_response": {"type": "file_unchanged"}}
```

The hook must stay silent here. Emitting an `updatedToolOutput` built from a
contentless response would blank the tool result.

### Output

```json
{
  "hookSpecificOutput": {
    "hookEventName": "PostToolUse",
    "updatedToolOutput": { "...the modified tool_response..." }
  }
}
```

Emit nothing when there is nothing to redact — an unconditional
`updatedToolOutput` rewrites every tool result in the session.

## UserPromptSubmit

**Cannot rewrite the prompt.** `updatedInput` exists for PreToolUse and
PermissionRequest only. At prompt submission a hook may:

- allow (exit 0, no output)
- block (`{"decision": "block", "reason": "..."}`)
- **append** context (`hookSpecificOutput.additionalContext`)

There is no fourth option. Anything appended as `[REDACTED]` sits *next to* the
untouched original, which leaks the value while implying it was protected —
which is why low-severity PII is warned, never "redacted", at this hook.

```json
{"session_id": "...", "prompt": "...", "cwd": "/app"}
```

## PreToolUse

```json
{
  "hookSpecificOutput": {
    "hookEventName": "PreToolUse",
    "permissionDecision": "deny",
    "permissionDecisionReason": "..."
  }
}
```

`permissionDecision` is one of `allow` / `deny` / `ask`.

## Why the canary test exists

A redactor pointed at `tool_output` or `.text` finds nothing, changes nothing,
and returns a structurally valid response. Unit tests over synthetic payloads
pass. The only thing that catches it is planting a unique token in a real file,
running the hook as a subprocess, and asserting the token appears in **zero
bytes** of the emitted JSON — see `tests/test_canary.py`.

That is not a hypothetical: it is how the first implementation of this hook
failed, and it looked like it was working the whole time.
