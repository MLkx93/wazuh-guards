# Screenshots

Referenced from the project README. Capture at **1440px wide or narrower** so
text stays legible when rendered inline.

| File | Shows | How to reproduce |
|---|---|---|
| `01-prompt-blocked.png` | A prompt refused for containing a credential | Send: `here's my key AKIAIOSFODNN7EXAMPLE can you check if it's valid` |
| `02-output-redacted.png` | Claude answering correctly while secrets read `[REDACTED:…]` | Create `/tmp/demo-config.env` (see `00-demo-setup.png`), then: `read /tmp/demo-config.env and tell me what service this configures` |
| `03-wazuh-alerts.png` | Alert stream filtered to guardrail activity | `/app/wazuh#/overview/?tab=general`, filter `rule.groups: claude_guardrail`, range 24h |
| `04-endpoint-groups.png` | `patterns.json` in the group file viewer | `/app/endpoint-groups` → **guardrail** → Files → `patterns.json` |
| `05-alert-detail.png` | One alert's full JSON, showing the scalar `guardrail.*` fields | Expand any alert in the stream → **JSON** tab |
| `00-demo-setup.png` | The command that creates the demo file | Reference only; not linked from the README |

## Before capturing

Use `AKIAIOSFODNN7EXAMPLE` — AWS's documented example key — and never a real
credential. The file on disk keeps the real value even though the model only
ever sees the redaction.

Check the frame for anything you do not want permanently in a repo: other
terminal tabs, browser bookmarks, internal hostnames, cluster names in a shell
prompt.

## Two shots to pick deliberately

**For `05-alert-detail.png`, choose an event with `pattern_source: wazuh`.**
`PostToolUse` events report `bundled` — accurate, but that is the documented
limitation, not the behaviour you want illustrating central management. A
`UserPromptSubmit` block is the right pick.

**Skip the protected-path denial** (`read ~/.ssh/id_rsa`). It demonstrates well
live, but in Wazuh it surfaces as rule `100220` (drift) rather than `100205`,
because level 10 outranks level 5 and only the highest match is reported. See
the Known issues section of the main README.

## Optional

| File | Shows | How |
|---|---|---|
| `06-watch-live.png` | Local events and Wazuh alerts side by side in a terminal | `./scripts/watch-live.sh` while running demo prompts |
