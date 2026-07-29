# wazuh-guards

A secret/PII guardrail for Claude Code. Blocks credentials in prompts, denies
reads of key material, and **redacts secrets out of tool output before they
reach the model**. Patterns are managed centrally on a Wazuh manager; every
verdict is emitted to Wazuh for alerting, correlation, and drift detection.

## Why the third enforcement point matters most

`UserPromptSubmit` only sees what you type — roughly **1% of what enters
context**. Reading one `.env` puts more credentials in front of the model than
a user would type in a week. So there are three hooks, not one:

| Hook | Action | What it catches |
|---|---|---|
| `UserPromptSubmit` | block high / warn low | Credentials you type |
| `PreToolUse` | deny | Reads of `.env`, `*.pem`, `~/.ssh/`, `~/.aws/` |
| `PostToolUse` | **redact** | Secrets in file content and command output |

Redaction at `PostToolUse` is real, not cosmetic: the original value never
enters context. This is verified by a canary test on every run.

## Install

```bash
git clone <this repo> && cd wazuh-guards
./scripts/install.sh
python -m pytest -q          # 250 tests
./scripts/register-hooks.sh  # arms the hooks; reversible with --remove
```

Installing and arming are separate steps. Nothing is enforced until you run
`register-hooks.sh`, and `--remove` restores your previous `settings.json`
(a `.bak` is written either way).

Wazuh is optional — see [deploy/docker/single-node/](deploy/docker/single-node/).
Without it the guardrail runs on bundled patterns and behaves identically at
every enforcement point.

## How it works

```
prompt ──> UserPromptSubmit ──┐
                              ├──> daemon (Unix socket, 0600) ── regex + Presidio
tool call ──> PreToolUse ─────┤         └─ daemon down ─> in-process regex only
                              │
tool output ──> PostToolUse ──┘         regex only, high severity only
                              │
                              └──> guardrail.json (ndjson) ──> Wazuh
```

Two detectors, split by what each is good at:

| Detector | Catches | Why |
|---|---|---|
| **Regex** (`patterns.json`) | API keys, tokens, private keys, JWTs, DB URIs, SSNs, cards | Rigid vendor-defined shapes. High precision. |
| **Presidio** (spaCy NLP) | Names, locations, emails, phones, passports, IBAN | Natural-language PII regex cannot find reliably. |

Presidio loads a spaCy pipeline in ~12s, so `daemon.py` holds it in memory and
answers over a Unix socket. Warm path is **~0.23s** end to end.

## Enforcement policy

Set in `SEVERITY_ACTION` (`patterns.py`) — the one place to change it.

| Severity | Action | Behavior |
|---|---|---|
| `high` | **block** | Prompt rejected; output redacted |
| `low` | **warn** | Prompt proceeds; you see a `⚠` notice |

Strongest action wins: a prompt with both a key and a name blocks, and the
block message still lists the low-severity findings separately.

### Two things this does not do

**`warn` does not redact.** A `UserPromptSubmit` hook **cannot rewrite the
prompt** — `updatedInput` is `PreToolUse`/`PermissionRequest` only. At prompt
submission a hook may allow, block, or *append*. Anything appended as
`[REDACTED]` would sit beside the untouched original, leaking the value while
implying it was protected. The notice names each detected value so this is
unambiguous. To stop them entirely, set `"low": "block"`.

**It cannot scrub what you never typed.** Claude Code separately injects
session context — your email, username, git config. None of that passes through
`UserPromptSubmit`.

## Failure behavior

The error policy is **deliberately different per hook**, because failing open
does not cost the same thing at each one.

| Condition | Behavior |
|---|---|
| Daemon down | Regex-only fallback. **Credentials still blocked**; NLP PII missed. Stated in the block message. |
| Wazuh down | No effect on enforcement. Patterns are fetched at startup and cached; a scan never touches the network. |
| Bad pattern push | Rejected wholesale; previous ruleset stays in force. Fallback is cache → bundled. **Never empty.** |
| Scanner crash (prompt) | Prompt allowed with a loud `⚠`. Silently dropping prompts is its own outage. |
| Scanner crash (**output**) | Loud warning. Here, failing open means an unredacted secret in context — so it is never silent. |

Detections always fail **closed**. Only infrastructure errors fail open.

## Central pattern management

Patterns live on the Wazuh manager at
`/var/ossec/etc/shared/guardrail/patterns.json` and are fetched read-only at
daemon **startup**, then cached.

```json
{"version": "2026.07.29",
 "rules": [{"name": "AWS Access Key ID", "severity": "high",
            "pattern": "\\b(?:AKIA|ASIA)[0-9A-Z]{16}\\b"}]}
```

Patterns are **Python regex**. Wazuh distributes the file; it does not detect.

`SEVERITY_ACTION`, `PRESIDIO_ENTITIES`, and the Presidio thresholds stay
**local** — they are engine config, not distributable patterns. A manager that
could change them could silently downgrade every rule to "allow".

Updating patterns means editing the file on the manager over SSH: the group
files endpoint is **GET-only**. Accepted deliberately so Wazuh stays the single
management plane.

### Three dead ends, verified — do not retry

- **Wazuh's ruleset has no PII/secret patterns.** Zero hits across all 167 rule
  files in v4.9.0. `pci_dss` appears 1,456× but only as a compliance tag.
- **OS_Regex cannot be auto-translated to Python.** `\.` means *any character*
  and `.` means *a literal dot* — inverted from Python `re`. Translated
  patterns compile fine and match the wrong text.
- **CDB lists hard-reject JSON.** `validate_cdb_list()` requires every line to
  match a `key:value` regex. No bypass flag.

## Alerting

Events are ndjson at `~/.local/state/wazuh-guards/guardrail.json`, ingested via
`<localfile>`. Fields are **aggregated scalars** under `guardrail.*` — Wazuh's
JSON decoder flattens arrays to `findings.0.rule`, so a rule matching
`findings.0.severity` would **miss a high finding at index 1**.

Redacted samples only. Never raw prompt text, never an unredacted value.

| Rule | Level | Condition |
|---|---|---|
| 100201 | 3 | PII warned in a prompt |
| 100202 | 10 | Credential typed and blocked |
| **100203** | **12** | **Secret at rest redacted from output** |
| 100206 | 10 | Guardrail failure — output not scanned |
| 100210 | 12 | 5 blocks in 300s, same session |
| 100211 | 13 | Same file leaked 3× in 24h — unremediated |
| 100220/1 | 10/7 | Pattern drift / host never fetched from manager |

`100203` is the highest-value signal: a blocked prompt is a mistake already
prevented, but a redacted output means a live secret is sitting in the codebase
and will keep being read until someone rotates it.

## Managing it

```bash
guardrailctl status              # daemon, pattern version, source, sha
guardrailctl test "my ssn is 123-45-6789"
guardrailctl scan path/to/file   # what would be redacted; exit 2 if dirty
guardrailctl patterns -v         # active ruleset
guardrailctl restart             # applies pattern changes
```

Patterns load at startup, so a pattern change needs a restart.

## Not an enforcement boundary

This raises the bar against accidental leaks. It is **not** a security
boundary: everything under `~/.claude/` is user-writable, so the hooks can be
unregistered. Making it non-circumventable requires a root-owned install plus
`/etc/claude-code/managed-settings.json` with `allowManagedHooksOnly: true`.

## Tests

```bash
python -m pytest -q                 # all
python -m pytest -m "not slow" -q   # skip the ~12s Presidio load
python -m pytest -m canary -q       # redaction proof only
```

The canary tests are the ones that matter. A redactor pointed at the wrong
field produces a valid response, looks like it works, and passes every secret
through — unit tests pass in that state. See [docs/hook-payloads.md](docs/hook-payloads.md).

## Layout

| Path | Role |
|---|---|
| `src/wazuh_guards/patterns.py` | Severity policy, Presidio tuning, Luhn, redaction |
| `src/wazuh_guards/ruleset.py` | Compile/validate patterns; wazuh → cache → bundled |
| `src/wazuh_guards/data/patterns.json` | Bundled default ruleset |
| `src/wazuh_guards/scanner.py` | Scan engine and redactor |
| `src/wazuh_guards/daemon.py` | Warm socket server, pattern refresh |
| `src/wazuh_guards/hooks/` | The three enforcement points |
| `src/wazuh_guards/wazuh/api.py` | Read-only manager client |
| `src/wazuh_guards/audit.py` | `guardrail.*` scalar event emitter |
| `deploy/wazuh/local_rules.xml` | Alert, correlation, and drift rules |
