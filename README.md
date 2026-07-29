# wazuh-guards

A secret/PII guardrail for Claude Code. Blocks credentials in prompts, denies
reads of key material, and **redacts secrets out of tool output before they
reach the model**. Patterns are managed centrally on a Wazuh manager; every
verdict is emitted to Wazuh for alerting, correlation, and drift detection.

![Architecture](docs/img/00-architecture.png)

## What a hook is

Claude Code can run your own programs at fixed points in its own execution.
Those points are called **hooks**, and they are the mechanism this whole project
is built on.

At each point, Claude Code runs the configured command, hands it a JSON
description of what is about to happen (or just happened) on **stdin**, and
reads JSON back from **stdout**. What the hook prints decides what happens next.

The available verdicts differ per event, and that asymmetry shapes the design:

| Event | Can allow | Can block | Can rewrite content |
|---|---|---|---|
| `UserPromptSubmit` | yes | yes | **no** — may only append a notice |
| `PreToolUse` | yes | yes (`deny`) | yes (`updatedInput`) |
| `PostToolUse` | yes | — | **yes** (`updatedToolOutput`) |

`PostToolUse` returning `updatedToolOutput` is what makes redaction real: the
model receives the rewritten text and never the original. `UserPromptSubmit`
has no equivalent, which is why a typed secret is *blocked* rather than
silently cleaned.

```
you type a prompt
      │
      ▼
  UserPromptSubmit hook ──► our scanner ──► "block" ──► prompt never sent
      │ (allowed)
      ▼
   the model decides to read a file
      │
      ▼
  PreToolUse hook ──────► our scanner ──► "deny"  ──► file never opened
      │ (allowed)
      ▼
   the file is read
      │
      ▼
  PostToolUse hook ─────► our scanner ──► rewritten content ──► model sees
      │                                                          [REDACTED]
      ▼
   the model continues
```

Three properties make this the right place for a guardrail:

- **It runs before the model sees anything.** A blocked prompt is never sent;
  a redacted file is rewritten in transit. This is interception, not
  after-the-fact detection.
- **It is out-of-process.** The hook is an ordinary program — here, Python. It
  is not part of the model, cannot be talked out of its decision, and is not
  subject to prompt injection.
- **It is configuration, not a fork.** Hooks live in `~/.claude/settings.json`.
  Nothing about Claude Code itself is modified, so nothing breaks when it
  updates.

The trade-off is in the same sentence: `settings.json` belongs to the user, so
a user can unregister the hooks. See
[Not an enforcement boundary](#not-an-enforcement-boundary).

`scripts/register-hooks.sh` writes that configuration; the payload shapes for
each event are in [docs/hook-payloads.md](docs/hook-payloads.md).

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
python -m pytest -q          # 250 tests; see Known issues for the 1 expected failure
./scripts/register-hooks.sh  # arms the hooks; reversible with --remove
```

Installing and arming are separate steps. Nothing is enforced until you run
`register-hooks.sh`, and `--remove` restores your previous `settings.json`
(a `.bak` is written either way).

Wazuh is optional — see [deploy/docker/single-node/](deploy/docker/single-node/).
Without it the guardrail runs on bundled patterns and behaves identically at
every enforcement point.

### Shipping events to Wazuh

Enforcement works the moment the hooks are registered. **Alerting does not** —
that needs a Wazuh agent on each monitored host, which is a separate install
from everything above. Without it, events accumulate in
`~/.local/state/wazuh-guards/guardrail.json` and never reach the manager.

```bash
# 1. install the agent, pointing it at the manager
curl -s https://packages.wazuh.com/key/GPG-KEY-WAZUH | sudo gpg --no-default-keyring \
  --keyring gnupg-ring:/usr/share/keyrings/wazuh.gpg --import
sudo chmod 644 /usr/share/keyrings/wazuh.gpg
echo "deb [signed-by=/usr/share/keyrings/wazuh.gpg] https://packages.wazuh.com/4.x/apt/ stable main" \
  | sudo tee /etc/apt/sources.list.d/wazuh.list
sudo apt-get update
sudo WAZUH_MANAGER='127.0.0.1' apt-get install -y wazuh-agent=4.9.0-1

# 2. tell it to tail the guardrail log (see deploy/wazuh/ossec-localfile.xml)
sudo tee -a /var/ossec/etc/ossec.conf > /dev/null <<'EOF'
<ossec_config>
  <localfile>
    <log_format>json</log_format>
    <location>/home/*/.local/state/wazuh-guards/guardrail.json</location>
  </localfile>
</ossec_config>
EOF

sudo systemctl enable --now wazuh-agent
```

Pin the agent version to the manager's. The trailing `<ossec_config>` wrapper
is required — `ossec.conf`'s existing element is already closed, so an
unwrapped `<localfile>` is a parse error.

Confirm the agent registered, then that events arrive:

```bash
docker exec single-node-wazuh.manager-1 /var/ossec/bin/agent_control -l
guardrailctl test "my key is AKIAIOSFODNN7EXAMPLE"
sleep 15
docker exec single-node-wazuh.manager-1 sh -c \
  'grep -c claude_guardrail /var/ossec/logs/alerts/alerts.json'
```

The agent tails from **end of file**, so events written before it started are
never ingested. That is normal, not a fault.

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

## Known issues

Open items as of 2026-07-29, verified against a live single-node deployment.
None block use; all are worth knowing before changing the code.

### `PostToolUse` redacts from the *bundled* ruleset, not the published one

`prompt_submit.py` scans via the daemon (`client.scan()`), so prompt
enforcement uses whatever `patterns.json` the manager published.
`post_tool_use.py` calls `scanner.redact_text()` **in-process**, and
`scanner.get_ruleset()` falls back to `load_bundled()` when no daemon has
called `set_ruleset()`. Tool-output redaction therefore ignores central
pattern management.

Harmless while the bundled and published rulesets are identical — which is the
case today, both `805897…0563`. It becomes a real gap the moment a new pattern
is published: prompts honour it immediately, tool output does not until a
release ships new bundled patterns. `PostToolUse` audit events report
`pattern_source: bundled`, which is accurate but easy to misread as a fault.

*Fix:* add a redact operation to `client.py` and the daemon dispatch, call it
from `post_tool_use.py` with in-process fallback on `OSError`/timeout, and take
version/sha/source from the daemon response rather than `get_ruleset()`.

### Rule `100220` false-positives on events with no `pattern_sha`

The drift rule matches `guardrail.pattern_sha` with `negate="yes"`, so an
**empty** field counts as drift. `PreToolUse` denials carry no `pattern_sha` —
it is a path check, no patterns involved — and so every protected-path denial
also raises a spurious drift alert.

Worse, it masks the real one: `100220` is level 10 and `100205`
(protected-path denial) is level 5, and Wazuh reports only the
highest-priority match. A denied `~/.ssh/id_rsa` read is reported as *pattern
drift*.

*Fix:* require a non-empty sha before the negated match, e.g. add
`<field name="guardrail.pattern_sha">.+</field>` to rule `100220` in
`deploy/wazuh/local_rules.xml`, then re-copy and restart the manager.

### `test_patterns_prints_provenance` fails on a machine that has fetched patterns

`pytest` shows 249 passed, 1 failed. The test calls the real
`cli.main(["patterns"])` with no mocking; `patterns` without `--refresh` walks
the documented cache → bundled chain, and asserts `source: bundled`. That holds
only until a real `~/.cache/wazuh-guards/patterns.json` exists — which a
successful Wazuh fetch creates. **Not a guardrail regression**; the CLI is
behaving correctly.

*Fix:* point `WAZUH_GUARDS_CACHE_DIR` (read at `ruleset.py:28`) at a `tmp_path`
in that test. Verified: it passes in isolation.

### `guardrailctl` is not on `PATH`

`install.sh` does not symlink it. It lives at
`~/.local/share/wazuh-guards/venv/bin/guardrailctl`, so `command -v
guardrailctl` and a system-python `import wazuh_guards` both fail on a working
install. Alias it, or use the full path.

Also note `guardrailctl patterns` and `guardrailctl status` can disagree —
`patterns` resolves independently and may print `source: cache` while the
daemon holds `source=wazuh`. **`status` is authoritative** for what is actually
enforcing.

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
| 100200 | 0 | Base event — no alert, parent for the rest |
| 100201 | 3 | PII warned in a prompt |
| 100202 | 10 | Credential typed and blocked |
| **100203** | **12** | **Secret at rest redacted from output** |
| 100204 | 5 | Low-severity data redacted from output |
| 100205 | 5 | Denied read of a protected path |
| 100206 | 10 | Guardrail failure — output not scanned |
| 100207 | 5 | Daemon down — regex-only, NLP PII undetected |
| 100210 | 12 | 5 blocks in 300s, same session |
| 100211 | 13 | Same file leaked 3× in 24h — unremediated |
| 100212 | 10 | 5 protected-path attempts in 600s, same session |
| 100220/1 | 10/7 | Pattern drift / host never fetched from manager |

`100203` is the highest-value signal: a blocked prompt is a mistake already
prevented, but a redacted output means a live secret is sitting in the codebase
and will keep being read until someone rotates it.

### Where to look in the dashboard

Wazuh 4.9 splits these into separate top-level apps — there is no combined
"Management" section, and the older `#/manager/?tab=…` hash routes do not
resolve.

| View | URL |
|---|---|
| Published patterns | `/app/endpoint-groups` → **guardrail** → Files → `patterns.json` |
| Alert rules | `/app/rules` → filter `claude_guardrail` |
| Alerts as they arrive | `/app/wazuh#/overview/?tab=general`, filter `rule.groups: claude_guardrail` |

Set the time picker to at least **Last 24 hours**; it defaults to 15 minutes.
Alert timestamps are container UTC, so they may sit an hour off local time.

For a terminal view of the same data, `scripts/watch-live.sh` follows local
scan events and manager alerts side by side (`--replay` for recent history).

### What it looks like

**A credential typed into a prompt never reaches the model.**

![Blocked prompt](docs/img/01-prompt-blocked.png)

The value is masked even in the refusal, and the reason names the rule that
matched.

**A config file is read; the answer is still useful, the secrets are not in it.**

![Redacted file read](docs/img/02-output-redacted.png)

This is the case that matters most. The developer never typed a secret — they
asked a reasonable question about a config file. Claude still identifies the
service correctly, because it can see the *shape* of the credentials without
the values.

**Every verdict becomes a Wazuh alert, attributed to the host.**

![Alerts in Wazuh](docs/img/03-wazuh-alerts.png)

**Each alert carries the full scalar event.**

![Alert detail](docs/img/05-alert-detail.png)

`pattern_source: wazuh` and `pattern_sha` are what make drift detection
possible: they say which ruleset this host actually enforced. Note every
`guardrail.*` field is a flat scalar — see [Alerting](#alerting) for why that
matters.

**Patterns are managed on the manager, not on laptops.**

![Published patterns](docs/img/04-endpoint-groups.png)

To recapture any of these, follow [docs/demo.md](docs/demo.md) — it drives each
state in order. Capture guidance is in [docs/img/README.md](docs/img/README.md).

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
