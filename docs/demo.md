# Demo script — Claude Code guardrail with Wazuh

~10 minutes. Two screens: a terminal running Claude Code, and the Wazuh
dashboard.

## Before they arrive

```bash
# 1. daemon healthy and on manager-supplied patterns
~/.local/share/wazuh-guards/venv/bin/guardrailctl status
#    expect: RUNNING ... source=wazuh

# 2. Wazuh up, agent connected
docker exec single-node-wazuh.manager-1 /var/ossec/bin/agent_control -l

# 3. demo file with test credentials
cat > /tmp/demo-config.env <<'EOF'
SERVICE_NAME=billing-api
AWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE
DATABASE_URL=postgres://admin:hunter2@db.internal:5432/billing
EOF
```

Open in the browser, logged in already:

- `https://localhost:443/app/endpoint-groups` → **guardrail** → Files → `patterns.json`
- `https://localhost:443/app/rules` → filter `claude_guardrail`
- `https://localhost:443/app/wazuh#/overview/?tab=general`

Optional third pane, live event stream:

```bash
./scripts/watch-live.sh
```

## The 30-second framing

> Developers paste secrets into AI assistants. Once a credential reaches the
> model provider it is out of our control and must be treated as rotated.
> This blocks that at the point of use — and every block is a Wazuh alert, so
> security sees it without asking developers to self-report.

## Act 1 — a secret in a prompt is blocked

In Claude Code, send:

```
here's my key AKIAIOSFODNN7EXAMPLE can you check if it's valid
```

**Expected:** the prompt is refused before reaching the model. The key never
leaves the machine.

Dashboard → rule **100202**, level 10, group `credential_exposure`.

> The developer gets an immediate, specific message. Security gets the alert.

## Act 2 — a secret in a *file* is redacted

Ask Claude Code:

```
read /tmp/demo-config.env and tell me what service this configures
```

**Expected:** Claude answers correctly — `billing-api` — but the AWS key and
the database password come through as `[REDACTED:…]`. The assistant stays
useful; the secrets do not reach the model.

Dashboard → rule **100203**, level 12, both rule names listed.

> This is the case people miss. The developer never typed a secret. They asked
> a reasonable question about a config file.

## Act 3 — protected paths are refused outright

```
read ~/.ssh/id_rsa
```

**Expected:** denied before the file is opened — not redacted after.

Dashboard → rule **100205**.

> Redaction is a safety net. For known credential stores we don't read at all.

## Act 4 — central management

Show `patterns.json` in **Endpoint groups → guardrail → Files**.

> 21 detection patterns, managed here, not on laptops. Publish once and every
> host picks it up on daemon restart. `pattern_sha` on every event tells us
> which hosts are actually on the published set — a host running stale or
> locally-edited patterns alerts as drift (rule 100220).

## Act 5 — it does not depend on Wazuh to work

```bash
docker compose -f ~/wazuh-docker/single-node/docker-compose.yml stop
~/.local/share/wazuh-guards/venv/bin/guardrailctl test "key AKIAIOSFODNN7EXAMPLE"
# still blocks
docker compose -f ~/wazuh-docker/single-node/docker-compose.yml start
```

> Patterns are cached at startup. If the manager is down we lose alerting, not
> enforcement. Wazuh is the management and visibility plane, not a dependency
> in the blocking path.

## Questions you should expect

**"Can a developer turn it off?"**
Yes — the hooks are in the user's own `settings.json`. This is a guardrail
against accident, not a control against a determined insider. Say so plainly;
claiming otherwise invites a bad follow-up question. The Wazuh side is what
makes disabling *visible*: a host that stops reporting is itself a signal.

**"What's the false-positive rate?"**
Credential patterns are high-precision (structured formats like `AKIA…`).
Presidio-based PII detection is fuzzier — names are flagged at low severity and
warn rather than block, which is why act 1 blocks and a person's name does not.

**"Latency?"**
A daemon holds the spaCy model in memory, so scans are a local socket
round-trip rather than a ~12s model load per call.

**"Does this cover tool output as well as prompts?"**
Yes — act 2 is exactly that. Be precise on one point: prompt scanning uses the
Wazuh-published patterns; tool-output redaction currently runs from the bundled
set. They are identical today, so behaviour matches, but a newly published
pattern reaches prompt scanning first. Known, documented, fix is scoped.

**"What if the daemon crashes?"**
Hooks fail open — a broken guardrail degrades to no protection, never to a
broken Claude Code. Rule **100206** alerts on scan failure and **100207** on
daemon-down, so failure is loud rather than silent.

## Do not improvise

Use `AKIAIOSFODNN7EXAMPLE` — AWS's documented example key. Never demo with a
real credential: it is a live secret in a room with a projector, and the file
on disk keeps the real value even though the model only sees the redaction.
