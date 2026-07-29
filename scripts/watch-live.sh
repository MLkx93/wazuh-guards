#!/usr/bin/env bash
# Live view of the guardrail: local scan events on the left of the pipeline,
# the Wazuh alerts they produce on the right.
#
#   watch-live.sh            follow both streams
#   watch-live.sh --replay   print the last 15 of each and exit
set -uo pipefail

STATE="${XDG_STATE_HOME:-$HOME/.local/state}/wazuh-guards/guardrail.json"
MANAGER="${WAZUH_MANAGER_CONTAINER:-single-node-wazuh.manager-1}"
ALERTS=/var/ossec/logs/alerts/alerts.json

B=$'\033[1m'; D=$'\033[2m'; R=$'\033[31m'; Y=$'\033[33m'; G=$'\033[32m'; C=$'\033[36m'; X=$'\033[0m'

fmt_event() {
  python3 -c '
import sys, json
C={"block":"\033[31m","read_denied":"\033[31m","output_redacted":"\033[33m",
   "warn":"\033[33m","error":"\033[35m","allow":"\033[32m"}
for line in sys.stdin:
    line=line.strip()
    if not line: continue
    try: g=json.loads(line)["guardrail"]
    except Exception: continue
    a=g.get("action",""); col=C.get(a,"")
    ts=g.get("timestamp","")[11:19]
    hook=g.get("hook",""); tool=g.get("tool","") or "-"
    rules=g.get("rules","") or "-"
    src=g.get("pattern_source","") or "?"
    print(f"\033[2m{ts}\033[0m  GUARD  {col}{a:15}\033[0m {hook:16} {tool:8} "
          f"\033[36m{rules:24}\033[0m src=\033[1m{src}\033[0m", flush=True)
'
}

fmt_alert() {
  python3 -c '
import sys, json
for line in sys.stdin:
    line=line.strip()
    if not line: continue
    try: a=json.loads(line)
    except Exception: continue
    if "claude_guardrail" not in json.dumps(a.get("rule",{}).get("groups",[])): continue
    r=a["rule"]; lvl=int(r.get("level",0))
    col="\033[31m" if lvl>=10 else ("\033[33m" if lvl>=6 else "\033[32m")
    ts=a.get("timestamp","")[11:19]
    agent=a.get("agent",{}).get("name","?")
    rid=r.get("id","?"); desc=r.get("description","")[:64]
    print(f"\033[2m{ts}\033[0m  WAZUH  {col}rule {rid} lvl {lvl:<2}\033[0m "
          f"{desc:64} \033[2m{agent}\033[0m", flush=True)
'
}

if [[ "${1:-}" == "--replay" ]]; then
  printf '%s\n' "${B}── recent guardrail events ─────────────────────────────${X}"
  tail -15 "$STATE" 2>/dev/null | fmt_event
  printf '\n%s\n' "${B}── recent Wazuh alerts ─────────────────────────────────${X}"
  docker exec "$MANAGER" sh -c "grep claude_guardrail $ALERTS 2>/dev/null | tail -15" | fmt_alert
  exit 0
fi

printf '%s\n' "${B}watching${X} ${D}$STATE${X}"
printf '%s\n' "${B}    and${X} ${D}$MANAGER:$ALERTS${X}"
printf '%s\n\n' "${D}GUARD = scanned here   WAZUH = alerted centrally   (ctrl-c to stop)${X}"

trap 'kill 0' EXIT INT TERM
tail -n0 -F "$STATE" 2>/dev/null | fmt_event &
docker exec "$MANAGER" sh -c "tail -n0 -F $ALERTS 2>/dev/null" | fmt_alert &
wait
