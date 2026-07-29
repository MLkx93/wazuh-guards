#!/usr/bin/env bash
# Install the guardrail: venv, systemd unit, runtime dirs.
#
# Does NOT touch ~/.claude/settings.json. Registering the hooks is a separate,
# reversible step you run when the tests pass -- see scripts/register-hooks.sh
# or the README. Installing and arming are deliberately not the same action.
set -euo pipefail

REPO="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
PREFIX="${WAZUH_GUARDS_PREFIX:-$HOME/.local/share/wazuh-guards}"
VENV="$PREFIX/venv"
UNIT_DIR="$HOME/.config/systemd/user"
UNIT="wazuh-guards.service"
CONFIG_DIR="$HOME/.config/wazuh-guards"
CACHE_DIR="${XDG_CACHE_HOME:-$HOME/.cache}/wazuh-guards"
STATE_DIR="${XDG_STATE_HOME:-$HOME/.local/state}/wazuh-guards"

say()  { printf '\033[1m==>\033[0m %s\n' "$*"; }
warn() { printf '\033[33m warning:\033[0m %s\n' "$*" >&2; }
die()  { printf '\033[31m error:\033[0m %s\n' "$*" >&2; exit 1; }

# --- preflight -------------------------------------------------------------

command -v python3 >/dev/null || die "python3 not found"
PYVER=$(python3 -c 'import sys; print("%d.%d" % sys.version_info[:2])')
python3 -c 'import sys; sys.exit(0 if sys.version_info >= (3,10) else 1)' \
  || die "python 3.10+ required, found $PYVER"
say "python $PYVER"

# --- venv ------------------------------------------------------------------
# --system-site-packages reuses the system-wide spaCy model. en_core_web_lg is
# ~560MB and is not a PyPI package under that name; re-downloading it into an
# isolated venv is slow and often fails behind a proxy.

if [[ ! -d "$VENV" ]]; then
  say "creating venv at $VENV (with system site-packages)"
  mkdir -p "$PREFIX"
  python3 -m venv --system-site-packages "$VENV"
else
  say "reusing venv at $VENV"
fi

say "installing wazuh-guards"
"$VENV/bin/pip" install --quiet --upgrade pip
"$VENV/bin/pip" install --quiet -e "$REPO"

# --- optional NLP ----------------------------------------------------------

if "$VENV/bin/python" -c 'import presidio_analyzer' 2>/dev/null; then
  say "presidio: found"
  if "$VENV/bin/python" -c 'import en_core_web_lg' 2>/dev/null; then
    say "spacy model en_core_web_lg: found"
  else
    warn "en_core_web_lg not importable - NLP PII detection will be OFF."
    warn "  install with: python3 -m spacy download en_core_web_lg"
  fi
else
  warn "presidio-analyzer not found - the daemon will run regex-only."
  warn "  credentials are still blocked; names/emails/phones are not detected."
  warn "  install with: $VENV/bin/pip install 'wazuh-guards[nlp]'"
fi

# --- runtime dirs ----------------------------------------------------------

say "creating runtime directories"
mkdir -p "$CACHE_DIR" "$STATE_DIR" "$CONFIG_DIR"
chmod 700 "$CONFIG_DIR"

if [[ ! -f "$CONFIG_DIR/wazuh.env" ]]; then
  cat > "$CONFIG_DIR/wazuh.env" <<'EOF'
# Wazuh manager credentials. Optional: with these unset the guardrail runs on
# bundled patterns and never contacts a manager.
#
# On stock wazuh-docker the API user is wazuh-wui, NOT wazuh -- wazuh is the
# indexer/dashboard user and returns 401 against the API. Confirm with:
#   docker exec <manager> printenv | grep -E 'API_USERNAME|API_PASSWORD'
#
# WAZUH_API_URL=https://127.0.0.1:55000
# WAZUH_API_USER=wazuh-wui
# WAZUH_API_PASSWORD=
#
# wazuh-docker ships a self-signed cert. Set this to false only after you have
# decided that is acceptable for your deployment.
# WAZUH_API_VERIFY_TLS=false
#
# WAZUH_GUARDS_GROUP=guardrail
# WAZUH_GUARDS_PATTERN_FILE=patterns.json
EOF
  chmod 600 "$CONFIG_DIR/wazuh.env"
  say "wrote credential template to $CONFIG_DIR/wazuh.env (0600)"
else
  say "keeping existing $CONFIG_DIR/wazuh.env"
fi

# --- systemd ---------------------------------------------------------------

say "installing systemd unit"
mkdir -p "$UNIT_DIR"
sed "s|%h/.local/share/wazuh-guards/venv|$VENV|g" \
  "$REPO/deploy/systemd/$UNIT" > "$UNIT_DIR/$UNIT"

systemctl --user daemon-reload
systemctl --user enable "$UNIT" >/dev/null 2>&1 || warn "could not enable $UNIT"

say "starting daemon (spaCy load takes ~12s)"
systemctl --user restart "$UNIT"

for _ in $(seq 1 45); do
  sleep 1
  if "$VENV/bin/guardrailctl" status >/dev/null 2>&1; then
    break
  fi
done

echo
if "$VENV/bin/guardrailctl" status; then
  :
else
  warn "daemon not answering yet - check: journalctl --user -u $UNIT -n 40"
fi

# --- next steps ------------------------------------------------------------

cat <<EOF

$(say "installed")

  CLI:      $VENV/bin/guardrailctl
  Config:   $CONFIG_DIR/wazuh.env
  Events:   $STATE_DIR/guardrail.json
  Patterns: $CACHE_DIR/patterns.json

The hooks are NOT registered yet. Nothing is enforced until you do that.

  1. Verify:   cd $REPO && $VENV/bin/python -m pytest -q
  2. Register: $REPO/scripts/register-hooks.sh
  3. Confirm:  $VENV/bin/guardrailctl test "my key is AKIAIOSFODNN7EXAMPLE"

EOF
