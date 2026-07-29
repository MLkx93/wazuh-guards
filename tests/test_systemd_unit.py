"""The systemd unit must actually start.

systemd does not ignore directives a --user service cannot honour -- it fails
the unit with 218/CAPABILITIES and enters a restart loop. `systemd-analyze
verify` accepts those directives happily, so static validation alone does not
catch it; the only reliable check is the documented user-service constraint.
"""

import os
import re
import shutil
import subprocess

import pytest

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
UNIT = os.path.join(REPO, "deploy", "systemd", "wazuh-guards.service")

# Directives that need privileges a user manager does not have. Any of these
# in a --user unit makes it fail to start, not merely lose the hardening.
SYSTEM_ONLY_DIRECTIVES = {
    "ProtectKernelTunables",
    "ProtectKernelModules",
    "ProtectKernelLogs",
    "ProtectControlGroups",
    "ProtectHome",
    "ProtectSystem",
    "PrivateDevices",
    "PrivateUsers",
    "ProtectClock",
    "ProtectHostname",
    "ProtectProc",
    "CapabilityBoundingSet",
    "AmbientCapabilities",
    "User",
    "Group",
    "DynamicUser",
    "RootDirectory",
}


@pytest.fixture(scope="module")
def unit_text():
    with open(UNIT, encoding="utf-8") as fh:
        return fh.read()


def _directives(text):
    found = {}
    for line in text.splitlines():
        line = line.strip()
        if not line or line.startswith("#") or "=" not in line or line.startswith("["):
            continue
        key, _, value = line.partition("=")
        found[key.strip()] = value.strip()
    return found


def test_no_system_only_directives(unit_text):
    """The bug this file exists for: 218/CAPABILITIES on every start."""
    present = SYSTEM_ONLY_DIRECTIVES & set(_directives(unit_text))
    assert not present, (
        f"directives requiring system privileges in a --user unit: "
        f"{sorted(present)} - systemd fails the unit with 218/CAPABILITIES"
    )


def test_hardening_that_does_work_is_kept(unit_text):
    directives = _directives(unit_text)
    for key in ("NoNewPrivileges", "PrivateTmp", "RestrictSUIDSGID"):
        assert directives.get(key) == "true", f"{key} should stay enabled"


def test_restart_is_configured(unit_text):
    directives = _directives(unit_text)
    assert directives["Restart"] == "on-failure"
    assert int(directives["RestartSec"]) >= 5


def test_credentials_file_is_optional(unit_text):
    """The leading '-' means a host with no manager configured still starts."""
    directives = _directives(unit_text)
    assert directives["EnvironmentFile"].startswith("-"), (
        "without '-', a missing wazuh.env stops the daemon from starting"
    )


def test_execstart_runs_the_daemon_module(unit_text):
    assert re.search(r"ExecStart=.*-m wazuh_guards\.daemon", unit_text)


def test_memory_cap_leaves_room_for_spacy(unit_text):
    """The spaCy pipeline is ~700MB resident; the cap is a runaway guard."""
    value = _directives(unit_text).get("MemoryMax", "")
    assert value.endswith("G") and int(value[:-1]) >= 2


@pytest.mark.skipif(not shutil.which("systemd-analyze"), reason="systemd-analyze absent")
def test_unit_parses(tmp_path):
    """Catches syntax errors. Does NOT catch the user/system capability split --
    that is what test_no_system_only_directives is for."""
    staged = tmp_path / "wazuh-guards.service"
    with open(UNIT, encoding="utf-8") as fh:
        staged.write_text(fh.read().replace("%h", str(tmp_path)))
    proc = subprocess.run(
        ["systemd-analyze", "verify", "--user", str(staged)],
        capture_output=True, text=True, timeout=60,
    )
    ignorable = (
        "Unknown",           # default.target is absent off-system
        "not found",
        # ExecStart points at the installed venv, which does not exist under the
        # rewritten %h. Whether the binary is installed is install.sh's problem,
        # not the unit file's.
        "is not executable",
    )
    fatal = [
        line for line in proc.stderr.splitlines()
        if line.strip() and not any(s in line for s in ignorable)
    ]
    assert not fatal, "\n".join(fatal)
