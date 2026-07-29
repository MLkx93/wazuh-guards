"""CLI behavior and the settings.json edit.

register-hooks.sh rewrites a live Claude Code config, so its merge logic is
tested here rather than trusted: the failure that matters is clobbering hooks
that belong to something else.
"""

import json
import os
import subprocess
import sys

import pytest

from wazuh_guards import cli

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
REGISTER = os.path.join(REPO, "scripts", "register-hooks.sh")


# --- CLI ------------------------------------------------------------------

def test_status_reports_stopped_daemon_without_crashing(monkeypatch, capsys):
    monkeypatch.setattr(cli.client, "status",
                        lambda **k: (_ for _ in ()).throw(OSError("no socket")))
    assert cli.main(["status"]) == 1
    out = capsys.readouterr().out
    assert "STOPPED" in out
    assert "regex-only" in out  # says what still works


def test_status_reports_running_daemon(monkeypatch, capsys):
    monkeypatch.setattr(cli.client, "status", lambda **k: {
        "ok": True, "rules": 21, "pattern_version": "2026.07.29",
        "pattern_sha": "a" * 64, "pattern_source": "wazuh", "presidio_error": None})
    assert cli.main(["status"]) == 0
    out = capsys.readouterr().out
    assert "RUNNING" in out
    assert "21 rules" in out
    assert "loaded" in out


def test_patterns_prints_provenance(capsys):
    assert cli.main(["patterns"]) == 0
    out = capsys.readouterr().out
    assert "source:  bundled" in out
    assert "sha256:" in out


def test_patterns_verbose_lists_rules(capsys):
    cli.main(["patterns", "-v"])
    out = capsys.readouterr().out
    assert "AWS Access Key ID" in out
    assert "[luhn]" in out  # validator is surfaced


def test_scan_reports_a_dirty_file(tmp_path, capsys):
    target = tmp_path / "config.py"
    target.write_text('KEY = "AKIAIOSFODNN7EXAMPLE"\n')
    assert cli.main(["scan", str(target)]) == 2  # non-zero: usable in CI
    out = capsys.readouterr().out
    assert "AWS Access Key ID" in out
    assert "AKIAIOSFODNN7EXAMPLE" not in out  # sample is redacted


def test_scan_reports_a_clean_file(tmp_path, capsys):
    target = tmp_path / "main.py"
    target.write_text("def main():\n    return 0\n")
    assert cli.main(["scan", str(target)]) == 0
    assert "clean" in capsys.readouterr().out


def test_scan_missing_file_errors(tmp_path, capsys):
    assert cli.main(["scan", str(tmp_path / "absent.py")]) == 1


# --- settings.json merge --------------------------------------------------

def _run_register(settings_path, *args, venv_python=None):
    env = dict(os.environ)
    env["CLAUDE_SETTINGS"] = str(settings_path)
    if venv_python:
        env["WAZUH_GUARDS_PREFIX"] = venv_python
    return subprocess.run(
        ["bash", REGISTER, *args], capture_output=True, text=True, env=env, timeout=60
    )


@pytest.fixture
def fake_prefix(tmp_path):
    """register-hooks.sh requires an installed venv python; fake one."""
    venv_bin = tmp_path / "prefix" / "venv" / "bin"
    venv_bin.mkdir(parents=True)
    python = venv_bin / "python"
    python.symlink_to(sys.executable)
    return str(tmp_path / "prefix")


def test_register_adds_all_three_hooks(tmp_path, fake_prefix):
    settings = tmp_path / "settings.json"
    settings.write_text(json.dumps({"model": "opus"}))

    proc = _run_register(settings, venv_python=fake_prefix)
    assert proc.returncode == 0, proc.stderr

    data = json.loads(settings.read_text())
    assert set(data["hooks"]) == {"UserPromptSubmit", "PreToolUse", "PostToolUse"}
    assert data["model"] == "opus"  # unrelated settings survive


def test_register_preserves_unrelated_hooks(tmp_path, fake_prefix):
    settings = tmp_path / "settings.json"
    settings.write_text(json.dumps({
        "hooks": {"PostToolUse": [
            {"matcher": "Write",
             "hooks": [{"type": "command", "command": "/usr/bin/my-formatter"}]}]}}))

    _run_register(settings, venv_python=fake_prefix)
    data = json.loads(settings.read_text())
    commands = [h["command"] for e in data["hooks"]["PostToolUse"] for h in e["hooks"]]
    assert "/usr/bin/my-formatter" in commands
    assert any("wazuh_guards" in c for c in commands)


def test_register_is_idempotent(tmp_path, fake_prefix):
    settings = tmp_path / "settings.json"
    settings.write_text("{}")

    _run_register(settings, venv_python=fake_prefix)
    first = json.loads(settings.read_text())
    _run_register(settings, venv_python=fake_prefix)
    second = json.loads(settings.read_text())
    assert first == second, "re-running duplicated the hook entries"


def test_remove_restores_original_settings(tmp_path, fake_prefix):
    settings = tmp_path / "settings.json"
    original = {"model": "opus", "hooks": {"PostToolUse": [
        {"matcher": "Write",
         "hooks": [{"type": "command", "command": "/usr/bin/my-formatter"}]}]}}
    settings.write_text(json.dumps(original))

    _run_register(settings, venv_python=fake_prefix)
    _run_register(settings, "--remove", venv_python=fake_prefix)
    assert json.loads(settings.read_text()) == original


def test_dry_run_changes_nothing(tmp_path, fake_prefix):
    settings = tmp_path / "settings.json"
    settings.write_text(json.dumps({"model": "opus"}))
    before = settings.read_text()

    proc = _run_register(settings, "--dry-run", venv_python=fake_prefix)
    assert proc.returncode == 0, proc.stderr
    assert settings.read_text() == before
    assert "UserPromptSubmit" in proc.stdout  # printed, not written


def test_register_backs_up_before_writing(tmp_path, fake_prefix):
    settings = tmp_path / "settings.json"
    settings.write_text(json.dumps({"model": "opus"}))
    _run_register(settings, venv_python=fake_prefix)
    backup = tmp_path / "settings.json.bak"
    assert backup.exists()
    assert json.loads(backup.read_text()) == {"model": "opus"}


def test_post_tool_use_matcher_is_scoped(tmp_path, fake_prefix):
    """PostToolUse fires on every tool call; the matcher keeps it off tools
    that return no readable content."""
    settings = tmp_path / "settings.json"
    settings.write_text("{}")
    _run_register(settings, venv_python=fake_prefix)

    entry = json.loads(settings.read_text())["hooks"]["PostToolUse"][0]
    assert "matcher" in entry
    assert "Read" in entry["matcher"] and "Bash" in entry["matcher"]
