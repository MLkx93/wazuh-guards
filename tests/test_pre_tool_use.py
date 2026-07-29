"""PreToolUse protected-path denial.

Two failure modes get equal weight here. Missing a .env read is the obvious
one. Denying `.env.example` is the quieter one: a hook that blocks ordinary
work gets disabled, and a disabled hook protects nothing.
"""

import json

import pytest

from wazuh_guards.hooks import pre_tool_use as hook


@pytest.mark.parametrize(
    "path",
    [
        ".env",
        "/app/.env",
        "/app/.env.production",
        "/app/.env.local",
        "~/.ssh/id_rsa",
        "/home/u/.ssh/id_ed25519",
        "/home/u/.ssh/config",
        "/etc/ssl/private/server.pem",
        "certs/client.key",
        "keystore.p12",
        "app.pfx",
        "/home/u/.aws/credentials",
        "/home/u/.kube/config",
        "/home/u/.gnupg/secring.gpg",
        "/home/u/.netrc",
        "/home/u/.pgpass",
        "service-account-prod.json",
        "vault.kdbx",
        "/etc/shadow",
    ],
)
def test_protected_paths_are_denied(path):
    denied, reason = hook.is_protected_path(path)
    assert denied, f"{path} should be protected"
    assert reason


@pytest.mark.parametrize(
    "path",
    [
        ".env.example",
        ".env.sample",
        ".env.template",
        ".env.dist",
        "/app/.env.example",
        "src/main.py",
        "README.md",
        "config.yaml",
        "package.json",
        "docker-compose.yml",
        "keyboard.py",           # contains "key" but is not a key file
        "monkey.txt",
        "/app/keys/README.md",
        "public.pem.md",         # documentation about a pem, not a pem
    ],
)
def test_ordinary_paths_are_allowed(path):
    denied, reason = hook.is_protected_path(path)
    assert not denied, f"{path} should be allowed, got: {reason}"


@pytest.mark.parametrize(
    "command",
    [
        "cat .env",
        "cat /app/.env.production",
        "head -20 .env",
        "less ~/.ssh/id_rsa",
        "base64 certs/server.key",
        "xxd vault.kdbx",
        "cp /home/u/.aws/credentials /tmp/x",
        "tar czf /tmp/s.tgz ~/.ssh",
        "cat ~/.netrc",
    ],
)
def test_bash_reads_of_protected_paths_are_denied(command):
    denied, reason = hook.check_bash_command(command)
    assert denied, f"{command!r} should be denied"
    assert reason


@pytest.mark.parametrize(
    "command",
    [
        "ls -la",
        "cat README.md",
        "git status",
        "docker compose up -d",
        "cat src/main.py",
        "echo 'set your .env before running'",   # mentions .env, reads nothing
        "grep -r TODO src/",
        "npm test",
        "cat package.json",
    ],
)
def test_ordinary_commands_are_allowed(command):
    denied, reason = hook.check_bash_command(command)
    assert not denied, f"{command!r} should be allowed, got: {reason}"


# --- payload-level behavior -----------------------------------------------

def test_read_of_env_is_denied():
    deny, reason, target = hook.evaluate({
        "tool_name": "Read", "tool_input": {"file_path": "/app/.env"}})
    assert deny
    assert target == "/app/.env"


def test_write_to_env_is_not_denied():
    """Blocking a write leaks nothing into context and stops legitimate setup."""
    deny, _, _ = hook.evaluate({
        "tool_name": "Write",
        "tool_input": {"file_path": "/app/.env", "content": "KEY=value"}})
    assert not deny


def test_edit_of_env_is_not_denied():
    deny, _, _ = hook.evaluate({
        "tool_name": "Edit",
        "tool_input": {"file_path": "/app/.env", "old_string": "a", "new_string": "b"}})
    assert not deny


def test_glob_rooted_in_ssh_is_denied():
    deny, reason, _ = hook.evaluate({
        "tool_name": "Glob", "tool_input": {"pattern": "*", "path": "/home/u/.ssh"}})
    assert deny


def test_unrelated_tool_is_ignored():
    deny, _, _ = hook.evaluate({
        "tool_name": "WebFetch", "tool_input": {"url": "https://example.com/.env"}})
    assert not deny


def test_response_shape_is_exact():
    payload = hook.build_response("test reason")
    hso = payload["hookSpecificOutput"]
    assert hso["hookEventName"] == "PreToolUse"
    assert hso["permissionDecision"] == "deny"
    assert "permissionDecisionReason" in hso


def test_deny_emits_json_and_exits_zero(monkeypatch, capsys):
    monkeypatch.setenv("WAZUH_GUARDS_LOG", "/dev/null")
    monkeypatch.setattr("sys.stdin", _stdin(json.dumps({
        "tool_name": "Read", "tool_input": {"file_path": "/app/.env"}})))
    with pytest.raises(SystemExit) as exc:
        hook.main()
    assert exc.value.code == 0
    emitted = json.loads(capsys.readouterr().out)
    assert emitted["hookSpecificOutput"]["permissionDecision"] == "deny"


def test_allow_emits_nothing(monkeypatch, capsys):
    monkeypatch.setattr("sys.stdin", _stdin(json.dumps({
        "tool_name": "Read", "tool_input": {"file_path": "/app/src/main.py"}})))
    with pytest.raises(SystemExit):
        hook.main()
    assert capsys.readouterr().out == ""


def test_check_failure_fails_open_with_warning(monkeypatch, capsys):
    """A crashing path check must not wedge every tool call; PostToolUse is the
    backstop."""
    monkeypatch.setattr(hook, "evaluate", lambda p: (_ for _ in ()).throw(RuntimeError("boom")))
    monkeypatch.setattr("sys.stdin", _stdin(json.dumps({
        "tool_name": "Read", "tool_input": {"file_path": "/app/.env"}})))
    with pytest.raises(SystemExit) as exc:
        hook.main()
    assert exc.value.code == 0
    emitted = json.loads(capsys.readouterr().out)
    assert "NOT checked" in emitted["systemMessage"]


class _stdin:
    def __init__(self, text):
        self._text = text

    def read(self):
        return self._text
