"""guardrailctl: inspect and exercise the guardrail.

Deliberately thin. Daemon lifecycle is systemd's job -- duplicating start/stop
here would let the two disagree about what is running.
"""

import argparse
import json
import os
import subprocess
import sys

from . import client

UNIT = "wazuh-guards.service"


def _systemctl(*args) -> int:
    return subprocess.call(["systemctl", "--user", *args])


def cmd_status(args) -> int:
    try:
        info = client.status()
    except OSError as exc:
        print(f"daemon:   STOPPED ({exc})")
        print("fallback: hooks scan regex-only (credentials still blocked,")
        print("          NLP PII missed). Start with: guardrailctl start")
        return 1

    print(f"daemon:   RUNNING at {client.SOCKET_PATH}")
    print(f"patterns: {info['rules']} rules, version={info['pattern_version']}")
    print(f"          source={info['pattern_source']} sha={info['pattern_sha'][:12]}")
    presidio = info.get("presidio_error")
    print(f"presidio: {'UNAVAILABLE - ' + presidio if presidio else 'loaded'}")
    return 0


def cmd_start(args) -> int:
    return _systemctl("start", UNIT)


def cmd_stop(args) -> int:
    return _systemctl("stop", UNIT)


def cmd_restart(args) -> int:
    """Patterns load at startup, so this is also how a pattern change is applied."""
    return _systemctl("restart", UNIT)


def cmd_log(args) -> int:
    return _systemctl("status", "--no-pager", "-n", str(args.lines), UNIT)


def cmd_test(args) -> int:
    """Run text through the prompt hook exactly as Claude Code would."""
    text = " ".join(args.text) or "my ssn is 123-45-6789 and key AKIAIOSFODNN7EXAMPLE"
    proc = subprocess.run(
        [sys.executable, "-m", "wazuh_guards.hooks.prompt_submit"],
        input=json.dumps({"prompt": text, "session_id": "guardrailctl"}),
        capture_output=True, text=True,
    )
    if proc.stderr:
        print(proc.stderr, file=sys.stderr)
    if not proc.stdout.strip():
        print("ALLOWED (no findings)")
        return 0
    print(json.dumps(json.loads(proc.stdout), indent=2))
    return 0


def cmd_scan(args) -> int:
    """Scan a file the way PostToolUse would, and report what it would redact."""
    from . import scanner

    try:
        with open(args.path, encoding="utf-8", errors="replace") as fh:
            content = fh.read()
    except OSError as exc:
        print(f"cannot read {args.path}: {exc}", file=sys.stderr)
        return 1

    redacted, findings = scanner.redact_text(content)
    if not findings:
        print(f"{args.path}: clean")
        return 0
    print(f"{args.path}: {len(findings)} secret(s) would be redacted")
    for f in findings:
        print(f"  • {f.rule}: {f.sample}")
    return 2


def cmd_patterns(args) -> int:
    """Show the active ruleset, and where it came from."""
    from .ruleset import load
    from .wazuh.api import pattern_fetcher

    fetcher = pattern_fetcher() if args.refresh else None
    ruleset, notes = load(fetcher=fetcher)
    for note in notes:
        print(note, file=sys.stderr)
    print(f"version: {ruleset.version}")
    print(f"source:  {ruleset.source}")
    print(f"sha256:  {ruleset.sha256}")
    print(f"rules:   {len(ruleset)}")
    if args.verbose:
        for rule in ruleset:
            marker = f" [{rule.validator}]" if rule.validator else ""
            print(f"  {rule.severity:5} {rule.name}{marker}")
    return 0


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(
        prog="guardrailctl",
        description="Inspect and exercise the Claude Code secret/PII guardrail.",
    )
    sub = parser.add_subparsers(dest="command")

    sub.add_parser("status", help="daemon and pattern status").set_defaults(func=cmd_status)
    sub.add_parser("start", help="start the daemon").set_defaults(func=cmd_start)
    sub.add_parser("stop", help="stop the daemon").set_defaults(func=cmd_stop)
    sub.add_parser(
        "restart", help="restart the daemon (applies pattern changes)"
    ).set_defaults(func=cmd_restart)

    p_log = sub.add_parser("log", help="recent daemon log")
    p_log.add_argument("-n", "--lines", type=int, default=40)
    p_log.set_defaults(func=cmd_log)

    p_test = sub.add_parser("test", help="run text through the prompt hook")
    p_test.add_argument("text", nargs="*")
    p_test.set_defaults(func=cmd_test)

    p_scan = sub.add_parser("scan", help="report what would be redacted from a file")
    p_scan.add_argument("path")
    p_scan.set_defaults(func=cmd_scan)

    p_pat = sub.add_parser("patterns", help="show the active ruleset")
    p_pat.add_argument("--refresh", action="store_true", help="fetch from Wazuh first")
    p_pat.add_argument("-v", "--verbose", action="store_true", help="list every rule")
    p_pat.set_defaults(func=cmd_patterns)

    args = parser.parse_args(argv)
    if not getattr(args, "func", None):
        return cmd_status(args)
    return args.func(args)


if __name__ == "__main__":
    sys.exit(main())
