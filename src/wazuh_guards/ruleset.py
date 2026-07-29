"""Compiled rule set, and the load chain that produces one.

A Ruleset is immutable and always non-empty. That second property is the whole
point of this module: a guardrail that silently ends up with zero rules looks
identical to a guardrail with nothing to report.

Load order, first success wins:

    Wazuh manager  ->  on-disk cache  ->  bundled defaults

Every pattern is re.compile()d before a set is accepted. Validation is
all-or-nothing: one bad regex rejects the entire payload and the previous
ruleset stays in force. A partial accept would let a malformed push silently
delete the AWS rule while keeping the rest, which is the failure mode most
likely to go unnoticed.
"""

import hashlib
import json
import os
import re
from dataclasses import dataclass, field
from importlib import resources
from typing import Callable

from .patterns import SEVERITIES, luhn_valid

CACHE_DIR = os.environ.get(
    "WAZUH_GUARDS_CACHE_DIR",
    os.path.join(
        os.environ.get("XDG_CACHE_HOME", os.path.expanduser("~/.cache")),
        "wazuh-guards",
    ),
)
CACHE_PATH = os.path.join(CACHE_DIR, "patterns.json")

# Extra validators a rule may name. A rule referencing an unknown validator is
# rejected rather than silently run unvalidated -- "validator": "lhun" must not
# quietly become "match every 13-19 digit run and call it a card".
VALIDATORS: dict[str, Callable[[str], bool]] = {
    "luhn": luhn_valid,
}


class PatternError(ValueError):
    """A pattern payload was malformed. Carries the reason for the daemon log."""


@dataclass(frozen=True)
class Rule:
    name: str
    severity: str
    regex: re.Pattern
    validator: str | None = None

    def validate(self, match: str) -> bool:
        if self.validator is None:
            return True
        return VALIDATORS[self.validator](match)

    @property
    def effective_severity(self) -> str:
        """A validated match is a confirmed one. A digit run that passes Luhn is
        a card number, not a maybe -- so validated rules report as high."""
        return "high" if self.validator else self.severity


@dataclass(frozen=True)
class Ruleset:
    version: str
    rules: tuple[Rule, ...]
    sha256: str
    source: str  # "wazuh" | "cache" | "bundled"
    raw: str = field(repr=False, default="")

    def __len__(self) -> int:
        return len(self.rules)

    def __iter__(self):
        return iter(self.rules)


def _sha256(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


def parse(raw: str, source: str) -> Ruleset:
    """Parse and fully validate a pattern payload.

    Raises PatternError on anything malformed. Callers treat that as "keep what
    you already have" -- never as "continue with fewer rules".
    """
    try:
        doc = json.loads(raw)
    except json.JSONDecodeError as exc:
        raise PatternError(f"not valid JSON: {exc}") from exc

    if not isinstance(doc, dict):
        raise PatternError(f"top level must be an object, got {type(doc).__name__}")

    version = doc.get("version")
    if not isinstance(version, str) or not version.strip():
        raise PatternError("missing or empty 'version'")

    entries = doc.get("rules")
    if not isinstance(entries, list):
        raise PatternError("'rules' must be a list")
    if not entries:
        # An empty ruleset is syntactically fine and operationally catastrophic.
        raise PatternError("'rules' is empty - refusing to disarm the guardrail")

    compiled: list[Rule] = []
    seen: set[str] = set()
    for i, entry in enumerate(entries):
        where = f"rules[{i}]"
        if not isinstance(entry, dict):
            raise PatternError(f"{where}: must be an object")

        name = entry.get("name")
        if not isinstance(name, str) or not name.strip():
            raise PatternError(f"{where}: missing or empty 'name'")
        where = f"rules[{i}] ({name})"
        if name in seen:
            raise PatternError(f"{where}: duplicate rule name")
        seen.add(name)

        severity = entry.get("severity")
        if severity not in SEVERITIES:
            raise PatternError(
                f"{where}: severity must be one of {SEVERITIES}, got {severity!r}"
            )

        pattern = entry.get("pattern")
        if not isinstance(pattern, str) or not pattern:
            raise PatternError(f"{where}: missing or empty 'pattern'")
        try:
            regex = re.compile(pattern)
        except re.error as exc:
            raise PatternError(f"{where}: does not compile: {exc}") from exc
        if regex.search("") and not regex.pattern.startswith("(?!"):
            # A pattern matching the empty string matches everywhere, which
            # would redact the entire output of every tool call.
            raise PatternError(f"{where}: matches the empty string")

        validator = entry.get("validator")
        if validator is not None:
            if not isinstance(validator, str) or validator not in VALIDATORS:
                raise PatternError(
                    f"{where}: unknown validator {validator!r} "
                    f"(known: {sorted(VALIDATORS)})"
                )

        compiled.append(
            Rule(name=name, severity=severity, regex=regex, validator=validator)
        )

    return Ruleset(
        version=version,
        rules=tuple(compiled),
        sha256=_sha256(raw),
        source=source,
        raw=raw,
    )


def load_bundled() -> Ruleset:
    """The floor. If this fails the install is broken and there is no guardrail,
    so the exception is allowed to propagate."""
    raw = resources.files("wazuh_guards.data").joinpath("patterns.json").read_text()
    return parse(raw, source="bundled")


def load_cache() -> Ruleset | None:
    try:
        with open(CACHE_PATH, encoding="utf-8") as fh:
            raw = fh.read()
    except OSError:
        return None
    try:
        return parse(raw, source="cache")
    except PatternError:
        # A corrupt cache is not fatal; the bundled set is one step down.
        return None


def write_cache(ruleset: Ruleset) -> bool:
    """Persist a ruleset for the next cold start. Best-effort: a read-only
    cache dir must not stop the daemon from serving scans."""
    try:
        os.makedirs(CACHE_DIR, exist_ok=True)
        tmp = f"{CACHE_PATH}.tmp"
        with open(tmp, "w", encoding="utf-8") as fh:
            fh.write(ruleset.raw)
        os.replace(tmp, CACHE_PATH)  # atomic: no torn file for a concurrent reader
        return True
    except OSError:
        return False


def load(fetcher: Callable[[], str] | None = None) -> tuple[Ruleset, list[str]]:
    """Resolve the active ruleset. Returns (ruleset, notes) where notes are
    human-readable lines for the daemon log -- callers should surface them,
    because a silent downgrade to bundled defaults is exactly the condition an
    operator needs to know about.

    Never raises for a fetch or cache failure; only a broken install can fail.
    """
    notes: list[str] = []

    if fetcher is not None:
        try:
            raw = fetcher()
            ruleset = parse(raw, source="wazuh")
            if write_cache(ruleset):
                notes.append(f"cached patterns to {CACHE_PATH}")
            else:
                notes.append(f"WARNING could not write cache at {CACHE_PATH}")
            notes.append(
                f"loaded {len(ruleset)} rules from wazuh "
                f"(version={ruleset.version} sha={ruleset.sha256[:12]})"
            )
            return ruleset, notes
        except PatternError as exc:
            notes.append(f"WARNING rejected pattern push from wazuh: {exc}")
        except Exception as exc:  # noqa: BLE001 - network/auth/anything
            notes.append(f"WARNING wazuh fetch failed: {type(exc).__name__}: {exc}")

    cached = load_cache()
    if cached is not None:
        notes.append(
            f"loaded {len(cached)} rules from cache "
            f"(version={cached.version} sha={cached.sha256[:12]})"
        )
        return cached, notes

    bundled = load_bundled()
    notes.append(
        f"loaded {len(bundled)} rules from bundled defaults "
        f"(version={bundled.version} sha={bundled.sha256[:12]})"
    )
    return bundled, notes
