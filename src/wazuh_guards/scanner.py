"""Scan engine: regex ruleset + optional Presidio NLP pass.

Two entry points:

  scan()   -> verdict dict for the prompt hook (findings + action)
  redact() -> rewritten text for the output hook (regex only, high only)

Presidio is loaded lazily and, if it is unavailable for any reason, the regex
pass still runs. A guardrail that fails open on its own import error is worse
than useless, so failures are recorded in the result rather than swallowed.

Findings carry (start, end) spans. The prompt hook ignores them; the redactor
needs them to rewrite text without re-running the match.
"""

import threading
from dataclasses import dataclass, asdict, field

from . import patterns as cfg
from .ruleset import Ruleset, load_bundled

_analyzer = None
_presidio_error: str | None = None
_analyzer_lock = threading.Lock()

# Module-level active ruleset. The daemon replaces this at startup and on
# refresh; hooks running out-of-process fall back to the bundled set.
_ruleset: Ruleset | None = None
_ruleset_lock = threading.Lock()


@dataclass
class Finding:
    rule: str
    severity: str          # "high" | "low"
    detector: str          # "regex" | "presidio"
    sample: str            # redacted
    score: float = 1.0
    start: int = field(default=-1)
    end: int = field(default=-1)

    def to_dict(self, spans: bool = False):
        d = asdict(self)
        if not spans:
            d.pop("start", None)
            d.pop("end", None)
        return d


def get_ruleset() -> Ruleset:
    global _ruleset
    with _ruleset_lock:
        if _ruleset is None:
            _ruleset = load_bundled()
        return _ruleset


def set_ruleset(ruleset: Ruleset) -> None:
    """Swap the active ruleset. Called by the daemon at startup and refresh.
    The swap is a single reference assignment, so in-flight scans finish
    against the set they started with rather than seeing a half-applied
    update."""
    global _ruleset
    with _ruleset_lock:
        _ruleset = ruleset


def _get_analyzer():
    """Load Presidio once per process. ~12s cold, hence the daemon."""
    global _analyzer, _presidio_error
    with _analyzer_lock:
        if _analyzer is not None or _presidio_error is not None:
            return _analyzer
        try:
            import logging
            logging.getLogger("presidio-analyzer").setLevel(logging.ERROR)
            from presidio_analyzer import AnalyzerEngine
            _analyzer = AnalyzerEngine()
        except Exception as exc:  # noqa: BLE001 - degrade to regex-only, but report
            _presidio_error = f"{type(exc).__name__}: {exc}"
        return _analyzer


def presidio_error() -> str | None:
    return _presidio_error


def _scan_regex(text: str, ruleset: Ruleset) -> list[Finding]:
    out = []
    for rule in ruleset:
        for m in rule.regex.finditer(text):
            hit = m.group(0)
            # Rules carrying a validator (cards -> Luhn) drop matches that fail
            # it, and report the survivors at their promoted severity.
            if not rule.validate(hit):
                continue
            out.append(
                Finding(
                    rule=rule.name,
                    severity=rule.effective_severity,
                    detector="regex",
                    sample=cfg.redact(hit),
                    start=m.start(),
                    end=m.end(),
                )
            )
    return out


def _scan_presidio(text: str) -> list[Finding]:
    analyzer = _get_analyzer()
    if analyzer is None:
        return []
    results = analyzer.analyze(
        text=text,
        language="en",
        entities=list(cfg.PRESIDIO_ENTITIES.keys()),
    )
    out = []
    for r in results:
        if r.entity_type in cfg.PRESIDIO_ENTITY_SCORE:
            floor = cfg.PRESIDIO_ENTITY_SCORE[r.entity_type]
        elif r.entity_type in cfg.PRESIDIO_STRICT_ENTITIES:
            floor = cfg.PRESIDIO_STRICT_SCORE
        else:
            floor = cfg.PRESIDIO_MIN_SCORE
        if r.score < floor:
            continue
        matched = text[r.start:r.end]
        if r.entity_type == "CREDIT_CARD" and not cfg.luhn_valid(matched):
            continue
        shape = cfg.PRESIDIO_SHAPE_REQUIRED.get(r.entity_type)
        if shape and not shape.search(matched):
            continue
        out.append(
            Finding(
                rule=r.entity_type.replace("_", " ").title(),
                severity=cfg.PRESIDIO_ENTITIES[r.entity_type],
                detector="presidio",
                sample=cfg.redact(matched),
                score=round(r.score, 2),
                start=r.start,
                end=r.end,
            )
        )
    return out


def _dedupe(findings: list[Finding]) -> list[Finding]:
    """Regex and Presidio overlap (both catch cards/SSNs). Keep one per
    rule+sample, preferring the higher severity."""
    best: dict[tuple, Finding] = {}
    for f in findings:
        key = (f.sample, f.rule)
        prior = best.get(key)
        if prior is None or (prior.severity != "high" and f.severity == "high"):
            best[key] = f
    order = {"high": 0, "low": 1}
    return sorted(best.values(), key=lambda f: (order[f.severity], f.rule))


def scan(text: str, use_presidio: bool = True, ruleset: Ruleset | None = None) -> dict:
    rs = ruleset or get_ruleset()
    findings = _scan_regex(text, rs)
    if use_presidio:
        try:
            findings += _scan_presidio(text)
        except Exception as exc:  # noqa: BLE001
            globals()["_presidio_error"] = f"{type(exc).__name__}: {exc}"
    findings = _dedupe(findings)

    # Strongest action across all findings wins: one credential outranks any
    # number of names.
    rank = {"allow": 0, "warn": 1, "block": 2}
    action = "allow"
    for f in findings:
        candidate = cfg.SEVERITY_ACTION.get(f.severity, "block")
        if rank[candidate] > rank[action]:
            action = candidate

    return {
        "findings": [f.to_dict() for f in findings],
        "action": action,
        "blocked": action == "block",
        "presidio_error": _presidio_error,
        "pattern_version": rs.version,
        "pattern_sha": rs.sha256,
        "pattern_source": rs.source,
    }


def redact_text(text: str, ruleset: Ruleset | None = None) -> tuple[str, list[Finding]]:
    """Replace high-severity matches with a marker naming the rule.

    Regex only -- this runs on every tool call, including a 50MB Read, where a
    Presidio pass would be unusable. Returns the rewritten text and the
    findings that drove it.

    Overlapping matches are resolved by replacing right-to-left, so earlier
    spans stay valid as the string is rewritten.
    """
    if not text:
        return text, []
    rs = ruleset or get_ruleset()
    findings = [
        f
        for f in _scan_regex(text, rs)
        if f.severity in cfg.REDACT_SEVERITIES
    ]
    if not findings:
        return text, []

    # Drop spans contained in an earlier-starting, longer match so nested hits
    # do not produce a marker inside a marker.
    ordered = sorted(findings, key=lambda f: (f.start, -(f.end - f.start)))
    kept: list[Finding] = []
    last_end = -1
    for f in ordered:
        if f.start >= last_end:
            kept.append(f)
            last_end = f.end

    out = text
    for f in sorted(kept, key=lambda f: f.start, reverse=True):
        out = out[: f.start] + cfg.redaction_marker(f.rule) + out[f.end :]
    return out, kept
