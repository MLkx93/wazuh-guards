"""Engine configuration: severity policy, Presidio tuning, shared helpers.

What lives here is deliberately *not* distributable. Wazuh ships regex rules
(see ruleset.py); it does not ship policy. Severity-to-action mapping and the
Presidio thresholds are properties of the local engine, and a manager that
could change them could silently downgrade every rule to "allow".

Regex rules themselves have moved to data/patterns.json.
"""

import re

# ---------------------------------------------------------------------------
# Enforcement policy. The single place to change how a severity tier behaves.
#   "block" -> prompt is rejected, never reaches the model
#   "warn"  -> prompt proceeds; user sees what was detected
#   "allow" -> detected, recorded in the audit log, no user-visible output
# ---------------------------------------------------------------------------

SEVERITY_ACTION = {
    "high": "block",
    "low": "warn",
}

SEVERITIES = ("high", "low")

# Only this tier is redacted from tool output. Redacting every PERSON would
# mangle author names, copyright headers, and changelog entries in source.
REDACT_SEVERITIES = {"high"}

# ---------------------------------------------------------------------------
# Presidio entity types -> severity. Entities absent from this map are ignored,
# which is how we keep low-value noise (URL, DATE_TIME, NRP...) out of verdicts.
# ---------------------------------------------------------------------------

PRESIDIO_ENTITIES = {
    # US_SSN is intentionally absent: UsSsnRecognizer does not fire on common
    # inputs ("123-45-6789" returns nothing) and bare SSNs sometimes decode as
    # DATE_TIME. SSNs are matched by our own regex rule instead.
    "US_PASSPORT": "high",
    "US_BANK_NUMBER": "high",
    "US_DRIVER_LICENSE": "low",
    "IBAN_CODE": "high",
    "CRYPTO": "high",
    "MEDICAL_LICENSE": "low",
    "CREDIT_CARD": "high",
    "PHONE_NUMBER": "low",
    "EMAIL_ADDRESS": "low",
    "PERSON": "low",
    "LOCATION": "low",
}

# Presidio confidence floor. Below this, a detection is treated as noise.
# PERSON/LOCATION are the weakest signals, so they carry a higher bar.
PRESIDIO_MIN_SCORE = 0.5
PRESIDIO_STRICT_SCORE = 0.85
PRESIDIO_STRICT_ENTITIES = {"PERSON", "LOCATION", "EMAIL_ADDRESS"}

# Per-entity overrides, applied before the tiers above.
# PHONE_NUMBER: Presidio scores common US formats ("(415) 555-0132",
# "415-555-0132") at only 0.4, so both the strict 0.85 and the default 0.5
# floor dropped them entirely.
PRESIDIO_ENTITY_SCORE = {
    "PHONE_NUMBER": 0.4,
}

# Extra shape check for entities whose low-confidence matches are ambiguous.
# At 0.4, Presidio cannot tell "1234567890" (an order ID) from a bare phone
# number. Requiring separator punctuation or a country code keeps real phone
# formats while letting plain digit runs through -- in the warn tier, a
# warning that fires on every long ID trains the user to ignore all warnings.
PRESIDIO_SHAPE_REQUIRED = {
    "PHONE_NUMBER": re.compile(r"[()\-.\s]|^\+"),
}


def luhn_valid(digits: str) -> bool:
    """Luhn checksum. Real card numbers pass; arbitrary digit runs rarely do."""
    nums = [int(c) for c in digits if c.isdigit()]
    if not 13 <= len(nums) <= 19:
        return False
    checksum, parity = 0, len(nums) % 2
    for i, n in enumerate(nums):
        if i % 2 == parity:
            n *= 2
            if n > 9:
                n -= 9
        checksum += n
    return checksum % 10 == 0


def redact(match: str) -> str:
    """Show enough to identify what fired, never enough to reuse the secret."""
    stripped = match.strip()
    if len(stripped) <= 8:
        return "*" * len(stripped)
    return f"{stripped[:4]}{'*' * 8}{stripped[-2:]}"


# Replacement written into tool output when a high-severity match is redacted.
# Carries the rule name so the model can reason about what was removed without
# seeing the value.
def redaction_marker(rule: str) -> str:
    return f"[REDACTED:{rule}]"
