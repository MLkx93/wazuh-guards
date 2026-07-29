"""Shared detection corpus. Single source of truth for every test that asserts
on detection behavior.

All credentials here are documentation/test values or structurally valid
fabrications. None are live.

The ALLOW cases matter as much as the BLOCK cases: they are the false-positive
traps that previous tuning rounds regressed on. A rule change that starts
blocking "the order id is 1234567890" is a broken rule, not a stricter one.
"""

# (label, text) -> must produce action "block"
BLOCK_CASES = [
    ("aws_access_key", "here is the key AKIAIOSFODNN7EXAMPLE for the bucket"),
    ("us_ssn", "my ssn is 123-45-6789 please file it"),
    ("github_pat", "token ghp_016C7f4b8A2d9E3f5B7c1D0a6E8b4F2c0A9d3B"),
    ("anthropic_key", "export ANTHROPIC_API_KEY=sk-ant-api03-abcdefghij0123456789KLMNOPQRSTUV"),
    ("stripe_key", "use sk_live_51H8xkjKLmnOpQrStUvWxYz0123456789"),
    ("credit_card_luhn", "card 4111 1111 1111 1111 expires soon"),
    ("db_uri_password", "connect to postgres://admin:hunter2pass@db.internal:5432/app"),
    ("private_key", "-----BEGIN RSA PRIVATE KEY-----\nMIIEowIBAAKCAQEA\n"),
    (
        "jwt",
        "auth header eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9."
        "eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4ifQ."
        "SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c",
    ),
    ("password_assignment", 'password = "supersecret123456"'),
]

# (label, text) -> must produce action "warn" (proceeds, never redacted)
# These depend on Presidio; regex-only runs will report "allow".
WARN_CASES = [
    ("person_location", "Sarah Chen moved to Portland last spring"),
    ("email", "ping me at malak.faiz@example.com when the build finishes"),
    ("phone_parens", "call me at (415) 555-0132 after standup"),
    ("phone_dashes", "the desk line is 415-555-0132"),
    ("phone_intl", "reach me on +1 415 555 0132"),
]

# (label, text) -> must produce action "allow". False-positive traps.
ALLOW_CASES = [
    ("order_id", "the order id is 1234567890 and status is pending"),
    ("version_bump", "we bumped from 1.2.3 to 1.3.0 and CI broke"),
    ("port_bind", "why does docker compose fail to bind port 8080"),
    ("iso_date_regex", "write a regex that matches ISO dates like 2024-01-15"),
    ("akia_prose", "explain what the AKIA prefix means in AWS docs"),
]

# Cases whose detection must survive without Presidio -- i.e. every credential
# rule. Used to assert the daemon-down fallback still blocks.
REGEX_ONLY_BLOCK_CASES = BLOCK_CASES

# Text used for redaction tests: a high-severity secret embedded in otherwise
# ordinary file content.
REDACTABLE_FILE = """\
# config.py
DEBUG = True
AWS_ACCESS_KEY_ID = "AKIAIOSFODNN7EXAMPLE"
DATABASE_URL = "postgres://admin:hunter2pass@db.internal:5432/app"
MAINTAINER = "Sarah Chen"
"""

# Values from REDACTABLE_FILE that must NOT survive redaction.
REDACTABLE_SECRETS = ["AKIAIOSFODNN7EXAMPLE", "hunter2pass"]

# Values from REDACTABLE_FILE that MUST survive: redacting every PERSON would
# mangle author names, and low severity is not a redaction tier.
REDACTABLE_KEPT = ["Sarah Chen", "DEBUG = True"]
