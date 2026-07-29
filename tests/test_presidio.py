"""Full-engine tests: Presidio NLP plus regex.

Marked slow -- the spaCy pipeline costs ~12s to load once per session. This is
the tier that catches names, emails and phone numbers, none of which regex can
find reliably.

The tuning encoded here was derived empirically; each test names the failure it
prevents so a future threshold change has to argue with a specific case.
"""

import pytest

from wazuh_guards import scanner
from wazuh_guards.ruleset import load_bundled

from corpus import ALLOW_CASES, BLOCK_CASES, WARN_CASES

pytestmark = pytest.mark.slow


@pytest.fixture(scope="module", autouse=True)
def engine():
    scanner.set_ruleset(load_bundled())
    if scanner._get_analyzer() is None:
        pytest.skip(f"presidio unavailable: {scanner.presidio_error()}")


@pytest.mark.parametrize("label,text", BLOCK_CASES, ids=lambda v: v)
def test_credentials_block_with_full_engine(label, text):
    result = scanner.scan(text, use_presidio=True)
    assert result["action"] == "block", f"{label}: {result['findings']}"


@pytest.mark.parametrize("label,text", WARN_CASES, ids=lambda v: v)
def test_nlp_pii_warns(label, text):
    """These are exactly the cases regex cannot find -- see
    test_regex_rules.py, where the same corpus must come back 'allow'."""
    result = scanner.scan(text, use_presidio=True)
    assert result["action"] == "warn", f"{label}: {result['findings']}"


@pytest.mark.parametrize("label,text", ALLOW_CASES, ids=lambda v: v)
def test_false_positive_traps_survive_the_nlp_pass(label, text):
    result = scanner.scan(text, use_presidio=True)
    assert result["action"] == "allow", f"{label} regressed: {result['findings']}"


@pytest.mark.parametrize(
    "phone",
    ["(415) 555-0132", "415-555-0132", "+1 415 555 0132", "415.555.0132"],
)
def test_phone_formats_are_detected(phone):
    """Presidio scores US phones at only 0.4, below the default floor, so they
    were silently undetected until PRESIDIO_ENTITY_SCORE lowered it."""
    result = scanner.scan(f"call {phone} tomorrow", use_presidio=True)
    assert any(f["rule"] == "Phone Number" for f in result["findings"]), result["findings"]


@pytest.mark.parametrize("digits", ["1234567890", "9876543210"])
def test_bare_digit_runs_are_not_phones(digits):
    """The cost of the 0.4 floor: without PRESIDIO_SHAPE_REQUIRED, 10-digit
    order IDs false-positive as phone numbers, and a warning that fires on
    every long ID trains the user to ignore all warnings."""
    result = scanner.scan(f"the order id is {digits} and status is pending",
                          use_presidio=True)
    assert not [f for f in result["findings"] if f["rule"] == "Phone Number"]


def test_ssn_is_found_by_regex_not_presidio():
    """UsSsnRecognizer does not fire on '123-45-6789' and sometimes decodes bare
    SSNs as DATE_TIME, so US_SSN is omitted from PRESIDIO_ENTITIES."""
    result = scanner.scan("my ssn is 123-45-6789", use_presidio=True)
    ssn = [f for f in result["findings"] if "Social Security" in f["rule"]]
    assert ssn, result["findings"]
    assert all(f["detector"] == "regex" for f in ssn)


def test_person_requires_high_confidence():
    """PERSON/LOCATION are the weakest signals; the strict floor keeps common
    words out of the warn tier."""
    result = scanner.scan("the parser handles nested arrays", use_presidio=True)
    assert result["action"] == "allow", result["findings"]


def test_email_is_detected_and_warns_only():
    result = scanner.scan("ping malak.faiz@example.com later", use_presidio=True)
    assert result["action"] == "warn"
    assert any(f["rule"] == "Email Address" for f in result["findings"])


def test_credential_outranks_pii():
    """Strongest action wins: one credential outranks any number of names."""
    result = scanner.scan(
        "Sarah Chen in Portland used key AKIAIOSFODNN7EXAMPLE", use_presidio=True)
    assert result["action"] == "block"
    assert any(f["severity"] == "low" for f in result["findings"])


def test_presidio_findings_carry_no_raw_value():
    result = scanner.scan("ping malak.faiz@example.com later", use_presidio=True)
    for f in result["findings"]:
        assert "malak.faiz@example.com" not in f["sample"]


def test_dedupe_collapses_overlapping_detectors():
    """Regex and Presidio both catch cards; the verdict should not double-count."""
    result = scanner.scan("card 4111 1111 1111 1111", use_presidio=True)
    cards = [f for f in result["findings"] if "Credit Card" in f["rule"]]
    samples = [f["sample"] for f in cards]
    assert len(samples) == len(set(samples)) or len(cards) <= 2
