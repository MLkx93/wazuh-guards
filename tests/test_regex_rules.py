"""Regex-tier detection, with Presidio explicitly off.

This is the tier that must hold when the daemon is down, so every credential
case is asserted here rather than only in the full-engine tests.
"""

import pytest

from wazuh_guards import scanner
from wazuh_guards.ruleset import load_bundled

from corpus import ALLOW_CASES, REGEX_ONLY_BLOCK_CASES, WARN_CASES


@pytest.fixture(scope="module")
def rs():
    return load_bundled()


@pytest.mark.parametrize("label,text", REGEX_ONLY_BLOCK_CASES, ids=lambda v: v)
def test_credentials_block_without_presidio(label, text, rs):
    result = scanner.scan(text, use_presidio=False, ruleset=rs)
    assert result["action"] == "block", f"{label}: {result['findings']}"
    assert result["blocked"] is True
    assert any(f["severity"] == "high" for f in result["findings"])


@pytest.mark.parametrize("label,text", ALLOW_CASES, ids=lambda v: v)
def test_false_positive_traps_stay_allowed(label, text, rs):
    result = scanner.scan(text, use_presidio=False, ruleset=rs)
    assert result["action"] == "allow", f"{label} regressed: {result['findings']}"


@pytest.mark.parametrize("label,text", WARN_CASES, ids=lambda v: v)
def test_nlp_pii_is_invisible_to_regex(label, text, rs):
    """Names, emails and phones are Presidio's job. Asserting regex ignores them
    documents the split -- and catches a stray pattern that starts matching
    prose."""
    result = scanner.scan(text, use_presidio=False, ruleset=rs)
    assert result["action"] == "allow", f"{label}: {result['findings']}"


def test_findings_carry_no_raw_secret(rs):
    text = "here is the key AKIAIOSFODNN7EXAMPLE for the bucket"
    result = scanner.scan(text, use_presidio=False, ruleset=rs)
    for f in result["findings"]:
        assert "AKIAIOSFODNN7EXAMPLE" not in f["sample"]
        assert f["sample"].count("*") >= 8


def test_luhn_invalid_card_is_dropped(rs):
    """A 16-digit run that fails the checksum is not a card. Without this the
    Credit Card rule fires on order numbers and invoice ids."""
    result = scanner.scan("ref 4111 1111 1111 1112 logged", use_presidio=False, ruleset=rs)
    assert result["action"] == "allow", result["findings"]


def test_luhn_valid_card_promotes_to_high(rs):
    """The bundled rule is declared severity=low and promoted by its validator;
    a card that passes Luhn must block, not warn."""
    result = scanner.scan("card 4111 1111 1111 1111", use_presidio=False, ruleset=rs)
    card = [f for f in result["findings"] if f["rule"] == "Credit Card Number"]
    assert card and card[0]["severity"] == "high"
    assert result["action"] == "block"


@pytest.mark.parametrize(
    "ssn",
    ["000-45-6789", "666-45-6789", "900-45-6789", "123-00-6789", "123-45-0000"],
)
def test_ssa_invalid_ssn_ranges_are_not_matched(ssn, rs):
    result = scanner.scan(f"id {ssn} on file", use_presidio=False, ruleset=rs)
    assert not [f for f in result["findings"] if "Social Security" in f["rule"]]


def test_anthropic_key_reports_under_its_own_rule(rs):
    """sk-ant- matches both the Anthropic and OpenAI shapes; the negative
    lookahead must keep it out of the OpenAI rule."""
    text = "key sk-ant-api03-abcdefghij0123456789KLMNOPQRSTUV"
    result = scanner.scan(text, use_presidio=False, ruleset=rs)
    names = {f["rule"] for f in result["findings"]}
    assert "Anthropic API Key" in names
    assert "OpenAI API Key" not in names


def test_verdict_reports_pattern_provenance(rs):
    """Every verdict carries the version and sha the Wazuh drift rule keys on."""
    result = scanner.scan("hello", use_presidio=False, ruleset=rs)
    assert result["pattern_version"] == rs.version
    assert result["pattern_sha"] == rs.sha256
    assert len(result["pattern_sha"]) == 64
