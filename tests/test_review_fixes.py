"""Tests for second-pass review fixes."""

from datetime import datetime, timedelta

import pytest
from cryptography.fernet import Fernet

from dpdp_agent import DPDPAgent, DataCategory


@pytest.fixture
def key():
    return Fernet.generate_key().decode()


@pytest.fixture
def agent(tmp_path, key):
    return DPDPAgent(
        storage_path=str(tmp_path / "store.json"),
        encryption_key=key,
        config_path=str(tmp_path / "no_config.json"),
    )


# --- Fix A: consented user must not be locked out by breach heuristic ---------

def test_consented_user_not_breach_blocked(agent):
    # User racks up breach_threshold blocked store attempts (no consent yet).
    for _ in range(agent.breach_threshold):
        with pytest.raises(PermissionError):
            agent.store_data("u", "Email x@y.com", purpose="marketing")
    assert agent.detect_breach_attempt("u") is True

    # Now the user grants consent. A subsequent request must be allowed, not
    # blocked as a breach.
    agent.grant_consent("u", "marketing")
    result = agent.process_data("u", "Email x@y.com", "marketing")
    assert result["status"] == "allowed"


def test_attacker_without_consent_still_breach_blocked(agent):
    for _ in range(agent.breach_threshold):
        with pytest.raises(PermissionError):
            agent.store_data("attacker", "Email x@y.com", purpose="marketing")
    # No consent granted -> still treated as breach.
    result = agent.process_data("attacker", "Email x@y.com", "marketing")
    assert result["status"] == "blocked"
    assert result["reason"] == "Potential breach detected"


# --- Fix E: erasure of a consent-only user is audited -------------------------

def test_erasure_of_consent_only_user_is_audited(agent):
    agent.grant_consent("consentonly", "marketing")
    assert "consentonly" not in agent.data_store  # no stored data

    agent.right_to_erasure("consentonly")

    assert "consentonly" not in agent.consents
    logs = agent.get_audit_report("consentonly")
    assert any(log["action"] == "data_erased" for log in logs), \
        "erasure must be audited even for consent-only users"


def test_erasure_with_no_records_still_audited(agent):
    agent.right_to_erasure("ghost")
    logs = agent.get_audit_report("ghost")
    assert any(log["action"] == "data_erased" for log in logs)


# --- Fix F: expired deletion keeps distinct-but-equal non-expired items -------

def test_delete_expired_keeps_identical_nonexpired_items(agent):
    # Two general items with identical field values but only one made expired.
    agent.store_data("u", "same text", retention_days=30)
    agent.store_data("u", "same text", retention_days=30)
    # Force both created_at equal so value-equality would treat them as one.
    ts = datetime.now()
    agent.data_store["u"][0].created_at = ts - timedelta(days=60)  # expired
    agent.data_store["u"][1].created_at = ts                       # fresh
    # Make the two items field-identical except expiry via created_at above;
    # content is already identical, categories/retention identical.

    deleted = agent.delete_expired_data()
    assert deleted == 1
    remaining = agent.get_user_data("u")
    assert len(remaining) == 1
    assert remaining[0]["content"] == "same text"


def test_delete_expired_removes_all_and_cleans_user(agent):
    agent.store_data("u", "text one", retention_days=1)
    agent.store_data("u", "text two", retention_days=1)
    for item in agent.data_store["u"]:
        item.created_at = datetime.now() - timedelta(days=5)
    deleted = agent.delete_expired_data()
    assert deleted == 2
    assert "u" not in agent.data_store
