"""Unit tests for DPDPAgent core flows and the fixed review issues."""

import json
from datetime import datetime, timedelta

import pytest
from cryptography.fernet import Fernet

from dpdp_agent import (
    DPDPAgent,
    DataCategory,
    ConsentStatus,
    RiskLevel,
)


@pytest.fixture
def key():
    return Fernet.generate_key().decode()


@pytest.fixture
def agent(tmp_path, key):
    """A fresh agent with isolated storage under tmp_path."""
    storage = tmp_path / "store.json"
    # config_path points to a nonexistent file so config defaults are used.
    return DPDPAgent(
        storage_path=str(storage),
        encryption_key=key,
        config_path=str(tmp_path / "no_config.json"),
    )


# --------------------------------------------------------------------------
# Encryption key handling
# --------------------------------------------------------------------------

def test_missing_encryption_key_raises(tmp_path, monkeypatch):
    monkeypatch.delenv("DPDP_ENCRYPTION_KEY", raising=False)
    with pytest.raises(ValueError):
        DPDPAgent(
            storage_path=str(tmp_path / "s.json"),
            encryption_key=None,
            config_path=str(tmp_path / "no_config.json"),
        )


def test_passphrase_key_derivation_roundtrip(tmp_path):
    """A non-Fernet passphrase should derive a working key and persist a salt."""
    storage = tmp_path / "s.json"
    a = DPDPAgent(storage_path=str(storage), encryption_key="a-passphrase-not-44-chars",
                  config_path=str(tmp_path / "nc.json"))
    salt_file = storage.with_suffix(".salt")
    assert salt_file.exists(), "per-deployment salt file should be created"

    a.grant_consent("u1", "marketing")
    a.store_data("u1", "hello world general text", purpose="marketing")

    # Re-open with same passphrase -> salt reused -> data decrypts.
    b = DPDPAgent(storage_path=str(storage), encryption_key="a-passphrase-not-44-chars",
                  config_path=str(tmp_path / "nc.json"))
    items = b.get_user_data("u1")
    assert len(items) == 1
    assert items[0]["content"] == "hello world general text"


def test_salt_is_random_per_deployment(tmp_path):
    s1 = tmp_path / "a.json"
    s2 = tmp_path / "b.json"
    DPDPAgent(storage_path=str(s1), encryption_key="passphrase-value",
              config_path=str(tmp_path / "nc.json"))
    DPDPAgent(storage_path=str(s2), encryption_key="passphrase-value",
              config_path=str(tmp_path / "nc.json"))
    assert s1.with_suffix(".salt").read_bytes() != s2.with_suffix(".salt").read_bytes()


# --------------------------------------------------------------------------
# Classification & anonymization
# --------------------------------------------------------------------------

@pytest.mark.parametrize("text,expected", [
    ("Contact user@example.com", DataCategory.PII),
    ("Card 4111 1111 1111 1111", DataCategory.FINANCIAL),
    ("Phone 9876543210", DataCategory.PII),
    ("Patient has diabetes", DataCategory.HEALTH),
    ("just some words", DataCategory.GENERAL),
])
def test_classify_data(agent, text, expected):
    assert agent.classify_data(text) == expected


def test_anonymize_masks_pii(agent):
    out = agent.anonymize("Email a@b.com phone 9876543210 card 4111 1111 1111 1111")
    assert "[EMAIL]" in out
    assert "[PHONE]" in out
    assert "[CARD]" in out
    assert "a@b.com" not in out


# --------------------------------------------------------------------------
# Consent
# --------------------------------------------------------------------------

def test_grant_and_check_consent(agent):
    agent.grant_consent("u1", "marketing")
    assert agent.check_consent("u1", "marketing") is True
    assert agent.check_consent("u1", "analytics") is False


def test_revoke_consent(agent):
    agent.grant_consent("u1", "marketing")
    agent.revoke_consent("u1", "marketing")
    assert agent.check_consent("u1", "marketing") is False


def test_expired_consent_auto_revoked(agent):
    agent.grant_consent("u1", "marketing", duration_days=1)
    # Force expiry in the past.
    agent.consents["u1"][0].expires_at = datetime.now() - timedelta(days=1)
    assert agent.check_consent("u1", "marketing") is False
    assert agent.consents["u1"][0].status == ConsentStatus.REVOKED


def test_grant_consent_validation(agent):
    with pytest.raises(ValueError):
        agent.grant_consent("", "marketing")
    with pytest.raises(ValueError):
        agent.grant_consent("u1", "marketing", duration_days=0)
    with pytest.raises(ValueError):
        agent.grant_consent("u1", "marketing", duration_days=True)  # bool rejected


# --------------------------------------------------------------------------
# Storage & DPDP enforcement
# --------------------------------------------------------------------------

def test_store_sensitive_requires_purpose(agent):
    with pytest.raises(ValueError):
        agent.store_data("u1", "Email user@example.com")  # PII, no purpose


def test_store_sensitive_without_consent_blocked(agent):
    with pytest.raises(PermissionError):
        agent.store_data("u1", "Email user@example.com", purpose="marketing")


def test_store_sensitive_with_consent_succeeds(agent):
    agent.grant_consent("u1", "marketing")
    agent.store_data("u1", "Email user@example.com", purpose="marketing")
    items = agent.get_user_data("u1")
    assert len(items) == 1
    assert items[0]["content"] == "Email user@example.com"


def test_stored_content_is_encrypted_at_rest(agent, tmp_path):
    agent.grant_consent("u1", "marketing")
    agent.store_data("u1", "Email secret@example.com", purpose="marketing")
    raw = agent.storage_path.read_text()
    assert "secret@example.com" not in raw  # encrypted on disk


def test_store_general_data_no_purpose_needed(agent):
    agent.store_data("u1", "just general words")
    assert len(agent.get_user_data("u1")) == 1


# --------------------------------------------------------------------------
# Breach detection (fixed issue #2)
# --------------------------------------------------------------------------

def test_blocked_store_attempts_trigger_breach_detection(agent):
    """Repeated blocked store attempts must count toward breach detection."""
    # No consent -> each store_data raises PermissionError and logs result 'blocked'.
    for _ in range(agent.breach_threshold):
        with pytest.raises(PermissionError):
            agent.store_data("attacker", "Email x@y.com", purpose="marketing")

    assert agent.detect_breach_attempt("attacker") is True

    # A subsequent process_data call for the same user should be blocked as breach.
    result = agent.process_data("attacker", "Email x@y.com", "marketing")
    assert result["status"] == "blocked"
    assert result["reason"] == "Potential breach detected"


def test_breach_not_triggered_below_threshold(agent):
    with pytest.raises(PermissionError):
        agent.store_data("u1", "Email x@y.com", purpose="marketing")
    assert agent.detect_breach_attempt("u1") is False


# --------------------------------------------------------------------------
# Erasure & export
# --------------------------------------------------------------------------

def test_right_to_erasure(agent):
    agent.grant_consent("u1", "marketing")
    agent.store_data("u1", "Email user@example.com", purpose="marketing")
    agent.right_to_erasure("u1")
    assert agent.get_user_data("u1") == []
    assert "u1" not in agent.consents


def test_export_user_data(agent):
    agent.grant_consent("u1", "marketing")
    agent.store_data("u1", "Email user@example.com", purpose="marketing")
    export = agent.export_user_data("u1")
    assert export["user_id"] == "u1"
    assert len(export["data"]) == 1
    assert export["data"][0]["content"] == "Email user@example.com"
    assert len(export["consents"]) == 1


def test_delete_expired_data(agent):
    agent.store_data("u1", "general text", retention_days=1)
    # Force the item to be past retention.
    agent.data_store["u1"][0].created_at = datetime.now() - timedelta(days=2)
    deleted = agent.delete_expired_data()
    assert deleted == 1
    assert agent.get_user_data("u1") == []


# --------------------------------------------------------------------------
# Risk assessment
# --------------------------------------------------------------------------

@pytest.mark.parametrize("category,consent,expected", [
    (DataCategory.HEALTH, False, RiskLevel.CRITICAL),
    (DataCategory.FINANCIAL, False, RiskLevel.HIGH),
    (DataCategory.PII, False, RiskLevel.MEDIUM),
    (DataCategory.PII, True, RiskLevel.LOW),
    (DataCategory.GENERAL, False, RiskLevel.LOW),
])
def test_assess_risk(agent, category, consent, expected):
    assert agent.assess_risk(category, consent) == expected


# --------------------------------------------------------------------------
# Persistence & corruption handling (fixed issue #5)
# --------------------------------------------------------------------------

def test_state_persists_across_instances(tmp_path, key):
    storage = tmp_path / "s.json"
    a = DPDPAgent(storage_path=str(storage), encryption_key=key,
                  config_path=str(tmp_path / "nc.json"))
    a.grant_consent("u1", "marketing")
    a.store_data("u1", "Email user@example.com", purpose="marketing")

    b = DPDPAgent(storage_path=str(storage), encryption_key=key,
                  config_path=str(tmp_path / "nc.json"))
    assert b.check_consent("u1", "marketing") is True
    assert len(b.get_user_data("u1")) == 1


def test_corrupt_state_is_backed_up(tmp_path, key):
    storage = tmp_path / "s.json"
    storage.write_text("{ this is not valid json ")
    agent = DPDPAgent(storage_path=str(storage), encryption_key=key,
                      config_path=str(tmp_path / "nc.json"))
    # Corrupt file moved aside; agent starts empty.
    backups = list(tmp_path.glob("s.corrupt-*.bak"))
    assert len(backups) == 1
    assert agent.get_audit_report() == []


def test_schema_corruption_is_backed_up(tmp_path, key):
    storage = tmp_path / "s.json"
    # Valid JSON, wrong structure (consents entries missing required fields).
    storage.write_text(json.dumps({"consents": {"u1": [{"bad": "shape"}]}}))
    agent = DPDPAgent(storage_path=str(storage), encryption_key=key,
                      config_path=str(tmp_path / "nc.json"))
    backups = list(tmp_path.glob("s.corrupt-*.bak"))
    assert len(backups) == 1
    assert agent.consents == {}


# --------------------------------------------------------------------------
# Audit log trimming (fixed issue #7)
# --------------------------------------------------------------------------

def test_audit_logs_trimmed_to_max(agent):
    agent.max_audit_logs = 10
    for i in range(50):
        agent._log_action("u1", "test", "N/A", "ok")
    assert len(agent.audit_logs) <= 10


# --------------------------------------------------------------------------
# Log injection sanitization
# --------------------------------------------------------------------------

def test_sanitize_for_log():
    assert DPDPAgent._sanitize_for_log("a\nb\rc\td") == "a\\nb\\rc\\td"
