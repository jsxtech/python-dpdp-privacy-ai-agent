"""API tests for the Flask app.

The api module initializes a module-level agent at import time and requires
DPDP_API_KEY and DPDP_ENCRYPTION_KEY. We set those up and import the module
fresh inside an isolated working directory so storage lands under tmp_path.
"""

import importlib
import os
import sys

import pytest
from cryptography.fernet import Fernet


API_KEY = "test-api-key"


@pytest.fixture
def client(tmp_path, monkeypatch):
    # Isolate storage/logs into tmp_path by running from there.
    monkeypatch.chdir(tmp_path)
    (tmp_path / "data").mkdir(exist_ok=True)

    monkeypatch.setenv("DPDP_API_KEY", API_KEY)
    monkeypatch.setenv("DPDP_ENCRYPTION_KEY", Fernet.generate_key().decode())
    monkeypatch.setenv("DPDP_TRUSTED_PROXIES", "0")  # disable ProxyFix for tests
    monkeypatch.setenv("DPDP_LOG_FILE", str(tmp_path / "dpdp_agent.log"))

    # Ensure a fresh import so module-level init runs against this env/cwd.
    sys.modules.pop("api", None)
    api = importlib.import_module("api")
    importlib.reload(api)

    api.app.config.update(TESTING=True)
    with api.app.test_client() as c:
        yield c

    sys.modules.pop("api", None)


def _auth():
    return {"X-API-Key": API_KEY}


def test_health_no_auth(client):
    resp = client.get("/health")
    assert resp.status_code == 200
    assert resp.get_json()["status"] == "healthy"


def test_missing_api_key_unauthorized(client):
    resp = client.post("/consent/grant", json={"user_id": "u1", "purpose": "marketing"})
    assert resp.status_code == 401


def test_wrong_content_type_415(client):
    resp = client.post("/consent/grant", data="not json", headers=_auth())
    assert resp.status_code == 415


@pytest.mark.parametrize("body", [5, 3.14, "a string", [1, 2, 3], True])
def test_non_object_json_body_returns_400(client, body):
    # A valid-JSON but non-object body must be rejected with 400, never 500.
    resp = client.post("/consent/grant", json=body, headers=_auth())
    assert resp.status_code == 400


def test_null_json_body_returns_400(client):
    resp = client.post("/consent/grant", data="null",
                       content_type="application/json", headers=_auth())
    assert resp.status_code == 400


def test_grant_consent_and_store_flow(client):
    r = client.post("/consent/grant",
                    json={"user_id": "u1", "purpose": "marketing"}, headers=_auth())
    assert r.status_code == 200

    r = client.post("/data/store",
                    json={"user_id": "u1", "text": "Email user@example.com",
                          "purpose": "marketing"}, headers=_auth())
    assert r.status_code == 201


def test_store_without_consent_returns_403(client):
    # PII with a purpose but no consent -> PermissionError -> 403 via error handler.
    r = client.post("/data/store",
                    json={"user_id": "nouser", "text": "Email user@example.com",
                          "purpose": "marketing"}, headers=_auth())
    assert r.status_code == 403


def test_store_missing_fields_400(client):
    r = client.post("/data/store", json={"user_id": "u1"}, headers=_auth())
    assert r.status_code == 400


def test_process_data_blocked_without_consent(client):
    r = client.post("/data/process",
                    json={"user_id": "u2", "text": "Email user@example.com",
                          "purpose": "marketing"}, headers=_auth())
    assert r.status_code == 200
    assert r.get_json()["status"] == "blocked"


def test_export_and_erase(client):
    client.post("/consent/grant",
                json={"user_id": "u3", "purpose": "marketing"}, headers=_auth())
    client.post("/data/store",
                json={"user_id": "u3", "text": "Email user@example.com",
                      "purpose": "marketing"}, headers=_auth())

    r = client.get("/data/export/u3", headers=_auth())
    assert r.status_code == 200
    assert len(r.get_json()["data"]) == 1

    r = client.delete("/data/erase/u3", headers=_auth())
    assert r.status_code == 200

    r = client.get("/data/export/u3", headers=_auth())
    assert r.get_json()["data"] == []


def test_audit_report(client):
    client.post("/consent/grant",
                json={"user_id": "u4", "purpose": "marketing"}, headers=_auth())
    r = client.get("/audit/u4", headers=_auth())
    assert r.status_code == 200
    assert any(log["action"] == "consent_granted" for log in r.get_json()["logs"])
