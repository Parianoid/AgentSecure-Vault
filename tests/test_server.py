from __future__ import annotations

from fastapi.testclient import TestClient

from tests.test_vault import InsecureTestKEM
from server import create_app
from vault import Vault


def make_client(tmp_path) -> TestClient:
    vault = Vault(tmp_path, backend_override=InsecureTestKEM())
    return TestClient(create_app(vault))


def test_full_api_flow(tmp_path, monkeypatch):
    monkeypatch.setenv("VAULT_AGENT_ID", "agent-demo-001")
    client = make_client(tmp_path)

    encrypted = client.post(
        "/encrypt",
        json={"name": "OPENAI_API_KEY", "value": "sk-api-test"},
    )
    assert encrypted.status_code == 201
    secret_id = encrypted.json()["id"]

    listed = client.get("/list_secrets")
    assert listed.status_code == 200
    assert listed.json()["secrets"][0]["name"] == "OPENAI_API_KEY"
    assert "value" not in listed.json()["secrets"][0]

    proof = client.get(f"/security_proof/{secret_id}")
    assert proof.status_code == 200
    assert proof.json()["plaintext_field_present"] is False
    assert proof.json()["kem_ciphertext_bytes"] > 0
    assert proof.json()["payload_ciphertext_bytes"] > 0
    assert "sk-api-test" not in proof.text

    missing_header = client.get(f"/get_secret/{secret_id}")
    assert missing_header.status_code == 401

    denied = client.get(
        f"/get_secret/{secret_id}", headers={"agent_id": "wrong-agent"}
    )
    assert denied.status_code == 403

    allowed = client.get(
        f"/get_secret/{secret_id}", headers={"agent_id": "agent-demo-001"}
    )
    assert allowed.status_code == 200
    assert allowed.json()["value"] == "sk-api-test"
    assert allowed.headers["cache-control"] == "no-store"


def test_missing_secret_returns_404(tmp_path, monkeypatch):
    monkeypatch.setenv("VAULT_AGENT_ID", "agent-demo-001")
    client = make_client(tmp_path)
    response = client.get(
        "/get_secret/not-real", headers={"agent_id": "agent-demo-001"}
    )
    assert response.status_code == 404


def test_zero_trust_access_flow_and_audit(tmp_path, monkeypatch):
    monkeypatch.setenv("VAULT_AGENT_ID", "agent-demo-001")
    client = make_client(tmp_path)
    created_agent = client.post(
        "/agents",
        json={
            "name": "Support Agent",
            "id": "agent-support-001",
            "description": "Customer support workflow",
            "permissions": ["SUPPORT_API_KEY"],
        },
    )
    assert created_agent.status_code == 201

    encrypted = client.post(
        "/encrypt",
        json={
            "name": "SUPPORT_API_KEY",
            "value": "private-demo-value",
            "allowed_agents": ["agent-support-001"],
            "max_requests_per_day": 5,
        },
    )
    assert encrypted.status_code == 201
    secret_id = encrypted.json()["id"]

    approved = client.post(
        "/request_access",
        json={"secret_id": secret_id, "agent_id": "agent-support-001"},
    )
    assert approved.status_code == 200
    assert approved.json()["status"] == "approved"
    assert approved.json()["secret"]["value"] == "private-demo-value"
    assert approved.json()["expires_in"] == "60 seconds"
    assert approved.headers["cache-control"] == "no-store"

    lease = client.get(
        f"/lease/{approved.json()['access_token']}",
        headers={"agent_id": "agent-support-001"},
    )
    assert lease.status_code == 200
    assert lease.json()["value"] == "private-demo-value"

    denied = client.post(
        "/request_access",
        json={"secret_id": secret_id, "agent_id": "agent-attacker-999"},
    )
    assert denied.status_code == 403

    audit = client.get("/audit").json()["events"]
    assert any(event["action"] == "ACCESS_GRANTED" for event in audit)
    assert any(event["action"] == "ACCESS_DENIED" for event in audit)
    assert "private-demo-value" not in str(audit)


def test_rotation_revocation_and_reporting(tmp_path, monkeypatch):
    monkeypatch.setenv("VAULT_AGENT_ID", "agent-demo-001")
    client = make_client(tmp_path)
    encrypted = client.post(
        "/encrypt",
        json={"name": "ROTATE_ME", "value": "first-version"},
    )
    secret_id = encrypted.json()["id"]

    rotated = client.put(
        f"/secret/{secret_id}",
        json={"value": "second-version"},
        headers={"agent_id": "agent-demo-001"},
    )
    assert rotated.status_code == 200
    assert rotated.json()["rotation_count"] == 1
    assert client.get(f"/secret/{secret_id}/policy").status_code == 200
    revealed = client.get(
        f"/get_secret/{secret_id}",
        headers={"agent_id": "agent-demo-001"},
    )
    assert revealed.json()["value"] == "second-version"

    score = client.get("/security_score")
    report = client.get("/security_report")
    assert score.status_code == 200
    assert score.json()["score"] == 100
    assert report.json()["contains_secret_values"] is False
    assert "second-version" not in report.text

    revoked = client.delete(
        f"/secret/{secret_id}",
        headers={"agent_id": "agent-demo-001"},
    )
    assert revoked.status_code == 200
    assert revoked.json()["status"] == "revoked"
    assert client.get("/list_secrets").json()["secrets"] == []
    assert client.get(f"/secret/{secret_id}/policy").status_code == 404
    actions = [event["action"] for event in client.get("/audit").json()["events"]]
    assert "SECRET_ROTATED" in actions
    assert "SECRET_REVOKED" in actions
