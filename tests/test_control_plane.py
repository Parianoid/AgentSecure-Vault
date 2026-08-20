from __future__ import annotations

from datetime import datetime, timedelta, timezone

import pytest

from control_plane import AgentShieldControlPlane, LeaseDenied


def make_control(tmp_path) -> AgentShieldControlPlane:
    return AgentShieldControlPlane(tmp_path, default_agent_id="agent-demo-001")


def test_identity_policy_and_access_decision(tmp_path):
    control = make_control(tmp_path)
    control.create_agent(
        name="Support Agent",
        agent_id="agent-support-001",
        description="Resolves customer incidents",
        permissions=["SUPPORT_API_KEY"],
    )
    control.set_policy(
        secret_id="secret-001",
        secret_name="SUPPORT_API_KEY",
        allowed_agents=["agent-support-001"],
        max_requests_per_day=2,
    )

    allowed, reason, _ = control.evaluate_access(
        secret_id="secret-001",
        secret_name="SUPPORT_API_KEY",
        agent_id="agent-support-001",
    )
    denied, denied_reason, _ = control.evaluate_access(
        secret_id="secret-001",
        secret_name="SUPPORT_API_KEY",
        agent_id="agent-attacker-999",
    )

    assert allowed is True
    assert "approved" in reason
    assert denied is False
    assert "unknown" in denied_reason


def test_daily_limit_is_enforced_from_persistent_audit(tmp_path):
    control = make_control(tmp_path)
    control.set_policy(
        secret_id="secret-001",
        secret_name="DEMO_KEY",
        allowed_agents=["agent-demo-001"],
        max_requests_per_day=1,
    )
    control.audit(
        action="ACCESS_GRANTED",
        http_status=200,
        reason="test approval",
        secret_id="secret-001",
        agent_id="agent-demo-001",
    )

    allowed, reason, _ = control.evaluate_access(
        secret_id="secret-001",
        secret_name="DEMO_KEY",
        agent_id="agent-demo-001",
    )

    assert allowed is False
    assert "limit" in reason


def test_lease_is_agent_bound_and_expires(tmp_path):
    control = make_control(tmp_path)
    lease = control.create_lease("secret-001", "agent-demo-001", ttl_seconds=60)
    assert control.validate_lease(
        str(lease["access_token"]), "agent-demo-001"
    )["secret_id"] == "secret-001"

    with pytest.raises(LeaseDenied):
        control.validate_lease(str(lease["access_token"]), "agent-other-001")

    control._leases[str(lease["access_token"])]["expires_at"] = (
        datetime.now(timezone.utc) - timedelta(seconds=1)
    ).isoformat()
    with pytest.raises(LeaseDenied):
        control.validate_lease(str(lease["access_token"]), "agent-demo-001")


def test_report_and_audit_are_metadata_only(tmp_path):
    control = make_control(tmp_path)
    control.audit(
        action="ACCESS_DENIED",
        http_status=403,
        reason="Agent is not allowed",
        secret_id="secret-001",
        agent_id="agent-attacker-999",
    )
    report = control.security_report(
        algorithm="ML-KEM-768",
        backend="test",
        secret_count=0,
        plaintext_safe=True,
    )

    assert report["blocked_attempts"] == 1
    assert report["contains_secret_values"] is False
    assert report["security_score"]["score"] == 100
    assert "secret value" not in (tmp_path / "audit_log.json").read_text().lower()
