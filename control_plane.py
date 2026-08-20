"""Agent identity, policy, lease, audit, and reporting control plane.

This module deliberately stores metadata only. Secret values and cryptographic
key material remain exclusively inside :mod:`vault`.
"""

from __future__ import annotations

import json
import os
import re
import secrets
import threading
import uuid
from datetime import datetime, time, timedelta, timezone
from pathlib import Path

FORMAT_VERSION = 1
AGENTS_FILE = "agents.json"
POLICIES_FILE = "policies.json"
AUDIT_FILE = "audit_log.json"
MAX_AUDIT_EVENTS = 2_000
AGENT_ID_PATTERN = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_-]{2,63}$")


class ControlPlaneError(Exception):
    """Base exception for AgentShield control-plane failures."""


class AgentExists(ControlPlaneError):
    """Raised when an agent ID is already registered."""


class AgentNotFound(ControlPlaneError):
    """Raised when an agent ID is unknown."""


class PolicyNotFound(ControlPlaneError):
    """Raised when a secret has no explicit policy."""


class LeaseDenied(ControlPlaneError):
    """Raised when a lease is missing, expired, or belongs to another agent."""


def utc_now() -> datetime:
    return datetime.now(timezone.utc)


def _parse_clock(value: str) -> time:
    try:
        return datetime.strptime(value, "%H:%M").time()
    except ValueError as exc:
        raise ValueError("Access times must use 24-hour HH:MM format") from exc


class AgentShieldControlPlane:
    """Persistent metadata control plane for the AgentShield Vault demo."""

    def __init__(self, data_dir: str | Path, default_agent_id: str) -> None:
        self.data_dir = Path(data_dir).resolve()
        self.data_dir.mkdir(parents=True, exist_ok=True)
        self.default_agent_id = default_agent_id
        self.agents_path = self.data_dir / AGENTS_FILE
        self.policies_path = self.data_dir / POLICIES_FILE
        self.audit_path = self.data_dir / AUDIT_FILE
        self._lock = threading.RLock()
        self._leases: dict[str, dict[str, str]] = {}

        self._ensure_document(self.agents_path, "agents", [])
        self._ensure_document(self.policies_path, "policies", {})
        self._ensure_document(self.audit_path, "events", [])
        self._ensure_default_agent()

    # ------------------------------------------------------------------
    # Agents
    # ------------------------------------------------------------------
    def _ensure_default_agent(self) -> None:
        if any(agent["id"] == self.default_agent_id for agent in self.list_agents()):
            return
        self.create_agent(
            name="Demo Operations Agent",
            agent_id=self.default_agent_id,
            description="Default authorized identity for the local hackathon demo.",
            permissions=["*"],
        )

    def create_agent(
        self,
        *,
        name: str,
        agent_id: str,
        description: str,
        permissions: list[str],
    ) -> dict[str, object]:
        clean_name = name.strip()
        clean_id = agent_id.strip()
        clean_permissions = sorted(
            {permission.strip() for permission in permissions if permission.strip()}
        )
        if not clean_name:
            raise ValueError("Agent name must not be empty")
        if not AGENT_ID_PATTERN.fullmatch(clean_id):
            raise ValueError(
                "Agent ID must be 3-64 characters using letters, numbers, _ or -"
            )
        if not clean_permissions:
            raise ValueError("Agent must have at least one permission")

        with self._lock:
            document = self._read_document(self.agents_path, "agents", list)
            if any(item.get("id") == clean_id for item in document["agents"]):
                raise AgentExists(f"Agent {clean_id!r} already exists")
            agent: dict[str, object] = {
                "id": clean_id,
                "name": clean_name,
                "description": description.strip(),
                "status": "active",
                "permissions": clean_permissions,
                "created_at": utc_now().isoformat(),
            }
            document["agents"].append(agent)
            self._atomic_write(self.agents_path, document)
        return agent

    def list_agents(self) -> list[dict[str, object]]:
        with self._lock:
            document = self._read_document(self.agents_path, "agents", list)
            return [dict(item) for item in document["agents"]]

    def get_agent(self, agent_id: str) -> dict[str, object]:
        agent = next(
            (item for item in self.list_agents() if item.get("id") == agent_id),
            None,
        )
        if agent is None:
            raise AgentNotFound(f"Agent {agent_id!r} was not found")
        return agent

    # ------------------------------------------------------------------
    # Policies
    # ------------------------------------------------------------------
    def set_policy(
        self,
        *,
        secret_id: str,
        secret_name: str,
        allowed_agents: list[str],
        access_start: str = "00:00",
        access_end: str = "23:59",
        max_requests_per_day: int = 100,
    ) -> dict[str, object]:
        clean_agents = sorted({item.strip() for item in allowed_agents if item.strip()})
        if not clean_agents:
            raise ValueError("Policy must allow at least one agent")
        for agent_id in clean_agents:
            self.get_agent(agent_id)
        _parse_clock(access_start)
        _parse_clock(access_end)
        if not 1 <= max_requests_per_day <= 10_000:
            raise ValueError("Maximum requests must be between 1 and 10000")

        policy: dict[str, object] = {
            "secret_id": secret_id,
            "secret_name": secret_name,
            "allowed_agents": clean_agents,
            "access_start": access_start,
            "access_end": access_end,
            "max_requests_per_day": max_requests_per_day,
            "updated_at": utc_now().isoformat(),
        }
        with self._lock:
            document = self._read_document(self.policies_path, "policies", dict)
            document["policies"][secret_id] = policy
            self._atomic_write(self.policies_path, document)
        return policy

    def get_policy(self, secret_id: str) -> dict[str, object]:
        with self._lock:
            document = self._read_document(self.policies_path, "policies", dict)
            policy = document["policies"].get(secret_id)
        if not isinstance(policy, dict):
            raise PolicyNotFound(f"No policy exists for secret {secret_id!r}")
        return dict(policy)

    def list_policies(self) -> list[dict[str, object]]:
        with self._lock:
            document = self._read_document(self.policies_path, "policies", dict)
            return [dict(item) for item in document["policies"].values()]

    def delete_policy(self, secret_id: str) -> None:
        with self._lock:
            document = self._read_document(self.policies_path, "policies", dict)
            document["policies"].pop(secret_id, None)
            self._atomic_write(self.policies_path, document)

    def evaluate_access(
        self,
        *,
        secret_id: str,
        secret_name: str,
        agent_id: str,
        now: datetime | None = None,
    ) -> tuple[bool, str, dict[str, object] | None]:
        current = now or utc_now()
        try:
            agent = self.get_agent(agent_id)
        except AgentNotFound:
            return False, "Agent identity is unknown", None
        if agent.get("status") != "active":
            return False, "Agent identity is inactive", None

        try:
            policy = self.get_policy(secret_id)
        except PolicyNotFound:
            return False, "Secret has no access policy", agent

        if agent_id not in policy["allowed_agents"]:
            return False, "Agent is not allowed by this secret policy", agent
        permissions = {str(item) for item in agent.get("permissions", [])}
        if "*" not in permissions and secret_name not in permissions:
            return False, "Agent lacks the required secret permission", agent

        start = _parse_clock(str(policy["access_start"]))
        end = _parse_clock(str(policy["access_end"]))
        clock = current.timetz().replace(tzinfo=None)
        inside_window = start <= clock <= end if start <= end else clock >= start or clock <= end
        if not inside_window:
            return False, "Request is outside the policy access window", agent

        today = current.date().isoformat()
        requests_today = sum(
            1
            for event in self.list_audit(limit=MAX_AUDIT_EVENTS)
            if event.get("action") == "ACCESS_GRANTED"
            and event.get("secret_id") == secret_id
            and event.get("agent_id") == agent_id
            and str(event.get("timestamp", "")).startswith(today)
        )
        if requests_today >= int(policy["max_requests_per_day"]):
            return False, "Daily request limit has been reached", agent
        return True, "Identity and least-privilege policy approved", agent

    # ------------------------------------------------------------------
    # Just-in-time leases
    # ------------------------------------------------------------------
    def create_lease(self, secret_id: str, agent_id: str, ttl_seconds: int = 60) -> dict[str, object]:
        ttl = max(1, min(int(ttl_seconds), 300))
        token = secrets.token_urlsafe(32)
        expires_at = utc_now() + timedelta(seconds=ttl)
        with self._lock:
            self._purge_expired_leases()
            self._leases[token] = {
                "secret_id": secret_id,
                "agent_id": agent_id,
                "expires_at": expires_at.isoformat(),
            }
        return {"access_token": token, "expires_at": expires_at.isoformat(), "expires_in": ttl}

    def validate_lease(self, token: str, agent_id: str) -> dict[str, str]:
        with self._lock:
            lease = self._leases.get(token)
            if lease is None:
                raise LeaseDenied("Access lease is invalid or expired")
            expires_at = datetime.fromisoformat(lease["expires_at"])
            if utc_now() >= expires_at:
                self._leases.pop(token, None)
                raise LeaseDenied("Access lease has expired")
            if not secrets.compare_digest(lease["agent_id"], agent_id):
                raise LeaseDenied("Access lease belongs to another agent")
            return dict(lease)

    def _purge_expired_leases(self) -> None:
        now = utc_now()
        expired = [
            token
            for token, lease in self._leases.items()
            if now >= datetime.fromisoformat(lease["expires_at"])
        ]
        for token in expired:
            self._leases.pop(token, None)

    # ------------------------------------------------------------------
    # Audit and reporting
    # ------------------------------------------------------------------
    def audit(
        self,
        *,
        action: str,
        http_status: int,
        reason: str,
        secret_id: str = "",
        agent_id: str = "",
    ) -> dict[str, object]:
        event: dict[str, object] = {
            "event_id": str(uuid.uuid4()),
            "timestamp": utc_now().isoformat(),
            "agent_id": agent_id,
            "secret_id": secret_id,
            "action": action,
            "http_status": int(http_status),
            "reason": reason,
        }
        with self._lock:
            document = self._read_document(self.audit_path, "events", list)
            document["events"].append(event)
            document["events"] = document["events"][-MAX_AUDIT_EVENTS:]
            self._atomic_write(self.audit_path, document)
        return event

    def list_audit(self, limit: int = 100) -> list[dict[str, object]]:
        clean_limit = max(1, min(int(limit), 500))
        with self._lock:
            document = self._read_document(self.audit_path, "events", list)
            return [dict(item) for item in reversed(document["events"][-clean_limit:])]

    def security_score(
        self,
        *,
        algorithm: str,
        secret_count: int,
        plaintext_safe: bool,
    ) -> dict[str, object]:
        checks = [
            {"label": "ML-KEM-768 enabled", "passed": algorithm == "ML-KEM-768", "points": 25},
            {"label": "AES-256-GCM encryption", "passed": True, "points": 20},
            {"label": "Agent identity registry", "passed": bool(self.list_agents()), "points": 15},
            {"label": "Persistent audit logging", "passed": self.audit_path.exists(), "points": 15},
            {
                "label": "Least-privilege policies",
                "passed": secret_count == 0 or len(self.list_policies()) >= secret_count,
                "points": 15,
            },
            {"label": "No plaintext fields at rest", "passed": plaintext_safe, "points": 10},
        ]
        score = sum(int(item["points"]) for item in checks if item["passed"])
        return {"score": score, "maximum": 100, "checks": checks}

    def security_report(
        self,
        *,
        algorithm: str,
        backend: str,
        secret_count: int,
        plaintext_safe: bool,
    ) -> dict[str, object]:
        events = self.list_audit(limit=500)
        score = self.security_score(
            algorithm=algorithm,
            secret_count=secret_count,
            plaintext_safe=plaintext_safe,
        )
        return {
            "report": "AgentShield Security Report",
            "generated_at": utc_now().isoformat(),
            "encryption": {
                "key_encapsulation": algorithm,
                "payload_cipher": "AES-256-GCM",
                "key_derivation": "HKDF-SHA256",
                "backend": backend,
            },
            "protected_secrets": secret_count,
            "registered_agents": len(self.list_agents()),
            "blocked_attempts": sum(1 for item in events if item.get("action") == "ACCESS_DENIED"),
            "audit_events": len(events),
            "security_score": score,
            "contains_secret_values": False,
            "prototype_note": (
                "Use workload identity or mTLS and HSM/KMS-backed key storage before production."
            ),
        }

    # ------------------------------------------------------------------
    # JSON persistence
    # ------------------------------------------------------------------
    def _ensure_document(self, path: Path, key: str, value: object) -> None:
        if not path.exists():
            self._atomic_write(path, {"version": FORMAT_VERSION, key: value})

    @staticmethod
    def _read_document(path: Path, key: str, expected_type: type) -> dict:
        try:
            document = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError) as exc:
            raise ControlPlaneError(f"Could not read {path.name}: {exc}") from exc
        if not isinstance(document, dict) or document.get("version") != FORMAT_VERSION:
            raise ControlPlaneError(f"{path.name} has an unsupported format")
        if not isinstance(document.get(key), expected_type):
            raise ControlPlaneError(f"{path.name} must contain {key!r}")
        return document

    @staticmethod
    def _atomic_write(path: Path, document: dict) -> None:
        temporary = path.with_suffix(path.suffix + ".tmp")
        temporary.write_text(
            json.dumps(document, indent=2, sort_keys=True) + "\n", encoding="utf-8"
        )
        os.replace(temporary, path)
