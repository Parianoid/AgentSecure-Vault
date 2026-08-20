"""FastAPI application for the AgentShield post-quantum agent vault."""

from __future__ import annotations

import logging
import os
import secrets
from pathlib import Path
from typing import Annotated, Any

from fastapi import FastAPI, Header, HTTPException, Query, status
from fastapi.responses import FileResponse, JSONResponse
from pydantic import BaseModel, Field

from control_plane import (
    AgentExists,
    AgentNotFound,
    AgentShieldControlPlane,
    ControlPlaneError,
    LeaseDenied,
    PolicyNotFound,
)
from vault import ALGORITHM, BackendUnavailable, SecretNotFound, Vault, VaultDataError

logging.basicConfig(
    level=os.getenv("LOG_LEVEL", "INFO").upper(),
    format="%(asctime)s | %(levelname)s | %(name)s | %(message)s",
)
LOGGER = logging.getLogger("agentshield-api")

DEFAULT_AGENT_ID = "agent-demo-001"
NO_CACHE_HEADERS = {"Cache-Control": "no-store", "Pragma": "no-cache"}


class EncryptRequest(BaseModel):
    name: str = Field(min_length=1, max_length=128, examples=["OPENAI_API_KEY"])
    value: str = Field(min_length=1, max_length=16_384, examples=["sk-demo-secret"])
    allowed_agents: list[str] | None = None
    access_start: str = Field(default="00:00", pattern=r"^\d{2}:\d{2}$")
    access_end: str = Field(default="23:59", pattern=r"^\d{2}:\d{2}$")
    max_requests_per_day: int = Field(default=100, ge=1, le=10_000)


class EncryptResponse(BaseModel):
    id: str
    name: str
    algorithm: str
    backend: str
    policy: dict[str, Any]


class SecretResponse(BaseModel):
    id: str
    name: str
    value: str


class SecretListItem(BaseModel):
    id: str
    name: str
    created_at: str
    last_rotated: str | None = None
    rotation_count: int = 0


class SecretListResponse(BaseModel):
    secrets: list[SecretListItem]


class EncryptionProofResponse(BaseModel):
    id: str
    name: str
    created_at: str
    algorithm: str
    backend: str
    kem_ciphertext_bytes: int
    payload_ciphertext_bytes: int
    nonce_bytes: int
    ciphertext_sha256: str
    ciphertext_preview: str
    stored_fields: list[str]
    plaintext_field_present: bool


class AgentCreateRequest(BaseModel):
    name: str = Field(min_length=1, max_length=80)
    id: str = Field(min_length=3, max_length=64)
    description: str = Field(default="", max_length=240)
    permissions: list[str] = Field(min_length=1)


class AgentResponse(BaseModel):
    id: str
    name: str
    description: str
    status: str
    permissions: list[str]
    created_at: str


class AgentListResponse(BaseModel):
    agents: list[AgentResponse]


class PolicyRequest(BaseModel):
    allowed_agents: list[str] = Field(min_length=1)
    access_start: str = Field(default="00:00", pattern=r"^\d{2}:\d{2}$")
    access_end: str = Field(default="23:59", pattern=r"^\d{2}:\d{2}$")
    max_requests_per_day: int = Field(default=100, ge=1, le=10_000)


class PolicyResponse(BaseModel):
    secret_id: str
    secret_name: str
    allowed_agents: list[str]
    access_start: str
    access_end: str
    max_requests_per_day: int
    updated_at: str


class AccessRequest(BaseModel):
    secret_id: str = Field(min_length=1)
    agent_id: str = Field(min_length=1)
    ttl_seconds: int = Field(default=60, ge=1, le=300)


class AccessResponse(BaseModel):
    status: str
    secret: SecretResponse
    agent_id: str
    access_token: str
    expires_at: str
    expires_in: str
    expires_in_seconds: int


class RotateRequest(BaseModel):
    value: str = Field(min_length=1, max_length=16_384)
    name: str | None = Field(default=None, min_length=1, max_length=128)


class RotateResponse(BaseModel):
    id: str
    name: str
    last_rotated: str
    rotation_count: int


class RevokeResponse(BaseModel):
    id: str
    name: str
    status: str


class AuditResponse(BaseModel):
    events: list[dict[str, Any]]


def create_app(
    vault_instance: Vault | None = None,
    control_instance: AgentShieldControlPlane | None = None,
) -> FastAPI:
    """Create an application, with injectable services for deterministic tests."""
    app = FastAPI(
        title="AgentShield Vault",
        description=(
            "Zero-trust, just-in-time secret access for autonomous AI agents, "
            "protected with ML-KEM-768 and AES-256-GCM."
        ),
        version="2.0.0",
    )

    configured_agent_id = os.getenv("VAULT_AGENT_ID", DEFAULT_AGENT_ID)
    holder: dict[str, Any] = {
        "vault": vault_instance,
        "control": control_instance,
    }

    def get_vault() -> Vault:
        if holder["vault"] is None:
            try:
                holder["vault"] = Vault(data_dir=Path(__file__).resolve().parent)
            except (BackendUnavailable, VaultDataError) as exc:
                LOGGER.exception("Vault initialization failed")
                raise HTTPException(status_code=503, detail=str(exc)) from exc
        return holder["vault"]

    def get_control() -> AgentShieldControlPlane:
        if holder["control"] is None:
            data_dir = (
                get_vault().data_dir
                if holder["vault"] is not None
                else Path(__file__).resolve().parent
            )
            try:
                holder["control"] = AgentShieldControlPlane(
                    data_dir=data_dir,
                    default_agent_id=configured_agent_id,
                )
            except ControlPlaneError as exc:
                LOGGER.exception("Control-plane initialization failed")
                raise HTTPException(status_code=503, detail=str(exc)) from exc
        return holder["control"]

    def require_legacy_agent(agent_id: str | None) -> str:
        if not agent_id:
            raise HTTPException(status_code=401, detail="Missing agent_id header")
        if not secrets.compare_digest(agent_id, configured_agent_id):
            raise HTTPException(status_code=403, detail="Agent is not authorized")
        return agent_id

    def secret_metadata(secret_id: str) -> dict[str, object]:
        secret = next(
            (item for item in get_vault().list_secrets() if item["id"] == secret_id),
            None,
        )
        if secret is None:
            raise HTTPException(status_code=404, detail="Secret was not found")
        return secret

    def plaintext_safe() -> bool:
        return all(
            not bool(get_vault().encryption_proof(str(item["id"]))["plaintext_field_present"])
            for item in get_vault().list_secrets()
        )

    @app.get("/", include_in_schema=False)
    def dashboard() -> FileResponse:
        dashboard_path = Path(__file__).resolve().with_name("dashboard.html")
        if not dashboard_path.exists():
            raise HTTPException(status_code=404, detail="Dashboard file is missing")
        return FileResponse(dashboard_path, headers={"Cache-Control": "no-cache"})

    @app.get("/health")
    def health() -> dict[str, object]:
        try:
            vault = get_vault()
            control = get_control()
            status_data = vault.status()
            score = control.security_score(
                algorithm=str(status_data["algorithm"]),
                secret_count=int(status_data["secret_count"]),
                plaintext_safe=plaintext_safe(),
            )
            return {
                "status": "ok",
                **status_data,
                "agent_count": len(control.list_agents()),
                "audit_count": len(control.list_audit(limit=500)),
                "security_score": score["score"],
            }
        except HTTPException:
            raise
        except Exception as exc:
            LOGGER.exception("Health check failed")
            raise HTTPException(status_code=503, detail=str(exc)) from exc

    @app.post("/encrypt", response_model=EncryptResponse, status_code=status.HTTP_201_CREATED)
    def encrypt_secret(request: EncryptRequest) -> EncryptResponse:
        vault = get_vault()
        control = get_control()
        allowed_agents = request.allowed_agents or [configured_agent_id]
        for agent_id in allowed_agents:
            try:
                control.get_agent(agent_id)
            except AgentNotFound as exc:
                raise HTTPException(status_code=400, detail=str(exc)) from exc

        secret_id = ""
        try:
            secret_id = vault.encrypt_secret(request.name, request.value)
            policy = control.set_policy(
                secret_id=secret_id,
                secret_name=request.name.strip(),
                allowed_agents=allowed_agents,
                access_start=request.access_start,
                access_end=request.access_end,
                max_requests_per_day=request.max_requests_per_day,
            )
        except (ValueError, ControlPlaneError) as exc:
            if secret_id:
                try:
                    vault.revoke_secret(secret_id)
                except (SecretNotFound, VaultDataError):
                    LOGGER.exception("Could not roll back a failed secret creation")
            raise HTTPException(status_code=400, detail=str(exc)) from exc
        except VaultDataError as exc:
            raise HTTPException(status_code=500, detail=str(exc)) from exc

        control.audit(
            action="SECRET_STORED",
            http_status=201,
            reason="Encrypted and attached to a least-privilege access policy",
            secret_id=secret_id,
            agent_id=configured_agent_id,
        )
        return EncryptResponse(
            id=secret_id,
            name=request.name.strip(),
            algorithm=ALGORITHM,
            backend=vault.backend.name,
            policy=policy,
        )

    @app.get("/get_secret/{secret_id}", response_model=SecretResponse)
    def get_secret_legacy(
        secret_id: str,
        agent_id: Annotated[str | None, Header(alias="agent_id")] = None,
    ) -> JSONResponse:
        control = get_control()
        try:
            authorized_agent = require_legacy_agent(agent_id)
        except HTTPException as exc:
            control.audit(
                action="ACCESS_DENIED",
                http_status=exc.status_code,
                reason=str(exc.detail),
                secret_id=secret_id,
                agent_id=agent_id or "anonymous",
            )
            raise
        try:
            decrypted = get_vault().decrypt_secret(secret_id)
        except SecretNotFound as exc:
            raise HTTPException(status_code=404, detail=str(exc)) from exc
        except VaultDataError as exc:
            raise HTTPException(status_code=500, detail=str(exc)) from exc
        control.audit(
            action="ACCESS_GRANTED",
            http_status=200,
            reason="Legacy authorized retrieval completed",
            secret_id=secret_id,
            agent_id=authorized_agent,
        )
        return JSONResponse(content=decrypted, headers=NO_CACHE_HEADERS)

    @app.get("/list_secrets", response_model=SecretListResponse)
    def list_secrets() -> SecretListResponse:
        try:
            return SecretListResponse(secrets=get_vault().list_secrets())
        except VaultDataError as exc:
            raise HTTPException(status_code=500, detail=str(exc)) from exc

    @app.get("/security_proof/{secret_id}", response_model=EncryptionProofResponse)
    def security_proof(secret_id: str) -> EncryptionProofResponse:
        try:
            return EncryptionProofResponse(**get_vault().encryption_proof(secret_id))
        except SecretNotFound as exc:
            raise HTTPException(status_code=404, detail=str(exc)) from exc
        except VaultDataError as exc:
            raise HTTPException(status_code=500, detail=str(exc)) from exc

    @app.post("/agents", response_model=AgentResponse, status_code=status.HTTP_201_CREATED)
    def create_agent(request: AgentCreateRequest) -> AgentResponse:
        control = get_control()
        try:
            agent = control.create_agent(
                name=request.name,
                agent_id=request.id,
                description=request.description,
                permissions=request.permissions,
            )
        except AgentExists as exc:
            raise HTTPException(status_code=409, detail=str(exc)) from exc
        except (ValueError, ControlPlaneError) as exc:
            raise HTTPException(status_code=400, detail=str(exc)) from exc
        control.audit(
            action="AGENT_REGISTERED",
            http_status=201,
            reason="Agent identity registered",
            agent_id=request.id,
        )
        return AgentResponse(**agent)

    @app.get("/agents", response_model=AgentListResponse)
    def list_agents() -> AgentListResponse:
        return AgentListResponse(agents=get_control().list_agents())

    @app.put("/secret/{secret_id}/policy", response_model=PolicyResponse)
    def set_policy(secret_id: str, request: PolicyRequest) -> PolicyResponse:
        metadata = secret_metadata(secret_id)
        try:
            policy = get_control().set_policy(
                secret_id=secret_id,
                secret_name=str(metadata["name"]),
                allowed_agents=request.allowed_agents,
                access_start=request.access_start,
                access_end=request.access_end,
                max_requests_per_day=request.max_requests_per_day,
            )
        except (ValueError, AgentNotFound, ControlPlaneError) as exc:
            raise HTTPException(status_code=400, detail=str(exc)) from exc
        get_control().audit(
            action="POLICY_UPDATED",
            http_status=200,
            reason="Least-privilege policy updated",
            secret_id=secret_id,
            agent_id=configured_agent_id,
        )
        return PolicyResponse(**policy)

    @app.get("/secret/{secret_id}/policy", response_model=PolicyResponse)
    def get_policy(secret_id: str) -> PolicyResponse:
        secret_metadata(secret_id)
        try:
            return PolicyResponse(**get_control().get_policy(secret_id))
        except PolicyNotFound as exc:
            raise HTTPException(status_code=404, detail=str(exc)) from exc

    @app.post("/request_access", response_model=AccessResponse)
    def request_access(request: AccessRequest) -> JSONResponse:
        metadata = secret_metadata(request.secret_id)
        control = get_control()
        allowed, reason, _ = control.evaluate_access(
            secret_id=request.secret_id,
            secret_name=str(metadata["name"]),
            agent_id=request.agent_id,
        )
        if not allowed:
            control.audit(
                action="ACCESS_DENIED",
                http_status=403,
                reason=reason,
                secret_id=request.secret_id,
                agent_id=request.agent_id,
            )
            raise HTTPException(status_code=403, detail=reason)

        try:
            decrypted = get_vault().decrypt_secret(request.secret_id)
        except SecretNotFound as exc:
            raise HTTPException(status_code=404, detail=str(exc)) from exc
        except VaultDataError as exc:
            raise HTTPException(status_code=500, detail=str(exc)) from exc
        lease = control.create_lease(
            request.secret_id,
            request.agent_id,
            request.ttl_seconds,
        )
        control.audit(
            action="ACCESS_GRANTED",
            http_status=200,
            reason=f"{reason}; {lease['expires_in']}-second lease issued",
            secret_id=request.secret_id,
            agent_id=request.agent_id,
        )
        body = AccessResponse(
            status="approved",
            secret=SecretResponse(**decrypted),
            agent_id=request.agent_id,
            access_token=str(lease["access_token"]),
            expires_at=str(lease["expires_at"]),
            expires_in=f"{lease['expires_in']} seconds",
            expires_in_seconds=int(lease["expires_in"]),
        )
        return JSONResponse(content=body.model_dump(), headers=NO_CACHE_HEADERS)

    @app.get("/lease/{access_token}", response_model=SecretResponse)
    def use_lease(
        access_token: str,
        agent_id: Annotated[str | None, Header(alias="agent_id")] = None,
    ) -> JSONResponse:
        if not agent_id:
            raise HTTPException(status_code=401, detail="Missing agent_id header")
        try:
            lease = get_control().validate_lease(access_token, agent_id)
            decrypted = get_vault().decrypt_secret(lease["secret_id"])
        except LeaseDenied as exc:
            raise HTTPException(status_code=403, detail=str(exc)) from exc
        except SecretNotFound as exc:
            raise HTTPException(status_code=404, detail=str(exc)) from exc
        except VaultDataError as exc:
            raise HTTPException(status_code=500, detail=str(exc)) from exc
        return JSONResponse(content=decrypted, headers=NO_CACHE_HEADERS)

    @app.put("/secret/{secret_id}", response_model=RotateResponse)
    def rotate_secret(
        secret_id: str,
        request: RotateRequest,
        agent_id: Annotated[str | None, Header(alias="agent_id")] = None,
    ) -> RotateResponse:
        authorized_agent = require_legacy_agent(agent_id)
        try:
            rotated = get_vault().rotate_secret(secret_id, request.value, request.name)
        except SecretNotFound as exc:
            raise HTTPException(status_code=404, detail=str(exc)) from exc
        except (ValueError, VaultDataError) as exc:
            raise HTTPException(status_code=400, detail=str(exc)) from exc

        try:
            policy = get_control().get_policy(secret_id)
            policy["secret_name"] = rotated["name"]
            get_control().set_policy(
                secret_id=secret_id,
                secret_name=str(rotated["name"]),
                allowed_agents=list(policy["allowed_agents"]),
                access_start=str(policy["access_start"]),
                access_end=str(policy["access_end"]),
                max_requests_per_day=int(policy["max_requests_per_day"]),
            )
        except PolicyNotFound:
            pass
        get_control().audit(
            action="SECRET_ROTATED",
            http_status=200,
            reason="Secret re-encrypted in place with new ciphertext",
            secret_id=secret_id,
            agent_id=authorized_agent,
        )
        return RotateResponse(**rotated)

    @app.delete("/secret/{secret_id}", response_model=RevokeResponse)
    def revoke_secret(
        secret_id: str,
        agent_id: Annotated[str | None, Header(alias="agent_id")] = None,
    ) -> RevokeResponse:
        authorized_agent = require_legacy_agent(agent_id)
        try:
            revoked = get_vault().revoke_secret(secret_id)
        except SecretNotFound as exc:
            raise HTTPException(status_code=404, detail=str(exc)) from exc
        except VaultDataError as exc:
            raise HTTPException(status_code=500, detail=str(exc)) from exc
        get_control().delete_policy(secret_id)
        get_control().audit(
            action="SECRET_REVOKED",
            http_status=200,
            reason="Encrypted record revoked; audit history retained",
            secret_id=secret_id,
            agent_id=authorized_agent,
        )
        return RevokeResponse(**revoked, status="revoked")

    @app.get("/audit", response_model=AuditResponse)
    def audit_log(limit: int = Query(default=100, ge=1, le=500)) -> AuditResponse:
        return AuditResponse(events=get_control().list_audit(limit=limit))

    @app.get("/security_score")
    def security_score() -> dict[str, object]:
        vault_status = get_vault().status()
        return get_control().security_score(
            algorithm=str(vault_status["algorithm"]),
            secret_count=int(vault_status["secret_count"]),
            plaintext_safe=plaintext_safe(),
        )

    @app.get("/security_report")
    def security_report() -> JSONResponse:
        vault_status = get_vault().status()
        report = get_control().security_report(
            algorithm=str(vault_status["algorithm"]),
            backend=str(vault_status["backend"]),
            secret_count=int(vault_status["secret_count"]),
            plaintext_safe=plaintext_safe(),
        )
        return JSONResponse(content=report, headers=NO_CACHE_HEADERS)

    return app


app = create_app()
