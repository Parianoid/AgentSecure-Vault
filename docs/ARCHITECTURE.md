# AgentShield Vault architecture

## System view

```mermaid
flowchart LR
    User[Operator / dashboard] -->|register, store, rotate, revoke| API[FastAPI control surface]
    Agent[Autonomous agent] -->|agent ID + secret ID| API

    subgraph Control[Zero-trust control plane]
      Registry[Agent registry]
      Policy[Per-secret policy engine]
      Lease[Short-lived lease manager]
      Audit[Persistent value-free audit]
    end

    subgraph Crypto[Post-quantum data plane]
      KEM[ML-KEM-768 encapsulation]
      KDF[HKDF-SHA256]
      AEAD[AES-256-GCM]
      Store[(Encrypted JSON vault)]
    end

    API --> Registry
    API --> Policy
    Policy -->|allow| Lease
    Policy -->|allow / deny evidence| Audit
    API --> KEM --> KDF --> AEAD --> Store
    Lease -->|authorized decrypt only| Store
    Store -. never returns values to .-> Audit
```

The control plane stores identities, policies, lease state, and audit metadata. The data plane stores cryptographic material and encrypted records. Secret values never enter lists, proofs, audit events, scores, or reports.

## Access decision sequence

```mermaid
sequenceDiagram
    participant A as AI agent
    participant F as FastAPI
    participant P as Policy engine
    participant V as ML-KEM vault
    participant L as Audit log

    A->>F: POST /request_access (agent_id, secret_id)
    F->>P: verify identity, permission, allowlist, UTC window, daily limit
    alt policy denied
      P-->>F: deny + reason
      F->>L: ACCESS_DENIED (metadata only)
      F-->>A: HTTP 403
    else policy approved
      P-->>F: approve
      F->>V: decapsulate + derive + AES-GCM decrypt
      F->>L: ACCESS_GRANTED (metadata only)
      F-->>A: HTTP 200 + value + agent-bound 60s lease
    end
```

## Storage boundaries

| Store | Persists | Explicitly excludes |
|---|---|---|
| `secrets.json` | KEM ciphertext, AES-GCM ciphertext, nonce, labels, timestamps | plaintext, shared secret, derived AES key |
| `agents.json` | identity ID/name/status/permissions | credentials or secret values |
| `policies.json` | allowed agents, time window, request limit | values and keys |
| `audit_log.json` | action, agent ID, secret ID, time, HTTP status, reason | values, tokens, key material |
| process memory | short-lived opaque lease token mapping | durable secret copies |

## Production evolution

Replace the local identity claim with attested workload identity; move ML-KEM private-key operations to an HSM/KMS; move metadata to a transactional store; export audit events to an append-only or tamper-evident sink; put the API behind TLS, rate limiting, and service authorization. The cryptographic and policy boundaries in this prototype make those substitutions explicit.
