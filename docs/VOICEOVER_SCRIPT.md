# AgentShield Vault — Voice-over Script

**Target length:** 2 minutes 52 seconds  
**Delivery:** Calm, confident, approximately 125–130 words per minute  
**Recording note:** The supplied video is intentionally silent. Begin speaking about half a second after playback starts.

## 0:00–0:09 — Opening

AI agents need credentials to deploy, investigate, and support customers. But giving an autonomous agent a permanent secret creates unnecessary risk.

## 0:09–0:19 — The problem

AgentShield Vault changes that relationship. An agent can request access when needed, without becoming the long-term owner of the credential.

## 0:19–0:35 — Store a synthetic secret

First, we store a clearly synthetic credential named Customer Email Key. The access policy allows only Support AI to request it. The demo value is masked and is not a real credential.

## 0:35–0:46 — Encrypt and persist safely

The live FastAPI backend performs real encryption. ML-KEM-768 establishes fresh post-quantum key material, HKDF derives a unique key, and AES-256-GCM seals the value. Plaintext is never persisted.

## 0:46–0:56 — Vault metadata

The vault lists safe operational metadata, including the record name and creation time. Secret values never appear in lists, reports, proofs, or audit events.

## 0:56–1:10 — Request as Support AI

Now Support AI requests the Customer Email Key for sixty seconds. AgentShield checks the identity, its permission, the secret allowlist, the access window, and the request limit before any value can be released.

## 1:10–1:28 — Approved temporary access

Every check passes, so the API returns HTTP 200 and issues an agent-bound lease. Access is temporary: the countdown is visible, and the dashboard clears the revealed value when the lease expires. The synthetic value is intentionally hidden in this recording.

## 1:28–1:40 — Replay as Unknown AI

Next, we request the exact same protected record as Unknown AI. Nothing else changes, so the policy decision is easy to compare.

## 1:40–1:56 — Access blocked

Unknown AI is not allowed by this secret policy. AgentShield returns HTTP 403, releases no value, and records the denial. The protection comes from the same real API path used for the approved request.

## 1:56–2:09 — Ciphertext proof

The Proof view makes the cryptography inspectable. It shows ML-KEM-768, the encapsulation size, authenticated payload information, and a SHA-256 fingerprint. Most importantly, Plaintext field present is false.

## 2:09–2:19 — Security posture

The security view summarizes evidence-backed controls: post-quantum key establishment, authenticated encryption, an identity registry, least-privilege policies, persistent audit logging, and no plaintext fields at rest.

## 2:19–2:29 — Post-quantum claim

AgentShield is precise about the threat. A cryptographically relevant quantum computer threatens RSA and elliptic-curve key establishment. ML-KEM-768 replaces that vulnerable layer, while AES-256-GCM continues protecting the payload.

## 2:29–2:42 — Audit evidence

The audit preserves both outcomes: HTTP 200 for Support AI and HTTP 403 for Unknown AI. It stores identities, decisions, timestamps, and reasons—but never the credential itself.

## 2:42–2:52 — Closing

AgentShield turns credentials from secrets agents possess into short-lived capabilities they must earn. Access when needed. Ownership never.

