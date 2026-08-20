# Winning presentation flow

## Slide 1 — The ownership problem

**Your AI agents need access. They should never own your secrets.**

Agents commonly receive long-lived credentials through prompts, code, environment variables, or memory. That makes an autonomous runtime a secret owner instead of a controlled requester.

## Slide 2 — Why current vaults are not enough

Traditional vaults protect storage, but autonomous agents also need workload identity, per-secret least privilege, just-in-time release, automatic expiry, denial evidence, and a migration path away from quantum-vulnerable key establishment.

## Slide 3 — AgentShield Vault

One control plane joins agent identity, secret policy, 60-second leases, audit, rotation, and revocation. One data plane joins ML-KEM-768, HKDF-SHA256, and AES-256-GCM. The two are visible and testable in a single local product.

## Slide 4 — Live proof

Use the guided tutorial for orientation, then perform the flow directly:

1. identity registered;
2. secret encrypted;
3. authorized agent returns HTTP 200;
4. unregistered attacker returns HTTP 403;
5. report confirms values are excluded.

Pause on the approved and denied rows in the persistent audit log.

## Slide 5 — Cryptographic evidence

Open **Proof** for the demo secret. Show the ML-KEM ciphertext size, AES-GCM ciphertext size, nonce size, SHA-256 fingerprint, stored schema, and `plaintext_field_present: false`. Explain that this is inspectable evidence, not a UI label.

## Slide 6 — Honest security posture

Switch the quantum simulator from current systems to a cryptographically relevant quantum computer. State precisely: Shor threatens RSA/ECC; AgentShield replaces vulnerable key establishment with standardized ML-KEM-768; AES-256-GCM remains the payload cipher. Acknowledge the prototype boundaries and production path.

## Closing line

**AgentShield turns credentials from things agents possess into capabilities they earn, use briefly, and leave an audit trail for.**

## Judge Q&A anchors

- **Is the crypto real?** Yes. The API performs ML-KEM encapsulation/decapsulation, HKDF derivation, and AES-GCM encryption/decryption. Tests use an isolated non-production KEM fixture only for deterministic speed.
- **Can an attacker call the endpoint?** Yes, but an unregistered or unauthorized identity receives HTTP 403 and creates an audit event. Production must replace the demo identity claim with attested workload identity.
- **What is stored?** Ciphertext and metadata. Lists, proofs, audits, scores, and reports exclude values.
- **What expires?** The agent-bound lease and dashboard reveal. The encrypted secret remains until rotation or revocation.
- **Why post-quantum now?** Long-lived secrets and encrypted traffic face harvest-now-decrypt-later risk, and cryptographic migrations take time.
