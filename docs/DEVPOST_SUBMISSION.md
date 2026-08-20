# AgentShield Vault

## Tagline

The zero-trust, post-quantum security layer for autonomous AI agents.

## Elevator pitch

Autonomous AI agents need API keys, database credentials, and deployment tokens to do useful work. Today those secrets are often placed in environment files, prompts, or agent memory—turning an agent process into a long-lived secret owner.

AgentShield Vault changes that relationship. Credentials remain encrypted at rest and are released only after a registered agent passes a per-secret policy covering permission, allowlist, time window, and daily request limit. Approved access is short-lived and agent-bound. Denials are persistent, value-free evidence. The vault uses real ML-KEM-768 key encapsulation, HKDF-SHA256, and AES-256-GCM.

## Inspiration

Agent security discussions often focus on prompt injection while credentials remain broadly available to the runtime. We wanted to protect the capability an attacker ultimately wants: the secret that lets an agent act elsewhere.

Post-quantum migration made the problem more urgent. Long-lived encrypted data can be collected now and attacked later, while cryptographic infrastructure takes years to replace. AgentShield demonstrates an agent-first vault in which post-quantum key establishment, not a decorative “quantum” label, is part of the data path.

## What it does

- registers named agent identities with status and secret-scoped permissions;
- encrypts each secret using ML-KEM-768, HKDF-SHA256, and AES-256-GCM;
- attaches a per-secret allowlist, UTC access window, and daily request cap;
- evaluates just-in-time requests and issues agent-bound leases, 60 seconds by default;
- returns HTTP 403 for unknown or unauthorized agents without decrypting for them;
- persists value-free approvals and denials;
- rotates a secret with fresh encapsulation, nonce, and ciphertext while preserving its ID and policy;
- revokes ciphertext and its policy while retaining audit history;
- exposes safe ciphertext evidence, an evidence-backed security score, and a downloadable metadata-only report;
- includes an optional guided tutorial that explains the real workflow without generating fake activity.

## How we built it

The backend is a FastAPI application with two explicit layers.

The **control plane** stores agent metadata, per-secret policies, audit events, and in-memory expiring leases. The **post-quantum data plane** stores only encrypted records and key metadata. On encryption, ML-KEM-768 encapsulates fresh key material, HKDF-SHA256 derives a unique 256-bit key using the secret ID, and AES-256-GCM encrypts and authenticates the value with the ID and name as additional authenticated data.

The frontend is a dependency-free responsive dashboard served by FastAPI. It reduces the product to three core workflows—Store Secret, Vault List, and Agent Access—then gives judges a live demo, safe ciphertext proof, accurate threat explainer, audit, and report.

## Why it is innovative

AgentShield combines concerns that are usually demonstrated separately:

1. agent workload identity;
2. least-privilege, per-secret authorization;
3. short-lived capability delivery;
4. standardized post-quantum key establishment;
5. an inspectable lifecycle and evidence trail.

The innovation is not “AES plus a dashboard.” It is the boundary: an agent never needs permanent ownership of a credential to use it, and every release is tied to an identity, policy decision, and expiration.

## A demo judges can verify

The dashboard makes the verification flow direct and inspectable:

1. create an authorized support agent;
2. store a synthetic post-quantum protected secret;
3. request it as the authorized identity and receive HTTP 200 plus a 60-second lease;
4. request it as an unregistered attacker and receive HTTP 403;
5. generate a value-free security report and score.

The Vault Proof action shows ciphertext sizes, nonce size, a SHA-256 fingerprint, stored fields, and confirmation that no plaintext field exists. The audit preserves both the 200 and 403 decisions without recording the credential.

## Challenges we ran into

- Treating ML-KEM correctly as key encapsulation instead of encrypting arbitrary payloads with it.
- Supporting more than one Python ML-KEM backend without silently mixing incompatible key material.
- Keeping backward-compatible endpoints while adding a policy-first access flow.
- Making rotation truly re-encrypt in place rather than only changing metadata.
- Designing a demo that is fast enough for judging without staging outcomes or weakening the real code path.
- Explaining the quantum threat honestly: Shor targets RSA/ECC, while AES-256 remains the conservative symmetric choice.

## Accomplishments we are proud of

- Real ML-KEM-768 encapsulation and decapsulation in the working backend.
- Ciphertext-only persistence and proofs that never reveal values or key material.
- A real authorized HTTP 200 versus attacker HTTP 403 story using the same Agent Access form.
- Agent-bound expiring leases, daily limits, rotation, revocation, and durable audit.
- Backward compatibility with the original vault API.
- Automated coverage across crypto, policy, leases, reports, and lifecycle operations.
- A polished interface that explains a complex trust model without overwhelming the judge.

## What we learned

Post-quantum migration is as much an architecture problem as a primitive-selection problem. Strong cryptography is insufficient when credentials are widely distributed, identities are ambiguous, or decrypted values live indefinitely. The useful product boundary is identity plus policy plus short lifetime plus evidence.

We also learned that the most persuasive security demo is inspectable: show the ciphertext structure, show an actual denial, show that the audit excludes values, and state the prototype limits clearly.

## What is next

- replace demo agent claims with mTLS or SPIFFE/SPIRE workload identity;
- move the ML-KEM private key into an HSM/KMS;
- use a transactional policy store and tamper-evident audit sink;
- add signed policy bundles, approval workflows, and secret-version rollback;
- issue secrets directly into sandboxed tool calls instead of returning plaintext to a general agent process;
- add multi-tenant isolation, rate limiting, and continuous identity posture checks.

## Built with

Python, FastAPI, Uvicorn, ML-KEM-768 (`liboqs-python` with a `cryptography` fallback), HKDF-SHA256, AES-256-GCM, HTML, CSS, and JavaScript.

## Responsible prototype note

The local demo identity is not production authentication, the private key is stored on disk, leases are process-local, and TLS is expected to terminate in front of the service. A production deployment requires attested workload identity, hardware-backed keys, transactional storage, tamper-evident audit, and operational controls. The project documentation describes these boundaries explicitly.
