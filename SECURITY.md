# Security and Responsible Use

AgentShield Vault is a working security prototype designed for demonstration and evaluation.

## Do not use production credentials

Use only clearly synthetic values. Public demo users can create and request demonstration records, and the prototype identity layer is not production authentication.

## Data excluded from this repository

The packaged repository intentionally excludes:

- ML-KEM private and public key files;
- stored ciphertext records and key metadata;
- agent and policy runtime stores;
- audit runtime data;
- local environment files;
- virtual environments and caches.

The application creates fresh local key material and empty runtime stores on first use.

## Prototype boundaries

- Agent IDs are demonstration claims rather than attested workload identities.
- Private-key operations occur in the application process rather than an HSM or KMS.
- JSON persistence is intended for an inspectable single-process demo.
- Leases are process-local and disappear on restart.
- HTTPS must terminate in front of the service when exposed beyond loopback.
- The app does not claim that quantum computers break AES-256.

## Production path

Use mTLS, SPIFFE/SPIRE, signed workload identity, or cloud-native workload attestation; place ML-KEM private-key operations in hardware-backed key management; use transactional storage and a tamper-evident audit sink; and add service authentication, TLS, rate limiting, tenant isolation, monitoring, and operational recovery controls.

