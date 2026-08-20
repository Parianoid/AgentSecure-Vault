# AgentShield — Post-Quantum Vault for AI Agents

AgentShield protects the secret passwords and API keys that AI agents need to do their jobs.

Instead of giving an AI agent a permanent secret, AgentShield checks whether that agent is allowed and gives temporary access only when needed.

## The problem

AI agents may need access to services such as email, cloud storage, payments, databases, or customer-support tools.

Giving every agent a permanent API key is risky. If an agent is misused, hacked, or given the wrong permission, important company secrets can be exposed.

## Our solution

AgentShield stores secrets in an encrypted vault.

Before an agent can use a secret, AgentShield checks rules such as:

- Is this the correct agent?
- Is this agent allowed to use this secret?
- Is access being requested during the allowed time?
- Has the daily access limit been reached?

If the checks pass, the agent gets a short-lived access lease. If they fail, access is blocked.

## Why post-quantum?

Future quantum computers may be able to break some of today’s encryption methods.

AgentShield uses post-quantum cryptography to help protect stored secrets against that future risk. It does not use a quantum computer; it uses modern security methods designed to resist future quantum attacks.

## Demo story

1. Store a fake secret named `Customer Email Key`.
2. Allow only `Support AI` to request it.
3. Request access as `Support AI` and show that access is allowed temporarily.
4. Request the same secret as `Unknown AI` and show that access is blocked.
5. Review the audit log without revealing the secret value.

## Key features

- Encrypted secret storage
- Post-quantum cryptography
- Agent identity checks
- Per-secret access policies
- Short-lived access leases
- Secret rotation and revocation
- Audit logs that do not expose secret values
- Clear allow-versus-block security evidence

## Run locally

1. Clone this repository.
2. Create and activate a Python virtual environment.
3. Install dependencies:

   ```bash
   pip install -r requirements.txt
