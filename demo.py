"""CLI proof of AgentShield's approved-versus-denied access flow."""

from __future__ import annotations

import argparse
import hashlib
import logging
import os
import sys

import requests

LOGGER = logging.getLogger("demo-agent")


def mock_external_service(api_key: str) -> None:
    """Pretend to call an external AI service without logging the raw key."""
    fingerprint = hashlib.sha256(api_key.encode("utf-8")).hexdigest()[:12]
    LOGGER.info("Mock external service accepted credential fingerprint=%s", fingerprint)
    print("Mock AI service response: [ok] authenticated request completed")


def create_demo_secret(base_url: str, name: str, value: str, agent_id: str) -> str:
    response = requests.post(
        f"{base_url}/encrypt",
        json={
            "name": name,
            "value": value,
            "allowed_agents": [agent_id],
            "max_requests_per_day": 100,
        },
        timeout=10,
    )
    response.raise_for_status()
    secret_id = response.json()["id"]
    LOGGER.info("Stored demo credential in the PQ vault as id=%s", secret_id)
    return secret_id


def request_secret(base_url: str, secret_id: str, agent_id: str) -> requests.Response:
    return requests.post(
        f"{base_url}/request_access",
        json={"secret_id": secret_id, "agent_id": agent_id, "ttl_seconds": 60},
        timeout=10,
    )


def retrieve_secret(base_url: str, secret_id: str, agent_id: str) -> str:
    response = request_secret(base_url, secret_id, agent_id)
    if response.status_code in {401, 403}:
        raise RuntimeError(f"Agent authentication failed: {response.text}")
    if response.status_code == 404:
        raise RuntimeError(f"Secret does not exist: {secret_id}")
    response.raise_for_status()
    payload = response.json()
    LOGGER.info(
        "Policy approved HTTP 200; agent-bound lease expires in %s",
        payload["expires_in"],
    )
    return str(payload["secret"]["value"])


def prove_attacker_denial(base_url: str, secret_id: str) -> None:
    response = request_secret(base_url, secret_id, "agent-attacker-999")
    if response.status_code != 403:
        raise RuntimeError(
            f"Expected attacker request to return 403, received {response.status_code}"
        )
    LOGGER.info("Unknown attacker blocked with HTTP 403; no secret was returned")


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Post-quantum vault AI-agent demo")
    parser.add_argument(
        "--base-url",
        default=os.getenv("VAULT_URL", "http://127.0.0.1:8001"),
        help="Vault API base URL",
    )
    parser.add_argument(
        "--agent-id",
        default=os.getenv("VAULT_AGENT_ID", "agent-demo-001"),
        help="Simulated authenticated agent ID",
    )
    parser.add_argument(
        "--secret-id",
        help="Retrieve an existing secret. If omitted, a fake demo key is created first.",
    )
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s | %(levelname)s | %(name)s | %(message)s",
    )

    try:
        secret_id = args.secret_id or create_demo_secret(
            args.base_url,
            "AGENTSHIELD_CLI_DEMO_KEY",
            "agh-hackathon-demo-not-a-real-key",
            args.agent_id,
        )

        LOGGER.info("AI Agent needs a credential; requesting it from the vault")
        api_key = retrieve_secret(args.base_url, secret_id, args.agent_id)

        # The raw key is deliberately never printed or logged by this demo.
        mock_external_service(api_key)
        del api_key

        prove_attacker_denial(args.base_url, secret_id)

        LOGGER.info(
            "Authorized HTTP 200 and attacker HTTP 403 are now recorded in the "
            "metadata-only audit log."
        )
        LOGGER.info(
            "Production note: run the API behind HTTPS/mTLS so plaintext is also "
            "protected in transit."
        )
        return 0
    except requests.RequestException as exc:
        LOGGER.error("Vault API request failed: %s", exc)
    except RuntimeError as exc:
        LOGGER.error("Demo failed: %s", exc)
    return 1


if __name__ == "__main__":
    sys.exit(main())
