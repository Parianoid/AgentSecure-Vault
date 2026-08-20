from __future__ import annotations

import hashlib
import secrets
from dataclasses import dataclass

import pytest

from vault import SecretNotFound, Vault


@dataclass(frozen=True)
class InsecureTestKEM:
    """Tiny deterministic-shape KEM fixture. NEVER used by production code."""

    name: str = "insecure-test-kem"
    algorithm: str = "ML-KEM-768"

    def generate_keypair(self) -> tuple[bytes, bytes]:
        private = secrets.token_bytes(32)
        public = hashlib.sha256(private).digest()
        return public, private

    def encapsulate(self, public_key: bytes) -> tuple[bytes, bytes]:
        shared = secrets.token_bytes(32)
        mask = hashlib.sha256(public_key).digest()
        ciphertext = bytes(a ^ b for a, b in zip(shared, mask, strict=True))
        return ciphertext, shared

    def decapsulate(self, private_key: bytes, kem_ciphertext: bytes) -> bytes:
        public = hashlib.sha256(private_key).digest()
        mask = hashlib.sha256(public).digest()
        return bytes(a ^ b for a, b in zip(kem_ciphertext, mask, strict=True))


def test_encrypt_decrypt_round_trip(tmp_path):
    vault = Vault(tmp_path, backend_override=InsecureTestKEM())
    secret_id = vault.encrypt_secret("OPENAI_API_KEY", "sk-test-value")

    recovered = vault.decrypt_secret(secret_id)

    assert recovered["name"] == "OPENAI_API_KEY"
    assert recovered["value"] == "sk-test-value"
    assert "sk-test-value" not in (tmp_path / "secrets.json").read_text()


def test_list_never_reveals_value(tmp_path):
    vault = Vault(tmp_path, backend_override=InsecureTestKEM())
    vault.encrypt_secret("DATABASE_PASSWORD", "super-secret")

    listed = vault.list_secrets()

    assert listed[0]["name"] == "DATABASE_PASSWORD"
    assert "value" not in listed[0]


def test_encryption_proof_is_safe_and_verifiable(tmp_path):
    vault = Vault(tmp_path, backend_override=InsecureTestKEM())
    secret_id = vault.encrypt_secret("DEPLOY_TOKEN", "proof-secret-value")

    proof = vault.encryption_proof(secret_id)

    assert proof["name"] == "DEPLOY_TOKEN"
    assert proof["kem_ciphertext_bytes"] > 0
    assert proof["payload_ciphertext_bytes"] > 0
    assert proof["nonce_bytes"] == 12
    assert len(proof["ciphertext_sha256"]) == 64
    assert proof["plaintext_field_present"] is False
    assert "proof-secret-value" not in str(proof)
    assert "value" not in proof["stored_fields"]


def test_missing_secret(tmp_path):
    vault = Vault(tmp_path, backend_override=InsecureTestKEM())
    with pytest.raises(SecretNotFound):
        vault.decrypt_secret("does-not-exist")


def test_rotation_reencrypts_in_place(tmp_path):
    vault = Vault(tmp_path, backend_override=InsecureTestKEM())
    secret_id = vault.encrypt_secret("ROTATING_TOKEN", "version-one")
    original_fingerprint = vault.encryption_proof(secret_id)["ciphertext_sha256"]

    rotated = vault.rotate_secret(secret_id, "version-two")

    assert rotated["id"] == secret_id
    assert rotated["rotation_count"] == 1
    assert vault.decrypt_secret(secret_id)["value"] == "version-two"
    assert vault.encryption_proof(secret_id)["ciphertext_sha256"] != original_fingerprint
    assert "version-one" not in (tmp_path / "secrets.json").read_text()
    assert "version-two" not in (tmp_path / "secrets.json").read_text()


def test_revocation_removes_ciphertext_record(tmp_path):
    vault = Vault(tmp_path, backend_override=InsecureTestKEM())
    secret_id = vault.encrypt_secret("SHORT_LIVED_TOKEN", "revocable")

    revoked = vault.revoke_secret(secret_id)

    assert revoked == {"id": secret_id, "name": "SHORT_LIVED_TOKEN"}
    assert vault.list_secrets() == []
    with pytest.raises(SecretNotFound):
        vault.decrypt_secret(secret_id)
