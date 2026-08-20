"""Post-Quantum Secret Protection vault.

The vault uses ML-KEM-768 as a KEM (key encapsulation mechanism), then derives
an AES-256-GCM key from the resulting shared secret. The actual API key,
password, or other secret is encrypted with AES-GCM.

Backend preference:
1. Open Quantum Safe ``liboqs-python`` (``oqs``)
2. ``cryptography``'s standardized ML-KEM-768 implementation

The private ML-KEM key is stored locally for this hackathon demo. In a real
production deployment, protect it with an HSM/KMS/TPM or equivalent key store.
"""

from __future__ import annotations

import base64
import hashlib
import importlib
import importlib.util
import json
import logging
import os
import secrets as py_secrets
import threading
import uuid
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Protocol

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

LOGGER = logging.getLogger(__name__)

ALGORITHM = "ML-KEM-768"
FORMAT_VERSION = 1
PUBLIC_KEY_FILE = "vault_public.pem"
PRIVATE_KEY_FILE = "vault_private.pem"
KEY_META_FILE = "key_meta.json"
SECRETS_FILE = "secrets.json"


class VaultError(Exception):
    """Base class for vault-specific errors."""


class BackendUnavailable(VaultError):
    """Raised when no supported ML-KEM backend can be used."""


class SecretNotFound(VaultError):
    """Raised when a requested secret ID does not exist."""


class VaultDataError(VaultError):
    """Raised when vault files are malformed or inconsistent."""


class KEMBackend(Protocol):
    """Minimal interface needed by the hybrid ML-KEM/AES vault."""

    name: str
    algorithm: str

    def generate_keypair(self) -> tuple[bytes, bytes]:
        """Return ``(public_key_bytes, private_key_bytes)``."""

    def encapsulate(self, public_key: bytes) -> tuple[bytes, bytes]:
        """Return ``(kem_ciphertext, shared_secret)``."""

    def decapsulate(self, private_key: bytes, kem_ciphertext: bytes) -> bytes:
        """Recover the shared secret from a KEM ciphertext."""


@dataclass(frozen=True)
class LibOQSBackend:
    """ML-KEM-768 backend using Open Quantum Safe's liboqs-python."""

    oqs: object
    name: str = "liboqs"
    algorithm: str = ALGORITHM

    @classmethod
    def create(cls) -> "LibOQSBackend":
        # liboqs-python can try to build liboqs at import time. Catch SystemExit
        # as well as ordinary exceptions so AUTO mode can fall back cleanly.
        if importlib.util.find_spec("oqs") is None:
            raise BackendUnavailable("liboqs-python is not installed")
        try:
            oqs = importlib.import_module("oqs")
            enabled = set(oqs.get_enabled_kem_mechanisms())
            if ALGORITHM not in enabled:
                raise BackendUnavailable(f"{ALGORITHM} is not enabled in liboqs")
            return cls(oqs=oqs)
        except SystemExit as exc:  # pragma: no cover - depends on liboqs loader
            raise BackendUnavailable(f"liboqs initialization exited: {exc}") from exc
        except BackendUnavailable:
            raise
        except Exception as exc:  # pragma: no cover - platform-specific loader
            raise BackendUnavailable(f"liboqs initialization failed: {exc}") from exc

    def generate_keypair(self) -> tuple[bytes, bytes]:
        with self.oqs.KeyEncapsulation(self.algorithm) as kem:
            public_key = bytes(kem.generate_keypair())
            private_key = bytes(kem.export_secret_key())
        return public_key, private_key

    def encapsulate(self, public_key: bytes) -> tuple[bytes, bytes]:
        with self.oqs.KeyEncapsulation(self.algorithm) as kem:
            kem_ciphertext, shared_secret = kem.encap_secret(public_key)
        return bytes(kem_ciphertext), bytes(shared_secret)

    def decapsulate(self, private_key: bytes, kem_ciphertext: bytes) -> bytes:
        with self.oqs.KeyEncapsulation(self.algorithm, private_key) as kem:
            shared_secret = kem.decap_secret(kem_ciphertext)
        return bytes(shared_secret)


@dataclass(frozen=True)
class CryptographyMLKEMBackend:
    """ML-KEM-768 backend from modern pyca/cryptography releases."""

    mlkem: object
    name: str = "cryptography-mlkem"
    algorithm: str = ALGORITHM

    @classmethod
    def create(cls) -> "CryptographyMLKEMBackend":
        try:
            mlkem = importlib.import_module(
                "cryptography.hazmat.primitives.asymmetric.mlkem"
            )
            # Generate one ephemeral key as a capability check. Some custom
            # cryptography builds expose the module but not a supporting backend.
            mlkem.MLKEM768PrivateKey.generate()
            return cls(mlkem=mlkem)
        except Exception as exc:
            raise BackendUnavailable(
                "cryptography ML-KEM-768 is unavailable. Install cryptography>=48 "
                "from an official wheel or use liboqs-python."
            ) from exc

    def generate_keypair(self) -> tuple[bytes, bytes]:
        private_key = self.mlkem.MLKEM768PrivateKey.generate()
        public_key = private_key.public_key()
        # cryptography intentionally serializes the 64-byte ML-KEM private seed.
        return public_key.public_bytes_raw(), private_key.private_bytes_raw()

    def encapsulate(self, public_key: bytes) -> tuple[bytes, bytes]:
        key = self.mlkem.MLKEM768PublicKey.from_public_bytes(public_key)
        shared_secret, kem_ciphertext = key.encapsulate()
        return bytes(kem_ciphertext), bytes(shared_secret)

    def decapsulate(self, private_key: bytes, kem_ciphertext: bytes) -> bytes:
        key = self.mlkem.MLKEM768PrivateKey.from_seed_bytes(private_key)
        return bytes(key.decapsulate(kem_ciphertext))


def _b64encode(value: bytes) -> str:
    return base64.b64encode(value).decode("ascii")


def _b64decode(value: str) -> bytes:
    return base64.b64decode(value.encode("ascii"), validate=True)


def _pem_encode(label: str, raw: bytes) -> str:
    payload = base64.b64encode(raw).decode("ascii")
    lines = [payload[index : index + 64] for index in range(0, len(payload), 64)]
    return (
        f"-----BEGIN {label}-----\n"
        + "\n".join(lines)
        + f"\n-----END {label}-----\n"
    )


def _pem_decode(label: str, text: str) -> bytes:
    begin = f"-----BEGIN {label}-----"
    end = f"-----END {label}-----"
    stripped = text.strip()
    if not stripped.startswith(begin) or not stripped.endswith(end):
        raise VaultDataError(f"Invalid PEM armor for {label}")
    body = stripped[len(begin) : -len(end)].strip().replace("\n", "")
    try:
        return base64.b64decode(body.encode("ascii"), validate=True)
    except Exception as exc:
        raise VaultDataError(f"Invalid base64 in {label}") from exc


class Vault:
    """Persistent local vault for post-quantum protected secrets."""

    def __init__(
        self,
        data_dir: str | Path = ".",
        backend_override: KEMBackend | None = None,
    ) -> None:
        self.data_dir = Path(data_dir).resolve()
        self.data_dir.mkdir(parents=True, exist_ok=True)

        self.public_key_path = self.data_dir / PUBLIC_KEY_FILE
        self.private_key_path = self.data_dir / PRIVATE_KEY_FILE
        self.key_meta_path = self.data_dir / KEY_META_FILE
        self.secrets_path = self.data_dir / SECRETS_FILE
        self._lock = threading.RLock()

        self.backend = backend_override or self._select_backend_for_current_vault()
        self._ensure_keypair()
        self._ensure_secrets_file()

    # ------------------------------------------------------------------
    # Backend and key management
    # ------------------------------------------------------------------
    def _select_backend_for_current_vault(self) -> KEMBackend:
        if self.key_meta_path.exists():
            meta = self._read_json(self.key_meta_path)
            backend_name = meta.get("backend")
            algorithm = meta.get("algorithm")
            if algorithm != ALGORITHM:
                raise VaultDataError(
                    f"Vault was created for {algorithm!r}, expected {ALGORITHM!r}"
                )
            return self._create_named_backend(str(backend_name))

        requested = os.getenv("PQS_BACKEND", "auto").strip().lower()
        if requested != "auto":
            return self._create_named_backend(requested)

        errors: list[str] = []
        for backend_name in ("liboqs", "cryptography-mlkem"):
            try:
                backend = self._create_named_backend(backend_name)
                LOGGER.info("Selected ML-KEM backend: %s", backend.name)
                return backend
            except BackendUnavailable as exc:
                errors.append(f"{backend_name}: {exc}")
                LOGGER.warning("ML-KEM backend unavailable (%s): %s", backend_name, exc)

        raise BackendUnavailable(
            "No ML-KEM-768 backend is available. "
            + " | ".join(errors)
            + ". Install the dependencies from requirements.txt."
        )

    @staticmethod
    def _create_named_backend(name: str) -> KEMBackend:
        normalized = name.strip().lower()
        if normalized in {"liboqs", "oqs"}:
            return LibOQSBackend.create()
        if normalized in {"cryptography", "cryptography-mlkem", "mlkem"}:
            return CryptographyMLKEMBackend.create()
        raise BackendUnavailable(
            f"Unknown PQS_BACKEND={name!r}; use auto, liboqs, or cryptography"
        )

    def _ensure_keypair(self) -> None:
        exists = (
            self.public_key_path.exists(),
            self.private_key_path.exists(),
            self.key_meta_path.exists(),
        )
        if all(exists):
            return
        if any(exists):
            raise VaultDataError(
                "Incomplete key material: expected vault_public.pem, "
                "vault_private.pem, and key_meta.json together"
            )

        LOGGER.info("Generating first-run %s key pair with %s", ALGORITHM, self.backend.name)
        public_key, private_key = self.backend.generate_keypair()
        self.public_key_path.write_text(
            _pem_encode(f"{ALGORITHM} PUBLIC KEY", public_key), encoding="ascii"
        )
        self.private_key_path.write_text(
            _pem_encode(f"{ALGORITHM} PRIVATE KEY", private_key), encoding="ascii"
        )
        self._restrict_private_key_permissions()
        self._atomic_write_json(
            self.key_meta_path,
            {
                "version": FORMAT_VERSION,
                "algorithm": ALGORITHM,
                "backend": self.backend.name,
                "created_at": datetime.now(timezone.utc).isoformat(),
            },
        )

    def _restrict_private_key_permissions(self) -> None:
        try:
            os.chmod(self.private_key_path, 0o600)
        except OSError as exc:  # pragma: no cover - platform dependent
            LOGGER.warning("Could not restrict private-key permissions: %s", exc)

    def _load_public_key(self) -> bytes:
        return _pem_decode(
            f"{ALGORITHM} PUBLIC KEY",
            self.public_key_path.read_text(encoding="ascii"),
        )

    def _load_private_key(self) -> bytes:
        return _pem_decode(
            f"{ALGORITHM} PRIVATE KEY",
            self.private_key_path.read_text(encoding="ascii"),
        )

    # ------------------------------------------------------------------
    # Secret storage
    # ------------------------------------------------------------------
    def _ensure_secrets_file(self) -> None:
        if not self.secrets_path.exists():
            self._atomic_write_json(
                self.secrets_path, {"version": FORMAT_VERSION, "secrets": []}
            )

    def encrypt_secret(self, name: str, value: str) -> str:
        """Encrypt and persist a secret, returning a random secret ID."""
        clean_name = name.strip()
        if not clean_name:
            raise ValueError("Secret name must not be empty")
        if not value:
            raise ValueError("Secret value must not be empty")

        secret_id = str(uuid.uuid4())
        public_key = self._load_public_key()
        kem_ciphertext, shared_secret = self.backend.encapsulate(public_key)
        encryption_key = self._derive_aes_key(shared_secret, secret_id)
        nonce = py_secrets.token_bytes(12)
        aad = self._aad(secret_id, clean_name)
        encrypted_value = AESGCM(encryption_key).encrypt(
            nonce, value.encode("utf-8"), aad
        )

        record = {
            "id": secret_id,
            "name": clean_name,
            "algorithm": ALGORITHM,
            "backend": self.backend.name,
            "kem_ciphertext_b64": _b64encode(kem_ciphertext),
            "nonce_b64": _b64encode(nonce),
            "ciphertext_b64": _b64encode(encrypted_value),
            "created_at": datetime.now(timezone.utc).isoformat(),
            "last_rotated": None,
            "rotation_count": 0,
        }

        with self._lock:
            document = self._load_secrets_document()
            document["secrets"].append(record)
            self._atomic_write_json(self.secrets_path, document)

        LOGGER.info("Encrypted secret '%s' as id=%s", clean_name, secret_id)
        return secret_id

    def decrypt_secret(self, secret_id: str) -> dict[str, str]:
        """Decrypt a stored secret by ID and return ``id``, ``name``, ``value``."""
        with self._lock:
            document = self._load_secrets_document()
            record = next(
                (item for item in document["secrets"] if item.get("id") == secret_id),
                None,
            )

        if record is None:
            raise SecretNotFound(f"Secret {secret_id!r} was not found")
        if record.get("algorithm") != ALGORITHM:
            raise VaultDataError("Stored secret uses a different KEM algorithm")
        if record.get("backend") != self.backend.name:
            raise VaultDataError(
                "Stored secret was created with a different ML-KEM backend"
            )

        try:
            kem_ciphertext = _b64decode(record["kem_ciphertext_b64"])
            nonce = _b64decode(record["nonce_b64"])
            encrypted_value = _b64decode(record["ciphertext_b64"])
        except (KeyError, ValueError, TypeError) as exc:
            raise VaultDataError("Stored secret record is malformed") from exc

        private_key = self._load_private_key()
        shared_secret = self.backend.decapsulate(private_key, kem_ciphertext)
        encryption_key = self._derive_aes_key(shared_secret, secret_id)
        aad = self._aad(secret_id, str(record["name"]))

        try:
            plaintext = AESGCM(encryption_key).decrypt(nonce, encrypted_value, aad)
        except Exception as exc:
            raise VaultDataError(
                "Secret authentication/decryption failed; vault data may be corrupted"
            ) from exc

        LOGGER.info("Decrypted secret id=%s for authorized retrieval", secret_id)
        return {
            "id": secret_id,
            "name": str(record["name"]),
            "value": plaintext.decode("utf-8"),
        }

    def rotate_secret(
        self,
        secret_id: str,
        value: str,
        name: str | None = None,
    ) -> dict[str, str | int]:
        """Re-encrypt a secret in place while preserving its ID and history."""
        if not value:
            raise ValueError("Secret value must not be empty")

        with self._lock:
            document = self._load_secrets_document()
            record = next(
                (item for item in document["secrets"] if item.get("id") == secret_id),
                None,
            )
        if record is None:
            raise SecretNotFound(f"Secret {secret_id!r} was not found")

        clean_name = (name if name is not None else str(record["name"])).strip()
        if not clean_name:
            raise ValueError("Secret name must not be empty")

        public_key = self._load_public_key()
        kem_ciphertext, shared_secret = self.backend.encapsulate(public_key)
        encryption_key = self._derive_aes_key(shared_secret, secret_id)
        nonce = py_secrets.token_bytes(12)
        encrypted_value = AESGCM(encryption_key).encrypt(
            nonce,
            value.encode("utf-8"),
            self._aad(secret_id, clean_name),
        )
        rotated_at = datetime.now(timezone.utc).isoformat()

        with self._lock:
            document = self._load_secrets_document()
            current = next(
                (item for item in document["secrets"] if item.get("id") == secret_id),
                None,
            )
            if current is None:
                raise SecretNotFound(f"Secret {secret_id!r} was not found")
            current.update(
                {
                    "name": clean_name,
                    "algorithm": ALGORITHM,
                    "backend": self.backend.name,
                    "kem_ciphertext_b64": _b64encode(kem_ciphertext),
                    "nonce_b64": _b64encode(nonce),
                    "ciphertext_b64": _b64encode(encrypted_value),
                    "last_rotated": rotated_at,
                    "rotation_count": int(current.get("rotation_count", 0)) + 1,
                }
            )
            self._atomic_write_json(self.secrets_path, document)

        LOGGER.info("Rotated secret id=%s", secret_id)
        return {
            "id": secret_id,
            "name": clean_name,
            "last_rotated": rotated_at,
            "rotation_count": int(current["rotation_count"]),
        }

    def revoke_secret(self, secret_id: str) -> dict[str, str]:
        """Permanently remove an encrypted record and return safe metadata."""
        with self._lock:
            document = self._load_secrets_document()
            record = next(
                (item for item in document["secrets"] if item.get("id") == secret_id),
                None,
            )
            if record is None:
                raise SecretNotFound(f"Secret {secret_id!r} was not found")
            document["secrets"] = [
                item for item in document["secrets"] if item.get("id") != secret_id
            ]
            self._atomic_write_json(self.secrets_path, document)
        LOGGER.info("Revoked secret id=%s", secret_id)
        return {"id": secret_id, "name": str(record["name"])}

    def list_secrets(self) -> list[dict[str, object]]:
        """Return metadata only; encrypted values are never included."""
        with self._lock:
            document = self._load_secrets_document()
            return [
                {
                    "id": str(record["id"]),
                    "name": str(record["name"]),
                    "created_at": str(record["created_at"]),
                    "last_rotated": (
                        str(record["last_rotated"])
                        if record.get("last_rotated")
                        else None
                    ),
                    "rotation_count": int(record.get("rotation_count", 0)),
                }
                for record in document["secrets"]
            ]

    def encryption_proof(self, secret_id: str) -> dict[str, object]:
        """Return safe, presentation-friendly evidence for one stored record.

        The proof exposes ciphertext sizes, the stored record schema, and a
        one-way fingerprint. It never returns key material, shared secrets, or
        decrypted values.
        """
        with self._lock:
            document = self._load_secrets_document()
            record = next(
                (item for item in document["secrets"] if item.get("id") == secret_id),
                None,
            )

        if record is None:
            raise SecretNotFound(f"Secret {secret_id!r} was not found")

        try:
            kem_ciphertext = _b64decode(str(record["kem_ciphertext_b64"]))
            nonce = _b64decode(str(record["nonce_b64"]))
            payload_ciphertext = _b64decode(str(record["ciphertext_b64"]))
        except (KeyError, ValueError, TypeError) as exc:
            raise VaultDataError("Stored secret record is malformed") from exc

        fingerprint = hashlib.sha256(
            kem_ciphertext + nonce + payload_ciphertext
        ).hexdigest()
        preview = str(record["ciphertext_b64"])

        return {
            "id": str(record["id"]),
            "name": str(record["name"]),
            "created_at": str(record["created_at"]),
            "algorithm": str(record["algorithm"]),
            "backend": str(record["backend"]),
            "kem_ciphertext_bytes": len(kem_ciphertext),
            "payload_ciphertext_bytes": len(payload_ciphertext),
            "nonce_bytes": len(nonce),
            "ciphertext_sha256": fingerprint,
            "ciphertext_preview": preview[:48],
            "stored_fields": sorted(str(key) for key in record.keys()),
            "plaintext_field_present": "value" in record,
        }

    def status(self) -> dict[str, str | int]:
        """Return presentation-friendly, non-secret vault status."""
        return {
            "algorithm": ALGORITHM,
            "backend": self.backend.name,
            "secret_count": len(self.list_secrets()),
        }

    @staticmethod
    def _derive_aes_key(shared_secret: bytes, secret_id: str) -> bytes:
        salt = hashlib.sha256(secret_id.encode("utf-8")).digest()
        return HKDF(
            algorithm=hashes.SHA256(),
            length=32,
            salt=salt,
            info=b"post-quantum-secret-protection:v1:aes-256-gcm",
        ).derive(shared_secret)

    @staticmethod
    def _aad(secret_id: str, name: str) -> bytes:
        return f"pqs-vault:v1:{secret_id}:{name}".encode("utf-8")

    def _load_secrets_document(self) -> dict:
        document = self._read_json(self.secrets_path)
        if document.get("version") != FORMAT_VERSION:
            raise VaultDataError("Unsupported secrets.json version")
        if not isinstance(document.get("secrets"), list):
            raise VaultDataError("secrets.json must contain a 'secrets' list")
        return document

    @staticmethod
    def _read_json(path: Path) -> dict:
        try:
            data = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError) as exc:
            raise VaultDataError(f"Could not read {path.name}: {exc}") from exc
        if not isinstance(data, dict):
            raise VaultDataError(f"{path.name} must contain a JSON object")
        return data

    @staticmethod
    def _atomic_write_json(path: Path, document: dict) -> None:
        temporary = path.with_suffix(path.suffix + ".tmp")
        temporary.write_text(
            json.dumps(document, indent=2, sort_keys=True) + "\n", encoding="utf-8"
        )
        os.replace(temporary, path)


if __name__ == "__main__":
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s | %(levelname)s | %(name)s | %(message)s",
    )
    vault = Vault()
    print(json.dumps(vault.status(), indent=2))
