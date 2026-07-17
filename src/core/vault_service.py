from __future__ import annotations

import base64
import json
import secrets
from datetime import datetime, timezone
from typing import Any

from sqlalchemy.orm import Session

from src.auth.password_service import validate_password_strength
from src.core.crypto import decrypt_bytes, encrypt_bytes
from src.core.kdf import derive_key
from src.core.vault_state import vault_state
from src.exceptions import MiniVaultError
from src.models.vault_metadata import VaultMetadata


class VaultService:
    def __init__(self, db: Session) -> None:
        self.db = db

    def is_initialized(self) -> bool:
        return self.db.query(VaultMetadata).count() > 0

    def initialize(self, master_passphrase: str, confirm_master_passphrase: str | None = None) -> dict[str, Any]:
        if self.is_initialized():
            raise MiniVaultError(409, "VAULT_ALREADY_INITIALIZED", "Vault has already been initialized.")
        if confirm_master_passphrase is not None and master_passphrase != confirm_master_passphrase:
            raise MiniVaultError(400, "PASSPHRASE_CONFIRMATION_MISMATCH", "Master passphrase confirmation mismatch.")
        if not validate_password_strength(master_passphrase, min_length=12):
            raise MiniVaultError(400, "WEAK_MASTER_PASSPHRASE", "Master passphrase does not satisfy the security policy.")

        salt = secrets.token_bytes(16)
        parameters = {
            "time_cost": 3,
            "memory_cost": 65536,
            "parallelism": 2,
            "hash_len": 32,
        }
        derived_key = derive_key(master_passphrase, salt, parameters)
        dek = secrets.token_bytes(32)
        nonce = secrets.token_bytes(12)
        encrypted_dek = encrypt_bytes(dek, derived_key, nonce)

        vault_entry = VaultMetadata(
            initialized=True,
            kdf_algorithm="argon2id",
            kdf_salt_b64=base64.b64encode(salt).decode("ascii"),
            kdf_parameters_json=json.dumps(parameters),
            nonce_b64=base64.b64encode(nonce).decode("ascii"),
            encrypted_dek_b64=base64.b64encode(encrypted_dek).decode("ascii"),
        )
        self.db.add(vault_entry)
        self.db.commit()
        vault_state.clear_dek()
        return {"message": "Vault initialized successfully", "initialized": True, "status": "locked"}

    def unlock(self, master_passphrase: str) -> dict[str, Any]:
        if not self.is_initialized():
            raise MiniVaultError(404, "VAULT_NOT_INITIALIZED", "Vault has not been initialized.")

        metadata = self.db.query(VaultMetadata).order_by(VaultMetadata.id.desc()).first()
        if metadata is None:
            raise MiniVaultError(404, "VAULT_NOT_INITIALIZED", "Vault has not been initialized.")

        try:
            salt = base64.b64decode(metadata.kdf_salt_b64)
            nonce = base64.b64decode(metadata.nonce_b64)
            encrypted_dek = base64.b64decode(metadata.encrypted_dek_b64)
            parameters = json.loads(metadata.kdf_parameters_json)
            derived_key = derive_key(master_passphrase, salt, parameters)
            dek = decrypt_bytes(encrypted_dek, derived_key, nonce)
        except Exception:
            vault_state.clear_dek()
            raise MiniVaultError(401, "UNLOCK_FAILED", "Unable to unlock vault.")

        vault_state.set_dek(dek)
        return {"message": "Vault unlocked successfully", "initialized": True, "status": "unlocked"}

    def lock(self) -> dict[str, Any]:
        vault_state.clear_dek()
        return {"message": "Vault locked successfully", "initialized": True, "status": "locked"}

    def status(self) -> dict[str, Any]:
        if not self.is_initialized():
            return {"initialized": False, "status": "not_initialized"}
        return {"initialized": True, "status": "unlocked" if vault_state.get_dek() is not None else "locked"}
