from __future__ import annotations

import base64
import secrets

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ed25519, padding, rsa, utils
from cryptography.hazmat.primitives.serialization import (
    Encoding,
    NoEncryption,
    PrivateFormat,
    PublicFormat,
    load_pem_private_key,
    load_pem_public_key,
)
from sqlalchemy.orm import Session

from src.core.crypto import decrypt_bytes, encrypt_bytes
from src.core.vault_state import vault_state
from src.exceptions import MiniVaultError
from src.logger import logger
from src.models.transit_key import TransitKey
from src.models.transit_key_grant import TransitKeyGrant


class TransitService:
    def __init__(self, db: Session):
        self.db = db

    def _get_transit_key_for_access(
        self, key_name: str, user_email: str, required_permission: str | None = None
    ) -> TransitKey:
        transit_key = self.db.query(TransitKey).filter_by(key_name=key_name).first()
        if not transit_key:
            logger.warning(f"Denied access attempt for key '{key_name}' from user '{user_email}'")
            raise MiniVaultError(403, "PERMISSION_DENIED", "Permission denied.")

        if transit_key.owner_email == user_email:
            return transit_key

        if required_permission is None:
            logger.warning(f"Denied access attempt for key '{key_name}' from user '{user_email}'")
            raise MiniVaultError(403, "PERMISSION_DENIED", "Permission denied.")

        has_grant = (
            self.db.query(TransitKeyGrant)
            .filter_by(
                transit_key_id=transit_key.id,
                grantee_email=user_email,
                permission=required_permission,
            )
            .first()
        )
        if has_grant:
            return transit_key

        logger.warning(f"Denied access attempt for key '{key_name}' from user '{user_email}'")
        raise MiniVaultError(403, "PERMISSION_DENIED", "Permission denied.")

    def create_key(self, key_name: str, owner_email: str) -> TransitKey:
        dek = vault_state.get_dek()
        if dek is None:
            raise MiniVaultError(400, "VAULT_LOCKED", "Vault is locked.")

        existing_key = (
            self.db.query(TransitKey)
            .filter_by(key_name=key_name, owner_email=owner_email)
            .first()
        )
        if existing_key:
            raise MiniVaultError(
                409, "KEY_ALREADY_EXISTS", f"Key '{key_name}' already exists."
            )

        new_key_material = secrets.token_bytes(32)
        nonce = secrets.token_bytes(12)
        encrypted_key_material = encrypt_bytes(new_key_material, dek, nonce)

        transit_key = TransitKey(
            key_name=key_name,
            owner_email=owner_email,
            key_usage="ENCRYPT_DECRYPT",
            encrypted_key_material=base64.b64encode(
                nonce + encrypted_key_material
            ).decode("ascii"),
        )
        self.db.add(transit_key)
        self.db.commit()
        return transit_key

    def list_keys(self, owner_email: str) -> list[TransitKey]:
        dek = vault_state.get_dek()
        if dek is None:
            raise MiniVaultError(400, "VAULT_LOCKED", "Vault is locked.")
        return self.db.query(TransitKey).filter_by(owner_email=owner_email).all()

    def revoke_key(self, key_name: str, owner_email: str) -> None:
        dek = vault_state.get_dek()
        if dek is None:
            raise MiniVaultError(400, "VAULT_LOCKED", "Vault is locked.")
        transit_key = self._get_transit_key_for_access(key_name, owner_email)
        self.db.delete(transit_key)
        self.db.commit()

    def create_grant(
        self, key_name: str, owner_email: str, grantee_email: str, permission: str
    ) -> TransitKeyGrant:
        transit_key = self._get_transit_key_for_access(key_name, owner_email)
        existing_grant = (
            self.db.query(TransitKeyGrant)
            .filter_by(
                transit_key_id=transit_key.id,
                grantee_email=grantee_email,
                permission=permission,
            )
            .first()
        )
        if existing_grant:
            return existing_grant

        grant = TransitKeyGrant(
            transit_key_id=transit_key.id,
            grantee_email=grantee_email,
            permission=permission,
        )
        self.db.add(grant)
        self.db.commit()
        self.db.refresh(grant)
        return grant

    def list_grants(self, key_name: str, owner_email: str) -> list[TransitKeyGrant]:
        transit_key = self._get_transit_key_for_access(key_name, owner_email)
        return (
            self.db.query(TransitKeyGrant)
            .filter_by(transit_key_id=transit_key.id)
            .order_by(TransitKeyGrant.created_at.asc())
            .all()
        )

    def revoke_grant(
        self, key_name: str, owner_email: str, grantee_email: str, permission: str
    ) -> None:
        transit_key = self._get_transit_key_for_access(key_name, owner_email)
        grant = (
            self.db.query(TransitKeyGrant)
            .filter_by(
                transit_key_id=transit_key.id,
                grantee_email=grantee_email,
                permission=permission,
            )
            .first()
        )
        if grant is not None:
            self.db.delete(grant)
            self.db.commit()

    def encrypt(self, key_name: str, owner_email: str, plaintext_b64: str) -> str:
        dek = vault_state.get_dek()
        if dek is None:
            raise MiniVaultError(400, "VAULT_LOCKED", "Vault is locked.")

        transit_key = self.db.query(TransitKey).filter_by(key_name=key_name, owner_email=owner_email).first()
        if not transit_key:
            logger.warning(
                f"Denied access attempt for key '{key_name}' from user '{owner_email}'"
            )
            raise MiniVaultError(403, "PERMISSION_DENIED", "Permission denied.")

        if transit_key.key_usage != "ENCRYPT_DECRYPT":
            raise MiniVaultError(
                400, "INVALID_KEY_USAGE", "This key cannot be used for encryption."
            )

        try:
            encrypted_key_material_with_nonce = base64.b64decode(
                transit_key.encrypted_key_material
            )
            key_nonce = encrypted_key_material_with_nonce[:12]
            encrypted_key_material = encrypted_key_material_with_nonce[12:]
            key_material = decrypt_bytes(encrypted_key_material, dek, key_nonce)
        except Exception:
            raise MiniVaultError(
                500, "ENCRYPTION_ERROR", "Could not decrypt key material."
            )

        try:
            plaintext = base64.b64decode(plaintext_b64)
            data_nonce = secrets.token_bytes(12)
            encrypted_data = encrypt_bytes(plaintext, key_material, data_nonce)
            ciphertext = f"vault:{key_name}:{base64.b64encode(data_nonce + encrypted_data).decode('ascii')}"
            return ciphertext
        except Exception:
            raise MiniVaultError(500, "ENCRYPTION_ERROR", "Could not encrypt data.")

    def decrypt(self, owner_email: str, ciphertext: str) -> str:
        dek = vault_state.get_dek()
        if dek is None:
            raise MiniVaultError(400, "VAULT_LOCKED", "Vault is locked.")

        try:
            parts = ciphertext.split(":", 2)
            if len(parts) != 3 or parts[0] != "vault":
                raise MiniVaultError(
                    400, "INVALID_CIPHERTEXT_FORMAT", "Invalid ciphertext format."
                )
            key_name = parts[1]
            encrypted_data_with_nonce_b64 = parts[2]
        except Exception:
            raise MiniVaultError(
                400, "INVALID_CIPHERTEXT_FORMAT", "Invalid ciphertext format."
            )

        transit_key = self.db.query(TransitKey).filter_by(key_name=key_name, owner_email=owner_email).first()
        if not transit_key:
            logger.warning(
                f"Denied access attempt for key '{key_name}' from user '{owner_email}'"
            )
            raise MiniVaultError(403, "PERMISSION_DENIED", "Permission denied.")

        if transit_key.key_usage != "ENCRYPT_DECRYPT":
            raise MiniVaultError(
                400, "INVALID_KEY_USAGE", "This key cannot be used for decryption."
            )

        try:
            encrypted_key_material_with_nonce = base64.b64decode(
                transit_key.encrypted_key_material
            )
            key_nonce = encrypted_key_material_with_nonce[:12]
            encrypted_key_material = encrypted_key_material_with_nonce[12:]
            key_material = decrypt_bytes(encrypted_key_material, dek, key_nonce)
        except Exception:
            raise MiniVaultError(
                500, "DECRYPTION_ERROR", "Could not decrypt key material."
            )

        try:
            encrypted_data_with_nonce = base64.b64decode(encrypted_data_with_nonce_b64)
            data_nonce = encrypted_data_with_nonce[:12]
            encrypted_data = encrypted_data_with_nonce[12:]
            plaintext = decrypt_bytes(encrypted_data, key_material, data_nonce)
            return base64.b64encode(plaintext).decode("ascii")
        except Exception:
            raise MiniVaultError(
                400,
                "DECRYPTION_FAILED",
                "Could not decrypt data. Ciphertext may be tampered.",
            )

    def create_signing_key(
        self, key_name: str, owner_email: str, signing_algorithm: str
    ) -> TransitKey:
        dek = vault_state.get_dek()
        if dek is None:
            raise MiniVaultError(400, "VAULT_LOCKED", "Vault is locked.")

        existing_key = (
            self.db.query(TransitKey)
            .filter_by(key_name=key_name, owner_email=owner_email)
            .first()
        )
        if existing_key:
            raise MiniVaultError(
                409, "KEY_ALREADY_EXISTS", f"Key '{key_name}' already exists."
            )

        if signing_algorithm == "ED25519":
            private_key = ed25519.Ed25519PrivateKey.generate()
        elif signing_algorithm == "RSA_2048":
            private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        else:
            raise MiniVaultError(
                400, "UNSUPPORTED_ALGORITHM", "Unsupported signing algorithm."
            )

        private_key_bytes = private_key.private_bytes(
            encoding=Encoding.PEM,
            format=PrivateFormat.PKCS8,
            encryption_algorithm=NoEncryption(),
        )
        public_key_bytes = private_key.public_key().public_bytes(
            encoding=Encoding.PEM, format=PublicFormat.SubjectPublicKeyInfo
        )

        nonce = secrets.token_bytes(12)
        encrypted_private_key = encrypt_bytes(private_key_bytes, dek, nonce)

        transit_key = TransitKey(
            key_name=key_name,
            owner_email=owner_email,
            key_usage="SIGN_VERIFY",
            encrypted_key_material=base64.b64encode(
                nonce + encrypted_private_key
            ).decode("ascii"),
            signing_algorithm=signing_algorithm,
            public_key_b64=base64.b64encode(public_key_bytes).decode("ascii"),
        )
        self.db.add(transit_key)
        self.db.commit()
        return transit_key

    def sign(
        self, key_name: str, owner_email: str, message_b64: str, message_type: str
    ) -> dict:
        dek = vault_state.get_dek()
        if dek is None:
            raise MiniVaultError(400, "VAULT_LOCKED", "Vault is locked.")

        transit_key = self._get_transit_key_for_access(key_name, owner_email)

        if transit_key.key_usage != "SIGN_VERIFY":
            raise MiniVaultError(
                400, "INVALID_KEY_USAGE", "This key cannot be used for signing."
            )

        try:
            encrypted_private_key_with_nonce = base64.b64decode(
                transit_key.encrypted_key_material
            )
            key_nonce = encrypted_private_key_with_nonce[:12]
            encrypted_private_key = encrypted_private_key_with_nonce[12:]
            private_key_bytes = decrypt_bytes(encrypted_private_key, dek, key_nonce)
            private_key = load_pem_private_key(private_key_bytes, password=None)
        except Exception:
            raise MiniVaultError(500, "SIGNING_ERROR", "Could not decrypt private key.")

        try:
            message = base64.b64decode(message_b64)
            if message_type == "DIGEST":
                if len(message) != 32:
                    raise MiniVaultError(
                        400, "INVALID_DIGEST_LENGTH", "Digest length must be 32 bytes."
                    )
                digest = message
            else:  # RAW
                digest = hashes.Hash(hashes.SHA256())
                digest.update(message)
                digest = digest.finalize()

            if transit_key.signing_algorithm == "ED25519":
                if not isinstance(private_key, ed25519.Ed25519PrivateKey):
                    raise MiniVaultError(500, "SIGNING_ERROR", "Key type mismatch.")
                signature = private_key.sign(digest)
            elif transit_key.signing_algorithm == "RSA_2048":
                if not isinstance(private_key, rsa.RSAPrivateKey):
                    raise MiniVaultError(500, "SIGNING_ERROR", "Key type mismatch.")
                signature = private_key.sign(
                    digest, padding.PKCS1v15(), utils.Prehashed(hashes.SHA256())
                )
            else:
                raise MiniVaultError(500, "SIGNING_ERROR", "Unsupported algorithm.")

            signature_b64 = base64.b64encode(signature).decode("ascii")

            return {
                "signature": signature_b64,
                "key_name": key_name,
                "signing_algorithm": transit_key.signing_algorithm,
            }

        except Exception as e:
            raise MiniVaultError(500, "SIGNING_ERROR", f"Could not sign message: {e}")

    def verify(
        self,
        key_name: str,
        owner_email: str,
        message_b64: str,
        message_type: str,
        signature_b64: str,
        passed_algorithm: str,
    ) -> dict:
        dek = vault_state.get_dek()
        if dek is None:
            raise MiniVaultError(400, "VAULT_LOCKED", "Vault is locked.")

        transit_key = self._get_transit_key_for_access(
            key_name,
            owner_email,
            required_permission="VERIFY",
        )

        if transit_key.key_usage != "SIGN_VERIFY" or not transit_key.public_key_b64:
            raise MiniVaultError(
                400, "INVALID_KEY_USAGE", "This key cannot be used for verification."
            )

        if passed_algorithm != transit_key.signing_algorithm:
            raise MiniVaultError(
                400,
                "INVALID_SIGNING_ALGORITHM",
                "The signing algorithm does not match the key configuration.",
            )

        try:
            public_key_bytes = base64.b64decode(transit_key.public_key_b64)
            public_key = load_pem_public_key(public_key_bytes)
        except Exception:
            raise MiniVaultError(
                500, "VERIFICATION_ERROR", "Could not load public key."
            )

        try:
            message = base64.b64decode(message_b64)
            signature = base64.b64decode(signature_b64)

            if message_type == "DIGEST":
                if len(message) != 32:
                    return {
                        "key_name": key_name,
                        "signature_valid": False,
                        "signing_algorithm": transit_key.signing_algorithm,
                    }
                digest = message
            else:  # RAW
                digest = hashes.Hash(hashes.SHA256())
                digest.update(message)
                digest = digest.finalize()

            if transit_key.signing_algorithm == "ED25519":
                if not isinstance(public_key, ed25519.Ed25519PublicKey):
                    raise MiniVaultError(
                        500, "VERIFICATION_ERROR", "Key type mismatch."
                    )
                public_key.verify(signature, digest)
                valid = True
            elif transit_key.signing_algorithm == "RSA_2048":
                if not isinstance(public_key, rsa.RSAPublicKey):
                    raise MiniVaultError(
                        500, "VERIFICATION_ERROR", "Key type mismatch."
                    )
                public_key.verify(
                    signature,
                    digest,
                    padding.PKCS1v15(),
                    utils.Prehashed(hashes.SHA256()),
                )
                valid = True
            else:
                raise MiniVaultError(
                    500, "VERIFICATION_ERROR", "Unsupported algorithm."
                )

        except Exception:
            valid = False

        return {
            "key_name": key_name,
            "signature_valid": valid,
            "signing_algorithm": transit_key.signing_algorithm,
        }
