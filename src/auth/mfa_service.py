from __future__ import annotations

import base64
import binascii
import hashlib
import hmac
import json
import os
import secrets
import time
from datetime import datetime, timedelta, timezone
from typing import Any

import pyotp
from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from sqlalchemy.orm import Session

from src.core.vault_state import vault_state
from src.exceptions import MiniVaultError
from src.models.mfa_setup_challenge import MFASetupChallenge
from src.models.user import User


class MFAService:
    _DEFAULT_SIGNING_KEY = secrets.token_bytes(32)
    def __init__(self, db: Session) -> None:
        self.db = db

    def setup_mfa(self, user: User) -> dict[str, Any]:
        if user.mfa_enabled:
            raise MiniVaultError(409, "MFA_ALREADY_ENABLED", "MFA is already enabled.")

        dek = vault_state.get_dek()
        if dek is None:
            raise MiniVaultError(423, "VAULT_LOCKED", "Vault is locked.")

        secret = pyotp.random_base32()
        provisioning_uri = pyotp.TOTP(secret, digits=6, interval=30).provisioning_uri(name=user.email, issuer_name="Mini Vault")
        encrypted_secret = self._encrypt_secret(secret, dek)

        challenge = self.db.query(MFASetupChallenge).filter(MFASetupChallenge.user_id == user.id).first()
        if challenge is None:
            challenge = MFASetupChallenge(user_id=user.id)
            self.db.add(challenge)
        challenge.encrypted_secret_b64 = encrypted_secret
        challenge.expires_at = datetime.now(timezone.utc) + timedelta(minutes=10)
        challenge.created_at = datetime.now(timezone.utc)
        self.db.commit()

        return {
            "provisioning_uri": provisioning_uri,
            "manual_entry_secret": secret,
            "expires_in": 600,
        }

    def confirm_mfa(self, user: User, otp_code: str) -> dict[str, Any]:
        dek = vault_state.get_dek()
        if dek is None:
            raise MiniVaultError(423, "VAULT_LOCKED", "Vault is locked.")

        challenge = self.db.query(MFASetupChallenge).filter(MFASetupChallenge.user_id == user.id).order_by(MFASetupChallenge.created_at.desc()).first()
        if challenge is None:
            raise MiniVaultError(404, "MFA_SETUP_NOT_STARTED", "MFA setup has not been started.")

        expires_at = challenge.expires_at
        if expires_at.tzinfo is None:
            expires_at = expires_at.replace(tzinfo=timezone.utc)
        if expires_at <= datetime.now(timezone.utc):
            self.db.delete(challenge)
            self.db.commit()
            raise MiniVaultError(410, "MFA_SETUP_EXPIRED", "MFA setup challenge has expired.")

        secret = self._decrypt_secret(challenge.encrypted_secret_b64, dek)
        current_timecode = self._verify_totp(secret, otp_code, user)

        user.mfa_enabled = True
        user.mfa_secret_encrypted_b64 = challenge.encrypted_secret_b64
        self.db.delete(challenge)
        self.db.commit()
        return {"message": "MFA enabled successfully"}

    def create_login_challenge(self, user: User) -> str:
        now = int(time.time())
        payload = {
            "sub": str(user.id),
            "purpose": "mfa_login",
            "exp": now + 300,
            "jti": secrets.token_urlsafe(16),
        }
        payload_json = json.dumps(payload, separators=(",", ":"), sort_keys=True)
        encoded_payload = self._b64url_encode(payload_json.encode("utf-8"))
        signature = hmac.new(self._get_signing_key(), encoded_payload.encode("ascii"), hashlib.sha256).hexdigest()
        return f"mfa.{encoded_payload}.{signature}"

    def verify_login_challenge(self, token: str) -> int:
        parts = token.split(".")
        if len(parts) != 3 or parts[0] != "mfa":
            raise MiniVaultError(401, "INVALID_MFA_CHALLENGE", "Invalid MFA challenge token.")

        encoded_payload = parts[1]
        signature = parts[2]
        expected_signature = hmac.new(self._get_signing_key(), encoded_payload.encode("ascii"), hashlib.sha256).hexdigest()
        if not hmac.compare_digest(signature, expected_signature):
            raise MiniVaultError(401, "INVALID_MFA_CHALLENGE", "Invalid MFA challenge token.")

        try:
            payload_bytes = base64.urlsafe_b64decode(encoded_payload + "=" * (-len(encoded_payload) % 4))
            payload = json.loads(payload_bytes.decode("utf-8"))
        except (ValueError, json.JSONDecodeError):
            raise MiniVaultError(401, "INVALID_MFA_CHALLENGE", "Invalid MFA challenge token.")

        if payload.get("purpose") != "mfa_login":
            raise MiniVaultError(401, "INVALID_MFA_CHALLENGE", "Invalid MFA challenge token.")

        exp = int(payload.get("exp", 0))
        if exp <= int(time.time()):
            raise MiniVaultError(401, "MFA_CHALLENGE_EXPIRED", "MFA challenge token has expired.")

        return int(payload.get("sub", 0))

    def verify_mfa_login(self, user: User, otp_code: str, challenge_token: str) -> dict[str, Any]:
        dek = vault_state.get_dek()
        if dek is None:
            raise MiniVaultError(423, "VAULT_LOCKED", "Vault is locked.")

        if not user.mfa_enabled:
            raise MiniVaultError(401, "INVALID_MFA_CHALLENGE", "MFA is not enabled for this user.")

        self.verify_login_challenge(challenge_token)
        secret = self._decrypt_secret(user.mfa_secret_encrypted_b64, dek)
        current_timecode = self._verify_totp(secret, otp_code, user)

        user.last_totp_timecode = current_timecode
        self.db.commit()
        return {"message": "MFA verified successfully"}

    def _encrypt_secret(self, secret: str, dek: bytes) -> str:
        nonce = secrets.token_bytes(12)
        aesgcm = AESGCM(dek)
        ciphertext = aesgcm.encrypt(nonce, secret.encode("utf-8"), b"mini-vault:user-mfa:v1")
        return base64.b64encode(nonce + ciphertext).decode("ascii")

    def _decrypt_secret(self, payload: str | None, dek: bytes) -> str:
        if not payload:
            raise MiniVaultError(400, "MFA_DATA_CORRUPTED", "MFA data is missing.")
        try:
            decoded = base64.b64decode(payload, validate=True)
        except (ValueError, binascii.Error):
            raise MiniVaultError(400, "MFA_DATA_CORRUPTED", "MFA data is invalid.")

        if len(decoded) < 12 + 16:
            raise MiniVaultError(400, "MFA_DATA_CORRUPTED", "MFA data is invalid.")

        nonce = decoded[:12]
        ciphertext = decoded[12:]
        try:
            plaintext = AESGCM(dek).decrypt(nonce, ciphertext, b"mini-vault:user-mfa:v1")
        except InvalidTag:
            raise MiniVaultError(400, "MFA_DATA_CORRUPTED", "MFA data could not be decrypted.")
        except ValueError:
            raise MiniVaultError(400, "MFA_DATA_CORRUPTED", "MFA data could not be decrypted.")
        return plaintext.decode("utf-8")

    def _verify_totp(self, secret: str, otp_code: str, user: User) -> int:
        if not otp_code or not otp_code.isdigit() or len(otp_code) != 6:
            raise MiniVaultError(401, "INVALID_OTP", "Invalid OTP code.")

        totp = pyotp.TOTP(secret, digits=6, interval=30)
        now = datetime.now(timezone.utc)
        current_timecode = totp.timecode(now)
        if user.last_totp_timecode is not None and current_timecode == user.last_totp_timecode:
            raise MiniVaultError(409, "OTP_REPLAYED", "OTP has already been used.")

        if not totp.verify(otp_code, valid_window=1, for_time=now):
            raise MiniVaultError(401, "INVALID_OTP", "Invalid OTP code.")

        return current_timecode

    def _get_signing_key(self) -> bytes:
        configured_key = os.getenv("MINI_VAULT_MFA_SIGNING_KEY")
        if configured_key:
            return configured_key.encode("utf-8")
        return self._DEFAULT_SIGNING_KEY

    def _b64url_encode(self, value: bytes) -> str:
        return base64.urlsafe_b64encode(value).decode("ascii").rstrip("=")
