from __future__ import annotations

from pydantic import BaseModel, Field


class CreateKeyRequest(BaseModel):
    key_name: str = Field(..., min_length=1)


class KeyResponse(BaseModel):
    key_name: str
    key_usage: str


class ListKeysResponse(BaseModel):
    keys: list[KeyResponse]


class EncryptRequest(BaseModel):
    plaintext: str = Field(..., min_length=1)


class EncryptResponse(BaseModel):
    ciphertext: str


class DecryptRequest(BaseModel):
    ciphertext: str = Field(..., min_length=1)


class DecryptResponse(BaseModel):
    plaintext: str


class CreateSigningKeyRequest(BaseModel):
    key_name: str = Field(..., min_length=1)
    signing_algorithm: str = Field("ED25519", min_length=1)


class SignRequest(BaseModel):
    message: str = Field(..., min_length=1)
    message_type: str = Field("RAW", min_length=1)


class SignResponse(BaseModel):
    signature: str
    key_name: str
    signing_algorithm: str


class VerifyRequest(BaseModel):
    message: str = Field(..., min_length=1)
    message_type: str = Field("RAW", min_length=1)
    signature: str = Field(..., min_length=1)
    signing_algorithm: str = Field("ED25519", min_length=1)


class VerifyResponse(BaseModel):
    key_name: str
    signature_valid: bool
    signing_algorithm: str
