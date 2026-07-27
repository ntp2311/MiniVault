from __future__ import annotations

from pydantic import BaseModel, Field


class RegisterRequest(BaseModel):
    email: str = Field(..., min_length=1)
    passphrase: str = Field(..., min_length=1)
    confirm_passphrase: str = Field(..., min_length=1)


class LoginRequest(BaseModel):
    email: str = Field(..., min_length=1)
    passphrase: str = Field(..., min_length=1)


class AuthResponse(BaseModel):
    access_token: str | None = None
    token_type: str = "bearer"
    expires_in: int | None = None
    mfa_required: bool | None = None
    mfa_challenge_token: str | None = None


class MFASetupResponse(BaseModel):
    provisioning_uri: str
    manual_entry_secret: str
    expires_in: int


class MFAConfirmRequest(BaseModel):
    otp_code: str = Field(..., min_length=1)


class LoginMFARequest(BaseModel):
    mfa_challenge_token: str = Field(..., min_length=1)
    otp_code: str = Field(..., min_length=1)


class MeResponse(BaseModel):
    id: int
    email: str
