from __future__ import annotations

from pydantic import BaseModel, Field, ConfigDict


class VaultInitRequest(BaseModel):
    master_passphrase: str = Field(..., min_length=1)
    confirm_master_passphrase: str = Field(..., min_length=1)


class VaultUnlockRequest(BaseModel):
    master_passphrase: str = Field(..., min_length=1)


class VaultStatusResponse(BaseModel):
    initialized: bool
    status: str


class VaultOperationResponse(BaseModel):
    message: str
    initialized: bool
    status: str
