from __future__ import annotations

from typing import Annotated

from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.orm import Session

from src.auth.dependencies import get_db, require_vault_unlocked
from src.core.vault_service import VaultService
from src.exceptions import MiniVaultError, error_response
from src.schemas.vault import VaultInitRequest, VaultOperationResponse, VaultStatusResponse, VaultUnlockRequest

router = APIRouter(prefix="/api/v1/vault", tags=["vault"])


@router.post("/init", response_model=VaultOperationResponse)
def initialize_vault(payload: VaultInitRequest, db: Annotated[Session, Depends(get_db)]) -> VaultOperationResponse:
    try:
        service = VaultService(db)
        result = service.initialize(payload.master_passphrase, payload.confirm_master_passphrase)
        return VaultOperationResponse(**result)
    except MiniVaultError as exc:
        raise exc


@router.post("/unlock", response_model=VaultOperationResponse)
def unlock_vault(payload: VaultUnlockRequest, db: Annotated[Session, Depends(get_db)]) -> VaultOperationResponse:
    try:
        service = VaultService(db)
        result = service.unlock(payload.master_passphrase)
        return VaultOperationResponse(**result)
    except MiniVaultError as exc:
        raise exc


@router.post("/lock", response_model=VaultOperationResponse)
def lock_vault(db: Annotated[Session, Depends(get_db)]) -> VaultOperationResponse:
    try:
        service = VaultService(db)
        result = service.lock()
        return VaultOperationResponse(**result)
    except MiniVaultError as exc:
        raise exc


@router.get("/status", response_model=VaultStatusResponse)
def vault_status(db: Annotated[Session, Depends(get_db)]) -> VaultStatusResponse:
    service = VaultService(db)
    result = service.status()
    return VaultStatusResponse(**result)
