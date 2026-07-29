from __future__ import annotations

from typing import Annotated

from fastapi import APIRouter, Depends, Response
from sqlalchemy.orm import Session

from src.auth.dependencies import get_current_user, get_db
from src.exceptions import MiniVaultError
from src.models.user import User
from src.schemas.transit import (
    CreateKeyRequest,
    CreateSigningKeyRequest,
    DecryptRequest,
    DecryptResponse,
    EncryptRequest,
    EncryptResponse,
    GrantRequest,
    GrantResponse,
    KeyResponse,
    ListGrantsResponse,
    ListKeysResponse,
    SignRequest,
    SignResponse,
    VerifyRequest,
    VerifyResponse,
)
from src.transit.transit_service import TransitService

router = APIRouter(prefix="/api/v1/transit", tags=["transit"])


@router.post("/keys", response_model=KeyResponse, status_code=201)
def create_key(
    payload: CreateKeyRequest,
    current_user: Annotated[User, Depends(get_current_user)],
    db: Annotated[Session, Depends(get_db)],
) -> KeyResponse:
    try:
        transit_service = TransitService(db)
        key = transit_service.create_key(payload.key_name, current_user.email)
        return KeyResponse(key_name=key.key_name, key_usage=key.key_usage)
    except MiniVaultError as exc:
        raise exc


@router.get("/keys", response_model=ListKeysResponse)
def list_keys(
    current_user: Annotated[User, Depends(get_current_user)],
    db: Annotated[Session, Depends(get_db)],
) -> ListKeysResponse:
    try:
        transit_service = TransitService(db)
        keys = transit_service.list_keys(current_user.email)
        return ListKeysResponse(
            keys=[KeyResponse(key_name=k.key_name, key_usage=k.key_usage) for k in keys]
        )
    except MiniVaultError as exc:
        raise exc


@router.delete("/keys/{key_name}", status_code=204)
def revoke_key(
    key_name: str,
    current_user: Annotated[User, Depends(get_current_user)],
    db: Annotated[Session, Depends(get_db)],
) -> Response:
    try:
        transit_service = TransitService(db)
        transit_service.revoke_key(key_name, current_user.email)
        return Response(status_code=204)
    except MiniVaultError as exc:
        raise exc


@router.post("/keys/{key_name}/grants", response_model=GrantResponse, status_code=201)
@router.post("/keys/{key_name}/grant", response_model=GrantResponse, status_code=201)
def create_grant(
    key_name: str,
    payload: GrantRequest,
    current_user: Annotated[User, Depends(get_current_user)],
    db: Annotated[Session, Depends(get_db)],
) -> GrantResponse:
    try:
        transit_service = TransitService(db)
        grant = transit_service.create_grant(
            key_name=key_name,
            owner_email=current_user.email,
            grantee_email=payload.grantee_email,
            permission=payload.permission,
        )
        return GrantResponse(
            key_name=key_name,
            grantee_email=grant.grantee_email,
            permission=grant.permission,
        )
    except MiniVaultError as exc:
        raise exc


@router.get("/keys/{key_name}/grants", response_model=ListGrantsResponse)
@router.get("/keys/{key_name}/grant", response_model=ListGrantsResponse)
def list_grants(
    key_name: str,
    current_user: Annotated[User, Depends(get_current_user)],
    db: Annotated[Session, Depends(get_db)],
) -> ListGrantsResponse:
    try:
        transit_service = TransitService(db)
        grants = transit_service.list_grants(key_name=key_name, owner_email=current_user.email)
        return ListGrantsResponse(
            grants=[
                GrantResponse(
                    key_name=key_name,
                    grantee_email=grant.grantee_email,
                    permission=grant.permission,
                )
                for grant in grants
            ]
        )
    except MiniVaultError as exc:
        raise exc


@router.delete("/keys/{key_name}/grants/{grantee_email}/{permission}", status_code=204)
@router.delete("/keys/{key_name}/grant/{grantee_email}/{permission}", status_code=204)
def revoke_grant(
    key_name: str,
    grantee_email: str,
    permission: str,
    current_user: Annotated[User, Depends(get_current_user)],
    db: Annotated[Session, Depends(get_db)],
) -> Response:
    try:
        transit_service = TransitService(db)
        transit_service.revoke_grant(
            key_name=key_name,
            owner_email=current_user.email,
            grantee_email=grantee_email,
            permission=permission,
        )
        return Response(status_code=204)
    except MiniVaultError as exc:
        raise exc


@router.post("/encrypt/{key_name}", response_model=EncryptResponse)
def encrypt(
    key_name: str,
    payload: EncryptRequest,
    current_user: Annotated[User, Depends(get_current_user)],
    db: Annotated[Session, Depends(get_db)],
) -> EncryptResponse:
    try:
        transit_service = TransitService(db)
        ciphertext = transit_service.encrypt(
            key_name, current_user.email, payload.plaintext
        )
        return EncryptResponse(ciphertext=ciphertext)
    except MiniVaultError as exc:
        raise exc


@router.post("/decrypt", response_model=DecryptResponse)
def decrypt(
    payload: DecryptRequest,
    current_user: Annotated[User, Depends(get_current_user)],
    db: Annotated[Session, Depends(get_db)],
) -> DecryptResponse:
    try:
        transit_service = TransitService(db)
        plaintext = transit_service.decrypt(current_user.email, payload.ciphertext)
        return DecryptResponse(plaintext=plaintext)
    except MiniVaultError as exc:
        raise exc


@router.post("/keys/sign", response_model=KeyResponse, status_code=201)
def create_signing_key(
    payload: CreateSigningKeyRequest,
    current_user: Annotated[User, Depends(get_current_user)],
    db: Annotated[Session, Depends(get_db)],
) -> KeyResponse:
    try:
        transit_service = TransitService(db)
        key = transit_service.create_signing_key(
            payload.key_name, current_user.email, payload.signing_algorithm
        )
        return KeyResponse(key_name=key.key_name, key_usage=key.key_usage)
    except MiniVaultError as exc:
        raise exc


@router.post("/sign/{key_name}", response_model=SignResponse)
def sign(
    key_name: str,
    payload: SignRequest,
    current_user: Annotated[User, Depends(get_current_user)],
    db: Annotated[Session, Depends(get_db)],
) -> SignResponse:
    try:
        transit_service = TransitService(db)

        result = transit_service.sign(
            key_name, current_user.email, payload.message, payload.message_type
        )

        return SignResponse(**result)

    except MiniVaultError as exc:
        raise exc


@router.post("/verify/{key_name}", response_model=VerifyResponse)
def verify(
    key_name: str,
    payload: VerifyRequest,
    current_user: Annotated[User, Depends(get_current_user)],
    db: Annotated[Session, Depends(get_db)],
) -> VerifyResponse:
    try:
        transit_service = TransitService(db)
        result = transit_service.verify(
            key_name=key_name,
            owner_email=current_user.email,
            message_b64=payload.message,
            message_type=payload.message_type,
            signature_b64=payload.signature,
            passed_algorithm=payload.signing_algorithm,
        )
        return VerifyResponse(**result)
    except MiniVaultError as exc:
        raise exc
