from fastapi import APIRouter, Depends
from sqlalchemy.orm import Session

from src.database import get_db
from src.schemas.kv import WriteSecretRequest
from src.kv.kv_service import KVService
from src.models.user import User
from typing import Optional
from src.auth.dependencies import require_authenticated_unlocked_user 
from src.core.vault_state import vault_state
from typing import Optional
# Chỉ khai báo router ở đây, không gọi app.include_router
router = APIRouter(prefix="/api/v1/kv", tags=["kv"])

@router.post("/write")
def write_secret(
    request: WriteSecretRequest, 
    db: Session = Depends(get_db),
    current_user: User = Depends(require_authenticated_unlocked_user)
):
    # Bước 1: Dependency require_authenticated_unlocked_user đã chạy ngầm và đảm bảo:
    # - Vault đã được mở khóa (không bị VAULT_LOCKED).
    # - Token hợp lệ, chưa hết hạn (không bị UNAUTHENTICATED).
    
    # Bước 2: Lấy khóa DEK từ bộ nhớ RAM
    dek = vault_state.get_dek()
    
    # Bước 3: Đưa toàn bộ dữ liệu vào Service để tiến hành mã hóa AES-GCM và lưu SQLite
    result = KVService.write_secret(
        db=db, 
        path=request.path, 
        data=request.data, 
        user_email=current_user.email, 
        dek=dek
    )
    
    return result

@router.get("/read")
def read_secret(
    path: str,
    version: Optional[int] = None,  # Thêm dòng này để web hiện ra ô nhập
    db: Session = Depends(get_db),
    current_user: User = Depends(require_authenticated_unlocked_user)
):
    dek = vault_state.get_dek()
    return KVService.read_secret(
        db=db, 
        path=path, 
        user_email=current_user.email, 
        dek=dek, 
        version=version # Truyền tiếp nó xuống đây
    )


@router.delete("/delete")
def delete_secret(
    path: str,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_authenticated_unlocked_user)
):
    dek = vault_state.get_dek()
    return KVService.delete_secret(db=db, path=path, user_email=current_user.email)