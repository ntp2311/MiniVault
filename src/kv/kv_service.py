import os
import json
import base64
import logging
from sqlalchemy.orm import Session
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.exceptions import InvalidTag

from src.exceptions import MiniVaultError
# Nhớ sửa lại đường dẫn import SecretItem cho đúng với cấu trúc thư mục của bạn
from src.models.kv import SecretItem 

logger = logging.getLogger(__name__)

class KVService:
    @staticmethod
    def _check_ownership(path: str, user_email: str) -> None:
        expected_prefix = f"secret/{user_email}/"
        if not path.startswith(expected_prefix):
            logger.warning(f"Access denied: User {user_email} attempted to access {path}")
            raise MiniVaultError(
                status_code=403,
                code="PERMISSION_DENIED",
                message="Permission denied or path does not exist."
            )

    @staticmethod
    def write_secret(db: Session, path: str, data: dict, user_email: str, dek: bytes):
        KVService._check_ownership(path, user_email)

        plaintext = json.dumps(data).encode('utf-8')
        nonce = os.urandom(12)
        aesgcm = AESGCM(dek)
        encrypted_data = aesgcm.encrypt(nonce, plaintext, None)
        
        ciphertext = encrypted_data[:-16]
        tag = encrypted_data[-16:]

        nonce_b64 = base64.b64encode(nonce).decode('utf-8')
        ciphertext_b64 = base64.b64encode(ciphertext).decode('utf-8')
        tag_b64 = base64.b64encode(tag).decode('utf-8')

        # Xử lý Versioning: Tìm bản ghi có version cao nhất của path này
        latest_record = db.query(SecretItem).filter(SecretItem.path == path).order_by(SecretItem.version.desc()).first()
        new_version = latest_record.version + 1 if latest_record else 1

        # Lưu thành một dòng mới hoàn toàn
        secret_record = SecretItem(
            path=path,
            version=new_version,
            owner_email=user_email,
            nonce_b64=nonce_b64,
            ciphertext_b64=ciphertext_b64,
            tag_b64=tag_b64
        )
        db.add(secret_record)
        db.commit()
        db.refresh(secret_record)
        
        return {
            "version": new_version,
            "created_at": secret_record.created_at.isoformat()
        }

    @staticmethod
    def read_secret(db: Session, path: str, user_email: str, dek: bytes, version: int = None):
        KVService._check_ownership(path, user_email)

        query = db.query(SecretItem).filter(SecretItem.path == path)
        # Nếu có truyền version thì lấy đúng bản đó, nếu không thì lấy bản mới nhất
        if version is not None:
            query = query.filter(SecretItem.version == version)
        else:
            query = query.order_by(SecretItem.version.desc())
            
        secret_record = query.first()

        if not secret_record:
            raise MiniVaultError(status_code=404, code="NOT_FOUND", message="Secret or version not found.")

        try:
            nonce = base64.b64decode(secret_record.nonce_b64)
            ciphertext = base64.b64decode(secret_record.ciphertext_b64)
            tag = base64.b64decode(secret_record.tag_b64)
            
            encrypted_data = ciphertext + tag
            aesgcm = AESGCM(dek)
            plaintext = aesgcm.decrypt(nonce, encrypted_data, None)
            
            return {
                "version": secret_record.version,
                "data": json.loads(plaintext.decode('utf-8'))
            }
        except InvalidTag:
            raise MiniVaultError(status_code=400, code="DECRYPTION_FAILED", message="Data corrupted or authentication tag mismatch.")

    @staticmethod
    def delete_secret(db: Session, path: str, user_email: str):
        KVService._check_ownership(path, user_email)
        
        records = db.query(SecretItem).filter(SecretItem.path == path).all()
        if not records:
            raise MiniVaultError(status_code=404, code="NOT_FOUND", message="Secret not found.")
            
        # Xóa toàn bộ lịch sử các version
        for record in records:
            db.delete(record)
            
        db.commit()
        return {"status": "success", "message": f"Deleted all versions of {path}."}