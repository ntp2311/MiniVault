import os
import json
import base64
import logging
from datetime import datetime, timezone
from sqlalchemy.orm import Session
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.exceptions import InvalidTag

from src.exceptions import MiniVaultError
from src.models.secret_item import SecretItem  # Đảm bảo bạn có Model này

# Cấu hình log để lưu các trường hợp truy cập trái phép
logger = logging.getLogger(__name__)

class KVService:
    @staticmethod
    def _check_ownership(path: str, user_email: str) -> None:
        """
        Kiểm tra quyền sở hữu (Yêu cầu 1.2)
        Thực hiện NGAY LẬP TỨC trước bất kỳ thao tác CSDL hay mã hóa nào.
        """
        expected_prefix = f"secret/{user_email}/"
        if not path.startswith(expected_prefix):
            # Log lại nỗ lực truy cập trái phép (Yêu cầu 1.2: Log every denied access attempt)
            logger.warning(f"Access denied: User {user_email} attempted to access {path}")
            
            # Trả về lỗi chung chung, không phân biệt là path không tồn tại hay sai quyền
            raise MiniVaultError(
                status_code=403,
                code="PERMISSION_DENIED",
                message="Permission denied or path does not exist."
            )

    @staticmethod
    def write_secret(db: Session, path: str, data: dict, user_email: str, dek: bytes):
        KVService._check_ownership(path, user_email)

        # Chuẩn bị dữ liệu dạng byte
        plaintext = json.dumps(data).encode('utf-8')
        
        # Tạo Nonce mới ngẫu nhiên cho MỖI lần ghi (Yêu cầu 1.1: 12 bytes cho GCM)
        nonce = os.urandom(12)
        
        # Mã hóa AES-256-GCM
        aesgcm = AESGCM(dek)
        # Thư viện cryptography sẽ tự động nối tag (16 bytes) vào cuối ciphertext
        encrypted_data = aesgcm.encrypt(nonce, plaintext, None)
        
        # Tách ciphertext và tag ra để lưu đúng Data Contract yêu cầu
        ciphertext = encrypted_data[:-16]
        tag = encrypted_data[-16:]

        # Encode ra chuỗi Base64
        nonce_b64 = base64.b64encode(nonce).decode('utf-8')
        ciphertext_b64 = base64.b64encode(ciphertext).decode('utf-8')
        tag_b64 = base64.b64encode(tag).decode('utf-8')

        # Ghi xuống SQLite (Ghi đè nếu đã tồn tại - Yêu cầu 1.1)
        secret_record = db.query(SecretItem).filter(SecretItem.path == path).first()
        now = datetime.now(timezone.utc)
        
        if secret_record:
            secret_record.nonce_b64 = nonce_b64
            secret_record.ciphertext_b64 = ciphertext_b64
            secret_record.tag_b64 = tag_b64
            secret_record.updated_at = now
        else:
            secret_record = SecretItem(
                path=path,
                nonce_b64=nonce_b64,
                ciphertext_b64=ciphertext_b64,
                tag_b64=tag_b64,
                created_at=now,
                updated_at=now
            )
            db.add(secret_record)
        
        db.commit()
        
        # Yêu cầu 1.1: Output của write chỉ trả về thời gian
        return {
            "created_at": secret_record.created_at.isoformat(),
            "updated_at": secret_record.updated_at.isoformat()
        }

    @staticmethod
    def read_secret(db: Session, path: str, user_email: str, dek: bytes):
        KVService._check_ownership(path, user_email)

        secret_record = db.query(SecretItem).filter(SecretItem.path == path).first()
        if not secret_record:
            raise MiniVaultError(status_code=404, code="NOT_FOUND", message="Secret not found.")

        try:
            # Decode từ Base64
            nonce = base64.b64decode(secret_record.nonce_b64)
            ciphertext = base64.b64decode(secret_record.ciphertext_b64)
            tag = base64.b64decode(secret_record.tag_b64)
            
            # Gộp lại để thư viện xử lý giải mã và xác thực đồng thời
            encrypted_data = ciphertext + tag
            
            aesgcm = AESGCM(dek)
            plaintext = aesgcm.decrypt(nonce, encrypted_data, None)
            
            # Yêu cầu 1.1: Output của read trả về decrypted data
            return json.loads(plaintext.decode('utf-8'))
            
        except InvalidTag:
            # Bắt chính xác lỗi Tag bị sai lệch (dữ liệu bị giả mạo/tampering)
            raise MiniVaultError(
                status_code=400, 
                code="DECRYPTION_FAILED", 
                message="Data corrupted or authentication tag mismatch."
            )

    @staticmethod
    def delete_secret(db: Session, path: str, user_email: str):
        KVService._check_ownership(path, user_email)
        
        secret_record = db.query(SecretItem).filter(SecretItem.path == path).first()
        if not secret_record:
            raise MiniVaultError(status_code=404, code="NOT_FOUND", message="Secret not found.")
            
        db.delete(secret_record)
        db.commit()
        
        # Yêu cầu 1.1: Output của delete trả về deletion confirmation
        return {"status": "success", "message": "Secret deleted successfully."}