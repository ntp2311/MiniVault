import json
import base64
import os
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from sqlalchemy.orm import Session
from src.models.kv import SecretItem
from src.exceptions import MiniVaultError

class KVService:
    @staticmethod
    def _check_ownership(path: str, user_email: str):
        # Feature 1.2: Phải bắt đầu bằng secret/<email>/...
        expected_prefix = f"secret/{user_email}/"
        if not path.startswith(expected_prefix):
            # Từ chối ngay lập tức trước khi đụng đến giải mã
            raise MiniVaultError(status_code=403, code="PERMISSION_DENIED", message="Access denied.")

    @staticmethod
    def write_secret(db: Session, path: str, data: dict, user_email: str, dek: bytes):
        # 1. Kiểm tra quyền (Feature 1.2)
        KVService._check_ownership(path, user_email)
        
        # 2. Chuẩn bị dữ liệu và sinh Nonce ngẫu nhiên
        plaintext = json.dumps(data).encode('utf-8')
        nonce = os.urandom(12) 
        
        # 3. Mã hóa bằng AES-256-GCM (Feature 1.1)
        aesgcm = AESGCM(dek)
        # AESGCM trong Python trả về ciphertext + tag gộp chung. Đồ án yêu cầu tách ra.
        encrypted_data = aesgcm.encrypt(nonce, plaintext, None)
        ciphertext = encrypted_data[:-16] # Phần dữ liệu đã mã hóa
        tag = encrypted_data[-16:]        # 16 bytes cuối là Authentication Tag
        
        # 4. Lưu xuống Database
        secret_record = db.query(SecretItem).filter(SecretItem.path == path).first()
        if not secret_record:
            secret_record = SecretItem(path=path, owner_email=user_email)
            db.add(secret_record)
            
        secret_record.nonce_b64 = base64.b64encode(nonce).decode('utf-8')
        secret_record.ciphertext_b64 = base64.b64encode(ciphertext).decode('utf-8')
        secret_record.tag_b64 = base64.b64encode(tag).decode('utf-8')
        
        db.commit()
        return {"status": "success", "message": "Secret written successfully"}
    @staticmethod
    def read_secret(db: Session, path: str, user_email: str, dek: bytes):
        # 1. Kiểm tra quyền sở hữu (Feature 1.2)
        KVService._check_ownership(path, user_email)
        
        # 2. Tìm dữ liệu trong Database
        secret_record = db.query(SecretItem).filter(SecretItem.path == path).first()
        if not secret_record:
            raise MiniVaultError(status_code=404, code="NOT_FOUND", message="Secret not found.")
            
        # 3. Chuẩn bị giải mã (Feature 1.1)
        try:
            nonce = base64.b64decode(secret_record.nonce_b64)
            ciphertext = base64.b64decode(secret_record.ciphertext_b64)
            tag = base64.b64decode(secret_record.tag_b64)
            
            # Khôi phục lại khối dữ liệu mã hóa như lúc ban đầu
            encrypted_data = ciphertext + tag
            
            # Giải mã và xác thực tag đồng thời
            aesgcm = AESGCM(dek)
            plaintext = aesgcm.decrypt(nonce, encrypted_data, None)
            
            return {"path": path, "data": json.loads(plaintext.decode('utf-8'))}
            
        except Exception:
            # Nếu tag không khớp hoặc có bất kỳ sự xáo trộn byte nào, bung lỗi ngay lập tức
            raise MiniVaultError(status_code=400, code="DECRYPTION_FAILED", message="Data corrupted or authentication tag mismatch.")

    @staticmethod
    def delete_secret(db: Session, path: str, user_email: str):
        # 1. Kiểm tra quyền sở hữu (Feature 1.2)
        KVService._check_ownership(path, user_email)
        
        # 2. Xóa khỏi Database
        secret_record = db.query(SecretItem).filter(SecretItem.path == path).first()
        if not secret_record:
            raise MiniVaultError(status_code=404, code="NOT_FOUND", message="Secret not found.")
            
        db.delete(secret_record)
        db.commit()
        return {"status": "success", "message": "Secret deleted successfully."}