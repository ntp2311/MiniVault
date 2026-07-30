from sqlalchemy import Column, String, DateTime
from sqlalchemy.sql import func
from src.database import Base

class SecretItem(Base):
    __tablename__ = "secrets"

    # Đường dẫn lưu bí mật (ví dụ: secret/alice@example.com/db)
    path = Column(String, primary_key=True, index=True)
    
    # Email của chủ sở hữu để kiểm tra quyền truy cập (Feature 1.2)
    owner_email = Column(String, nullable=False, index=True)
    
    # Các thành phần mã hóa (Feature 1.1)
    nonce_b64 = Column(String, nullable=False)
    ciphertext_b64 = Column(String, nullable=False)
    tag_b64 = Column(String, nullable=False)
    
    created_at = Column(DateTime(timezone=True), server_default=func.now())
    updated_at = Column(DateTime(timezone=True), onupdate=func.now())