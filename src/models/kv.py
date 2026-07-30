from sqlalchemy import Column, String, DateTime, Integer
from sqlalchemy.sql import func
from src.database import Base

class SecretItem(Base):
    __tablename__ = "secrets"

    # Thêm ID làm khóa chính để 1 path có thể có nhiều version
    id = Column(Integer, primary_key=True, index=True)
    
    # Path không còn là khóa chính nữa
    path = Column(String, index=True, nullable=False)
    
    # Thêm cột version
    version = Column(Integer, nullable=False, default=1)
    
    owner_email = Column(String, nullable=False, index=True)
    nonce_b64 = Column(String, nullable=False)
    ciphertext_b64 = Column(String, nullable=False)
    tag_b64 = Column(String, nullable=False)
    
    created_at = Column(DateTime(timezone=True), server_default=func.now())
    updated_at = Column(DateTime(timezone=True), onupdate=func.now())