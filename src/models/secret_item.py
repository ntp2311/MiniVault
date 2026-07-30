from sqlalchemy import Column, Integer, String, DateTime
from src.database import Base

class SecretItem(Base):
    __tablename__ = "secret_items"

    id = Column(Integer, primary_key=True, index=True)
    path = Column(String, index=True, nullable=False)
    version = Column(Integer, nullable=False, default=1) # <-- THÊM CỘT NÀY
    
    nonce_b64 = Column(String, nullable=False)
    ciphertext_b64 = Column(String, nullable=False)
    tag_b64 = Column(String, nullable=False)
    created_at = Column(DateTime, nullable=False)
    updated_at = Column(DateTime, nullable=False)