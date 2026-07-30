from pydantic import BaseModel
from typing import Any, Dict

class WriteSecretRequest(BaseModel):
    path: str
    data: Dict[str, Any]  # Yêu cầu data là một JSON object

class ReadSecretResponse(BaseModel):
    path: str
    data: Dict[str, Any]