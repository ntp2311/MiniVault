from __future__ import annotations

from typing import Any


class MiniVaultError(Exception):
    def __init__(self, status_code: int, code: str, message: str, details: dict[str, Any] | None = None) -> None:
        super().__init__(message)
        self.status_code = status_code
        self.code = code
        self.message = message
        self.details = details or {}


def error_response(exc: MiniVaultError) -> dict[str, Any]:
    payload: dict[str, Any] = {"error": {"code": exc.code, "message": exc.message}}
    if exc.details:
        payload["error"].update(exc.details)
    return payload
