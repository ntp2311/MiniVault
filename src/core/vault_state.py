from __future__ import annotations

from threading import Lock


class VaultState:
    def __init__(self) -> None:
        self._dek: bytes | None = None
        self._lock = Lock()

    def is_initialized(self) -> bool:
        return self._dek is not None

    def is_unlocked(self) -> bool:
        return self._dek is not None

    def set_dek(self, dek: bytes) -> None:
        with self._lock:
            self._dek = dek

    def get_dek(self) -> bytes | None:
        with self._lock:
            return self._dek

    def clear_dek(self) -> None:
        with self._lock:
            self._dek = None


vault_state = VaultState()
