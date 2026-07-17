from __future__ import annotations

from typing import Any

from argon2.low_level import Type, hash_secret_raw


def derive_key(passphrase: str, salt: bytes, parameters: dict[str, Any]) -> bytes:
    return hash_secret_raw(
        secret=passphrase.encode("utf-8"),
        salt=salt,
        time_cost=parameters["time_cost"],
        memory_cost=parameters["memory_cost"],
        parallelism=parameters["parallelism"],
        hash_len=parameters["hash_len"],
        type=Type.ID,
    )
