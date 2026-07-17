from __future__ import annotations

import re
from typing import Any

from argon2 import PasswordHasher

ph = PasswordHasher(time_cost=3, memory_cost=65536, parallelism=2, hash_len=32, salt_len=16)

COMMON_PASSWORDS = {
    "password",
    "password123",
    "admin",
    "123456",
    "12345678",
    "qwerty",
}


def normalize_email(email: str) -> str:
    return email.strip().lower()


def is_valid_email(email: str) -> bool:
    pattern = re.compile(r"^[^@\s]+@[^@\s]+\.[^@\s]+$")
    return bool(pattern.match(email))


def validate_password_strength(password: str, *, email: str | None = None, min_length: int = 12, common_passwords: set[str] | None = None) -> bool:
    common = common_passwords or COMMON_PASSWORDS
    if not password or len(password.strip()) < min_length:
        return False
    if not any(char.isupper() for char in password):
        return False
    if not any(char.islower() for char in password):
        return False
    if not any(char.isdigit() for char in password):
        return False
    if not re.search(r"[^A-Za-z0-9]", password):
        return False
    if password.strip() == "":
        return False
    if password.lower() in common:
        return False
    if email is not None and password.lower() == email.lower():
        return False
    return True


def hash_password(password: str) -> str:
    return ph.hash(password)


def verify_password(password_hash: str, password: str) -> bool:
    try:
        return ph.verify(password_hash, password)
    except Exception:
        return False
