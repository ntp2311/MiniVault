from __future__ import annotations

import hashlib
import hmac
import json
import os
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from src.logger import logger
from src.exceptions import MiniVaultError

AUDIT_DIR = Path("data/logs")
AUDIT_FILE = AUDIT_DIR / "audit.jsonl"
GENESIS_HASH = "GENESIS"
REQUIRED_FIELDS = [
    "sequence",
    "timestamp",
    "actor_email",
    "action",
    "resource_type",
    "resource",
    "result",
    "previous_hash",
    "entry_hash",
]


def _canonical_json(data: dict[str, Any]) -> str:
    return json.dumps(
        data,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
    )


def _compute_entry_hash(record: dict[str, Any]) -> str:
    payload = {k: record[k] for k in record if k != "entry_hash"}
    hash_input = _canonical_json(payload).encode("utf-8")
    return hashlib.sha256(hash_input).hexdigest()


class AuditService:
    def __init__(self, path: Path | str | None = None) -> None:
        effective_path = path if path else os.environ.get("MINI_VAULT_AUDIT_PATH")
        self.path = Path(effective_path) if effective_path else AUDIT_FILE
        self.path.parent.mkdir(parents=True, exist_ok=True)
        if not self.path.exists():
            self.path.touch(mode=0o600, exist_ok=True)

    def _read_last_record(self) -> tuple[int, str] | None:
        try:
            with self.path.open("r", encoding="utf-8") as handle:
                lines = [line.rstrip("\n") for line in handle if line.strip()]
        except FileNotFoundError:
            return None

        if not lines:
            return None

        last_line = lines[-1]
        try:
            last_record = json.loads(last_line)
        except json.JSONDecodeError as exc:
            raise MiniVaultError(
                500,
                "AUDIT_LOG_CORRUPTED",
                f"Audit log contains malformed JSON in final line: {exc}",
            )

        if "sequence" not in last_record or "entry_hash" not in last_record:
            raise MiniVaultError(
                500,
                "AUDIT_LOG_CORRUPTED",
                "Audit log contains invalid final record.",
            )

        return last_record["sequence"], last_record["entry_hash"]

    def record(
        self,
        *,
        actor_email: str,
        action: str,
        resource_type: str,
        resource: str,
        result: str,
        request_id: str | None = None,
        details: dict[str, object] | None = None,
    ) -> dict[str, object]:
        if not actor_email or not action or not resource_type or not resource or not result:
            raise MiniVaultError(400, "AUDIT_LOG_INVALID", "Invalid audit record parameters.")

        previous = self._read_last_record()
        if previous is None:
            sequence = 1
            previous_hash = GENESIS_HASH
        else:
            sequence = previous[0] + 1
            previous_hash = previous[1]

        timestamp = datetime.now(timezone.utc).replace(tzinfo=timezone.utc).isoformat(timespec="microseconds").replace("+00:00", "Z")
        record: dict[str, Any] = {
            "sequence": sequence,
            "timestamp": timestamp,
            "actor_email": actor_email,
            "action": action,
            "resource_type": resource_type,
            "resource": resource,
            "result": result,
            "details": details or {},
            "previous_hash": previous_hash,
        }
        if request_id is not None:
            record["request_id"] = request_id
        record["entry_hash"] = _compute_entry_hash(record)

        try:
            with self.path.open("a", encoding="utf-8") as handle:
                handle.write(_canonical_json(record) + "\n")
                handle.flush()
                os.fsync(handle.fileno())
        except Exception as exc:
            logger.error("Audit log write failed.")
            raise MiniVaultError(500, "AUDIT_LOG_WRITE_FAILED", "Unable to write audit log.") from exc

        return record
