from __future__ import annotations

import argparse
import hashlib
import hmac
import json
import os
from pathlib import Path
from typing import Any

AuditVerificationResult = dict[str, Any]
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


def verify_audit_log(path: Path | str | None = None) -> AuditVerificationResult:
    file_path = Path(path) if path else Path(os.environ.get("MINI_VAULT_AUDIT_PATH", "data/logs/audit.jsonl"))
    if not file_path.exists():
        return {
            "valid": False,
            "entries_checked": 0,
            "first_invalid_sequence": None,
            "reason": "FILE_NOT_FOUND",
        }

    expected_sequence = 1
    previous_hash = GENESIS_HASH
    entries_checked = 0

    try:
        with file_path.open("r", encoding="utf-8") as handle:
            for line in handle:
                if not line.strip():
                    continue
                entries_checked += 1
                try:
                    record = json.loads(line)
                except json.JSONDecodeError:
                    return {
                        "valid": False,
                        "entries_checked": entries_checked,
                        "first_invalid_sequence": expected_sequence,
                        "reason": "MALFORMED_JSON",
                    }

                missing = [field for field in REQUIRED_FIELDS if field not in record]
                if missing:
                    return {
                        "valid": False,
                        "entries_checked": entries_checked,
                        "first_invalid_sequence": record.get("sequence", expected_sequence),
                        "reason": "MISSING_REQUIRED_FIELD",
                    }

                if not isinstance(record["sequence"], int) or record["sequence"] != expected_sequence:
                    return {
                        "valid": False,
                        "entries_checked": entries_checked,
                        "first_invalid_sequence": record.get("sequence", expected_sequence),
                        "reason": "INVALID_SEQUENCE",
                    }

                if record["previous_hash"] != previous_hash:
                    return {
                        "valid": False,
                        "entries_checked": entries_checked,
                        "first_invalid_sequence": record["sequence"],
                        "reason": "CHAIN_LINK_MISMATCH",
                    }

                computed_hash = _compute_entry_hash(record)
                if not hmac.compare_digest(computed_hash, record["entry_hash"]):
                    return {
                        "valid": False,
                        "entries_checked": entries_checked,
                        "first_invalid_sequence": record["sequence"],
                        "reason": "ENTRY_HASH_MISMATCH",
                    }

                previous_hash = record["entry_hash"]
                expected_sequence += 1

    except Exception as exc:
        return {
            "valid": False,
            "entries_checked": entries_checked,
            "first_invalid_sequence": expected_sequence,
            "reason": "MALFORMED_JSON",
        }

    return {
        "valid": True,
        "entries_checked": entries_checked,
        "first_invalid_sequence": None,
        "reason": None,
    }


def _main() -> int:
    parser = argparse.ArgumentParser(description="Verify the Mini Vault audit log.")
    parser.add_argument(
        "--path",
        default="data/logs/audit.jsonl",
        help="Path to the audit log file.",
    )
    args = parser.parse_args()
    result = verify_audit_log(args.path)
    print(json.dumps(result, indent=2))
    return 0 if result["valid"] else 1


if __name__ == "__main__":
    raise SystemExit(_main())
