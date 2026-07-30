from __future__ import annotations

import base64
import json
from pathlib import Path
from urllib import response

from fastapi.testclient import TestClient

from src.audit.audit_service import AuditService
from src.audit.verifier import verify_audit_log


def test_first_record_uses_genesis(tmp_path: Path) -> None:
    audit_file = tmp_path / "audit.jsonl"
    service = AuditService(audit_file)
    record = service.record(
        actor_email="alice@example.com",
        action="TRANSIT_KEY_ACCESS_DENIED",
        resource_type="TRANSIT_KEY",
        resource="alice-key",
        result="PERMISSION_DENIED",
    )

    assert record["sequence"] == 1
    assert record["previous_hash"] == "GENESIS"
    assert record["entry_hash"]


def test_multiple_records_form_valid_chain(tmp_path: Path) -> None:
    service = AuditService(tmp_path / "audit.jsonl")
    record1 = service.record(
        actor_email="alice@example.com",
        action="TRANSIT_KEY_ACCESS_DENIED",
        resource_type="TRANSIT_KEY",
        resource="alice-key",
        result="PERMISSION_DENIED",
    )
    record2 = service.record(
        actor_email="bob@example.com",
        action="TRANSIT_KEY_ACCESS_DENIED",
        resource_type="TRANSIT_KEY",
        resource="alice-key",
        result="PERMISSION_DENIED",
    )

    assert record2["sequence"] == 2
    assert record2["previous_hash"] == record1["entry_hash"]
    assert verify_audit_log(service.path)["valid"] is True


def test_verify_valid_log(tmp_path: Path) -> None:
    service = AuditService(tmp_path / "audit.jsonl")
    service.record(
        actor_email="alice@example.com",
        action="TRANSIT_KEY_ACCESS_DENIED",
        resource_type="TRANSIT_KEY",
        resource="alice-key",
        result="PERMISSION_DENIED",
    )
    service.record(
        actor_email="alice@example.com",
        action="TRANSIT_KEY_ACCESS_DENIED",
        resource_type="TRANSIT_KEY",
        resource="alice-key",
        result="PERMISSION_DENIED",
    )

    result = verify_audit_log(service.path)
    assert result["valid"] is True
    assert result["entries_checked"] == 2
    assert result["first_invalid_sequence"] is None
    assert result["reason"] is None


def test_detect_modified_record(tmp_path: Path) -> None:
    service = AuditService(tmp_path / "audit.jsonl")
    service.record(
        actor_email="alice@example.com",
        action="TRANSIT_KEY_ACCESS_DENIED",
        resource_type="TRANSIT_KEY",
        resource="alice-key",
        result="PERMISSION_DENIED",
    )
    service.record(
        actor_email="bob@example.com",
        action="TRANSIT_KEY_ACCESS_DENIED",
        resource_type="TRANSIT_KEY",
        resource="alice-key",
        result="PERMISSION_DENIED",
    )
    service.record(
        actor_email="bob@example.com",
        action="TRANSIT_KEY_ACCESS_DENIED",
        resource_type="TRANSIT_KEY",
        resource="alice-key",
        result="PERMISSION_DENIED",
    )

    lines = service.path.read_text(encoding="utf-8").splitlines()
    record2 = json.loads(lines[1])
    record2["result"] = "INVALID"  # tamper with the second record
    lines[1] = json.dumps(record2, sort_keys=True, separators=(",", ":"))
    service.path.write_text("\n".join(lines) + "\n", encoding="utf-8")

    result = verify_audit_log(service.path)
    assert result["valid"] is False
    assert result["reason"] == "ENTRY_HASH_MISMATCH"
    assert result["first_invalid_sequence"] == 2


def test_detect_deleted_middle_record(tmp_path: Path) -> None:
    service = AuditService(tmp_path / "audit.jsonl")
    service.record(
        actor_email="alice@example.com",
        action="TRANSIT_KEY_ACCESS_DENIED",
        resource_type="TRANSIT_KEY",
        resource="alice-key",
        result="PERMISSION_DENIED",
    )
    service.record(
        actor_email="bob@example.com",
        action="TRANSIT_KEY_ACCESS_DENIED",
        resource_type="TRANSIT_KEY",
        resource="alice-key",
        result="PERMISSION_DENIED",
    )
    service.record(
        actor_email="bob@example.com",
        action="TRANSIT_KEY_ACCESS_DENIED",
        resource_type="TRANSIT_KEY",
        resource="alice-key",
        result="PERMISSION_DENIED",
    )

    lines = service.path.read_text(encoding="utf-8").splitlines()
    lines.pop(1)
    service.path.write_text("\n".join(lines) + "\n", encoding="utf-8")

    result = verify_audit_log(service.path)
    assert result["valid"] is False
    assert result["reason"] in {"INVALID_SEQUENCE", "CHAIN_LINK_MISMATCH"}


def test_detect_reordered_records(tmp_path: Path) -> None:
    service = AuditService(tmp_path / "audit.jsonl")
    service.record(
        actor_email="alice@example.com",
        action="TRANSIT_KEY_ACCESS_DENIED",
        resource_type="TRANSIT_KEY",
        resource="alice-key",
        result="PERMISSION_DENIED",
    )
    service.record(
        actor_email="bob@example.com",
        action="TRANSIT_KEY_ACCESS_DENIED",
        resource_type="TRANSIT_KEY",
        resource="alice-key",
        result="PERMISSION_DENIED",
    )
    service.record(
        actor_email="bob@example.com",
        action="TRANSIT_KEY_ACCESS_DENIED",
        resource_type="TRANSIT_KEY",
        resource="alice-key",
        result="PERMISSION_DENIED",
    )

    lines = service.path.read_text(encoding="utf-8").splitlines()
    lines[1], lines[2] = lines[2], lines[1]
    service.path.write_text("\n".join(lines) + "\n", encoding="utf-8")

    result = verify_audit_log(service.path)
    assert result["valid"] is False
    assert result["reason"] in {"INVALID_SEQUENCE", "CHAIN_LINK_MISMATCH"}


def test_detect_malformed_json(tmp_path: Path) -> None:
    service = AuditService(tmp_path / "audit.jsonl")
    service.path.write_text("{invalid json}\n", encoding="utf-8")

    result = verify_audit_log(service.path)
    assert result["valid"] is False
    assert result["reason"] == "MALFORMED_JSON"


def test_detect_invalid_sequence(tmp_path: Path) -> None:
    service = AuditService(tmp_path / "audit.jsonl")
    service.record(
        actor_email="alice@example.com",
        action="TRANSIT_KEY_ACCESS_DENIED",
        resource_type="TRANSIT_KEY",
        resource="alice-key",
        result="PERMISSION_DENIED",
    )
    service.record(
        actor_email="bob@example.com",
        action="TRANSIT_KEY_ACCESS_DENIED",
        resource_type="TRANSIT_KEY",
        resource="alice-key",
        result="PERMISSION_DENIED",
    )

    lines = service.path.read_text(encoding="utf-8").splitlines()
    record2 = json.loads(lines[1])
    record2["sequence"] = 5
    lines[1] = json.dumps(record2, sort_keys=True, separators=(",", ":"))
    service.path.write_text("\n".join(lines) + "\n", encoding="utf-8")

    result = verify_audit_log(service.path)
    assert result["valid"] is False
    assert result["reason"] == "INVALID_SEQUENCE"


def test_denied_transit_access_is_logged(
    client: TestClient,
    unlocked_and_registered_user: tuple[TestClient, dict],
    second_unlocked_user: tuple[TestClient, dict],
    tmp_path: Path,
) -> None:
    audit_file = tmp_path / "audit.jsonl"
    client.post(
        "/api/v1/transit/keys",
        json={"key_name": "alice-secret-key"},
        headers=unlocked_and_registered_user[1],
    )

    import os

    original_value = os.environ.get("MINI_VAULT_AUDIT_PATH")
    os.environ["MINI_VAULT_AUDIT_PATH"] = str(audit_file)
    try:
        response = client.post(
            "/api/v1/transit/encrypt/alice-secret-key",
            json={"plaintext": base64.b64encode(b"hello").decode("ascii")},
            headers=second_unlocked_user[1],
        )

        print("STATUS:", response.status_code)
        print("BODY:", response.text)
        assert response.status_code == 403

        result = verify_audit_log(audit_file)
        assert result["valid"] is True
        assert result["entries_checked"] == 1

        body = audit_file.read_text(encoding="utf-8").strip().splitlines()[0]
        assert "TRANSIT_KEY_ACCESS_DENIED" in body
        assert "alice-secret-key" in body
    finally:
        if original_value is None:
            del os.environ["MINI_VAULT_AUDIT_PATH"]
        else:
            os.environ["MINI_VAULT_AUDIT_PATH"] = original_value


def test_denied_transit_access_still_returns_permission_denied(
    client: TestClient,
    unlocked_and_registered_user: tuple[TestClient, dict],
    second_unlocked_user: tuple[TestClient, dict],
) -> None:
    client.post(
        "/api/v1/transit/keys",
        json={"key_name": "alice-secret-key"},
        headers=unlocked_and_registered_user[1],
    )

    response = client.post(
        "/api/v1/transit/encrypt/alice-secret-key",
        json={"plaintext": base64.b64encode(b"hello").decode("ascii")},
        headers=second_unlocked_user[1],
    )
    assert response.status_code == 403


def test_audit_log_does_not_contain_sensitive_material(tmp_path: Path) -> None:
    service = AuditService(tmp_path / "audit.jsonl")
    service.record(
        actor_email="alice@example.com",
        action="TRANSIT_KEY_ACCESS_DENIED",
        resource_type="TRANSIT_KEY",
        resource="alice-key",
        result="PERMISSION_DENIED",
        details={"operation": "encrypt"},
    )

    content = service.path.read_text(encoding="utf-8")
    assert "passphrase" not in content
    assert "secret" not in content.lower()
    assert "ciphertext" not in content.lower()
    assert "signature" not in content.lower()
    assert "private" not in content.lower()
    assert "token" not in content.lower()
