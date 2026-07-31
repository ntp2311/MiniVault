# Mini Vault

Mini Vault là hệ thống quản lý bí mật và cung cấp dịch vụ mật mã thông qua REST API. Hệ thống bao gồm Vault Core, xác thực người dùng, lưu trữ KV mã hóa, Transit Engine, quản lý named key, chữ ký số và audit log chống chỉnh sửa.

## 1. Chức năng chính

### Feature 0 – Vault Core và xác thực

- Khởi tạo Vault bằng Master Passphrase.
- Dẫn xuất Key Encryption Key bằng Argon2id.
- Sinh DEK 256-bit và mã hóa bằng AES-256-GCM.
- Chỉ giữ DEK dạng rõ trong RAM khi Vault đang `unlocked`.
- Đăng ký, đăng nhập và đăng xuất người dùng.
- Cấp session token có thời hạn và chỉ lưu token hash.
- Khóa tài khoản tạm thời sau nhiều lần đăng nhập sai.

### Feature 1 – Encrypted KV Storage

- Ghi, đọc, cập nhật và xóa dữ liệu KV.
- Dữ liệu được mã hóa trước khi lưu xuống disk.
- Hỗ trợ dữ liệu chuỗi hoặc JSON.
- Phát hiện ciphertext, nonce hoặc authentication tag bị thay đổi.
- Kiểm soát quyền truy cập theo namespace:

```text
secret/<owner-email>/<resource>
```

- User chỉ được thao tác trên dữ liệu thuộc sở hữu của mình.
- Truy cập trái phép được ghi vào audit log.

### Feature 2 – Transit Engine và Signing

- Tạo và quản lý named AES keys.
- Liệt kê và revoke key.
- Encrypt và decrypt dữ liệu mà không lưu plaintext.
- Kiểm soát ownership đối với từng key.
- Tạo signing key pair.
- Sign message bằng private key.
- Verify message bằng public key.
- Private key và key material được mã hóa trước khi lưu.

### Extra Features

- MFA bằng TOTP.
- Tamper-evident audit log dạng hash chain.
- Audit verifier phát hiện sửa, xóa hoặc đảo thứ tự record.

---

## 2. Kiến trúc hệ thống

```text
Client / Swagger UI
        │
        ▼
FastAPI Routers
        │
        ▼
Authentication and Authorization
        │
        ▼
Service Layer
 ┌────────────┬────────────┬──────────────┬─────────────┐
 │ Vault Core │ Auth       │ KV Storage   │ Transit     │
 └────────────┴────────────┴──────────────┴─────────────┘
        │
        ▼
Cryptographic Layer
        │
        ├── Argon2id
        ├── AES-256-GCM
        ├── TOTP
        └── Digital Signature
        │
        ▼
SQLAlchemy ORM
        │
        ├── SQLite Database
        └── Hash-chained Audit Log
```

Luồng xử lý request:

```text
Request
  │
  ▼
Validate request
  │
  ▼
Verify session token
  │
  ▼
Resolve current user
  │
  ▼
Check Vault unlocked
  │
  ▼
Check ownership
  │
  ▼
Execute cryptographic operation
  │
  ▼
Read or write storage
  │
  ▼
Write audit event
  │
  ▼
Return response
```

---

## 3. Công nghệ sử dụng

| Thành phần | Công nghệ |
|---|---|
| Backend API | FastAPI |
| Ngôn ngữ | Python 3.12 |
| ORM | SQLAlchemy 2.0 |
| Database | SQLite |
| Validation | Pydantic |
| Mật mã | `cryptography` |
| Password hashing / KDF | Argon2id |
| MFA | PyOTP |
| Testing | pytest |
| API documentation | Swagger UI |

---

## 4. Cấu trúc thư mục

```text
Mini Vault/
├── main.py
├── requirements.txt
├── README.md
├── src/
│   ├── audit/
│   ├── auth/
│   ├── core/
│   ├── kv/
│   ├── models/
│   ├── routers/
│   ├── schemas/
│   ├── storage/
│   └── transit/
├── tests/
├── data/
│   └── logs/
└── docs/
```

Tên file hoặc thư mục cụ thể có thể khác tùy phiên bản cuối cùng của repository.

---

## 5. Yêu cầu môi trường

- Ubuntu Linux hoặc hệ điều hành tương thích.
- Python 3.12.
- `pip`.
- `venv`.
- SQLite.
- Git.

Kiểm tra Python:

```bash
python3 --version
```

---

## 6. Cài đặt

Clone repository:

```bash
git clone <repository-url>
cd "Mini Vault"
```

Tạo môi trường ảo:

```bash
python3 -m venv .venv
source .venv/bin/activate
```

Cài dependency:

```bash
python -m pip install --upgrade pip
python -m pip install -r requirements.txt
```

Kiểm tra import:

```bash
python -c "import main; print('Import main OK')"
```

---

## 7. Chạy ứng dụng

```bash
python -m uvicorn main:app --reload
```

Swagger UI:

```text
http://127.0.0.1:8000/docs
```

OpenAPI schema:

```text
http://127.0.0.1:8000/openapi.json
```

---

## 8. Thứ tự sử dụng đề xuất

1. Kiểm tra trạng thái Vault.
2. Khởi tạo Vault nếu chưa tồn tại.
3. Unlock Vault.
4. Đăng ký người dùng.
5. Đăng nhập và lấy session token.
6. Bấm **Authorize** trong Swagger UI.
7. Sử dụng KV Storage.
8. Tạo named key.
9. Encrypt hoặc decrypt dữ liệu.
10. Tạo signing key, sign và verify.
11. Kiểm tra audit log.
12. Lock Vault hoặc logout sau khi hoàn tất.

---

## 9. API chính

### Vault Core

| Method | Endpoint | Chức năng |
|---|---|---|
| `POST` | `/api/v1/vault/init` | Khởi tạo Vault |
| `POST` | `/api/v1/vault/unlock` | Mở khóa Vault |
| `POST` | `/api/v1/vault/lock` | Khóa Vault |
| `GET` | `/api/v1/vault/status` | Kiểm tra trạng thái |

### Authentication

| Method | Endpoint | Chức năng |
|---|---|---|
| `POST` | `/api/v1/auth/register` | Đăng ký user |
| `POST` | `/api/v1/auth/login` | Đăng nhập |
| `GET` | `/api/v1/auth/me` | Lấy current user |
| `POST` | `/api/v1/auth/logout` | Thu hồi session |

### KV Storage

| Method | Endpoint | Chức năng |
|---|---|---|
| `POST` | `/api/v1/kv/write` | Ghi hoặc cập nhật secret |
| `GET/POST` | `/api/v1/kv/read` | Đọc secret |
| `DELETE` | `/api/v1/kv/delete` | Xóa secret |

### Transit Engine

Các endpoint chính bao gồm:

- Tạo named key.
- Liệt kê key.
- Revoke key.
- Encrypt.
- Decrypt.
- Tạo signing key.
- Sign message.
- Verify signature.

Tên endpoint cần được đối chiếu với Swagger UI của phiên bản mã nguồn cuối cùng.

---

## 10. Ví dụ sử dụng

### Đăng ký user

```json
{
  "email": "alice.demo@example.com",
  "passphrase": "AliceDemo@2026!",
  "confirm_passphrase": "AliceDemo@2026!"
}
```

### Ghi KV

```json
{
  "path": "secret/alice.demo@example.com/database",
  "data": {
    "username": "demo_admin",
    "password": "DemoDatabasePassword@2026",
    "host": "db.internal.local",
    "port": 5432
  }
}
```

### Quy tắc ownership

User `alice.demo@example.com` chỉ được truy cập:

```text
secret/alice.demo@example.com/...
```

User khác truy cập path này phải nhận:

```json
{
  "error": {
    "code": "PERMISSION_DENIED",
    "message": "Permission denied."
  }
}
```

---


## 11. Kiểm tra encrypted-at-rest

Sau khi ghi dữ liệu demo:

```bash
grep -aF "DemoDatabasePassword@2026" data/mini_vault.db
```

Hoặc:

```bash
strings data/mini_vault.db |
grep -E "DemoDatabasePassword@2026|demo_admin|db.internal.local"
```

Kết quả mong đợi: không có plaintext được tìm thấy.

---

## 12. Tamper-evident audit log

Audit log hash-chained được lưu tại:

```text
data/logs/audit.jsonl
```

Mỗi record có thể bao gồm:

```json
{
  "sequence": 2,
  "timestamp": "2026-07-29T10:16:38.301746Z",
  "actor_email": "bob.demo@example.com",
  "action": "TRANSIT_ACCESS_DENIED",
  "resource": "alice-secret-key",
  "resource_type": "TRANSIT_KEY",
  "result": "PERMISSION_DENIED",
  "previous_hash": "...",
  "record_hash": "..."
}
```

Xác minh audit chain:

```bash
python -m src.audit.verifier
```

Kết quả hợp lệ:

```text
true
```

Sau khi sửa, xóa hoặc đảo thứ tự record, verifier phải trả:

```text
false
```

---

## 13. Log hệ thống

Các file log có thể gồm:

```text
data/logs/audit.jsonl
data/logs/minivault.log
logs/security.log
```

Trong đó:

- `audit.jsonl`: audit log hash-chained.
- `security.log`: cảnh báo truy cập trái phép hoặc sự kiện bảo mật.
- `minivault.log`: application log tổng quát.

Không ghi Master Passphrase, DEK, session token, private key hoặc plaintext secret vào log.

---

## 14. Nguyên tắc bảo mật

- Không lưu Master Passphrase.
- Không lưu DEK hoặc KEK dạng rõ trên disk.
- Không lưu passphrase dạng rõ.
- Không lưu session token dạng rõ.
- Không lưu private signing key dạng rõ.
- Không ghi secret hoặc key material vào log.
- Dùng Argon2id cho KDF và password hashing.
- Dùng AES-256-GCM để bảo vệ tính bí mật và toàn vẹn.
- Kiểm tra authentication trước ownership.
- Kiểm tra ownership trước encrypt hoặc decrypt.
- Từ chối thao tác mật mã khi Vault đang `locked`.
- Không trả stack trace hoặc dữ liệu nội bộ trong response lỗi.

---


