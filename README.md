# Mini Vault – Feature 0

Feature 0 xây dựng lớp bảo mật nền tảng cho hệ thống Mini Vault, bao gồm:

- Khởi tạo và mở khóa Vault bằng Master Passphrase.
- Sinh và bảo vệ Data Encryption Key – DEK.
- Đăng ký và đăng nhập người dùng.
- Quản lý session token và đăng xuất.
- Khóa tạm thời tài khoản sau nhiều lần đăng nhập sai.
- Cung cấp dependency xác thực để Feature 1 và Feature 2 sử dụng.

---

## 1. Mục tiêu của Feature 0

Feature 0 gồm hai nhóm chức năng chính:

### Feature 0.1 – Vault Initialization and Unlock

- Khởi tạo Vault bằng một Master Passphrase.
- Dẫn xuất khóa từ Master Passphrase bằng Argon2id.
- Sinh ngẫu nhiên một DEK 256-bit.
- Mã hóa DEK bằng AES-256-GCM trước khi lưu xuống database.
- Chỉ giữ DEK dạng rõ trong RAM khi Vault đang được mở khóa.
- Sau mỗi lần khởi động lại chương trình, Vault luôn trở về trạng thái `locked`.

### Feature 0.2 – User Authentication

- Đăng ký người dùng bằng email và passphrase.
- Hash passphrase bằng Argon2id.
- Đăng nhập và cấp session token có thời hạn.
- Lưu hash của session token thay vì lưu token dạng rõ.
- Đăng xuất và thu hồi session.
- Khóa tài khoản trong 5 phút sau 5 lần đăng nhập sai liên tiếp.
- Cung cấp dependency để xác định người dùng hiện tại.

---

## 2. Kiến trúc khóa

Luồng bảo vệ khóa của Mini Vault:

```text
Master Passphrase
        │
        │ Argon2id + Salt
        ▼
Derived Key / KEK
        │
        │ AES-256-GCM
        ▼
Encrypted DEK lưu trong database
        │
        │ Unlock thành công
        ▼
Plaintext DEK chỉ tồn tại trong RAM


python3 -m venv .venv
source .venv/bin/activate

pip install -r requirements.txt
uvicorn main:app --reload