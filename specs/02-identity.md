# 02 — Identity

Nguồn: Blueprint v10 (Anti-Impersonation & Device Trust), v12 §1, v13 §1 (C7), v11 §16.6.

## Khóa

- Mỗi principal có **một cặp khóa Ed25519 riêng**. Không có shared secret, không có khóa dùng chung cho cả nhà/doanh nghiệp (v7 §10), không có master key toàn cục (C7).
- **Key id** (`kid`) = 16 byte đầu của `SHA-256(public_key_32_bytes)`.
- Chữ ký request dùng COSE alg `Ed25519` (-19) — spec 07. Thuật toán được ghi tường minh trên dây để có đường chuyển sang suite mới/PQC (v7 §13) mà không đổi ngữ nghĩa.

## Phân tầng khóa của một domain (v10 §10)

| Khóa | Vai trò | Ở đâu (v0.1) |
|---|---|---|
| Domain authority key | Ký capability token của domain | `keys/domain-authority.key` trên node; NÊN chuyển vào TPM/secure element (v5 §8) |
| Node service key (`service:node`) | Ký checkpoint audit | `keys/service-node.key` |
| Principal key (person/ai/service/device) | Ký request CSME | Thiết bị của chính principal. `chitala init` đặt chung một thư mục chỉ để thử nghiệm trên một máy. |

Khóa ký token (authority) tách khỏi khóa ký audit (node) để compromise một service không chiếm toàn domain (v10 §10 "Service key tách Authority/Broker/Update").

## File khóa

Một dòng hex của seed Ed25519 32 byte, quyền file `0600`. Tên file: `<kind>-<local>.key` (`person-alice.key`). Không ghi đè file đã tồn tại.

## Identity Registry

- Một principal = `(id, public_key, roles, security_state)`.
- `id` và `kid` đều duy nhất trong domain (enroll trùng → lỗi).
- `domain:*` không thể enroll làm principal.
- **Role** khớp `[a-z][a-z0-9_-]{0,63}`. Role `owner` và `admin` chỉ dành cho `person:*` (C1, C11): AI không bao giờ trở thành chủ hay quản trị của domain.
- Role chỉ có nghĩa thông qua policy (spec 06). Với principal không phải người, role **không** tạo ambient authority (policy `C12-*`).

## Test keys

`test_seed(label) = SHA-256("chitala-test-vector:" || label)` sinh seed tất định cho test vector giữa các implementation. KHÔNG ĐƯỢC dùng ngoài test.

## Chưa có ở v0.1 (đã chừa chỗ)

- Enrollment theo luồng `DISCOVER → … → ISSUE CREDENTIAL → JOIN` (v4 §5) và onboarding kiểu FIDO FDO (v10 §4): v0.1 enroll qua file config do owner ký tay.
- Manager authentication ngược chiều (device xác thực node, v10 §2): response của node hiện chưa ký.
- Attestation (RATS/EAT, v10 §5).
