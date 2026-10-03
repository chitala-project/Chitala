# 07 — Chitala Secure Message Envelope (CSME) v1

Nguồn: v4 §3 (trường CSME), §7 (versioning/extension), §14 (chống downgrade và protocol confusion), §16 (canonical representation), §21 (JSON + CBOR, đóng băng CSME Core v0.1).

CSME là lớp ổn định của Communication Stack; transport bên dưới (Unix socket, QUIC, MQTT…) có thể thay mà không đổi CSME.

## Cấu trúc

```
COSE_Sign1 (RFC 9052), tagged (CBOR tag 18)
  protected header:
    1  alg           = -19  (Ed25519, fully-specified)           ← bắt buộc, khác → E_ALG
    3  content type  = "application/chitala-csme"                ← bắt buộc
    4  kid           = 16 byte key id của người ký (spec 02)    ← bắt buộc
  unprotected header: rỗng                                       ← bắt buộc
  payload: deterministic CBOR map (bên dưới)                     ← không detached
  signature: Ed25519 trên Sig_structure("Signature1", protected, b"", payload)
```

Không chấp nhận `EdDSA (-8)` đã deprecated, không chấp nhận tham số `crit` của COSE, không chấp nhận header lạ. Content type nằm trong phần được ký nên một chữ ký CSME không thể bị diễn giải lại thành chữ ký của định dạng khác (v4 §14).

## Payload map

| Key | Trường (v4 §3) | Kiểu | Bắt buộc |
|---:|---|---|---|
| 1 | protocolVersion | uint, = 1 | ✓ |
| 2 | messageId — đồng thời là nonce chống replay | bstr(16), ngẫu nhiên | ✓ |
| 3 | correlationId | bstr(16) | |
| 4 | source (endpoint gửi) | tstr EntityId | ✓ |
| 5 | destination (target) | tstr EntityId | ✓ |
| 6 | actorIdentity — PHẢI là người ký | tstr EntityId | ✓ |
| 7 | capabilityId | tstr | ✓ |
| 8 | capability version | uint | ✓ |
| 9 | messageType: 1 command · 2 event · 3 intent · 4 goal · 5 query · 6 response | uint | ✓ |
| 10 | timestamp (issued at, ms) | uint | ✓ |
| 11 | expiry (ms) | uint | ✓ |
| 12 | contextRef | tstr ≤ 128 | |
| 13 | authorityRef — capability token (spec 05) | bstr 1..4096 | |
| 14 | safetyClass = `RiskClass` | uint 0–3 | ✓ |
| 15 | payload `tstr → bool/int/tstr`, bỏ khi rỗng | map ≤ 32 mục | |
| 16 | critical extensions | array of uint | |

Toàn bộ COSE ≤ 16 KiB. Độ sâu lồng ≤ 8.

## Canonical encoding

Payload PHẢI ở dạng deterministic CBOR (RFC 8949 §4.2.1): số nguyên dạng ngắn nhất, độ dài xác định, khóa map sắp theo thứ tự byte của bản mã hóa, không trùng khóa, không float, không null, không tag. Bên nhận giải mã rồi mã hóa lại; khác một byte (kể cả byte thừa phía sau) → `E_NON_CANONICAL`. Nhờ vậy mỗi message có đúng một biểu diễn, và hash/chữ ký so sánh được giữa các implementation.

## Version và extension (v4 §7)

- `protocolVersion ≠ 1` hoặc thiếu → `E_VERSION`. Phiên bản lõi chỉ tăng khi có thay đổi phá vỡ.
- Khóa không biết (≥ 17) được **bỏ qua an toàn**, trừ khi được liệt kê trong key 16 → `E_CRITICAL_EXT` (fail closed).
- Message type 3 (intent) và 4 (goal) được giữ chỗ cho v15 Planning; monitor v0.1 trả `E_UNSUPPORTED_TYPE`.

## Thứ tự xử lý của bên nhận

1. Kiểm tra cấu trúc COSE và protected header (chưa đụng tới payload).
2. Tìm khóa theo `kid`, **xác minh chữ ký**.
3. Chỉ sau đó mới giải mã payload CBOR.

Parser payload vì vậy không bao giờ nhận byte từ người gửi chưa xác thực — thu nhỏ bề mặt tấn công parser (v13 §9). Fuzz/property test: `garbage_never_opens`, `signed_garbage_never_panics`.

## Chống replay

`messageId` 128 bit ngẫu nhiên là nonce; cặp `(kid, messageId)` chỉ dùng được một lần trong cửa sổ hiệu lực (spec 08). `expiry − timestamp ≤ 60 s`.
