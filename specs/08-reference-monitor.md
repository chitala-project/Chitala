# 08 — Reference Monitor

Nguồn: v8 §1 (Non-bypassable AI Reference Monitor), v11 §16.1, v13 §3 (confused deputy), v17 §3 ("Mọi sensitive operation phải đi qua Reference Monitor").

```
AI / App / Person → (CSME đã ký) → Reference Monitor → Adapter / Domain operation
```

## Không thể bypass

Trong implementation tham chiếu, kết quả cho phép là kiểu `Authorized`: không có constructor public, không `Clone`, không `Default`. Adapter và domain operation chỉ nhận `&Authorized`, nên không có đường code nào điều khiển thiết bị mà không qua `Monitor::check` — kể cả code test (spec 10). Monitor nằm ngoài tiến trình AI và chỉ gồm code Rust memory-safe (`#![forbid(unsafe_code)]`).

## Pipeline

Lỗi đầu tiên dừng pipeline và trả mã tương ứng. Thứ tự là một phần của hợp đồng.

| # | Stage | Kiểm tra | Mã |
|---|---|---|---|
| 1 | envelope | COSE hợp lệ, kích thước, header | `E_DECODE` |
| | | alg = Ed25519 (-19) | `E_ALG` |
| | | không có COSE `crit` | `E_CRITICAL_EXT` |
| 2 | identity | `kid` đã enroll | `E_UNKNOWN_KEY` |
| | | chữ ký | `E_BAD_SIGNATURE` |
| | | payload: CBOR, canonical, version, crit, message type | `E_DECODE`, `E_NON_CANONICAL`, `E_VERSION`, `E_CRITICAL_EXT`, `E_UNSUPPORTED_TYPE` |
| | | actor = người ký | `E_ACTOR_KEY_MISMATCH` |
| | | security state cho phép hành động | `E_PRINCIPAL_STATE` |
| | | ≤ 30 request / 10 s / actor | `E_RATE_LIMITED` |
| 3 | freshness | type ∈ {command, query} | `E_UNSUPPORTED_TYPE` |
| | | `timestamp ≤ now + 5 s` | `E_NOT_YET_VALID` |
| | | `timestamp < expiry`, `now < expiry` | `E_EXPIRED` |
| | | `expiry − timestamp ≤ 60 s` | `E_LIFETIME_TOO_LONG` |
| | | `timestamp ≥` thời điểm node khởi động | `E_REPLAY` |
| | | `(kid, messageId)` chưa từng thấy | `E_REPLAY` |
| 4 | capability | target tồn tại trong domain | `E_UNKNOWN_TARGET` |
| | | capability có trong registry | `E_UNKNOWN_CAPABILITY` |
| | | version khớp | `E_CAPABILITY_VERSION` |
| | | target hỗ trợ capability, đúng loại target | `E_UNSUPPORTED_BY_TARGET` |
| | | action ↔ command, query ↔ query | `E_KIND_MISMATCH` |
| | | risk khai báo = risk của registry | `E_RISK_MISMATCH` |
| | | risk ≤ trần của security state (spec 03 M3) | `E_PRINCIPAL_STATE` |
| | | payload theo schema / trong safety envelope | `E_PAYLOAD_INVALID` / `E_SAFETY_ENVELOPE` |
| 5 | authority | principal không phải người PHẢI có token | `E_TOKEN_MISSING` |
| | | token: chữ ký domain, thu hồi, authorize | `E_TOKEN_INVALID`, `E_TOKEN_REVOKED`, `E_TOKEN_DENIED` |
| | | policy (Cedar) | `E_POLICY_DENIED`, `E_POLICY_ERROR` |

`E_INTERNAL` dành cho lỗi nội bộ không lường trước; luôn là deny.

## Quy tắc bảo mật của pipeline

- **Xác thực trước khi parse** (spec 07).
- **Không quy lỗi cho người chưa xác thực**: denial trước khi chữ ký được xác minh có `authenticated = false` và không mang `actor`. Kẻ tấn công giả mạo request đứng tên người khác không thể làm nạn nhân bị containment (spec 11).
- **Request dùng một lần**: `messageId` bị tiêu thụ ngay sau stage 3, kể cả khi stage sau từ chối. Một request bị từ chối hôm nay không thể được phát lại sau khi quyền được cấp (test `denied_request_cannot_be_replayed_after_a_grant`).
- **Replay qua restart**: replay cache nằm trong RAM, nên mọi request ký trước thời điểm node khởi động đều bị từ chối.
- **Khai báo risk thấp hơn thực tế** để lách policy → `E_RISK_MISMATCH`.
- **Confused deputy** (v13 §3): monitor luôn đánh giá quyền của *actor đã ký* — broker MCP ký bằng khóa của AI, không bằng khóa của chính nó.
- Kích thước replay cache bị chặn (100 000); khi đầy và không dọn được → từ chối (`E_RATE_LIMITED`) thay vì quên nonce.

## Phản hồi cho người gửi

Lý do chi tiết (`reason`) chỉ được trả cho requester đã xác thực; request chưa xác thực chỉ nhận mã lỗi (v4 §5 hạn chế lộ metadata).
