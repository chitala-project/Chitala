# 05 — Capability Token

Nguồn: v8 §2 (Capability Token cực hẹp), v8 §8 (delegation không khuếch đại quyền), v12 §18 (cross-domain capability), v13 §3 (audience-bound, object-scoped).

## Định dạng

Token là một [Biscuit](https://www.biscuitsec.org/) (Ed25519) ký bằng **khóa authority của domain** (không phải khóa toàn cục — C7). Authority block:

```datalog
chitala_token(1);                                   // phiên bản định dạng
holder("ai:assistant");                             // token chỉ dùng được bởi principal này
issuer("person:alice");                             // người ủy quyền
depth(1);                                           // 1 = cấp từ quyền ambient; tối đa 3
expires_ms(1790999985000);                          // căn theo giây
right("device:living-room-light", "light.turn_on"); // 1..32 quyền tường minh, không wildcard
parent("<revocation id của token cha>");            // chỉ có ở token ủy quyền lại
check if time($t), $t < 2026-10-03T…Z;
```

Giới hạn: ≤ 4096 byte, ≤ 8 block, ≤ 32 right. Revocation id của token = hex chữ ký của authority block (128 ký tự hex).

## Ánh xạ v8 §2 → token

| Thuộc tính (v8 §2) | v0.1 |
|---|---|
| Actor | `holder` — holder-bound: CSME phải được ký bởi chính holder |
| Target, Capability | `right(target, capability)` |
| Context | (dự phòng) attenuation block có thể ràng buộc thêm |
| Time | `expires_ms` + `check if time` |
| Rate/quantity | rate limit theo actor ở monitor (30 request/10 s); quota theo token: sau v0.1 |
| Safety budget | registry envelope + policy (không nằm trong token) |
| Delegation chain | `issuer`, `depth`, `parent(...)` |
| Revocation | revocation list của domain; lan xuống mọi token con |

## Xác minh và ủy quyền một request

1. Chữ ký chuỗi block bằng khóa authority của domain (sai → `E_TOKEN_INVALID`).
2. Bất kỳ revocation id nào của token (mọi block + mọi `parent`) nằm trong revocation list → `E_TOKEN_REVOKED`.
3. Authorizer chèn `actor`, `target`, `capability`, `time` của request và chạy:
   `allow if actor($a), holder($a), target($t), capability($c), right($t, $c);`
   Mọi `check` của mọi block phải đạt. Không đạt → `E_TOKEN_DENIED`.

Token hợp lệ chỉ đặt `context.token_granted = true` cho policy; Constitution vẫn có thể `forbid` (ví dụ AI có token `lock.unlock` vẫn bị `C11-ai-no-high-risk`).

## Thu hẹp offline (attenuation)

Holder có thể tự thêm block chỉ chứa `check` (giới hạn target, capability, thời hạn ngắn hơn) mà không cần hỏi ai. Biscuit bảo đảm block sau **chỉ thu hẹp**: fact `right`/`holder` trong block attenuation không được authority block hay authorizer tin (test `attenuation_block_cannot_inject_rights_or_holder`).

## Ủy quyền cho principal khác (server-mediated)

Đổi `holder` không thể làm offline — phải qua `domain.delegate` (spec 11), node kiểm tra:

| Quy tắc | Lỗi |
|---|---|
| Người ủy quyền là holder của token cha (hoặc có quyền ambient theo policy khi không có token cha) | `X_DELEGATION_DENIED` |
| `child.rights ⊆ parent.rights` và token cha thực sự authorize từng quyền lúc này | `X_DELEGATION_DENIED` |
| `child.expiry = min(yêu cầu, parent.expiry)` | (tự cắt) |
| `depth ≤ 3` | `X_DELEGATION_DENIED` |
| Token cha **không** được là token đã attenuate (các check của nó sẽ bị mất khi cấp token mới) | `X_DELEGATION_DENIED` |
| Không tự ủy quyền cho chính mình | `X_DELEGATION_DENIED` |
| Holder phải *có thể* dùng quyền đó theo policy (`token_granted = true`) — không cấp cho AI một quyền mà Constitution cấm nó dùng | `X_DELEGATION_DENIED` |

Property test `delegation_never_amplifies` kiểm chứng: với mọi tập quyền cha/con và mọi thời hạn, token con không bao giờ authorize một quyền mà token cha không có.

## Ghi chú bảo mật

- Token nằm trong CSME (key 13) và vì vậy đi qua IPC; một bên nghe lén lấy được token **không dùng được** vì token holder-bound và CSME phải có chữ ký của holder.
- Token không bao giờ được ghi vào audit log: log chỉ chứa revocation id (`parent_token` bị redact — spec 09).
- File token trên đĩa có quyền `0600` trong thư mục `0700`.
