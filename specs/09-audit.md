# 09 — Audit Log

Nguồn: v16 §3 (Structured Logging Contract), §4 (time integrity), §7 (Tamper-Evident Audit), §8 (Privacy & Secret Redaction), §27 (khi hệ thống logging lỗi); v13 §7 (anti-rollback).

## Định dạng bản ghi

JSON Lines, mỗi dòng một object ở dạng **canonical JSON** (RFC 8785, giới hạn ở string, số nguyên, bool, null, array, object — không float). Trường chung:

| Trường | Ý nghĩa |
|---|---|
| `v` | phiên bản định dạng = 1 |
| `seq` | 1, 2, 3, … liên tục |
| `ts_ms` | thời gian node |
| `kind` | `node` · `decision` · `execution` · `authority` · `security_state` · `checkpoint` |
| `prev` | `hash` của bản ghi trước (64 số 0 cho bản ghi đầu) |
| `hash` | xem dưới |

```
hash = SHA-256( "chitala-audit-v1" 0x00 ‖ prev(32 byte) ‖ JCS(bản ghi không có "hash") )
```

Trường theo `kind` (đều là contract ổn định, v16 §3):

- `decision`: `decision` (allow/deny), `code`, `stage`, `reason`, `authenticated`, `actor`, `mid`, `target`, `capability`, `risk`, `token` (revocation id, issuer, depth), `policy` (các `@id`), `policy_fp`, `epoch`, `payload` (đã redact, chỉ khi allow).
- `execution`: `mid`, `decision_seq`, `outcome`, `code`, `message`, `state_version`.
- `authority`: `op` (issue/revoke), `token`, `holder`, `issuer`, `right`, `depth`, `expires_at_ms`, `parent`, `by`, `epoch`.
- `security_state`: `principal`, `from`, `to`, `by`, `reason`, `epoch`.

## Checkpoint có chữ ký

```
sig = Ed25519_node( "chitala-audit-checkpoint-v1" 0x00 ‖ head(32 byte) ‖ seq(u64 big-endian) )
```

Bản ghi `checkpoint` (`signer`, `kid`, `sig`) cũng nằm trong chuỗi. Node ghi checkpoint: mỗi 64 bản ghi, **ngay sau mỗi thay đổi về quyền** (`authority`, `security_state`) và khi được yêu cầu. Khóa ký là khóa service của node, tách khỏi khóa authority (spec 02). Không có khóa ký toàn hệ sinh thái (v16 §7).

## Kiểm chứng

`chitala audit verify` chỉ cần **khóa công khai** của node lấy từ config, nên bên kiểm chứng độc lập với node đang bị điều tra (v16 §7). Phát hiện được: sửa nội dung, xóa, chèn, đổi thứ tự, định dạng không canonical, và kẻ tấn công tự tính lại hash mà không có khóa node (lộ ở checkpoint kế tiếp). Phần đuôi sau checkpoint cuối (`unsigned_tail`) chỉ được bảo vệ bởi chuỗi hash, không bởi chữ ký.

## Không ghi bí mật (v16 §8)

- Token không bao giờ vào log, chỉ revocation id.
- Tham số có tên chứa `password`, `passwd`, `secret`, `token`, `credential`, `private`, `pin`, hoặc là `key`/`*_key` → `"[REDACTED]"`.
- Text dài hơn 200 ký tự bị cắt.
- Payload của request bị từ chối không được ghi (có thể là rác hoặc nội dung tấn công).

## An toàn vận hành

- File log tạo với quyền `0600`; node từ chối mở log có thể ghi bởi group/others. Tamper-evident ≠ public (v16 §7).
- Mở log = kiểm chứng toàn bộ chuỗi trước; chuỗi hỏng → node không khởi động.
- **"Không có bằng chứng thì không hành động"**: một hành động đã được cho phép chỉ thực thi sau khi bản ghi `decision` của nó đã ghi xuống đĩa (`fsync`). Ghi thất bại → không thực thi (`X_INTERNAL`).
- **Anchor chống rollback**: state file của domain lưu `(seq, hash)` của audit tại thời điểm ghi; khi khởi động, log PHẢI còn chứa đúng bản ghi đó và không được ghi nhận `epoch` cao hơn state (spec 11 "Toàn vẹn khi khởi động").
