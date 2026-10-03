# 11 — Home/Site Node, IPC và vận hành

Nguồn: v9 "Chitala Home/Site Server", v10 §2/§6–8/§10–11 (manager authentication, khóa, revocation), v8 §9 (containment tự động), v13 §7 (anti-rollback), §8 (anti-DoS), §11 (Security State Machine), v17 §3–4.

## Config (`chitala.json`)

```json
{
  "domain": "domain:home",
  "node_id": "service:node",
  "authority_public_key": "<hex>",
  "node_public_key": "<hex>",
  "keys_dir": "keys",
  "socket": "chitala.sock",
  "audit_log": "audit.audit.jsonl",
  "state_file": "domain-state.json",
  "policy_file": null,
  "principals": [ { "id": "person:alice", "public_key": "<hex>", "roles": ["owner"] } ],
  "devices":    [ { "id": "device:front-door", "name": "…", "adapter": "mock",
                    "capabilities": ["device.read_state", "lock.lock", "lock.unlock"],
                    "security_class": "SC3", "room": "entrance" } ],
  "home_assistant": { "base_url": "https://…", "token_env": "HA_TOKEN", "entities": {}, "allow_insecure_http": false },
  "containment": { "window_ms": 60000, "suspicious_after": 5, "restricted_after": 10, "quarantine_after": 20 }
}
```

Config chỉ chứa **khóa công khai**. Đường dẫn tương đối tính từ thư mục chứa config.

## Quyền file

| Đối tượng | Quyền | Thực thi |
|---|---|---|
| `keys/`, `tokens/` | `0700` | `chitala init` |
| file khóa | `0600`; group/others đọc được → **từ chối dùng** (như ssh) | `read_key` |
| audit log, state file | `0600`; audit ghi được bởi group/others → từ chối mở | node |
| socket | `0600` | node |

## IPC

JSON Lines qua Unix domain socket: `{"op":"hello"}`, `{"op":"submit","csme":"<hex>"}`. Giới hạn: dòng ≤ 64 KiB, ≤ 64 kết nối đồng thời, timeout đọc/ghi 30 s. Lỗi giao thức → đóng kết nối.

**Socket không phải ranh giới tin cậy** (v9 §13): mọi request là CSME có chữ ký và qua Reference Monitor.

### Xác thực ngược chiều (v10 §2)

Mọi phản hồi được node ký:

```
reply.request = hex( SHA-256(request bytes)[0..16] )
reply.node, reply.kid
reply.sig     = Ed25519_node( "chitala-node-reply-v1" 0x00 ‖ JCS(reply không có "sig") )
```

Client PHẢI xác minh `sig` bằng `node_public_key` **ghim trong config**, và `request` khớp đúng request vừa gửi. Không khớp → bỏ phản hồi. Nhờ đó tiến trình giả mạo socket không thể báo "allow" giả, trao token giả, hay lấy phản hồi thật của request khác đem trả lời request này (test `client_refuses_an_impostor_node`, `forged_or_misbound_replies_are_rejected`).

### Đường dẫn socket

Đường dẫn Unix socket bị giới hạn khoảng 104 byte (macOS). Nếu đường dẫn cấu hình dài hơn, node và client cùng dùng `/tmp/chitala-<uid>/<hash>.sock`. Thư mục `/tmp/chitala-<uid>` PHẢI là thư mục thật (không phải symlink), thuộc chủ của thư mục domain và có quyền `0700`; nếu không, node từ chối. Node chỉ xóa file cũ khi đó thật sự là socket và không có tiến trình nào đang nghe.

## Thao tác domain

Đều là capability có `target = domain`, đi qua cùng Reference Monitor và policy.

| Capability | Ai (policy mặc định) | Kiểm tra thêm ở node |
|---|---|---|
| `domain.list_devices` | owner, admin, adult; AI chỉ khi có token | — |
| `domain.delegate` | owner, admin, adult; **không AI** (C11) | spec 05 "Ủy quyền cho principal khác" |
| `domain.revoke_token` | owner, admin, adult; không AI | người gọi phải là issuer trong chuỗi delegation của token, hoặc owner/admin |
| `domain.set_principal_state` | owner, admin; không AI | chuyển trạng thái hợp lệ (spec 03); không tự đổi trạng thái của chính mình |

Mỗi thay đổi về quyền: `epoch += 1` → ghi state file → ghi audit có checkpoint ký → phát event.

## Containment tự động (v8 §9, v11 §16.4)

Chỉ áp dụng cho principal **không phải người**, và chỉ với denial **đã xác thực** thuộc nhóm dò quyền: `E_PRINCIPAL_STATE`, `E_TOKEN_MISSING`, `E_TOKEN_INVALID`, `E_TOKEN_REVOKED`, `E_TOKEN_DENIED`, `E_POLICY_DENIED`, `E_UNKNOWN_TARGET`, `E_UNKNOWN_CAPABILITY`, `E_UNSUPPORTED_BY_TARGET`, `E_RISK_MISMATCH`, `E_REPLAY`, `E_RATE_LIMITED`. Trong cửa sổ 60 s: 5 lần → `SUSPICIOUS`, 10 → `RESTRICTED`, 20 → `QUARANTINED`.

- Lỗi trung thực (hết hạn do lệch đồng hồ, sai tham số) không bị tính.
- Request giả mạo đứng tên người khác không bị tính (chưa xác thực).
- Máy chỉ **leo thang**, không bao giờ tự hạ: đưa về `TRUSTED` là quyết định của con người, qua `RECOVERY → RE_ATTEST → TRUSTED`.
- Con người không bị cách ly tự động (tránh tự khóa owner); họ vẫn bị rate limit.

## Thời gian (Blueprint v16 §4, threat model R3)

Hạn của token, request và lệnh thực thi đều dựa vào thời gian của node. Đồng hồ hệ thống chỉ là **đầu vào**, không phải authority:

```
now = max(đồng hồ hệ thống, lần đọc trước + thời gian trôi đo bằng đồng hồ monotonic)
```

- **Không bao giờ lùi**: đồng hồ hệ thống bị chỉnh lùi (kẻ tấn công muốn hồi sinh token đã hết hạn, pin RTC hỏng, NTP step sai) bị bỏ qua; thời gian tiếp tục trôi theo đồng hồ monotonic, và mỗi lần lùi ≥ 1 s được ghi vào audit (`kind: "clock"`, `event: "wall_clock_regression"`) kèm checkpoint ký.
- **Theo các hiệu chỉnh tiến** (NTP đồng bộ sau khi khởi động): đi tiến là hướng an toàn — token/request chỉ có thể hết hạn sớm hơn.
- **Sàn**: node không bao giờ bắt đầu sớm hơn sự kiện cuối cùng trong audit log (`max ts_ms`).
- **Khởi động**: nếu đồng hồ hệ thống chậm hơn sự kiện cuối trong audit quá 60 s, node **từ chối khởi động** — sửa giờ hệ thống trước.
- Adapter host dùng cùng thuật toán, nên node và host thống nhất về hạn của lệnh thực thi.

Kiểm chứng: `time::clock_rollback_cannot_revive_an_expired_token`, `time::startup_refuses_a_clock_behind_the_audit`, `clock::tests::*`.

Giới hạn: chưa có nguồn thời gian có xác thực (NTS/Roughtime) hay đồng hồ phần cứng tin cậy; đồng bộ thời gian giữa nhiều node là việc của giai đoạn phân tán.

## Toàn vẹn khi khởi động

Trước khi nhận request, node kiểm tra:

1. Khóa authority và khóa node trên đĩa khớp với khóa công khai trong config.
2. Toàn bộ chuỗi audit hợp lệ, checkpoint ký đúng.
3. Audit còn chứa `audit_anchor` ghi trong state file → phát hiện audit bị **xóa, cắt hoặc thay**.
4. `epoch` lớn nhất trong audit ≤ `epoch` của state file → phát hiện state file bị **rollback hoặc xóa**. Đây là kiểu tấn công gỡ thu hồi token bằng cách chép đè một bản state cũ.
5. Đồng hồ hệ thống không chậm hơn sự kiện cuối trong audit quá 60 s (xem "Thời gian").
6. Mọi request ký trước thời điểm khởi động bị từ chối (replay cache không sống qua restart).

Bất kỳ kiểm tra nào thất bại → `NodeError::Integrity`, **node không khởi động**: thà dừng còn hơn âm thầm quên các lần thu hồi hoặc cách ly (fail closed).

Thứ tự ghi (state trước, audit sau) bảo đảm sự cố mất điện giữa hai bước chỉ để lại state *mới hơn* audit, trường hợp được chấp nhận, không bị nhầm là rollback.

### Recovery

Khi node từ chối khởi động vì integrity, người vận hành điều tra (`chitala audit verify`), khôi phục cặp state + audit nhất quán từ backup sạch (v11 §21.1), rồi mới khởi động lại. Không có cờ "bỏ qua kiểm tra".

**Giới hạn đã biết**: kẻ có quyền ghi file có thể cùng lúc thay state cũ *và* cắt audit về đúng anchor cũ; hai file trên cùng một đĩa không tự chứng minh được độ mới. Cần một anchor bên ngoài như TPM monotonic counter, checkpoint đẩy ra thiết bị khác, hoặc transparency log (spec 13).

## Lỗi bên trong node

Nếu một request làm node panic giữa chừng (mutex poisoned), node coi trạng thái của mình không còn đáng tin và **từ chối mọi request** cho tới khi khởi động lại.
