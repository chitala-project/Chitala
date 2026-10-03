# Chitala OS

**Distributed operating fabric cho thế giới vật lý và trí tuệ phân tán — Security & Safety by Design.**

Chitala không phải kernel mới. Nó là lớp chuẩn hóa chạy trên Linux/RTOS/MCU/server, giúp người, ứng dụng, thiết bị, robot và AI nhận diện nhau, mô tả khả năng, trao quyền, giao tiếp và hành động an toàn. Tầm nhìn đầy đủ nằm trong Blueprint 2026–2046 (`Chitala_OS_Blueprint_2026_2046_*.pdf`).

Repository này là **implementation tham chiếu v0.0.x** bằng Rust, theo thứ tự xây dựng của Blueprint v17: trước hết là một *Trusted Core* nhỏ, kiểm chứng được — chưa phải AI, chưa phải UI.

```
Identity → Capability → Authority → Reference Monitor → Message → Device Action → State → Audit
```

## Trạng thái

| Milestone (v17 §18) | | |
|---|---|---|
| 0.0.1 | Đèn ảo bật/tắt có ủy quyền + state + audit; AI không quyền → DENY → security event → audit | ✅ |
| 0.0.2 | Nhiều user/device; delegation và revocation | ✅ |
| 0.0.3 | Adapter HTTP/MQTT/WoT + virtual home | 🟡 virtual home, Home Assistant REST |

94 test (unit, integration, property-based), gồm một bộ test tấn công: node giả mạo, rollback state, xóa audit, replay, prompt injection, khuếch đại quyền qua delegation… Xem [`specs/13-threat-model.md`](specs/13-threat-model.md).

## Thử ngay

Cần Rust ≥ 1.89 (MSRV được CI kiểm tra).

```bash
cargo test --workspace          # toàn bộ test
cargo run -p chitala-cli -- demo # kịch bản 0.0.1/0.0.2 chạy trong bộ nhớ, có giải thích từng bước
```

Chạy một Home Node thật với 4 thiết bị ảo:

```bash
cargo build --workspace
B=target/debug
$B/chitala init ./home
export CHITALA_CONFIG=./home/chitala.json
$B/chitala node &                                   # Home Node trên Unix socket

$B/chitala invoke --as person:alice device:living-room-light light.turn_on
$B/chitala invoke --as ai:assistant device:living-room-light light.turn_off    # DENY E_TOKEN_MISSING
$B/chitala delegate --as person:alice --to ai:assistant \
                    device:living-room-light light.set_brightness --ttl 600     # token → home/tokens/
$B/chitala invoke --as ai:assistant --token home/tokens/ai-assistant.token \
                  device:living-room-light light.set_brightness brightness_pct=30
$B/chitala audit verify
```

Cho một AI (MCP client như Claude Desktop) dùng thiết bị trong phạm vi được ủy quyền:

```bash
$B/chitala-mcp --config ./home/chitala.json --as ai:assistant
```

> `chitala init` đặt mọi khóa của domain mẫu vào một thư mục `keys/` (quyền 0700) để thử trên một máy. Khi triển khai thật, khóa của mỗi người nằm trên thiết bị của chính họ; khóa authority nên nằm trong TPM/secure element.

## Cấu trúc

| Crate | Vai trò | Spec |
|---|---|---|
| `chitala-model` | Định danh, thang phân loại, capability registry, payload | 01, 03, 04 |
| `chitala-identity` | Khóa Ed25519 riêng cho từng principal, registry | 02 |
| `chitala-token` | Capability token (Biscuit): holder-bound, thu hẹp offline, delegation không khuếch đại, thu hồi | 05 |
| `chitala-policy` | Cedar policy + Security Constitution, schema sinh từ registry | 00, 06 |
| `chitala-csme` | Chitala Secure Message Envelope: COSE_Sign1 + canonical CBOR | 07 |
| `chitala-monitor` | Reference Monitor — điểm quyết định duy nhất, không thể bypass | 08 |
| `chitala-audit` | Audit log chuỗi hash, checkpoint ký, redaction, anchor chống rollback | 09 |
| `chitala-state`, `chitala-bus` | Digital Twin (reported/desired/drift), event bus ưu tiên event bảo mật | 10 |
| `chitala-adapters` | Adapter host tách tiến trình (chỉ nhận lệnh ký bằng khóa node), thiết bị ảo, bridge Home Assistant | 10 |
| `chitala-node` | Home Node: IPC ký hai chiều, thao tác domain, containment, kiểm tra toàn vẹn khi khởi động; binary `chitala-adapter-host` | 11 |
| `chitala-mcp` | AI Action Broker qua Model Context Protocol | 12 |
| `chitala-cli` | Lệnh `chitala` | — |

Đặc tả (tiếng Việt) nằm trong [`specs/`](specs/README.md); policy mặc định ở [`specs/policy/default.cedar`](specs/policy/default.cedar), registry ở [`specs/registry/capabilities-v0.1.json`](specs/registry/capabilities-v0.1.json).

## Nguyên tắc bảo mật

- AI là principal **không tin cậy mặc định**: không có ambient authority, chỉ hành động qua token do con người ủy quyền, không bao giờ làm việc rủi ro cao hay sửa cơ chế bảo vệ (Security Constitution C11/C12).
- Mọi request đều có chữ ký và đi qua Reference Monitor; mọi phản hồi của node đều có chữ ký và gắn với đúng request.
- Delegation chỉ thu hẹp quyền (property test), thu hồi lan xuống mọi token con.
- Không có bằng chứng thì không hành động: quyết định được ghi vào audit trước khi thực thi.
- Fail closed: policy lỗi, audit hỏng, state bị rollback hay node panic đều dẫn tới từ chối.
- Toàn bộ code `#![forbid(unsafe_code)]`.

## Roadmap và giấy phép

Dòng `0.0.x` đang **đóng băng tính năng** để hoàn thiện Trusted Core; thứ tự ưu tiên ở [`ROADMAP.md`](ROADMAP.md).

Báo lỗi bảo mật: xem [`SECURITY.md`](SECURITY.md) — xin đừng mở issue công khai.

Giấy phép [Apache-2.0](LICENSE).
