# Chitala OS

**Hệ điều hành cho thế giới mà con người, AI, robot, thiết bị và compute phân tán cùng tác động lên thế giới vật lý — Security & Safety by Design.**

Chitala xem Human, AI/Agent, Robot, Device, Service và Compute là các principal có identity, capability, authority, state và provenance. Nó có thể chạy trên Linux/macOS/Windows/RTOS trong giai đoạn bootstrap (**Hosted Mode**), nhưng kiến trúc không phụ thuộc host OS, ISA, AI runtime, giao thức hay cloud; đích dài hạn là **Chitala Native** — boot thẳng trên phần cứng. Blueprint hiện hành: **v20** (`Chitala_OS_Blueprint_2026_2046_v20.pdf`); đối chiếu với code: [`docs/v20-alignment.md`](docs/v20-alignment.md).

Repository này là **implementation tham chiếu v0.0.x** bằng Rust, chạy ở Hosted Mode: trước hết là một *Trusted Core* nhỏ, kiểm chứng được — chưa phải AI, chưa phải UI, chưa phải kernel.

```
Principal → Identity → Capability → Intent → Authority → Reference Monitor → Execution → State → Audit
```

> **Invariant số 1 — AI produces Intent. Chitala produces Authority. Only the trusted execution boundary produces physical Commands.**

AI không bao giờ gửi lệnh. Nó gửi một *intent* đã ký: *actor → on_behalf_of → action → resource → context → constraints → requested_at*. Authority Engine trả lời WHO → ON_BEHALF_OF → WHAT → OBJECT → CONTEXT → DELEGATION → RISK → APPROVAL → ALLOW/DENY/ESCALATE; một lớp Safety độc lập chỉ có thể từ chối; và chỉ ranh giới thực thi tin cậy của node mới tạo lệnh vật lý. Đó là thứ làm Chitala khác một MCP gateway. Spec: [14 Resource](specs/14-resource-model.md) · [15 Intent](specs/15-intent.md) · [16 Authority Engine](specs/16-authority-engine.md) · [17 Safety](specs/17-safety.md).

## Trạng thái

| Milestone (v17 §18) | | |
|---|---|---|
| 0.0.1 | Đèn ảo bật/tắt có ủy quyền + state + audit; AI không quyền → DENY → security event → audit | ✅ |
| 0.0.2 | Nhiều user/device; delegation và revocation | ✅ |
| 0.0.3 | Adapter HTTP/MQTT/WoT + virtual home | 🟡 virtual home, Home Assistant REST |
| **Physical Authority Slice v0.1** | MCP → Intent → Authority → Safety → Approval → Capability → cửa mô phỏng | ✅ |

| # | Case của Physical Authority Slice v0.1 | Bắt buộc | |
|---|---|---|---|
| 1 | AI của owner → bật đèn | ALLOW | ✅ |
| 2 | AI của khách → bật đèn được ủy quyền | ALLOW | ✅ |
| 3 | AI của trẻ → mở cửa khi không có quyền | DENY | ✅ |
| 4 | AI của owner → mở cửa (rủi ro cao) | ESCALATE → con người duyệt | ✅ |
| 5 | AI A → nhờ AI B mở cửa để né policy | DENY | ✅ |

166 test (unit, integration, property-based) và 11 fuzz target, gồm một bộ test tấn công: node giả mạo, rollback state, xóa audit, replay, prompt injection, khuếch đại quyền qua delegation, rửa quyền qua AI khác, phê duyệt giả, approval fatigue… Xem [`specs/13-threat-model.md`](specs/13-threat-model.md).

## Thử ngay

Cần Rust ≥ 1.89 (MSRV được CI kiểm tra).

```bash
cargo test --workspace          # toàn bộ test
cargo run -p chitala-cli -- demo # Physical Authority Slice v0.1 trong bộ nhớ, giải thích từng bước
```

Chạy một Home Node thật với 4 thiết bị ảo:

```bash
cargo build --workspace
B=target/debug
$B/chitala init ./home
export CHITALA_CONFIG=./home/chitala.json
$B/chitala node &                                   # Home Node trên Unix socket

$B/chitala invoke --as person:alice device:living-room-light light.turn_on   # người: request trực tiếp
$B/chitala invoke --as ai:assistant device:living-room-light light.turn_off  # DENY E_INTENT_REQUIRED
$B/chitala intent --as ai:assistant resource:living-room-light light.turn_off # DENY E_TOKEN_MISSING
$B/chitala delegate --as person:alice --to ai:assistant resource:front-door lock.unlock  # token → home/tokens/
$B/chitala intent --as ai:assistant resource:front-door lock.unlock --purpose "thợ sửa ống nước"
                                                    # ESCALATE (exit 4): chờ alice
$B/chitala approvals --as person:alice              # xem đúng yêu cầu, kèm digest
$B/chitala approve --as person:alice <intent-id>    # ALLOW → cửa mở khóa
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
| `chitala-identity` | Khóa Ed25519 riêng cho từng principal, registry, quan hệ đại diện (`serves`) | 02, 15 |
| `chitala-resource` | Resource Model: thế giới vật lý được quản trị (sở hữu, cây cha/con, vị trí, state ref, binding) | 14 |
| `chitala-intent` | Intent và Approval: wire format ký, chuỗi relay, kiểu `Verified*` không làm giả được | 15 |
| `chitala-token` | Capability token (Biscuit): holder-bound, thu hẹp offline, delegation không khuếch đại, thu hồi | 05 |
| `chitala-policy` | Cedar policy + Security Constitution, schema sinh từ registry; **Authority Engine** | 00, 06, 16 |
| `chitala-safety` | Lớp safety độc lập, chỉ có thể từ chối (SAFE-1…6) | 17 |
| `chitala-csme` | Chitala Secure Message Envelope: COSE_Sign1 + canonical CBOR | 07 |
| `chitala-monitor` | Reference Monitor — điểm quyết định duy nhất, không thể bypass | 08 |
| `chitala-audit` | Audit log chuỗi hash, checkpoint ký, redaction, anchor chống rollback | 09 |
| `chitala-state`, `chitala-bus` | Digital Twin (reported/desired/drift), event bus ưu tiên event bảo mật | 10 |
| `chitala-adapters` | Adapter host tách tiến trình (chỉ nhận lệnh ký bằng khóa node), thiết bị ảo, bridge Home Assistant | 10 |
| `chitala-node` | Home Node: IPC ký hai chiều, đường intent, hàng chờ phê duyệt, **trusted execution boundary**, thao tác domain, containment, kiểm tra toàn vẹn khi khởi động; binary `chitala-adapter-host` | 11, 15–17 |
| `chitala-mcp` | AI Action Broker qua Model Context Protocol — chỉ phát intent | 12 |
| `chitala-cli` | Lệnh `chitala` | — |

Đặc tả (tiếng Việt) nằm trong [`specs/`](specs/README.md); policy mặc định ở [`specs/policy/default.cedar`](specs/policy/default.cedar), registry ở [`specs/registry/capabilities-v0.1.json`](specs/registry/capabilities-v0.1.json).

## Nguyên tắc bảo mật

- **AI produces Intent. Chitala produces Authority. Only the trusted execution boundary produces physical Commands.**
- AI là principal **không tin cậy mặc định**: không có ambient authority, chỉ hành động cho người mà nó được khai báo phục vụ, qua token do con người ủy quyền; hành động rủi ro cao luôn cần owner duyệt; không sửa cơ chế bảo vệ (Security Constitution C11/C12).
- Nhờ AI khác không thêm quyền: quyền của một chuỗi relay là giao của mọi mắt xích.
- Safety độc lập với policy và chỉ có thể từ chối; một approval của con người cũng không vượt qua được safety.
- Mọi request đều có chữ ký và đi qua Reference Monitor; mọi phản hồi của node đều có chữ ký và gắn với đúng request.
- Delegation chỉ thu hẹp quyền (property test), thu hồi lan xuống mọi token con.
- Không có bằng chứng thì không hành động: quyết định được ghi vào audit trước khi thực thi.
- Fail closed: policy lỗi, audit hỏng, state bị rollback hay node panic đều dẫn tới từ chối.
- Toàn bộ code `#![forbid(unsafe_code)]`.

## Roadmap và giấy phép

Dòng `0.0.x` đang **đóng băng tính năng** để hoàn thiện Trusted Core; thứ tự ưu tiên ở [`ROADMAP.md`](ROADMAP.md).

Báo lỗi bảo mật: xem [`SECURITY.md`](SECURITY.md) — xin đừng mở issue công khai.

Giấy phép [Apache-2.0](LICENSE).
