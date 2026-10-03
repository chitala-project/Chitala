# Đối chiếu Blueprint v20 với repository

Blueprint hiện hành: **v20** (`Chitala_OS_Blueprint_2026_2046_v20.pdf`, 03/10/2026). Tài liệu này ghi lại v20 thay đổi hướng đi ra sao so với v18/v19, repository hiện đáp ứng đến đâu, và thứ tự việc tiếp theo. Trạng thái đối chiếu: commit `5d9cd81` (Trusted Core v0.0.2 + hardening).

## 1. v20 thay đổi gì

| | v18 | v19 | **v20** |
|---|---|---|---|
| Định vị | Distributed OS fabric rất rộng | Authority & Safety Fabric (CASF); "OS" chỉ là tên hệ sinh thái | **Hệ điều hành độc lập**: Hosted Mode ngay bây giờ, Native Mode (boot thẳng trên phần cứng) là đích dài hạn |
| Quan hệ với Linux | Chạy trên Linux/RTOS | Chạy trên OS hiện có | Linux là nền **bootstrap**, không phải nền móng; kiến trúc không phụ thuộc host OS, ISA, AI runtime, giao thức hay cloud |
| Lớp mới | — | — | **Platform Abstraction Layer (PAL)**, System API, Native substrate, Fabric |
| Primitive mới trong Core | — | Intent, Context, Evidence… (ở mức khái niệm) | **Intent & Execution Lease**, **Resource Model** (compute/storage/network/actuator), principal Robot/Compute/Organization |
| Phạm vi | Mọi domain trong lõi | Future Profiles tách khỏi Core | Giữ cách tách Profiles của v19 và thêm luật kiểm soát độ phức tạp (§21) |

Hai điều v20 **giữ nguyên** từ trước: chuỗi kiểm soát (thêm Intent), và kỷ luật "Core nhỏ, kiểm chứng được; integration nằm ngoài TCB".

```
Principal → Identity → Capability → Intent → Authority → Reference Monitor → Execution → State → Audit
```

## 2. Definition of Done của v0.1 mới (v20 §22)

| Tiêu chí | Trạng thái |
|---|---|
| PAL tồn tại; Trusted Core không import API Unix trực tiếp ngoài backend | 🟡 `chitala-platform` + backend Memory/Hosted + contract tests trên branch `feat/pal` (tạm gác để làm domain model trước) |
| 94+ test hiện tại tiếp tục pass; thêm PAL contract tests | 🟡 166 test pass; PAL contract tests ở `feat/pal` |
| CI/security pipeline hoạt động | ✅ fmt → clippy → test (x86_64/ARM64/macOS) → audit → deny, MSRV, CodeQL, SBOM, zizmor, release ký + attestation |
| Coverage-guided fuzz cho CSME/token/IPC | ✅ 9 target libFuzzer + ASan, chạy trong CI |
| Intent v0.1 và Resource Model v0.1 có spec + implementation tối thiểu | ✅ spec 14–17; `chitala-resource`, `chitala-intent`, `chitala-safety`, Authority Engine; Physical Authority Slice v0.1 |
| Adapter isolation prototype | ✅ `chitala-adapter-host`, lệnh ký bằng khóa node, kill/restart, nhả khóa |
| Linux hosted node hoạt động như trước | ✅ (và cả macOS) |
| Native architecture ADR + boot experiment tối thiểu | ❌ |
| Threat model cập nhật cho ranh giới tin cậy hosted vs native | ❌ threat model hiện chỉ mô tả hosted |

**4/9 đạt, 1 đạt một phần, 4 chưa có.**

## 3. Việc v20 yêu cầu trong repository (§18)

| Việc | Trạng thái | Ghi chú |
|---|---|---|
| Crate `chitala-platform` với PAL traits: time, entropy, key store, storage, IPC, network, execution host | ❌ | Xem §4 |
| Đưa Unix socket, quyền/đường dẫn POSIX và system clock ra khỏi Trusted Core | ❌ | Xem §4 |
| `chitala-mcp`, Home Assistant, MQTT/WoT ở adapter layer, không định nghĩa core semantics | ✅ | MCP chỉ là broker ký CSME; HA nằm trong adapter host |
| Crate `chitala-resource` | ❌ | |
| Crate `chitala-intent`: typed intent, plan, execution lease; prompt không đi thẳng tới device action | ❌ | `ExecOrder` hiện có là dạng ký của một lease, nhưng thiếu resource budget và cancellation |
| Version negotiation và crypto agility cho CSME/wire formats | 🟡 | Có version check, `crit`, alg id tường minh; **chưa có negotiation, chưa có security suite registry** |
| CI: fmt, clippy, test, audit, deny; SBOM, signed release, reproducible build | 🟡 | Mọi mục đã có trừ **kiểm chứng build tái lập** |
| Fuzz CSME/token/IPC/adapters | ✅ | |
| Chaos/mixed-version tests | ❌ | |
| Tách adapter process khỏi node/monitor; giới hạn capability IPC | 🟡 | Đã tách tiến trình. **Chưa sandbox ở mức OS** và kênh IPC chưa scope theo capability |
| Native Architecture ADR, chưa triển khai kernel trước khi PAL ổn định | ❌ | |

## 4. PAL: các chỗ đang khóa vào host OS

Kiểm kê phụ thuộc host OS theo crate:

| Crate | Phụ thuộc host OS | PAL trait đề xuất |
|---|---|---|
| `model`, `policy`, `monitor`, `state`, `bus` | **không có** — đã thuần | — |
| `token` | không đọc đồng hồ (chỉ đổi kiểu thời gian sang Biscuit) | — |
| `identity` | `OsRng` khi sinh khóa; `Keypair` giữ seed trong RAM | `Entropy`, `SecureKeyStore` (ký theo key reference, không export key) |
| `csme` | `OsRng` cho message id | `Entropy` |
| `audit` | file append + `fsync`, kiểm tra quyền Unix | `Storage` (append-only log, atomic write, "private" thay cho mode bits) |
| `adapters::clock` | `SystemTime` + `Instant` | `TimeSource` (wall + monotonic); `TrustedClock` dựng trên trait này và thuộc về Core |
| `node::ipc` | `UnixListener`/`UnixStream`, quyền socket | `IpcTransport` (Unix socket, named pipe, native IPC) |
| `node::config`, `setup` | `std::fs`, quyền `0600/0700`, `/tmp/chitala-<uid>` | `Storage`, `SecureKeyStore` |
| `node::executor` | `std::process::Command`, pipe | `ExecutionHost` (spawn thành phần cô lập kèm kênh riêng) |
| `adapters::home_assistant` | `ureq` (HTTP) | `NetworkTransport` (ở adapter layer) |

Hệ quả: PAL chủ yếu là tái cấu trúc `chitala-node` và `chitala-audit`, cộng các thay đổi nhỏ ở `identity`/`csme`. Trusted Core logic (monitor, policy, token, csme decoding) **không phải viết lại**, đúng với yêu cầu của v20 §2.

Hai điểm thiết kế cần lưu ý:

- **Ký không export khóa**: `TokenAuthority` hiện dựng Biscuit `KeyPair` từ seed (`Keypair::seed()`). Muốn khóa authority nằm trong TPM/Secure Element, `SecureKeyStore` phải ký qua key reference, và cách tạo token Biscuit cần một hướng ký bên ngoài (third-party block hoặc đổi định dạng token). Đây là quyết định cho ADR, không chặn PAL v0.1.
- **Quyền file**: các kiểm tra `0600/0700` hiện tại là thuộc tính *bảo mật* (private, owner-only), không phải chi tiết POSIX. PAL cần biểu diễn chúng dưới dạng yêu cầu ngữ nghĩa (`Private`), để backend Windows ánh xạ sang ACL thay vì bỏ qua.

## 5. Primitive mới của v20 so với Core hiện tại

| v20 | Hiện có | Khoảng trống |
|---|---|---|
| Principal: Human, AI/Agent, Robot, Device, Service, **Compute**, **Organization/Domain** (§6) | `person`, `ai`, `device`, `service`, `domain` | Chưa có `robot`, `compute` (xem quyết định D1) |
| Resource Model: CPU/GPU/NPU/…/FutureCompute, storage, network, actuator theo capability (§7) | `DeviceDescriptor`, `HardwareProfile` H0–HX | Chưa có descriptor tài nguyên |
| Intent → Plan → Capability Resolution → Policy/Safety → **Execution Lease** → Action → Observation → Audit (§8) | Request CSME trực tiếp; `ExecOrder` có hạn và dùng một lần | Intent, Plan, lease có budget/cancellation, HDC (no-response = deny) |
| Device action: precondition, safety envelope, evidence, **recovery** (§11) | Risk, range envelope, device invariant | Precondition, rate/geofence, recovery/safe state |
| Authority = identity + token + policy + context + safety + **human approval** (§5) | Ba thành phần đầu, cùng safety envelope | Context ABAC, human approval |
| Risk class `safety-critical` (§11) | `critical` | Chỉ khác tên: giữ nhãn wire `critical`, ghi ánh xạ |

## 6. Quan hệ với v19

v20 không mâu thuẫn với các phần governance của v19, chỉ không nhắc tới chúng. Các mục này vẫn hữu ích và được giữ ở backlog:

- Một spec chỉ được gọi là **Stable** khi có ≥ 2 implementation độc lập interoperate (v19 §9).
- Trường token bổ sung: `not-before`, `max-use`, proof-of-possession, approval evidence (v19 §4.2).
- Two-key approval cho hành động rủi ro cao (v19 §5).
- Gói bằng chứng tuân thủ: CRA, ETSI EN 303 645, AI Act, bảo vệ dữ liệu cá nhân VN (v19 §15).

Mâu thuẫn duy nhất là định vị (v19: "không phải kernel", v20: "OS độc lập"). Repository theo v20.

## 7. Quyết định cần chủ dự án chốt

| # | Câu hỏi | Đề xuất |
|---|---|---|
| D1 | Thêm kind `robot`, `compute` vào `EntityId` (thay đổi wire, stable lâu dài)? | Thêm `compute` cùng Resource Model. Robot vẫn biểu diễn là `device` kèm các `ai` principal riêng (v12 §1), cho tới khi có ≥ 2 profile cần kind riêng (luật v20 §21) |
| D2 | Backend PAL thứ hai trong v0.1: Windows hay một `MemoryPlatform` cho test/simulator? | `MemoryPlatform` trước: rẻ, làm được PAL contract tests và mở đường cho simulator; Windows khi có nhu cầu thật |
| D3 | Cơ chế ký token khi khóa authority không export được | ADR riêng trước khi làm SecureKeyStore phần cứng |
| D4 | Con đường Native để thử nghiệm đầu tiên (§13: microkernel/hypervisor) | Chỉ viết ADR và boot experiment tối thiểu (ví dụ Trusted Core `no_std` chạy trên QEMU) sau khi PAL ổn định |

## 8. Thứ tự việc tiếp theo

Theo v20 §4 ("PAL là thay đổi kiến trúc cần làm sớm nhất"), §18 và §22:

1. **PAL** — crate `chitala-platform` (`TimeSource`, `Entropy`, `SecureKeyStore`, `Storage`, `IpcTransport`, `NetworkTransport`, `ExecutionHost`, `DeviceIo`); backend `HostedPlatform` (Unix) và `MemoryPlatform` (test); chuyển `node`/`audit`/`identity`/`csme` sang dùng PAL; PAL contract tests chạy trên mọi backend.
2. **Intent v0.1** — `chitala-intent`: spec + typed `Intent`/`Plan`/`ExecutionLease`; CSME message type 3 đi qua Reference Monitor; plan không tạo quyền; lease có deadline, budget, cancellation; điểm móc Human Decision Center (no-response = deny).
3. **Resource Model v0.1** — `chitala-resource`: descriptor compute/storage/network/actuator theo capability.
4. **CSME version negotiation + crypto agility** — security suite registry, negotiation chống downgrade.
5. **Threat model hosted vs native**, chaos/mixed-version tests, kiểm chứng build tái lập.
6. **Native Architecture ADR + boot experiment tối thiểu**.
7. Sau đó: khóa phần cứng (backend `SecureKeyStore`), attestation, enrollment, Human Decision Center đầy đủ, sandbox OS cho adapter host, simulator, Fabric multi-node.

Mỗi primitive mới vào Core phải qua ba câu hỏi của v20 §21: (1) có phải abstraction lâu dài không; (2) có ≥ 2 profile cần nó không; (3) bỏ nó thì Chitala có mất một thuộc tính OS cốt lõi không.

## Cập nhật: thứ tự đổi sau v20 (domain model trước PAL)

Ưu tiên được chủ dự án chốt lại: phần còn thiếu quan trọng nhất không phải protocol/adapter hay PAL mà là **domain model làm Chitala khác một MCP gateway**. Kết quả (milestone *Physical Authority Slice v0.1*, xem `ROADMAP.md`):

- **Invariant số 1** — AI produces Intent. Chitala produces Authority. Only the trusted execution boundary produces physical Commands (spec 15).
- **Resource Model v0.1** (spec 14) bao phủ thế giới **vật lý** (site, space, door, lock, light, robot, vehicle, mở rộng `x-vendor.kind`). Resource compute/storage/network của v20 chưa có; quyết định D1 vẫn mở — thêm qua kind mới khi có ≥ 2 profile cần (quy tắc §21).
- **Intent v0.1** (spec 15) là intent → authority → lệnh; chưa có *Plan* và *Execution Lease* nhiều bước của v20 — lệnh vật lý hiện là `ExecOrder` một lần, ≤ 30 s.
- **Authority Engine** (spec 16) và **Safety** độc lập (spec 17) là hiện thực đầu tiên của "Authority & Safety Fabric" của v19 cho một node.
