# Roadmap

Blueprint hiện hành: **v20** (`Chitala_OS_Blueprint_2026_2046_v20.pdf`). Đối chiếu chi tiết giữa v20 và repository: [`docs/v20-alignment.md`](docs/v20-alignment.md).

Chitala là một kiến trúc hệ điều hành. Giai đoạn hiện tại là **Hosted Mode**: Trusted Core chạy như một hệ thống dịch vụ trên Linux/macOS. Đích dài hạn là **Chitala Native**, boot thẳng trên phần cứng. Mọi thay đổi bây giờ phải giữ được đường đi tới Native: Trusted Core không được phụ thuộc host OS, ISA, AI runtime, giao thức hay cloud (v20 §1, §19).

> **Invariant số 1:** AI produces Intent. Chitala produces Authority. Only the trusted execution boundary produces physical Commands. (spec 15)

## Kỷ luật phạm vi (feature freeze)

Dòng `0.0.x` đang **đóng băng tính năng sản phẩm**. Chỉ những thay đổi sau được merge:

- hạng mục kiến trúc của Definition of Done v0.1 bên dưới (PAL, Intent, Resource Model, version negotiation, ADR…);
- sửa lỗi hoặc lỗ hổng, kèm test tái hiện;
- tăng khả năng kiểm chứng: test, property test, fuzz target, test vector, conformance;
- CI, chuỗi cung ứng, SBOM, ký artifact;
- thay đổi nhằm **cô lập** hoặc **thu nhỏ** Trusted Core;
- tài liệu và spec.

Không thêm capability, adapter, giao thức, transport, profile hay thành phần AI mới. MQTT/WoT, Robot/Mobility/Medical… chờ sau v0.1.

Mỗi primitive mới vào Core phải trả lời được ba câu hỏi (v20 §21):

1. Đây có phải abstraction lâu dài không?
2. Có ít nhất hai profile độc lập cần nó không?
3. Bỏ nó đi thì Chitala có mất một thuộc tính OS cốt lõi không?

## Definition of Done cho v0.1 (v20 §22)

| Tiêu chí | Trạng thái |
|---|---|
| PAL (`chitala-platform`) tồn tại; Trusted Core không import API Unix trực tiếp ngoài backend | 🟡 crate + backend Memory/Hosted + contract tests trên branch `feat/pal` (tạm gác); chưa migrate Core |
| Các test hiện có tiếp tục pass; thêm PAL contract tests | 🟡 166 test pass trên `main`; PAL contract tests nằm ở `feat/pal` |
| CI/security pipeline hoạt động | ✅ |
| Coverage-guided fuzz cho CSME/token/IPC | ✅ 11 target (thêm intent, approval) |
| Intent v0.1 và Resource Model v0.1: spec + implementation tối thiểu | ✅ spec 14–17, Physical Authority Slice v0.1 |
| Adapter isolation prototype | ✅ |
| Linux hosted node hoạt động như trước | ✅ (cả macOS) |
| Native Architecture ADR + boot experiment tối thiểu (chưa cần full kernel) | ⏳ |
| Threat model cập nhật cho ranh giới hosted vs native | ⏳ |

## Milestone hiện tại: Physical Authority Slice v0.1 — ✅ xong

Domain model làm Chitala khác một MCP gateway thông thường, chứng minh end-to-end trên cửa mô phỏng trước khi nối Matter/Home Assistant thật:

```text
MCP → Intent → Authority → Safety → Approval → Capability → simulated door
```

| # | Case | Bắt buộc | Kết quả |
|---|---|---|---|
| 1 | Owner AI → bật đèn | ALLOW | ✅ |
| 2 | Guest AI → bật đèn được ủy quyền | ALLOW | ✅ |
| 3 | Child AI → mở cửa khi không có quyền | DENY | ✅ (`E_POLICY_DENIED` ở bước DELEGATION) |
| 4 | Owner AI → mở cửa (high risk) | ESCALATE → human approval | ✅ (cửa chỉ động sau khi owner ký approval) |
| 5 | AI A → nhờ AI B mở cửa để né policy | DENY | ✅ (`E_ON_BEHALF_OF` / `E_PROVENANCE`) |

Test: `crates/chitala-mcp/tests/physical_authority_slice.rs` (qua MCP broker thật, node, adapter), `chitala_policy::authority` (engine, chữ ký và token thật), `chitala demo`. Crate mới: `chitala-resource`, `chitala-intent`, `chitala-safety`; `chitala-policy` thành Authority Engine.

## Thứ tự ưu tiên

| # | Hạng mục | Trạng thái |
|---|---|---|
| 1 | Feature freeze; Trusted Core kiểm chứng được | đang duy trì |
| 2 | CI/security pipeline (fmt → clippy → test → audit → deny; CodeQL, Dependabot, SBOM, release ký + attestation) | xong — còn kiểm chứng build tái lập |
| 3 | Fuzz các trust boundary (R8) | xong — 11 target |
| 4 | Tách adapter khỏi tiến trình Trusted Core (R4) | xong — còn sandbox mức OS |
| 5 | Trusted time: monotonic, phát hiện lùi đồng hồ (R3) | xong — còn nguồn thời gian có xác thực |
| 6 | **Physical Authority Slice v0.1** — Resource, Intent, Authority Engine, Safety, vertical slice | **xong** |
| 7 | **Delegation token cho agent** — token mang `on_behalf_of` và ràng buộc theo task (not-before, max-use, proof-of-possession) | **tiếp theo** |
| 8 | **Two-key approval** cho `critical`; phê duyệt có điều kiện (thời lượng, số lần) | |
| 9 | **Revocation** trên đường intent: thu hồi giữa chừng escalation, thu hồi theo agent/người, epoch | |
| 10 | **Outcome verification** — so trạng thái sau lệnh với mục tiêu của intent; evidence | |
| 11 | Home Assistant / Matter adapter cho đường intent (thay cửa mô phỏng) | |
| 12 | MCP/A2A có trung gian — tin nhắn giữa agent qua Chitala, provenance tự động (đóng R12) | |
| 13 | Implementation độc lập thứ hai (conformance theo wire format + test vector) | |
| 14 | PAL — tiếp tục migrate Core sang `chitala-platform` (branch `feat/pal`) | tạm gác |
| 15 | CSME version negotiation + crypto agility; threat model hosted vs native; build tái lập; Native ADR | |
| 16 | Khóa phần cứng (TPM/Secure Element), attestation, enrollment, sandbox OS cho adapter host | sau v0.1 |
| 17 | Simulator, Chitala Fabric (multi-node), Chitala Tiny, Future Profiles (Humanoid, eVTOL, Mobility, marketplace…) | khi Trusted Core ổn định — v19 giữ chúng ở Future Profiles |

## Lộ trình dài hạn (v20 §17)

| Giai đoạn | Mục tiêu |
|---|---|
| 2026–2027 · Core | Ổn định spec; PAL; CI/SBOM/fuzz; intent/resource model; adapters sandbox; simulator |
| 2027–2029 · Host | Linux production node; backend Windows/macOS khi cần; thử nghiệm Home/Robot/Medical; multi-node fabric |
| 2029–2032 · Native Lab | Prototype Chitala Native boot được; đánh giá microkernel/hypervisor; driver tối thiểu; secure key/time |
| 2032–2036 · Native | Native node cho edge/server/robot; compatibility VM/container; update/recovery bền vững |
| 2036–2040 · Fabric | Federation liên domain, compute dị thể, provenance quy mô lớn, safety island |
| 2040–2046 · Evolution | Chuyển đổi crypto, mô hình compute mới, dạng trí tuệ mới — không reset kiến trúc |

*"Mục tiêu 2026–2046 không phải dự đoán chính xác phần cứng hay AI tương lai. Mục tiêu là xây những abstraction đủ ổn định để Chitala có thể hấp thụ các thay đổi đó mà không phải viết lại nền tảng."* (v20 §23)
