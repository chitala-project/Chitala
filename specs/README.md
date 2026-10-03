# Chitala Specification v0.1 (provisional)

Blueprint hiện hành là **v20** (`Chitala_OS_Blueprint_2026_2046_v20.pdf`): Chitala là một kiến trúc hệ điều hành, chạy Hosted trước, hướng tới Native. Các spec 00–13 dưới đây đặc tả **Trusted Core** — phần v20 §5 yêu cầu kế thừa nguyên vẹn — và vẫn trích dẫn số mục của Blueprint v18 (bản chi tiết nhất về an ninh) ở những chỗ v20 không thay đổi ngữ nghĩa. Spec mới của v20 (PAL, Intent, Resource Model) sẽ được thêm theo [`ROADMAP.md`](../ROADMAP.md); khác biệt giữa v20 và repository nằm ở [`docs/v20-alignment.md`](../docs/v20-alignment.md).

Thứ tự xây dựng ban đầu theo **v17 §1–4**:

> Specification → Identity → Capability/Authority → Reference Monitor → Messaging → Device Model/SDK → Logging → Digital Twin/State → Adapters → …

Spec là hợp đồng sống lâu hơn code (v1 "Chuẩn phải sống lâu hơn code"). Implementation tham chiếu là Rust trong `crates/`, nhưng mọi định dạng trên dây (CSME, token, audit) được định nghĩa đủ chặt để một implementation bằng ngôn ngữ khác tương thích được (v11 "Protocol phải language-neutral").

## Danh mục

| Spec | Nội dung | Blueprint | Crate |
|---|---|---|---|
| [00-security-constitution.md](00-security-constitution.md) | Các bất biến C1–C14 và nơi chúng được thực thi | v13 §1, v8 §8/§14/§18, v15 §12 | toàn bộ |
| [01-core-model.md](01-core-model.md) | Entity/Principal, định danh, payload | §4, v12 §9, v17 §2 | `chitala-model` |
| [02-identity.md](02-identity.md) | Khóa Ed25519, key id, registry principal, role | v10, v12 §1 | `chitala-identity` |
| [03-classification.md](03-classification.md) | Thang phân loại hợp nhất + bảng ánh xạ về v18 | v4 §8/§13, v5 §15, v13 §2/§4/§11, v14 §17, v15 §10, v16 §15 | `chitala-model` |
| [04-capability-registry.md](04-capability-registry.md) | Capability Registry, safety envelope, target | Bổ sung A.1–A.2 | `chitala-model` |
| [05-capability-token.md](05-capability-token.md) | Capability token (Biscuit), attenuation, delegation, revocation | v8 §2/§8, v12 §18 | `chitala-token` |
| [06-policy.md](06-policy.md) | Policy Engine (Cedar), schema sinh từ registry | v9 "Authority Engine", v11 §15 | `chitala-policy` |
| [07-csme.md](07-csme.md) | Chitala Secure Message Envelope v1 (wire format) | v4 §3/§7/§14 | `chitala-csme` |
| [08-reference-monitor.md](08-reference-monitor.md) | Pipeline quyết định + deny codes | v8 §1, v17 §3 | `chitala-monitor` |
| [09-audit.md](09-audit.md) | Audit log tamper-evident, redaction | v16 §3/§7/§8 | `chitala-audit` |
| [10-twin-and-events.md](10-twin-and-events.md) | Digital Twin, event bus, adapter | v9 §3–4, v15 §5, v17 §6–7 | `chitala-state`, `chitala-bus`, `chitala-adapters` |
| [11-node-ipc.md](11-node-ipc.md) | Home Node, config, IPC, containment, domain operations | v9 "Home/Site Server", v8 §9 | `chitala-node`, `chitala-cli` |
| [12-ai-broker-mcp.md](12-ai-broker-mcp.md) | AI Action Broker qua MCP | v8 §1/§6, v12 §4, v17 §11 | `chitala-mcp` |
| [13-threat-model.md](13-threat-model.md) | Ranh giới tin cậy, tấn công đã chặn (có test), rủi ro còn lại | v13 §18, v8 §19 | — |
| [registry/capabilities-v0.1.json](registry/capabilities-v0.1.json) | Core Capability Registry (normative) | A.2 | — |
| [policy/default.cedar](policy/default.cedar) | Policy mặc định + Constitution | v13 §1 | — |

## Quy ước

- **PHẢI / KHÔNG ĐƯỢC / NÊN** có nghĩa như MUST / MUST NOT / SHOULD (RFC 2119).
- Mọi thời gian là mili-giây Unix epoch (UTC), kiểu `uint`.
- Mọi mã lỗi (`E_*`, `X_*`) là một phần của hợp đồng conformance; không được đổi nghĩa, không tái sử dụng (v4 §7).
- Trạng thái registry/spec: `experimental → provisional → stable → deprecated` (v4 §7). Toàn bộ v0.1 đang ở **provisional**.

## Phạm vi v0.1 so với roadmap v17 §18

| Milestone | Nội dung | Trạng thái |
|---|---|---|
| 0.0.1 | Virtual light: authorized ON/OFF + state + audit; AI không quyền bị DENY → security event → audit | **xong** |
| 0.0.2 | Nhiều user/device; capability delegation/revoke | **xong** |
| 0.0.3 | MQTT/HTTP/WoT adapters + virtual home | một phần: virtual home + Home Assistant REST; MQTT/WoT chưa có |
| 0.1 | 10–20 devices, Digital Twin, rules/workflows, observability | twin + bus có; rules/workflow chưa |

Những gì **cố ý chưa làm** (theo v11 §29, v17 §17): Intent/Goal (type code 3/4 đã được giữ chỗ), Human Decision Center (A4 — vì vậy `human_approved` luôn `false`), federation, PQC, SC4/Q4 safety domain, Personal Vault.
