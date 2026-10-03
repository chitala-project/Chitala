# 03 — Thang phân loại hợp nhất

Blueprint v18 tích lũy qua nhiều phiên bản nên có **chín thang chồng lấn**: hai bộ `S0–S4` khác nghĩa (v4 §13 security profiles và v13 §4 security classes), `D0–D5` (v15 §10) và `R0–R5` (v16 §15), `C0–C4` (v14 §17) và nhãn IFC (v13 §2), `L1–L6` (v8 §13) và Security State Machine (v11 §16.5 = v13 §11)…

v0.1 giữ **nguyên ý nghĩa** của từng thang trong PDF nhưng mỗi khái niệm chỉ còn **một** thang với **tiền tố riêng**, để trên dây và trong log không bao giờ nhầm "S2" của thang này với "S2" của thang kia. Bảng ánh xạ dưới đây là chuẩn: một tài liệu dùng tên cũ của v18 dịch sang v0.1 bằng bảng này, không mất thông tin.

## Bảng ánh xạ về Blueprint v18

| Khái niệm | Tên trong v18 | v0.1 | Mã trên dây |
|---|---|---|---|
| Mức bảo đảm của entity | v13 §4 S0 Legacy/Untrusted · S1 Basic · S2 Secure · S3 High Assurance · S4 Safety Critical | `SC0`…`SC4` (giữ nguyên nghĩa v13) | 0–4 |
| Hồ sơ triển khai truyền thông | v4 §13 S0 Legacy Bridge · S1 Consumer · S2 Enterprise · S3 High Assurance · S4 Safety Domain | *deployment profile* (không phải thuộc tính của từng message); ánh xạ gần đúng sang SC cùng số | — |
| Rủi ro của một hành động | CSME `safetyClass` (v4 §3); low/medium/high/critical (v8 §10); "Safety budget" của token (v8 §2) | `RiskClass` low · medium · high · critical | 0–3 |
| Mức tự chủ | v15 §10 D0 Observe … D5 Critical authority; v16 §15 R0 Observe … R5 Critical | `A0`…`A5` (D_n = R_n = A_n; hai thang của PDF song song từng bậc) | 0–5 |
| Phân loại dữ liệu | v13 §2 Public / Shared / Private / Restricted / Safety-critical; v14 §17 C0 Public … C4 Critical | `DC0`…`DC4` (DC_n = C_n; IFC label tương ứng theo thứ tự) | 0–4 |
| QoS truyền thông | v4 §8 Q0–Q4 | `Q0`…`Q4` (giữ nguyên) | 0–4 |
| Phần cứng | v5 §15 H0–H5, HX | `H0`…`H5`, `HX` (giữ nguyên) | 0–5, 255 |
| Trạng thái an ninh | v11 §16.5 = v13 §11 | `TRUSTED` → `SUSPICIOUS` → `RESTRICTED` → `QUARANTINED` → `RECOVERY` → `RE_ATTEST` | 0–5 |
| Mức containment | v8 §13 L1 Restrict · L2 Revoke · L3 Quarantine Agent · L4 Quarantine Device · L5 Safety Island · L6 Recovery | L1 → `RESTRICTED`; L2 → `domain.revoke_token`; L3/L4 → `QUARANTINED` (AI và device là principal riêng nên "quarantine agent" và "quarantine device" là cùng thao tác trên hai principal khác nhau); L5 → SC4 (sau 1.0); L6 → `RECOVERY`/`RE_ATTEST` | — |

`SC4` và `Q4` được định nghĩa nhưng **chưa được hỗ trợ** trong dòng v0.x (`supported_in_v0`): safety domain cần controller chứng nhận, không thuộc phạm vi general OS (v5 §12, v6 §8).

## Ma trận ràng buộc

**M1 — Rủi ro → mức tự chủ tối đa của AI** (`RiskClass::max_ai_autonomy`). Trên mức này, con người hoặc controller chứng nhận là authority cuối.

| Risk | low | medium | high | critical |
|---|---|---|---|---|
| AI tối đa | A2 (tự làm, rủi ro thấp) | A3 (trong envelope) | A4 (cần người duyệt) | A5 (authority đặc biệt) |

Vì Human Decision Center (A4) chưa có ở v0.1, policy `C11-ai-no-high-risk` cấm AI mọi hành động `high`/`critical`.

**M2 — Security class → phần cứng tối thiểu** (`SecurityClass::min_hardware`): SC0/SC1 → H0, SC2 → H1, SC3 → H2, SC4 → H2. Một thiết bị không được khai báo SC cao hơn những gì phần cứng của nó chứng minh được (v13 §19).

**M3 — Security state → rủi ro tối đa được phép** (`SecurityState::max_risk`):

| State | Được làm | Ghi chú v13 §11 |
|---|---|---|
| TRUSTED | mọi mức (theo policy) | |
| SUSPICIOUS | ≤ medium | "giảm quyền nhạy cảm" |
| RESTRICTED | ≤ low | "chỉ allowlist tối thiểu" |
| QUARANTINED | không gì cả | "chỉ safety/diagnostic/recovery" — diagnostic chưa có ở v0.1 |
| RECOVERY, RE_ATTEST | không gì cả | chưa được tin lại |

## Chuyển trạng thái hợp lệ (`SecurityState::can_transition`)

- Leo thang tới trạng thái chặt hơn trên thang `TRUSTED < SUSPICIOUS < RESTRICTED < QUARANTINED` luôn được phép (kể cả nhảy bậc).
- `SUSPICIOUS`/`RESTRICTED → TRUSTED`: được phép (dương tính giả, do con người quyết định).
- Từ `QUARANTINED` chỉ có một đường: `→ RECOVERY → RE_ATTEST → TRUSTED`. Reboot hay restore **không** tự động tái tin một principal (v11 §30).
- `RECOVERY`/`RE_ATTEST → QUARANTINED`: được phép (recovery thất bại).
- Không principal nào đổi trạng thái của chính mình (spec 11).
