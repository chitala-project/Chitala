# 15 — Intent và Approval

Nguồn: Blueprint v19 (Authority & Safety Fabric), v20 "Intent Model"; crate `chitala-intent`.

## Invariant số 1

> **AI produces Intent. Chitala produces Authority. Only the trusted execution boundary produces physical Commands.**

Đây là bất biến đầu tiên của codebase, đứng trước C1–C14 (spec 00). Hệ quả:

| Ai | Được tạo | Không bao giờ được tạo |
|---|---|---|
| AI principal | `Intent` (ký bằng khóa của chính nó) | CSME `command` (`E_INTENT_REQUIRED`), lệnh vật lý |
| Chitala (Authority Engine, spec 16) | `Grant` cho đúng một intent | lệnh vật lý |
| Safety (spec 17) | `Clearance` cho đúng một hành động | quyền (chỉ có thể từ chối) |
| Trusted execution boundary (`chitala-node::boundary`) | lệnh vật lý = `ExecOrder` ký bằng khóa node (`application/chitala-order`) | — |

`Grant` và `Clearance` không có constructor công khai, không `Clone`; `boundary::physical_command(grant, clearance, now)` tiêu thụ cả hai và chỉ chấp nhận clearance mô tả đúng hành động đã được grant (resource, capability, device, tham số) và còn mới (≤ 1 s). Adapter host chỉ thực thi `ExecOrder` (spec 10). Người và service vẫn dùng đường CSME trực tiếp ở v0.1; với AI, đường duy nhất là intent.

## Intent ≠ Command

```text
actor → on_behalf_of → action → resource → context → constraints → requested_at
```

| | Intent | Command (`ExecOrder`) |
|---|---|---|
| Người ký | AI (actor) | node |
| Đích | **resource** (`resource:front-door`) | device (`device:front-door`) |
| Rủi ro | không khai — Chitala tính | đã quyết |
| Phiên bản capability | không | có |
| Hiệu lực | ≤ 10 phút (đủ để con người trả lời) | ≤ 30 s, dùng một lần |
| Content type COSE | `application/chitala-intent` | `application/chitala-order` |

Content type khác nhau nên chữ ký của loại này không bao giờ được chấp nhận như loại kia (test `intents_are_not_commands`).

## Wire format

`COSE_Sign1` (Ed25519, kid 16 byte) của một map CBOR deterministic, **đúng** các khóa sau (khóa lạ → từ chối):

| Khóa | Trường | Kiểu |
|---:|---|---|
| 1 | version (= 1) | uint |
| 2 | intent id | bstr(16) |
| 3 | actor — PHẢI là người ký | tstr entity id |
| 4 | on_behalf_of — PHẢI là `person:*` | tstr |
| 5 | action | tstr capability id |
| 6 | resource | tstr `resource:*` |
| 7 | params (bỏ khi rỗng) | map tstr → bool/int/tstr |
| 8 | context.purpose — dữ liệu, không bao giờ là chỉ thị | tstr ≤ 280, tùy chọn |
| 9 | context.cause — intent đã ký mà intent này chuyển tiếp | bstr, tùy chọn |
| 10 | constraints.deadline (ms) | uint |
| 11 | constraints.max_risk | uint, tùy chọn |
| 12 | constraints.no_escalation (chỉ có mặt dưới dạng `true`) | bool, tùy chọn |
| 13 | requested_at (ms) | uint |
| 14 | authority — capability token của actor | bstr ≤ 4096, tùy chọn |

Luật hình dạng: `on_behalf_of` là người; một người chỉ hành động cho chính mình; `requested_at < deadline ≤ requested_at + 600 000`. Constraints **chỉ thu hẹp**: `max_risk` → từ chối thay vì thực hiện khi rủi ro cao hơn; `no_escalation` → từ chối thay vì hỏi con người.

### On behalf of

Quan hệ đại diện được **khai báo khi enroll** (`serves` trong config, `IdentityRegistry::set_serves`), không được khai trong từng request. Một AI chỉ gửi intent cho người mà nó phục vụ (`E_ON_BEHALF_OF`).

### Relay (agent-to-agent)

Một agent chuyển tiếp yêu cầu của agent khác bằng cách đính intent đã ký của agent kia vào `context.cause` (tối đa 3 cause). Mọi mắt xích được kiểm chữ ký (actor = người ký, khóa đã enroll). Authority của chuỗi là **giao** của mọi mắt xích (spec 16): chuyển tiếp không bao giờ thêm quyền.

## Approval

Câu trả lời của con người cho một intent bị escalate. `COSE_Sign1` với content type `application/chitala-approval`:

| Khóa | Trường | Kiểu |
|---:|---|---|
| 1 | version (= 1) | uint |
| 2 | intent id | bstr(16) |
| 3 | intent digest = SHA-256 của body intent | bstr(32) |
| 4 | approver — PHẢI là người ký, `person:*` | tstr |
| 5 | verdict: 1 approve, 2 reject | uint |
| 6 | issued_at (ms) | uint |
| 7 | expires_at (ms), ≤ issued_at + 600 000 | uint |
| 8 | note | tstr ≤ 280, tùy chọn |

Digest ràng approval vào **đúng** nội dung intent mà con người đã thấy (`domain.list_approvals` trả về digest). Approval dùng một lần (replay theo `(kid, intent id)`).

## Kiểu không làm giả được

`VerifiedIntent` và `VerifiedApproval` chỉ tạo được bằng `SignedIntent::open` / `SignedApproval::open` (kiểm chữ ký, giải mã, actor/approver = người ký, mở mọi cause). Authority Engine chỉ nhận hai kiểu này, nên code trong node không thể đưa cho nó một intent chưa được xác thực.
