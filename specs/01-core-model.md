# 01 — Core Model

Nguồn: Blueprint §4 (primitive), v12 §9 (`Device_ID ≠ AI_ID`), v17 §2 (Person_ID, Device_ID, AI_ID, Service_ID, Domain_ID, Resource_ID là các principal/object khác nhau).

## Identifiers

### EntityId

```
entity-id = kind ":" local
kind      = "person" / "ai" / "device" / "service" / "domain"
local     = [a-z0-9] *127( [a-z0-9] / "." / "_" / "-" )
```

Ví dụ: `person:alice`, `ai:assistant`, `device:living-room-light`, `service:node`, `domain:home`.

- Năm kind là năm loại **khác nhau**. Một robot có `device:robot-17` và các AI chạy trên nó có `ai:vision-17a`, `ai:nav-17c`… Mỗi AI là một principal riêng, có khóa riêng, quyền riêng và bị cách ly độc lập (v12 §9).
- `person`, `ai`, `service`, `device` là **principal** (có thể ký request). `domain` chỉ là target/trust domain, không bao giờ là principal.
- `local` phân biệt chữ hoa/thường: chỉ chữ thường được chấp nhận, nên không có hai cách viết cho cùng một entity.
- Danh tính **không** dựa trên IP/MAC/serial (v5 §19).

### CapabilityId

```
capability-id = first-segment 1*( "." segment )
first-segment = segment / vendor
segment       = [a-z] *( [a-z0-9_] )
vendor        = "x-" 1*[a-z0-9]
```

Tối đa 128 ký tự. Ví dụ `light.turn_on`, `climate.set_target_temperature`, `x-acme.fan.set_speed`. Không có wildcard (`light.*`): quyền luôn tường minh.

## Primitive trong v0.1

| Primitive (Blueprint §4) | v0.1 |
|---|---|
| Entity | `EntityId` + `DeviceDescriptor` |
| Capability | `CapabilityDef` trong registry (spec 04) |
| Property | `reported` state của Digital Twin (spec 10) |
| Action | capability `kind = action`, gửi bằng message type `command` |
| Event | `Event` trên bus (spec 10) |
| Actor | principal (`person`/`ai`/`service`/`device`) |
| Authority | token (spec 05) + policy (spec 06) |
| Delegation | `domain.delegate` (spec 11) |
| Context | `context_ref` của CSME (opaque, ≤128 ký tự); room của device |
| Trust | `SecurityClass`, `SecurityState` (spec 03) |
| Intent, Goal | message type 3/4 đã được **giữ chỗ**; monitor v0.1 trả `E_UNSUPPORTED_TYPE` |

## Payload

Payload v0.1 là map phẳng `text → (bool | int64 | text)`:

- **Không float**: tránh mơ hồ khi mã hóa canonical và khi so sánh với safety envelope; giá trị vật lý dùng số nguyên với đơn vị trong tên (`brightness_pct`, `celsius`).
- **Không lồng nhau**: v0.1 chưa cần; giữ parser nhỏ.
- Tên tham số ≤ 64 ký tự; tối đa 32 tham số; text ≤ 4096 byte trên dây (giới hạn chặt hơn do registry quyết định).

## DeviceDescriptor (Entity Manifest tối thiểu)

```json
{
  "id": "device:front-door",
  "name": "Khóa cửa chính",
  "adapter": "mock",
  "capabilities": ["device.read_state", "lock.lock", "lock.unlock"],
  "security_class": "SC3",
  "room": "entrance"
}
```

Đây là tập con của Entity Manifest (§8, Bổ sung A.4). Các nhóm Interface/AI/Lifecycle/Attestation/Privacy sẽ được thêm dưới dạng trường tùy chọn; parser PHẢI bỏ qua trường lạ không critical.
