# 04 — Capability Registry

Nguồn: Bổ sung A.1–A.2 (Universal Semantic Layer, Capability Registry), v4 §7 (versioning), v4 §17 (chống fragmentation).

Registry là **ngữ nghĩa chung**: AI, automation và ứng dụng chỉ cần hiểu capability chuẩn, không cần API riêng của từng hãng. Core registry v0.1 nằm ở [`registry/capabilities-v0.1.json`](registry/capabilities-v0.1.json) và được nhúng nguyên văn vào binary.

## Định dạng

```json
{
  "registry": "chitala-core",
  "registry_version": "0.1.0",
  "status": "provisional",
  "capabilities": [
    {
      "id": "light.set_brightness",
      "version": 1,
      "kind": "action",
      "risk": "low",
      "target": "device",
      "description": "Đặt độ sáng theo phần trăm; 0 tương đương tắt.",
      "params": [ { "name": "brightness_pct", "type": "integer", "min": 0, "max": 100, "required": true } ]
    }
  ]
}
```

| Trường | Ý nghĩa |
|---|---|
| `id` | `CapabilityId` (spec 01), duy nhất trong registry |
| `version` | ≥ 1. Thay đổi phá vỡ ⇒ version mới; không bao giờ đổi nghĩa của một version đã phát hành |
| `kind` | `action` (thay đổi thế giới, gửi bằng `command`) hoặc `query` (chỉ đọc, gửi bằng `query`) |
| `risk` | `RiskClass` (spec 03). Người gửi PHẢI khai báo đúng risk này trong CSME; khai báo khác → `E_RISK_MISMATCH` |
| `target` | `device` (mặc định) hoặc `domain` — capability quản trị domain đi qua cùng Reference Monitor |
| `params` | `integer {min,max}` · `boolean` · `text {max_len}`; `required` mặc định `true` |

## Safety envelope

Biên `min/max` của tham số `integer` **là** safety envelope mặc định (A.1 "Safety metadata"). Giá trị ngoài biên → `E_SAFETY_ENVELOPE`, sai kiểu/thiếu/thừa tham số → `E_PAYLOAD_INVALID`. Kiểm tra chặt: tham số không khai báo bị từ chối, không bị bỏ qua — một trường thừa có thể là nỗ lực nhét chỉ thị vào payload (v8 §6).

Thiết bị vẫn có thể có invariant chặt hơn và từ chối lệnh đã được cho phép (C5, spec 10).

## Core registry v0.1

| Capability | kind | risk | target |
|---|---|---|---|
| `device.read_state` | query | low | device |
| `light.turn_on`, `light.turn_off` | action | low | device |
| `light.set_brightness` (`brightness_pct` 0–100) | action | low | device |
| `switch.turn_on`, `switch.turn_off` | action | low | device |
| `climate.set_target_temperature` (`celsius` 16–30) | action | medium | device |
| `lock.lock` | action | medium | device |
| `lock.unlock` | action | **high** | device |
| `domain.list_devices` | query | low | domain |
| `domain.delegate` | action | medium | domain |
| `domain.revoke_token` | action | medium | domain |
| `domain.set_principal_state` | action | **high** | domain |

Rủi ro của `domain.delegate` chỉ là *medium* vì delegation không thể khuếch đại quyền (C13): ai cũng chỉ trao được tập con của những gì mình có.

## Vendor extension

Namespace `x-<vendor>.` dành cho hãng (v4 §17). Extension NÊN ánh xạ về capability chuẩn khi có. Capability không có trong registry của node → `E_UNKNOWN_CAPABILITY`: node không bao giờ "đoán" nghĩa của capability lạ (v4 §19).

## Tiến hóa

- Trạng thái registry: `experimental → provisional → stable → deprecated`.
- Không tái sử dụng id đã deprecated cho nghĩa khác.
- Thêm units, quality (accuracy/confidence), privacy class và test vectors cho từng capability là bước tiếp theo của A.1.
