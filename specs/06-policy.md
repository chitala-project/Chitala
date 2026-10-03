# 06 — Policy Engine

Nguồn: v9 "Authority Engine", v11 §15 (nhiều người dùng chung thiết bị), v13 §1 (Security Constitution), v5 §11 / v13 §4 (thiết bị legacy).

Policy viết bằng [Cedar](https://www.cedarpolicy.com/) — ngôn ngữ có ngữ nghĩa hình thức, phân tích được, tách khỏi code (v13 §18 "machine-testable invariants").

## Schema (sinh từ registry)

```cedarschema
namespace Chitala {
  entity Role;
  entity Domain;
  entity Person  in [Role] { state: String };
  entity AI      in [Role] { state: String };
  entity Service in [Role] { state: String };
  entity Device  in [Role] { state: String, security_class: Long, room: String };
  entity Resource in [Resource] { kind: String, boundary: String, zone: String,
                                  security_class: Long, owners: Set<Person> };
  type RequestContext = { token_granted: Bool, human_approved: Bool, risk: Long };
  action "risk-low"; action "risk-medium"; action "risk-high"; action "risk-critical";
  action "light.turn_on" in ["risk-low"] appliesTo {
    principal: [Person, AI, Service, Device], resource: [Device, Resource], context: RequestContext };
  // … một action cho mỗi capability, thuộc đúng một nhóm risk
}
```

- Entity UID dùng nguyên `EntityId`: `Chitala::Person::"person:alice"`.
- `principal in Chitala::Role::"owner"` ⇔ principal có role `owner`.
- `context.token_granted`: request mang token đã qua bước xác minh/authorize (spec 05).
- `context.human_approved`: có approval hợp lệ của owner (spec 16). Authority Engine đánh giá Cedar cả khi `false` và `true`: nếu kết quả đổi thì hành động cần con người → ESCALATE. Policy diễn đạt "cần người duyệt" bằng `unless { context.human_approved }`.
- `context.risk` trên Resource là **rủi ro hiệu dụng** (registry nâng bởi `risk_floor`); grant theo role cho Resource dựa trên nó (`adult-resources-low-medium`, `guest-resources-low`…).
- Resource: mọi tổ tiên là cha, nên `resource in Chitala::Resource::"resource:living-room"` đúng cho mọi thứ trong phòng; `security_class` là của device được bind cho capability được yêu cầu; `owners` là owner hiệu dụng (policy `resource-owner`).

## Nạp và đánh giá

1. Policy được **validate strict** với schema khi nạp; lỗi kiểu, action không tồn tại → node không khởi động (`PolicyError::Validation`). Policy sai không được phép "âm thầm không khớp".
2. Mỗi policy PHẢI có `@id("...")` duy nhất; id xuất hiện trong audit log và trong lý do từ chối.
3. Template chưa được hỗ trợ.
4. **Fail closed**: Cedar bỏ qua policy lỗi khi đánh giá — một `forbid` lỗi sẽ thành *allow*. Vì vậy bất kỳ lỗi đánh giá nào → `E_POLICY_ERROR` (deny).
5. `forbid` luôn thắng `permit`. Không có `permit` nào khớp → `E_POLICY_DENIED`.
6. Fingerprint (8 byte đầu SHA-256 của nguồn policy) được ghi vào mọi bản ghi quyết định (`policy_fp`).

## Policy mặc định

Xem [`policy/default.cedar`](policy/default.cedar). Tóm tắt:

| @id | Loại | Nội dung |
|---|---|---|
| `owner-all` | permit | owner làm mọi thứ |
| `admin-domain`, `admin-devices-low-medium` | permit | admin quản trị domain, thiết bị low/medium |
| `adult-devices-low-medium`, `adult-delegate` | permit | người lớn: thiết bị low/medium; ủy quyền/thu hồi/liệt kê |
| `child-devices-low`, `guest-devices-low` | permit | trẻ em, khách: chỉ low |
| `token-grant` | permit | token hợp lệ là một grant cụ thể |
| `C12-ai-needs-token`, `C12-service-needs-token`, `C12-device-needs-token` | forbid | không có ambient authority cho principal không phải người |
| `C11-ai-no-domain-admin` | forbid | AI không ủy quyền/thu hồi/đổi security state |
| `C11-ai-no-high-risk` | forbid | AI không làm high/critical (cần A4) |
| `C9-critical-needs-approval` | forbid | critical cần phê duyệt riêng |
| `child-no-high-risk` | forbid | trẻ em không làm high/critical kể cả có token |
| `SC0-no-high-risk-target`, `SC0-principal-low-only` | forbid | thiết bị legacy SC0 |

Domain có thể thay policy bằng `policy_file` trong config. Quy tắc: được thêm `forbid`, không được gỡ các policy `C*-` (spec 00).

## Hai lớp độc lập

Với đường tấn công quan trọng nhất của Blueprint — AI tự hành động — v0.1 có hai lớp: monitor trả `E_TOKEN_MISSING` cho mọi principal không phải người không mang token, **và** policy `C12-ai-needs-token` cấm cùng điều đó. Một lỗi ở một lớp không mở được quyền.
