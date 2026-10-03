# 14 — Resource Model

Nguồn: Blueprint v20 "Resource Model", v19 "physical world under authority"; crate `chitala-resource`.

Một **resource** là bất cứ thứ gì trong thế giới vật lý mà domain quản trị: nhà, phòng, cửa, ổ khóa, đèn, robot, xe, hay một loại chưa ai làm ra. Principal *hành động*; resource *bị tác động*. Device là phần cứng thực thi được gắn (bind) vào resource. AI luôn nói về resource ("mở cửa chính"), không bao giờ về device.

## Một primitive cho mọi thứ

| Khía cạnh | Trường | Ý nghĩa |
|---|---|---|
| định danh | `id` | `resource:<local>` — một `EntityId` kind `resource`; ổn định khi vật được di chuyển |
| loại | `kind` | `site`, `space`, `door`, `window`, `gate`, `lock`, `light`, `switch`, `climate`, `sensor`, `camera`, `appliance`, `robot`, `vehicle`, hoặc mở rộng `x-<vendor>.<kind>` |
| sở hữu | `owners` | những **người** có quyền quyết định cuối; rỗng = kế thừa từ tổ tiên gần nhất có owner |
| cha/con | `parent` | chứa hoặc là-một-phần-của (site ⊃ phòng ⊃ cửa ⊃ khóa); là một cây |
| vị trí | `zone`, `boundary` → `Location` | suy ra: site, space gần nhất, nhãn zone, `interior`/`perimeter` |
| tham chiếu trạng thái | `state` (`StateRef`) | device nào báo trạng thái, và trạng thái được phép cũ tối đa bao lâu |
| gắn capability | `bindings` (`CapabilityBinding`) | capability nào do device nào thực thi, với `risk_floor` tùy chọn |
| safety envelope | `envelope` (`ParamLimit`) | giới hạn tham số chặt hơn registry, theo từng resource |

## Bất biến của đồ thị (kiểm khi khởi động node)

1. Id duy nhất; cha tồn tại; không chu trình; độ sâu ≤ 8; ≤ 10 000 resource.
2. **Mọi resource có ít nhất một owner hiệu dụng là người** (`E`/`Unowned`): luôn có một con người có quyền quyết định cuối.
3. Owner chỉ là `person:*`.
4. `site`/`space` là container: không có binding hay state (một capability trên cả phòng là group command — để sau).
5. Binding: capability có trong registry và nhắm device; device là `device:*` và hỗ trợ capability (kiểm với danh sách device của node); mỗi capability bind tối đa một lần.
6. `risk_floor` chỉ **nâng** rủi ro (phải > rủi ro registry): mở khóa cửa chính có thể là `critical` ở một nhà cụ thể.
7. Resource có action được bind PHẢI có `StateRef` — safety phải biết trạng thái của nó (spec 17, SAFE-3).
8. Envelope chỉ cho tham số integer của capability đã bind, nằm trong khoảng của registry.

## Quyền theo cây

- Capability token có thể cấp quyền trên một resource **hoặc một container**: quyền trên `resource:living-room` bao phủ mọi thứ bên trong (`token.authorize` được thử trên resource rồi từng tổ tiên).
- Ủy quyền (`domain.delegate`) với target là resource: capability phải được bind tại target hoặc bên dưới; holder phải dùng được quyền đó ở mọi nơi nó bao phủ (có thể cần người duyệt); với grant gốc, người cấp phải được hưởng quyền đó ở mọi nơi nó bao phủ.
- Cedar thấy resource là entity `Chitala::Resource` với mọi tổ tiên là cha, nên policy viết được `resource in Chitala::Resource::"resource:living-room"` (spec 06).

## Cấu hình

`resources` trong `chitala.json` (xem `chitala init`): nhà mẫu có `home` (site, owner `person:alice`) ⊃ `living-room` ⊃ `living-room-light`, `thermostat` (envelope 18–28 °C); `bedroom` ⊃ `fan`; `entrance` (zone `entrance`) ⊃ `front-door` (perimeter, bind `device:front-door`).
