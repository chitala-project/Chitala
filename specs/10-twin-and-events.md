# 10 — Digital Twin, Event Bus và Adapter

Nguồn: v9 §3 (Event Fabric), §4 (Distributed State & Reconciliation), v15 §5 (World Model), v16 §27, v17 §6–9 (Device Model tách khỏi Protocol, mock-first), v5 §11 (thiết bị không có Chitala native), v7 §10.

## Digital Twin

Mỗi entity có:

| Thành phần | Ý nghĩa |
|---|---|
| `reported` | trạng thái thiết bị báo — **nguồn sự thật** về thế giới vật lý |
| `desired` | trạng thái Chitala đã yêu cầu |
| `drift` | các khóa desired chưa khớp reported |
| `version` | tăng mỗi khi reported đổi |
| `reported_at_ms`, `source`, `freshness` (`fresh`/`stale`/`unknown`, mặc định stale sau 5 phút) | |

Quy tắc hợp nhất (v9 §4):

- Desired **không bao giờ** ghi đè reported. Khi thiết bị từ chối lệnh, twin không nói dối: `desired.locked = true`, `reported.locked = false`, `drift` hiện rõ.
- Quan sát cũ hơn quan sát hiện tại bị bỏ qua — reconnect/replay không kéo trạng thái lùi lại.
- Không dùng "last-write-wins theo timestamp" cho dữ liệu safety.

`device.read_state` trả view của twin sau khi quan sát lại thiết bị; quan sát lỗi thì trả view cũ kèm `observe_error` và freshness tương ứng.

## Event Bus

Event: `id`, `kind`, `source`, `ts_ms`, `data` (payload phẳng), `caused_by` (messageId gây ra). Các kind: `state_changed`, `security_denied`, `adapter_error`, `authority_changed`, `security_state_changed`.

- **Chỉ event đi trên bus**. Không có API gửi command qua bus, nên bus không thể thành đường vòng qua Authority/Safety (v9 §3).
- Mỗi subscriber có hàng đợi giới hạn. Khi đầy, bỏ event cũ nhất *không phải bảo mật* trước; event bảo mật chỉ bị bỏ khi hàng đợi không còn gì khác. Mọi lần bỏ đều được đếm (v16 §27).
- Publisher không bao giờ bị chặn bởi subscriber chậm.

## Adapter

Adapter dịch capability chuẩn sang thiết bị/giao thức cụ thể, nằm **dưới** Reference Monitor: `execute(&Authorized)`. Kết nối được với thiết bị không mang lại quyền nào (v17 §6).

| Adapter | Mục đích |
|---|---|
| `mock` | Đèn, công tắc, điều hòa, khóa ảo; fault injection (offline, lỗi một lần); invariant cục bộ: khóa từ chối `lock.lock` khi cửa đang mở → `X_DEVICE_REFUSED` (C5) |
| `home-assistant` | Bridge REST tới Home Assistant có sẵn. Thiết bị loại này không tự xác thực được đường lệnh của Chitala nên NÊN khai báo `SC0`/`SC1`. Token HA lấy từ biến môi trường, không bao giờ ghi vào config/log. `http://` chỉ được dùng với localhost, trừ khi config đặt `allow_insecure_http: true` (v7 §10) |

Lỗi thực thi sau khi đã được cho phép: `X_DEVICE_UNAVAILABLE`, `X_DEVICE_REFUSED`, `X_ADAPTER`.

Tiếp theo (v17 §8): adapter MQTT và W3C WoT/Thingweb, chạy sandbox và fuzz parser (v13 §9).
