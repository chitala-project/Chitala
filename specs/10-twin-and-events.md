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

Adapter dịch capability chuẩn sang thiết bị/giao thức cụ thể. Kết nối được với thiết bị không mang lại quyền nào (v17 §6).

| Adapter | Mục đích |
|---|---|
| `mock` | Đèn, công tắc, điều hòa, khóa ảo; fault injection (offline, lỗi một lần); invariant cục bộ: khóa từ chối `lock.lock` khi cửa đang mở → `X_DEVICE_REFUSED` (C5) |
| `home-assistant` | Bridge REST tới Home Assistant có sẵn. Thiết bị loại này không tự xác thực được đường lệnh của Chitala nên NÊN khai báo `SC0`/`SC1`. Token HA lấy từ biến môi trường, không bao giờ ghi vào config/log. `http://` chỉ được dùng với localhost trừ khi config đặt `allow_insecure_http: true` (v7 §10) |

Lỗi thực thi sau khi đã được cho phép: `X_DEVICE_UNAVAILABLE`, `X_DEVICE_REFUSED`, `X_ORDER_REJECTED`, `X_ADAPTER`.

## Cô lập adapter (Blueprint A.3, v8 §3, §12)

Adapter **không chạy trong tiến trình Trusted Core**. Adapter lỗi, treo hay bị chiếm quyền không được ảnh hưởng Reference Monitor (A.3 "Crash của adapter không được làm sập Authority/Safety Core").

```
 node (Trusted Core)                                        chitala-adapter-host (1 tiến trình / loại adapter)
 Reference Monitor ─ Authorized ─▶ ExecOrder ký bằng khóa node ─stdin─▶ OrderGate: chữ ký node, hạn, dùng 1 lần
                                                                       └▶ adapter (mock, home-assistant)
              ◀─stdout─ reply: dữ liệu KHÔNG tin cậy (giới hạn kích thước, kiểu) ─┘
```

### Lệnh thực thi (ExecOrder)

COSE_Sign1 (Ed25519) ký bằng **khóa node**, content type `application/chitala-order` — khác CSME nên chữ ký request không bao giờ dùng làm lệnh được và ngược lại (v4 §14). Thân là CBOR tất định với khóa 1–9: version, order id (= message id của request đã được cho phép), actor, target, capability, capability version, decided-at, expires-at, payload. Khóa lạ bị từ chối.

Adapter host chỉ thực thi lệnh:

1. ký bằng khóa công khai của node được ghim lúc khởi động;
2. còn hạn: `decided_at ≤ now + 5 s`, `now < expires_at`, thời hạn ≤ 30 s (mặc định 10 s — lệnh cũ không được chạy muộn, v15 §7);
3. chưa từng thực thi (order id dùng một lần);
4. dành cho đúng thiết bị được yêu cầu.

Không thỏa → `X_ORDER_REJECTED`.

### Tiến trình adapter host

- Node khởi động **một tiến trình cho mỗi loại adapter**: lỗi của Home Assistant không kéo theo thiết bị ảo.
- Kênh giao tiếp là stdin/stdout của tiến trình con — riêng giữa cha và con, không có socket để tiến trình khác chen vào. Giao thức JSON Lines: `init`, `execute`, `observe`, `simulate`; mỗi dòng ≤ 64 KiB.
- Adapter host **không giữ khóa bí mật nào**; chỉ có khóa công khai của node.
- Môi trường rỗng (`env_clear`); host Home Assistant chỉ nhận đúng biến chứa token của nó.
- Phản hồi của host là **dữ liệu không tin cậy**: state ≤ 64 mục, khóa ≤ 64 ký tự, giá trị chỉ bool/số nguyên/chuỗi ≤ 256 ký tự, thông báo lỗi bị cắt và lọc ký tự điều khiển.
- Host không trả lời trong thời hạn (5 s; Home Assistant 30 s), thoát, hay vi phạm giao thức → node trả `X_DEVICE_UNAVAILABLE`, **kill** tiến trình và khởi động lại ở lần gọi sau (tối đa một lần mỗi giây).
- Node **nhả khóa** trong lúc chờ adapter host (xử lý request theo 3 pha: quyết định → thực thi → ghi nhận). Một thiết bị chậm không làm chậm quyết định cho request khác.

Kiểm chứng: `isolation::crashed_adapter_host_never_reaches_the_monitor`, `hung_adapter_host_does_not_stall_the_node`, `garbage_from_an_adapter_host_is_contained`, `adapter_host_gets_an_empty_environment`; fuzz target `exec_order`, `host_line`.

**Giới hạn hiện tại**: adapter host chạy cùng user với node; sandbox ở mức hệ điều hành (user riêng, seccomp/Landlock, sandbox-exec, network namespace) là bước tiếp theo. Các yêu cầu tới cùng một adapter host được xử lý tuần tự.

Tiếp theo (v17 §8, sau feature freeze): adapter MQTT và W3C WoT/Thingweb.
