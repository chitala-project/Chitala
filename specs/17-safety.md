# 17 — Safety

Nguồn: Blueprint v19 "Safety Fabric", v8 §10, Security Constitution C5/C9; crate `chitala-safety`.

Policy trả lời *ai được làm gì* — owner và admin thay đổi nó. Safety trả lời *điều gì không bao giờ được xảy ra về mặt vật lý, bất kể ai yêu cầu*. Hai lớp được tách có chủ đích:

- `chitala-safety` không phụ thuộc policy engine, token hay identity;
- safety được hỏi **sau** Authority, và **lại** ngay trước khi trusted boundary tạo lệnh (trạng thái có thể đổi trong lúc con người đang quyết);
- safety **chỉ có thể từ chối**: không có luật, cấu hình hay lời gọi nào biến một DENY của Authority thành ALLOW, và không policy nào tắt được một luật safety. Một approval của con người cũng không vượt qua được safety.

## Luật (v0.1)

| Id | Từ chối |
|---|---|
| `SAFE-1-HOLD` | mọi hành động trên một resource đang bị *safety hold*, hoặc nằm dưới một resource bị hold (hold/release là quyết định ngoài băng của con người) |
| `SAFE-2-DEVICE` | mọi hành động qua device bị cách ly (QUARANTINED/RECOVERY/RE_ATTEST); hành động `high`+ qua device không TRUSTED |
| `SAFE-3-STATE` | hành động `medium`+ khi trạng thái của resource chưa biết, hoặc cũ hơn `StateRef.max_age_ms` (mặc định 120 s) — fail safe |
| `SAFE-4-PHYSICAL` | hành động mâu thuẫn trạng thái vật lý được báo (v0.1: `lock.lock` khi cửa đang mở) |
| `SAFE-5-ENVELOPE` | tham số ngoài envelope riêng của resource (chặt hơn registry) |
| `SAFE-6-RATE` | quá số lần actuate một resource trong cửa sổ (mặc định 6/60 s; 3/60 s cho `high`+) — chống dao động, agent lặp |

Query (đọc trạng thái) không bị safety chặn. Vi phạm trả `E_SAFETY` với `stage: "safety"` và id luật trong audit; vi phạm safety **không** tính vào containment (đó không phải dò quyền).

## Clearance

`Safety::check` chạy mọi luật không side effect (dùng trước khi hỏi con người: không ai bị hỏi để duyệt thứ safety sẽ từ chối). `Safety::clear` chạy lại, ghi nhận lần actuate và trả về `Clearance` cho đúng một hành động (resource, capability, device, tham số, thời điểm). `Clearance` không có constructor công khai, không `Clone`; trusted boundary đòi nó cùng với `Grant` (spec 15–16).

## Hai lớp an toàn vật lý

Safety của Chitala là lớp *trước* lệnh. Thiết bị vẫn giữ invariant cục bộ của nó (C5, `X_DEVICE_REFUSED`) — lớp *sau* lệnh, độc lập, vẫn đúng khi Chitala sai.
