# 00 — Security Constitution

Nguồn: Blueprint v13 §1 (C1–C10), bổ sung từ v8 §8, §14, §18 và v15 §12 (C11–C14).

Constitution là tập bất biến **không application/AI nào bypass được**. Mỗi điều phải được thực thi ở ít nhất một điểm *ngoài* AI/application và — với đường tấn công nghiêm trọng — ở hai lớp độc lập (v13 "ưu tiên ít nhất hai lớp phòng thủ độc lập"). Bảng dưới là hợp đồng: mỗi dòng có test tự động tương ứng (v13 §20 "Security Constitution được chuyển thành automated conformance tests").

| # | Bất biến | Thực thi trong v0.1 | Test |
|---|---|---|---|
| C1 | Không AI/app/device nào tự cấp hoặc khuếch đại quyền cho chính mình. | `HUMAN_ONLY_ROLES` (AI không thể là owner/admin); delegation `child ⊆ parent`; cấm self-delegation; principal không tự đổi security state của mình. | `identity::ai_cannot_be_owner`, `token::props::delegation_never_amplifies`, `node::delegation_cannot_amplify` |
| C2 | Device A không điều khiển Device B nếu không có capability/delegation hợp lệ. | Monitor: principal không phải Person → `E_TOKEN_MISSING`; policy `C12-device-needs-token`. | `policy::default_policy_matrix` |
| C3 | Cùng LAN, cùng hãng, cùng cloud không tạo trust. | Mọi request là CSME có chữ ký; Unix socket chỉ là transport (spec 11). | `monitor::garbage_and_unknown_keys`, `node::ipc_round_trip` |
| C4 | Nội dung không tin cậy (text, ảnh, audio, web, output AI khác) không bao giờ thành authority. | Authority chỉ nằm ở CSME key 13 (token đã ký); tool argument của MCP là dữ liệu; tham số lạ bị từ chối. | `mcp::prompt_injection_is_just_data` |
| C5 | Lệnh đã ký hợp lệ vẫn có thể bị Safety Kernel hoặc invariant cục bộ từ chối. | Safety envelope của registry (`E_SAFETY_ENVELOPE`); thiết bị từ chối (`X_DEVICE_REFUSED`). | `monitor::capability_checks`, `node::device_refuses_unsafe_authorized_command` |
| C6 | Quản trị thiết bị ≠ quyền đọc Personal Vault. | Dự phòng: role `admin` tách khỏi `owner`; Personal Vault chưa có ở v0.1. | — |
| C7 | Không có universal master key. | Token ký bằng khóa authority **của từng domain**; mỗi principal một khóa riêng; không có khóa chung toàn hệ sinh thái. | `token::foreign_or_tampered_tokens_are_invalid`, `monitor::token_checks` |
| C8 | Compromise một AI/device/service/domain không suy ra quyền ở trust domain khác. | Token holder-bound + domain-bound; target ngoài domain → `E_UNKNOWN_TARGET`; containment theo từng principal. | `monitor::token_checks`, `mcp::probing_through_the_broker_quarantines_the_ai` |
| C9 | Chức năng safety-critical có hành vi an toàn cục bộ khi cloud/server/AI mất. | Node local-first, không phụ thuộc cloud; policy `C9-critical-needs-approval`. SC4/Q4 để sau 1.0. | `policy::default_policy_matrix` |
| C10 | Ngữ nghĩa bảo mật ổn định khi crypto/transport/DB/AI thay đổi. | Versioning CSME (`E_VERSION`), crit extension (`E_CRITICAL_EXT`), alg id tường minh (`E_ALG`), registry có version. | `csme::version_and_extensions` |
| C11 | AI không sửa cơ chế bảo vệ (policy, revocation, security state) và không là authority cuối cho hành động rủi ro cao. | Policy `C11-ai-no-domain-admin`, `C11-ai-no-high-risk`; delegation cho AI một quyền nó không bao giờ dùng được bị từ chối ngay khi cấp. | `monitor::policy_checks`, `monitor::delegated_ai_can_turn_on_but_never_unlock` |
| C12 | Không AI nào có quyền mặc định điều khiển entity khác. | `E_TOKEN_MISSING` (monitor) **và** `C12-ai-needs-token` (policy) — hai lớp độc lập. | `monitor::unauthorized_ai_is_denied`, `node::milestone_0_0_1_…` |
| C13 | Delegation không khuếch đại: `child_scope ⊆ parent_scope`, `child_expiry ≤ parent_expiry`, độ sâu giới hạn. | `chitala-token` (depth ≤ 3, token attenuated không được tái ủy quyền); revocation lan xuống mọi token con. | `token::delegation_rules`, `token::depth_is_bounded`, `token::revocation_cascades_to_children` |
| C14 | Không phản hồi ≠ đồng ý. | Dự phòng cho Human Decision Center (0.3). v0.1 không có luồng "chờ phê duyệt" nên không có default-allow nào. | — |

## Quy tắc diễn giải

1. Khi một bất biến và một tính năng xung đột, bất biến thắng; tính năng phải được thiết kế lại.
2. Thêm bất biến mới được phép (C15…); sửa nghĩa hoặc xóa một bất biến là thay đổi phá vỡ và cần phiên bản spec mới.
3. Policy domain (`policy/default.cedar`) có thể **thêm** `forbid`, nhưng không được gỡ các policy có tiền tố `C*-` — việc đó tương đương sửa Constitution.
