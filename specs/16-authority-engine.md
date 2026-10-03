# 16 — Authority Engine

Nguồn: Blueprint v19 "Authority Fabric", v9 "Authority Engine"; module `chitala_policy::authority`.

> AI produces Intent. **Chitala produces Authority.** Only the trusted execution boundary produces physical Commands.

Authority Engine trả lời, cho một intent đã xác thực (và mọi intent nó chuyển tiếp), một chuỗi câu hỏi cố định — câu đầu tiên trả lời "không" quyết định DENY:

```text
WHO → ON_BEHALF_OF → WHAT → OBJECT → CONTEXT → DELEGATION → RISK → APPROVAL → ALLOW | DENY | ESCALATE
```

| Bước | Câu hỏi | Mã từ chối |
|---|---|---|
| WHO | Mọi actor trong chuỗi đã enroll và được phép hành động (security state)? | `E_UNKNOWN_KEY`, `E_PRINCIPAL_STATE` |
| ON_BEHALF_OF | Người được đại diện là `person:*` đã enroll, không bị cách ly; actor phục vụ người đó (khai báo khi enroll)? | `E_ON_BEHALF_OF` |
| WHAT | Action là capability của registry, nhắm device, tham số hợp lệ và trong envelope của registry? | `E_UNKNOWN_CAPABILITY`, `E_UNSUPPORTED_BY_TARGET`, `E_PAYLOAD_INVALID`, `E_SAFETY_ENVELOPE` |
| OBJECT | Resource tồn tại, bind action vào một device đã biết? | `E_UNKNOWN_RESOURCE`, `E_UNSUPPORTED_BY_TARGET`, `E_UNKNOWN_TARGET` |
| CONTEXT | Intent còn hạn; mọi relay trung thực (cùng action/resource/params, **cùng người được đại diện**), không vòng lặp, cause không mới hơn relay? | `E_EXPIRED`, `E_PROVENANCE` |
| DELEGATION | Với mọi mắt xích: người được đại diện có quyền (Cedar, giả định họ đồng ý); actor không phải người có token hợp lệ, chưa thu hồi, đúng holder, bao phủ resource (hoặc tổ tiên); policy cho phép actor (giả định có người duyệt)? | `E_POLICY_DENIED`, `E_TOKEN_MISSING`, `E_TOKEN_INVALID`, `E_TOKEN_REVOKED`, `E_TOKEN_DENIED` |
| RISK | Rủi ro hiệu dụng = max(rủi ro registry, `risk_floor` của binding); không vượt trần security state của bất kỳ actor **hay người được đại diện** nào; không vượt `max_risk` của bất kỳ requester nào? | `E_PRINCIPAL_STATE`, `E_CONSTRAINT` |
| APPROVAL | Policy hoặc constitution có đòi con người không? Nếu có: có câu trả lời hợp lệ từ một owner của resource không? | `E_CONSTRAINT`, `E_POLICY_DENIED`, `E_APPROVAL_INVALID`, `E_APPROVAL_REJECTED` |

## Authority của một chuỗi = giao của các mắt xích

Với một relay A → B, quyền hiệu dụng là `người(A) ∩ token(A) ∩ policy(A) ∩ người(B) ∩ token(B) ∩ policy(B)`. Không agent nào cho agent khác mượn quyền: case 5 của Physical Authority Slice (AI của trẻ nhờ AI của owner mở cửa) bị từ chối ở ON_BEHALF_OF (B không phục vụ trẻ) hoặc ở CONTEXT (B khai là cho owner nhưng mang yêu cầu của trẻ — rửa quyền).

## Khi nào cần con người

Một actor cần người duyệt nếu:

1. Cedar từ chối actor khi `human_approved = false` nhưng cho phép khi `true` (policy diễn đạt "cần người" bằng `unless { context.human_approved }`), hoặc
2. **Constitution trong code** (không gỡ được bằng policy): actor không phải người và rủi ro ≥ `high`; hoặc rủi ro `critical` mà actor không phải owner của resource tự hành động.

Intent của chính một owner trên resource của họ được coi là quyết định của con người. Không có câu trả lời → **ESCALATE** với danh sách approver = owner hiệu dụng của resource mà security state còn cho phép quyết định ở mức rủi ro đó. Không còn ai → DENY. `no_escalation` → DENY.

Một câu trả lời hợp lệ khi: đúng intent id **và** digest; approver là một trong các approver đó; `issued_at` không trước request và không ở tương lai; chưa hết hạn. `reject` → `E_APPROVAL_REJECTED`.

## Đầu vào không làm giả được, đầu ra không làm giả được

`decide(world, &VerifiedIntent, Option<&VerifiedApproval>)`: intent và approval chỉ có thể đến từ việc kiểm chữ ký (spec 15); token được engine tự kiểm (`delegation_evidence`). Kết quả `Verdict::Allow(Grant)` — `Grant` không có constructor công khai, không `Clone`, là bằng chứng mà trusted boundary đòi. Mọi quyết định mang theo `trace`: một dòng cho mỗi câu hỏi đã trả lời, được ghi vào audit.

## Trong node

```text
Monitor::admit_intent  (envelope · identity · freshness · replay · relay chain)
  → decide_intent       (Authority Engine)
  → DENY      → audit + SecurityDenied + containment (AI)
  → ESCALATE  → safety chạy thử → hàng chờ (≤ 3/actor, ≤ 256/domain) → ApprovalRequested
  → ALLOW     → Safety::clear → audit ("no evidence, no action") → boundary → ExecOrder → adapter host
Monitor::admit_approval → decide_intent(…, Some(answer)) → (như trên, Safety chạy lại)
```

Câu trả lời từ người không có quyền trả lời **không** đóng câu hỏi (nếu không, bất kỳ ai cũng hủy được escalation của người khác). Escalation hết hạn theo deadline của intent và được ghi audit (C14: không phản hồi ≠ đồng ý).
