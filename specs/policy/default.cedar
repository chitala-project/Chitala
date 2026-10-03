// Chitala default domain policy v0.1 — spec `specs/06-policy.md`.
//
// Cedar schema được sinh tự động từ Capability Registry (namespace Chitala):
//   principal: Chitala::Person | Chitala::AI | Chitala::Service | Chitala::Device
//   resource : Chitala::Device | Chitala::Domain | Chitala::Resource (spec §14; `in` = cây cha/con)
//   action   : Chitala::Action::"<capability id>", thuộc nhóm "risk-low|medium|high|critical"
//   context  : { token_granted: Bool, human_approved: Bool, risk: Long }
//
// Quy tắc: mỗi policy PHẢI có @id duy nhất; id được ghi vào audit log làm lý do quyết định.
// forbid luôn thắng permit (ngữ nghĩa Cedar). Policy lỗi khi đánh giá ⇒ cả quyết định là DENY
// (E_POLICY_ERROR) — fail closed.

// ───────────────────────── Grants (RBAC/ABAC) ─────────────────────────

@id("owner-all")
permit (principal in Chitala::Role::"owner", action, resource);

@id("admin-domain")
permit (principal in Chitala::Role::"admin", action, resource is Chitala::Domain);

@id("admin-devices-low-medium")
permit (
  principal in Chitala::Role::"admin",
  action in [Chitala::Action::"risk-low", Chitala::Action::"risk-medium"],
  resource is Chitala::Device
);

@id("adult-devices-low-medium")
permit (
  principal in Chitala::Role::"adult",
  action in [Chitala::Action::"risk-low", Chitala::Action::"risk-medium"],
  resource is Chitala::Device
);

// Người lớn được ủy quyền tiếp những gì mình có (node kiểm tra child ⊆ parent),
// thu hồi token do mình cấp, và xem danh sách thiết bị.
@id("adult-delegate")
permit (
  principal in Chitala::Role::"adult",
  action in [
    Chitala::Action::"domain.delegate",
    Chitala::Action::"domain.revoke_token",
    Chitala::Action::"domain.list_devices",
    Chitala::Action::"domain.list_approvals"
  ],
  resource is Chitala::Domain
);

@id("child-devices-low")
permit (
  principal in Chitala::Role::"child",
  action in Chitala::Action::"risk-low",
  resource is Chitala::Device
);

@id("guest-devices-low")
permit (
  principal in Chitala::Role::"guest",
  action in Chitala::Action::"risk-low",
  resource is Chitala::Device
);

// ───────────── Resource grants (đường Intent, spec §15–16) ─────────────
// Với Resource, quyền theo vai trò dựa trên rủi ro HIỆU DỤNG (context.risk = max(rủi ro
// registry, risk_floor của binding)), không theo nhóm action tĩnh: một resource có thể
// nâng rủi ro của một capability.

// Chủ sở hữu (owner hiệu dụng của resource hoặc tổ tiên) có toàn quyền trên resource đó.
@id("resource-owner")
permit (principal is Chitala::Person, action, resource is Chitala::Resource)
when { resource.owners.contains(principal) };

@id("admin-resources-low-medium")
permit (principal in Chitala::Role::"admin", action, resource is Chitala::Resource)
when { context.risk <= 1 };

@id("adult-resources-low-medium")
permit (principal in Chitala::Role::"adult", action, resource is Chitala::Resource)
when { context.risk <= 1 };

@id("child-resources-low")
permit (principal in Chitala::Role::"child", action, resource is Chitala::Resource)
when { context.risk == 0 };

@id("guest-resources-low")
permit (principal in Chitala::Role::"guest", action, resource is Chitala::Resource)
when { context.risk == 0 };

// Một capability token hợp lệ (Biscuit authorizer đã chấp nhận) là một grant cụ thể.
@id("token-grant")
permit (principal, action, resource)
when { context.token_granted };

// ──────────────────── Security Constitution (forbid) ────────────────────

// C12: không AI/Service/Device nào có quyền mặc định điều khiển entity khác;
// mọi hành động của principal không phải con người phải có token.
@id("C12-ai-needs-token")
forbid (principal is Chitala::AI, action, resource)
unless { context.token_granted };

@id("C12-service-needs-token")
forbid (principal is Chitala::Service, action, resource)
unless { context.token_granted };

@id("C12-device-needs-token")
forbid (principal is Chitala::Device, action, resource)
unless { context.token_granted };

// C11: AI không sửa cơ chế bảo vệ: không ủy quyền, không thu hồi, không đổi security state,
// và không nhìn vào hàng đợi phê duyệt của con người.
@id("C11-ai-no-domain-admin")
forbid (
  principal is Chitala::AI,
  action in [
    Chitala::Action::"domain.delegate",
    Chitala::Action::"domain.revoke_token",
    Chitala::Action::"domain.set_principal_state",
    Chitala::Action::"domain.list_approvals"
  ],
  resource
);

// v15 D4 / v8 §10: AI không phải authority cuối cho hành động rủi ro cao.
// human_approved luôn false ở v0.1 (Human Decision Center chưa có) ⇒ AI không bao giờ
// mở khóa cửa, kể cả khi có token.
@id("C11-ai-no-high-risk")
forbid (
  principal is Chitala::AI,
  action in [Chitala::Action::"risk-high", Chitala::Action::"risk-critical"],
  resource
)
unless { context.human_approved };

// v8 §10: Critical chỉ qua quy trình phê duyệt riêng / controller chứng nhận.
@id("C9-critical-needs-approval")
forbid (principal, action in Chitala::Action::"risk-critical", resource)
unless { context.human_approved };

// v11 §15: trẻ em không thực hiện hành động rủi ro cao, kể cả khi được ủy quyền.
@id("child-no-high-risk")
forbid (
  principal in Chitala::Role::"child",
  action in [Chitala::Action::"risk-high", Chitala::Action::"risk-critical"],
  resource
);

// v5 §11 / v13 §4: thiết bị SC0 (legacy, không xác thực được đường lệnh) không nhận
// lệnh rủi ro cao; thiết bị SC0 làm principal chỉ được hành động rủi ro thấp.
@id("SC0-no-high-risk-target")
forbid (
  principal,
  action in [Chitala::Action::"risk-high", Chitala::Action::"risk-critical"],
  resource is Chitala::Device
)
when { resource.security_class == 0 };

@id("SC0-no-high-risk-resource")
forbid (principal, action, resource is Chitala::Resource)
when { resource.security_class == 0 && context.risk >= 2 };

// Bản theo rủi ro hiệu dụng của C11/C9/child cho Resource: risk_floor có thể đưa một
// capability "medium" lên "high" ở một resource cụ thể.
@id("C11-ai-no-high-risk-effective")
forbid (principal is Chitala::AI, action, resource is Chitala::Resource)
when { context.risk >= 2 }
unless { context.human_approved };

@id("C9-critical-needs-approval-effective")
forbid (principal, action, resource is Chitala::Resource)
when { context.risk >= 3 }
unless { context.human_approved };

@id("child-no-high-risk-effective")
forbid (principal in Chitala::Role::"child", action, resource is Chitala::Resource)
when { context.risk >= 2 };

@id("SC0-principal-low-only")
forbid (principal is Chitala::Device, action, resource)
when { principal.security_class == 0 }
unless { action in Chitala::Action::"risk-low" };
