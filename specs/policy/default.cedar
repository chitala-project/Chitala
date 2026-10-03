// Chitala default domain policy v0.1 — spec `specs/06-policy.md`.
//
// Cedar schema được sinh tự động từ Capability Registry (namespace Chitala):
//   principal: Chitala::Person | Chitala::AI | Chitala::Service | Chitala::Device
//   resource : Chitala::Device | Chitala::Domain
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
    Chitala::Action::"domain.list_devices"
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

// C11: AI không sửa cơ chế bảo vệ: không ủy quyền, không thu hồi, không đổi security state.
@id("C11-ai-no-domain-admin")
forbid (
  principal is Chitala::AI,
  action in [
    Chitala::Action::"domain.delegate",
    Chitala::Action::"domain.revoke_token",
    Chitala::Action::"domain.set_principal_state"
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

@id("SC0-principal-low-only")
forbid (principal is Chitala::Device, action, resource)
when { principal.security_class == 0 }
unless { action in Chitala::Action::"risk-low" };
