# Roadmap

## Feature freeze (hiện tại)

Dòng `0.0.x` đang **đóng băng tính năng**. Mục tiêu ngắn hạn là biến Trusted Core hiện có thành một lõi **thực sự kiểm chứng được**, không phải mở rộng nó.

Trong thời gian freeze, một thay đổi chỉ được merge nếu nó thuộc một trong các nhóm sau:

- sửa lỗi hoặc lỗ hổng, kèm test tái hiện;
- tăng khả năng kiểm chứng: test, property test, fuzz target, test vector, conformance;
- CI, chuỗi cung ứng, SBOM, ký artifact;
- thay đổi kiến trúc nhằm **cô lập** hoặc **thu nhỏ** Trusted Core (TCB);
- tài liệu và spec.

Không thêm capability, adapter, giao thức, transport hay thành phần AI mới. Ví dụ: MQTT/WoT là tính năng nên chờ, còn tách adapter ra khỏi tiến trình lõi là hardening nên được làm.

## Thứ tự ưu tiên

| # | Hạng mục | Trạng thái |
|---|---|---|
| 1 | Feature freeze; Trusted Core kiểm chứng được | đang làm (liên tục) |
| 2 | CI/security pipeline: `fmt --check` → `clippy` → `test` → `cargo audit` → `cargo deny`; CodeQL, Dependabot; SBOM; ký artifact/release | xong |
| 3 | Fuzz các trust boundary: CSME/CBOR, token, IPC, adapter parser (threat model R8) | xong — 9 target |
| 4 | Tách adapter ra khỏi tiến trình Trusted Core: adapter lỗi không được ảnh hưởng Reference Monitor (R4) | xong — sandbox mức OS còn lại |
| 5 | Monotonic time, phát hiện lùi đồng hồ/rollback, trước khi mở rộng sang hệ phân tán (R3) | xong — thời gian có xác thực còn lại |
| 6 | Human Decision Center (A4), khóa phần cứng (TPM/Secure Element), attestation, enrollment | sau |
| 7 | Simulator, multi-node/federation, Future Profiles (Mobility, Robotics…) | khi Trusted Core ổn định |

Thứ tự này theo nguyên tắc của Blueprint v17: *"Hạt nhân đầu tiên của Chitala không phải AI; đó là một chuỗi tin cậy có thể kiểm chứng."*
