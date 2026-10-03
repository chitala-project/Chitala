# 13 — Threat Model v0.1

Nguồn: v13 §18 (Formal Threat Model & Verification Program), v8 §19 (kiểm thử bắt buộc), v10 §1/§17, v11 §17.

Mục tiêu không phải "không thể bị hack" mà là làm cho compromise **khó xảy ra, khó lan rộng, khó tồn tại lâu, và phục hồi được** (v13).

## Ranh giới tin cậy

```
 ┌──────────── untrusted ────────────┐   ┌──────────────── trusted core (Rust, no unsafe) ────────────────┐
 │ LLM / prompt / web / tool output  │   │                                                                  │
 │ AI principal  (ai:*)              │──▶│  chitala-mcp ──CSME──▶ IPC ──▶ Reference Monitor ──▶ Adapter ──▶│ device
 │ local processes, other users      │   │  (holds AI key)              (identity, freshness,               │
 │ the network, legacy devices (SC0) │   │                               capability, token, Cedar)          │
 └───────────────────────────────────┘   │  domain authority key · node key · audit · state                │
                                          └──────────────────────────────────────────────────────────────────┘
```

Giả định: hệ điều hành của máy node và tài khoản chạy node chưa bị chiếm; người giữ khóa owner là chủ hợp pháp.

## Tấn công đã được chặn — mỗi dòng có test

| Tấn công | Phòng thủ | Test |
|---|---|---|
| AI tự điều khiển thiết bị khi chưa được ủy quyền | `E_TOKEN_MISSING` + policy `C12-ai-needs-token` (2 lớp) | `unauthorized_ai_is_denied`, `milestone_0_0_1_…` |
| AI dùng token đèn để mở cửa | token scope (`E_TOKEN_DENIED`) | `token_checks`, `tools_follow_the_token` |
| AI được (lỡ) trao token mở cửa | Constitution `C11-ai-no-high-risk`; node từ chối cấp ngay từ đầu | `delegated_ai_can_turn_on_but_never_unlock`, `delegation_cannot_amplify` |
| AI ủy quyền/thu hồi/tự gỡ cách ly | `C11-ai-no-domain-admin`, cấm tự đổi state | `policy_checks`, `probing_ai_is_contained_…` |
| AI khác đánh cắp token | token holder-bound | `token_checks` |
| Khuếch đại quyền qua chuỗi delegation | child ⊆ parent, expiry, depth, cấm token đã attenuate | `delegation_never_amplifies` (property), `depth_is_bounded` |
| Block attenuation chèn quyền | scoping của Biscuit | `attenuation_block_cannot_inject_rights_or_holder` |
| Token của domain khác / token bị sửa | chữ ký authority của domain | `foreign_or_tampered_tokens_are_invalid` |
| Prompt injection qua tham số tool | tham số là dữ liệu, schema chặt | `prompt_injection_is_just_data` |
| AI dò quyền liên tục | containment tự động lên QUARANTINED | `probing_through_the_broker_quarantines_the_ai` |
| Giả mạo request đứng tên người khác để họ bị cách ly | chỉ tính denial đã xác thực | `forged_signature_is_not_attributed` |
| Request có chữ ký bị sửa một bit | chữ ký COSE | `bit_flips_never_allow` (property) |
| Byte rác / CBOR độc làm parser lỗi | xác thực trước khi parse, canonical CBOR, giới hạn kích thước/độ sâu | `garbage_never_opens`, `signed_garbage_never_panics` |
| Replay request | nonce `(kid, mid)`, ≤ 60 s, request dùng một lần | `freshness_and_replay` |
| Replay request đã bị từ chối sau khi quyền được cấp | nonce bị tiêu thụ cả khi deny | `denied_request_cannot_be_replayed_after_a_grant` |
| Replay sau khi node restart | từ chối request ký trước lúc khởi động | `replay_after_restart_is_refused` |
| Khai báo risk thấp để lách policy | `E_RISK_MISMATCH` | `capability_checks` |
| Giá trị nguy hiểm (độ sáng 140%) | safety envelope | `capability_checks` |
| Lệnh hợp lệ nhưng không an toàn (khóa khi cửa mở) | invariant ở thiết bị (C5) | `device_refuses_unsafe_authorized_command` |
| Tiến trình giả mạo node trên socket | phản hồi ký bằng khóa node đã ghim, gắn với request | `client_refuses_an_impostor_node`, `forged_or_misbound_replies_are_rejected` |
| Chiếm trước đường dẫn socket trong `/tmp` | thư mục riêng 0700, kiểm tra chủ sở hữu, không theo symlink | `private_files_and_sockets` |
| Chép đè state cũ để gỡ thu hồi token | epoch của audit ≤ epoch của state | `rollback_truncation_and_deletion_refuse_to_start` |
| Xóa/cắt audit log | anchor của audit trong state | `rollback_truncation_and_deletion_refuse_to_start` |
| Sửa audit log | chuỗi hash + checkpoint ký | `tampering_is_detected` |
| Bí mật lọt vào log | redaction, token không bao giờ được log | `redaction`, `delegation_cannot_amplify` |
| File khóa đọc được bởi người khác | từ chối dùng | `private_files_and_sockets` |
| Lộ token Home Assistant qua HTTP | chỉ https hoặc loopback | `plaintext_http_only_to_loopback_or_when_explicitly_allowed` |
| Flood request | rate limit theo actor, giới hạn kết nối/timeout IPC, replay cache có giới hạn | `rate_limit_per_actor` |

## Rủi ro còn lại (theo mức ưu tiên)

| # | Rủi ro | Hướng xử lý | Mốc (v13 §21) |
|---|---|---|---|
| R1 | Khóa authority/node nằm trong file; ai chiếm tài khoản node sẽ có cả hai khóa | Credential Provider: TPM 2.0 / Secure Element, khóa không export được (v5 §8, v7 §14) | v0.5 |
| R2 | Rollback đồng thời state + cắt audit về anchor cũ không phát hiện được trên một đĩa | TPM NV monotonic counter, hoặc đẩy checkpoint ra thiết bị/domain khác, transparency log | v0.5 |
| R3 | Node tin đồng hồ hệ thống; lùi đồng hồ làm token hết hạn dùng lại được | Lưu thời điểm lớn nhất từng thấy và từ chối khi đồng hồ lùi; nguồn thời gian có xác thực (v16 §4) | v0.2 |
| R4 | Adapter chạy trong tiến trình node và lúc đang giữ khóa node: thiết bị chậm (HA timeout 10 s) chặn mọi request khác, adapter lỗi chạy chung không gian nhớ | Adapter chạy tiến trình riêng/sandbox, IPC có capability, thực thi ngoài khóa (v8 §3, A.3) | v0.2 |
| R5 | Chưa có attestation của thiết bị/node (RATS/EAT) | v10 §5 | v0.5 |
| R6 | Chưa có Human Decision Center: mọi hành động high-risk của AI bị cấm hẳn thay vì "cần người duyệt" | v15 §11–13, A4 với deadline và no-response = deny (C14) | v0.3 |
| R7 | Enrollment thủ công qua file config; chưa có onboarding/chuyển chủ kiểu FIDO FDO, chưa có ownership epoch | v10 §4 | v0.2 |
| R8 | Chưa fuzz bằng coverage-guided fuzzer (mới có property test) | `cargo-fuzz` cho CSME, token, IPC, adapter parser (v13 §10) | v0.1 |
| R9 | Chuỗi cung ứng: chưa có CI, SBOM, `cargo audit`/`cargo deny`, build tái lập, release có chữ ký | v13 §15, v11 §18 | v0.1 |
| R10 | Khóa bí mật trong RAM không được xóa sạch tường minh khi đọc file (chuỗi hex trung gian) | `zeroize` cho bộ đệm khóa | v0.2 |
| R11 | Personal Vault, IFC, E2EE, federation chưa có | v7, v13 §2, v12 | sau 0.5 |

## Kiểm thử bắt buộc chưa có (v8 §19)

Red-team agent tự động, mixed-version network, chaos (mất mạng giữa nhiệm vụ, xoay khóa giữa chừng), compromise cloud trong khi safety island vẫn an toàn — sẽ được thêm cùng simulator (v4 §21).
