# 13 — Threat Model v0.1

Nguồn: v13 §18 (Formal Threat Model & Verification Program), v8 §19 (kiểm thử bắt buộc), v10 §1/§17, v11 §17.

Mục tiêu không phải "không thể bị hack" mà là làm cho compromise **khó xảy ra, khó lan rộng, khó tồn tại lâu, và phục hồi được** (v13).

## Ranh giới tin cậy

```
 ┌──────────── untrusted ────────────┐   ┌──────────── trusted core (Rust, no unsafe) ───────────┐   ┌─ adapter host (per adapter) ─┐
 │ LLM / prompt / web / tool output  │   │                                                       │   │ no private keys, empty env   │
 │ AI principal  (ai:*)              │──▶│ chitala-mcp ─CSME─▶ IPC ─▶ Reference Monitor ─────────│──▶│ OrderGate ─▶ adapter ─▶ device│
 │ local processes, other users      │   │ (holds AI key)            (identity, freshness,       │ord│ (mock, Home Assistant)       │
 │ the network, legacy devices (SC0) │   │                            capability, token, Cedar)  │◀──│ replies = untrusted data     │
 └───────────────────────────────────┘   │ domain authority key · node key · audit · state       │   └──────────────────────────────┘
                                          └───────────────────────────────────────────────────────┘
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
| Adapter host bị crash/kill | node trả `X_DEVICE_UNAVAILABLE`, Reference Monitor và audit không bị ảnh hưởng, host được khởi động lại | `crashed_adapter_host_never_reaches_the_monitor` |
| Adapter host treo | timeout, kill; khóa node được nhả trong lúc chờ | `hung_adapter_host_does_not_stall_the_node` |
| Adapter host trả dữ liệu độc | phản hồi bị kiểm tra như dữ liệu không tin cậy; host vi phạm giao thức bị kill | `garbage_from_an_adapter_host_is_contained`, `replies_are_untrusted_data` |
| Lệnh giả/cũ/phát lại tới adapter host | `ExecOrder` ký bằng khóa node, hạn ≤ 30 s, dùng một lần, đúng thiết bị | `gate_admits_only_fresh_single_use_node_orders`, `executes_only_admitted_orders_for_the_named_device` |
| Adapter host đọc bí mật của node qua biến môi trường | `env_clear`; chỉ cấp đúng biến cần | `adapter_host_gets_an_empty_environment` |
| Chỉnh lùi đồng hồ để hồi sinh token/request đã hết hạn | `TrustedClock` không lùi; lần lùi được ghi audit | `clock_rollback_cannot_revive_an_expired_token` |
| Chỉnh lùi đồng hồ trước khi node khởi động | so với sự kiện cuối trong audit; > 60 s → từ chối khởi động | `startup_refuses_a_clock_behind_the_audit` |
| Flood request | rate limit theo actor, giới hạn kết nối/timeout IPC, replay cache có giới hạn | `rate_limit_per_actor` |

## Rủi ro còn lại (theo mức ưu tiên)

| # | Rủi ro | Hướng xử lý | Mốc (v13 §21) |
|---|---|---|---|
| R1 | Khóa authority/node nằm trong file; ai chiếm tài khoản node sẽ có cả hai khóa | Credential Provider: TPM 2.0 / Secure Element, khóa không export được (v5 §8, v7 §14) | v0.5 |
| R2 | Rollback đồng thời state + cắt audit về anchor cũ không phát hiện được trên một đĩa | TPM NV monotonic counter, hoặc đẩy checkpoint ra thiết bị/domain khác, transparency log | v0.5 |
| R3 | ~~Node tin đồng hồ hệ thống~~ → **đã xử lý**: `TrustedClock` không bao giờ lùi (max của đồng hồ hệ thống và đồng hồ monotonic), sàn là sự kiện cuối trong audit, từ chối khởi động khi đồng hồ chậm hơn audit > 60 s, mọi lần đồng hồ hệ thống bị lùi được ghi audit có chữ ký; node và adapter host dùng cùng thuật toán. Còn lại: nguồn thời gian có xác thực (NTS/Roughtime), đồng bộ nhiều node | v0.2 |
| R4 | ~~Adapter chạy trong tiến trình node~~ → **đã xử lý**: adapter chạy trong `chitala-adapter-host` (một tiến trình cho mỗi loại adapter, môi trường rỗng, không giữ khóa bí mật), chỉ thực thi `ExecOrder` ký bằng khóa node, còn hạn và dùng một lần; node coi phản hồi là dữ liệu không tin cậy, kill/khởi động lại host treo hoặc hỏng, và nhả khóa trong lúc chờ (spec 10). Còn lại: sandbox ở mức OS (user riêng, seccomp/Landlock, network namespace) | v0.2 |
| R5 | Chưa có attestation của thiết bị/node (RATS/EAT) | v10 §5 | v0.5 |
| R6 | Chưa có Human Decision Center: mọi hành động high-risk của AI bị cấm hẳn thay vì "cần người duyệt" | v15 §11–13, A4 với deadline và no-response = deny (C14) | v0.3 |
| R7 | Enrollment thủ công qua file config; chưa có onboarding/chuyển chủ kiểu FIDO FDO, chưa có ownership epoch | v10 §4 | v0.2 |
| R8 | ~~Chưa fuzz bằng coverage-guided fuzzer~~ → **đã xử lý**: 7 target libFuzzer + ASan trên mọi trust boundary (`fuzz/`), bất biến được kiểm chứ không chỉ "không panic"; CI fuzz mỗi PR 60 s/target, hằng đêm 15 phút/target; harness cũng chạy trên stable trong CI. Còn lại: fuzz có cấu trúc (structure-aware) cho CSME sau chữ ký | v0.1 |
| R9 | ~~Chuỗi cung ứng~~ → **đã xử lý phần lớn**: CI `fmt → clippy → test (x86_64/ARM64/macOS) → cargo audit → cargo deny`, MSRV, CodeQL, Dependabot, zizmor; toolchain được pin; action pin theo SHA; release dùng `cargo auditable`, SBOM CycloneDX, SLSA provenance + SBOM attestation, `SHA256SUMS` ký bằng cosign. Còn lại: build tái lập bit-for-bit, branch protection/required review trên GitHub | v0.1 |
| R10 | Khóa bí mật trong RAM không được xóa sạch tường minh khi đọc file (chuỗi hex trung gian) | `zeroize` cho bộ đệm khóa | v0.2 |
| R11 | Personal Vault, IFC, E2EE, federation chưa có | v7, v13 §2, v12 | sau 0.5 |

## Fuzzing (R8)

| Target | Ranh giới | Bất biến kiểm tra |
|---|---|---|
| `csme_envelope` | COSE từ peer chưa xác thực | parse/verify không panic |
| `csme_payload` | CBOR sau khi xác thực | `decode ∘ encode = id` |
| `token` | capability token | chỉ token domain ký mới verify |
| `node_request` | toàn bộ pipeline Reference Monitor | không bao giờ ALLOW nếu không có chữ ký hợp lệ của principal đã enroll; mọi reply được ký và gắn với request; caller chưa xác thực không nhận chi tiết |
| `ipc` | dòng request (server), dòng reply (client) | reply không có chữ ký của node không bao giờ được chấp nhận |
| `ha_state` | JSON từ Home Assistant | state ra có kích thước chặn trên |
| `audit_log` | file audit khi khởi động/khôi phục | verify không panic |
| `exec_order` | lệnh đi vào adapter host | chỉ lệnh ký bằng khóa node, còn hạn, dùng một lần, đúng thiết bị mới được thực thi |
| `host_line` | dòng request phía host, dòng reply phía node | reply được chấp nhận luôn có kích thước và kiểu bị chặn |

Seed corpus được sinh tất định từ test key (`cargo run --example gen_corpus` trong `fuzz/`) để fuzzer bắt đầu từ input hợp lệ có chữ ký.

## Kiểm thử bắt buộc chưa có (v8 §19)

Red-team agent tự động, mixed-version network, chaos (mất mạng giữa nhiệm vụ, xoay khóa giữa chừng), compromise cloud trong khi safety island vẫn an toàn — sẽ được thêm cùng simulator (v4 §21).
