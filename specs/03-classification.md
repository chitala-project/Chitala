# 03 — Unified classification scales

Blueprint v18 accumulated over many versions and ended up with **nine overlapping scales**:

- two different `S0–S4` scales (v4 §13 security profiles and v13 §4 security classes);
- `D0–D5` (v15 §10) and `R0–R5` (v16 §15);
- `C0–C4` (v14 §17) and the IFC labels (v13 §2);
- `L1–L6` (v8 §13) and the security state machine (v11 §16.5 = v13 §11).

v0.1 keeps **the meaning** of every scale in the PDF, but each concept now has **one** scale with **its own prefix**. On the wire and in logs, "S2" of one scale can never be confused with "S2" of another. The mapping below is normative: a document that uses a v18 name translates to v0.1 through this table without losing information.

## Mapping to Blueprint v18

| Concept | Name in v18 | v0.1 | Wire code |
|---|---|---|---|
| Assurance of an entity | v13 §4 S0 Legacy/Untrusted · S1 Basic · S2 Secure · S3 High Assurance · S4 Safety Critical | `SC0`…`SC4` (same meaning as v13) | 0–4 |
| Communication deployment profile | v4 §13 S0 Legacy Bridge · S1 Consumer · S2 Enterprise · S3 High Assurance · S4 Safety Domain | a *deployment profile* (not a property of each message); maps approximately to the SC with the same number | — |
| Risk of an action | CSME `safetyClass` (v4 §3); low/medium/high/critical (v8 §10); the token's "safety budget" (v8 §2) | `RiskClass` low · medium · high · critical | 0–3 |
| Autonomy | v15 §10 D0 Observe … D5 Critical authority; v16 §15 R0 Observe … R5 Critical | `A0`…`A5` (D_n = R_n = A_n; the two PDF scales run in parallel step by step) | 0–5 |
| Data classification | v13 §2 Public / Shared / Private / Restricted / Safety-critical; v14 §17 C0 Public … C4 Critical | `DC0`…`DC4` (DC_n = C_n; the IFC labels in the same order) | 0–4 |
| Communication QoS | v4 §8 Q0–Q4 | `Q0`…`Q4` (unchanged) | 0–4 |
| Hardware | v5 §15 H0–H5, HX | `H0`…`H5`, `HX` (unchanged) | 0–5, 255 |
| Security state | v11 §16.5 = v13 §11 | `TRUSTED` → `SUSPICIOUS` → `RESTRICTED` → `QUARANTINED` → `RECOVERY` → `RE_ATTEST` | 0–5 |
| Containment level | v8 §13 L1 Restrict · L2 Revoke · L3 Quarantine Agent · L4 Quarantine Device · L5 Safety Island · L6 Recovery | see the list below | — |

The containment levels map as follows:

- L1 → `RESTRICTED`
- L2 → `domain.revoke_token`
- L3 and L4 → `QUARANTINED`. AIs and devices are separate principals, so "quarantine agent" and "quarantine device" are the same operation on two different principals.
- L5 → SC4 (after 1.0)
- L6 → `RECOVERY` / `RE_ATTEST`

`SC4` and `Q4` are defined but **not supported** in the v0.x line (`supported_in_v0`). A safety domain needs a certified controller and is outside the scope of a general OS (v5 §12, v6 §8).

## Constraint matrices

**M1 — risk → highest autonomy of an AI** (`RiskClass::max_ai_autonomy`). Above this level a human or a certified controller is the final authority.

| Risk | low | medium | high | critical |
|---|---|---|---|---|
| AI at most | A2 (acts on its own, low risk) | A3 (within the envelope) | A4 (needs human approval) | A5 (special authority) |

On the intent path, A4 is implemented: a high-risk action requested by an AI is escalated and proceeds only with an owner's signed approval (spec 16).

**M2 — security class → minimum hardware** (`SecurityClass::min_hardware`): SC0/SC1 → H0, SC2 → H1, SC3 → H2, SC4 → H2. A device may not claim a higher SC than its hardware can prove (v13 §19).

**M3 — security state → highest permitted risk** (`SecurityState::max_risk`):

| State | May do | v13 §11 note |
|---|---|---|
| TRUSTED | every level (subject to policy) | |
| SUSPICIOUS | ≤ medium | "reduce sensitive rights" |
| RESTRICTED | ≤ low | "minimal allowlist only" |
| QUARANTINED | nothing | "safety/diagnostic/recovery only" — no diagnostics in v0.1 yet |
| RECOVERY, RE_ATTEST | nothing | not trusted again yet |

On the intent path the ceiling applies to every actor of a chain **and** to the person each actor represents (spec 16, RISK step).

## Valid transitions (`SecurityState::can_transition`)

- Escalating to a stricter state on the ladder `TRUSTED < SUSPICIOUS < RESTRICTED < QUARANTINED` is always allowed, including skipping steps.
- `SUSPICIOUS`/`RESTRICTED → TRUSTED` is allowed (a false positive, decided by a human).
- From `QUARANTINED` there is only one way out: `→ RECOVERY → RE_ATTEST → TRUSTED`. A reboot or a restore **never** re-trusts a principal (v11 §30).
- `RECOVERY`/`RE_ATTEST → QUARANTINED` is allowed (recovery failed).
- No principal changes its own state (spec 11).
