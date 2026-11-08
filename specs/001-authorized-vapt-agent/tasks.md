# Tasks: Authorized VAPT Agent

**Input**: Design documents from `/specs/001-authorized-vapt-agent/`

**Tests**: Safety-critical validation, scope, persistence, and UI smoke tests are required.

## Phase 1: Setup

- [x] T001 Create single-application package structure in `src/cipher_lens/` and tests in `tests/`
- [x] T002 Create Python dependency manifest and local environment instructions in `requirements.txt` and `README.md`
- [x] T003 [P] Create application configuration and ignored environment template in `src/cipher_lens/config.py` and `.env.example`

## Phase 2: Foundational Safety and Persistence

- [x] T004 Create SQLite schema for scopes, scan_runs, evidence, findings, approvals, and audit_events in `src/cipher_lens/persistence/schema.py`
- [x] T005 [P] Create Pydantic domain models for scope registration, audit events, evidence records, and action classes in `src/cipher_lens/domain/models.py`
- [x] T006 Create an append-only audit service used by every decision path in `src/cipher_lens/services/audit.py`
- [x] T007 Create strict IPv4/hostname and numeric/range port validators that reject rather than coerce invalid values in `src/cipher_lens/domain/validation.py`
- [x] T008 Create `is_in_scope(target, port, action)` with normalized host comparison and allowed-action enforcement in `src/cipher_lens/domain/scope.py`
- [x] T009 Create SQLite repositories that persist scope and audit records in `src/cipher_lens/persistence/repositories.py`
- [x] T010 [P] Create unit tests for validation rejection, localhost normalization, exclusions, action classes, and audit event persistence in `tests/unit/test_scope.py`

**Checkpoint**: T001-T010 complete; Graphify confirms the scope/audit dependency path before Phase 2 work begins. The formal Spec Kit analyzer was not run at this checkpoint.

## Phase 3: User Story 1 - Create a Safe Assessment (Priority: P1)

**Goal**: Register and persist an explicitly authorized scope and display its decisions.

**Independent Test**: An analyst can save a valid scope, see it after restart, and see invalid or excluded requests rejected and audited.

- [x] T011 [US1] Create Streamlit application entry point and navigation in `src/cipher_lens/app.py`
- [x] T012 [US1] Create Mono token helpers and accessibility-first shared components in `src/cipher_lens/ui/mono.py`
- [x] T013 [US1] Create a Mono-styled scope registration page with authorization attestation in `src/cipher_lens/ui/scope_page.py`
- [x] T014 [US1] Wire registration submission to validation, persistence, and audit logging in `src/cipher_lens/services/scope_registration.py`
- [x] T015 [US1] Show persisted scopes, validation feedback, and an empty state in `src/cipher_lens/ui/scope_page.py`
- [x] T016 [US1] Add an integration test for valid registration, rejected registration, restart persistence, and audit rows in `tests/integration/test_scope_registration.py`

## Phase 4: User Story 2 - Ingest and Correlate Evidence (Priority: P2)

- [x] T017 [US2] Create typed scan profile and PlanProposal models in `src/cipher_lens/domain/proposals.py`
- [x] T018 [US2] Create LLM proposal gateway with schema retry and deterministic gate sequence in `src/cipher_lens/services/planning.py`
- [x] T019 [US2] Create common validate/start/poll/parse adapter contract in `src/cipher_lens/adapters/base.py`
- [x] T020 [US2] Implement Nmap, Nikto, and ZAP adapters with scope/audit path and local evidence storage in `src/cipher_lens/adapters/`
- [x] T021 [US2] Create live-status workspace in `src/cipher_lens/ui/assessment_page.py`

## Phase 5: User Story 3 - Review, Approve, and Report (Priority: P3)

- [x] T022 [US3] Implement `src/cipher_lens/services/findings.py` to normalize only parsed adapter/import evidence into the shared Finding model; preserve source, affected asset, evidence reference, raw artifact hash/path, confidence, severity/CVSS/CVE/CWE fields when present, deterministically identify duplicates without discarding provenance, and derive a stable review priority without LLM-invented findings or severity. Add focused tests for normalization, duplicate provenance, missing optional fields, and deterministic ordering.
- [x] T023 [US3] Implement the generic persisted approval state machine and searchable audit-history workspace in `src/cipher_lens/ui/audit_page.py`, reusing the existing approvals/audit repositories and shared UI helpers. Model only explicit, auditable state transitions (including actor, rationale, timestamp, and expiry); never let this page bypass the adapter validation ticket, scope gate, rate-limit gate, or active-validation approval boundary. Add tests for transition rejection, expiry, search/filter behavior, and read-only audit rendering.
- [x] T024 [US3] Create `src/cipher_lens/ui/integrations_page.py` as an honest seven-tool integration matrix for Nmap, Nikto, ZAP, Nessus, Burp Community, Metasploit, and the approved import paths. Display installed/reachable/import-only/unavailable state from actual checks or declared capability metadata; do not imply a free-tier tool can be automated where its licensing or local availability does not permit it. Use the shared hero, tokens, accessible cards, and friendly errors.
- [x] T025 [US3] Create `src/cipher_lens/services/reporting.py` and `src/cipher_lens/ui/report_page.py` to generate a deterministic PDF snapshot from persisted scope, scan runs, evidence, findings, approvals, and audit history. Clearly label unavailable/failed scans, retain evidence hashes and provenance, exclude secrets and raw provider keys, and never manufacture conclusions absent from recorded evidence. Test the report service for traceability and a no-data/partial-data case before exposing the page.
- [x] T026 [US3] Add `tests/integration/test_assessment_to_report.py` for one seeded, authorized lab assessment that exercises scope registration, a proposal/gate decision, persisted run/evidence/findings, approval/audit records where applicable, and PDF output. Use fixtures or imported artifacts instead of requiring live third-party targets or locally installed scanners; assert each displayed/reported finding traces back to persisted evidence and audit events.

## Phase 6: Cross-Cutting Verification

- [x] T027 Regenerate the complete project graph with the Python 3.13 `.venv` Graphify installation after T022–T026, refresh the visual graph/report rather than relying on the Phase 1 snapshot, and record the reviewed result in `Project-Context.md`. Explicitly trace every adapter/import path to `is_in_scope()` and audit logging before subprocess/API work, or append a convergence gap if any bypass is found.
- [x] T028 Run the final non-destructive Spec Kit analyzer across `spec.md`, `plan.md`, `data-model.md`, `contracts/api.md`, and `tasks.md`; resolve approved conflicts through normal implementation/clarification, rerun analysis, and retain its outcome in the phase record before declaring the MVP complete.
- [x] T029 Perform a clean-client quickstart validation using the exact README commands and canonical Python 3.13 `.venv`; verify `.env.example`, dependency installation, Streamlit startup, test command, and graceful unavailable-tool states. Document the commands, outcome, client-visible limitations, required local authorizations/tools, and recovery guidance in `Project-Context.md` and README without exposing internal development-stage wording in the product UI.

### Continuation quality gate (applies to T022–T029)

- Begin Phase 5 with a phase-scoped clarification pass (maximum five critical questions). Record accepted answers in `spec.md` before code; do not use assumptions to settle data retention, severity, approval, report, or tool-capability policy.
- Work in the listed dependency order. Update `Project-Context.md` after every completed checkpoint and mark each checklist item only after its code and targeted tests land.
- Preserve all six non-negotiable safety rules, the 45-second configurable per-`(target, action)` rate-limit policy, the two-attempt provider schema cap, `.env` loading, and the durable 15-minute exact-request active-validation approval policy.
- Every page must use `apply_tokens()` and `heading()` from `src/cipher_lens/ui/mono.py`: the shared cream/lime/dark-teal bento system, accessible labels, friendly validation helper, and one-card `Logo-landscape.png` background hero. Do not use `st.image()` or an `<img>` tag for the hero logo, and do not add execution controls to a read-only page.
- At the end of each approved phase, perform a read-only convergence pass against the relevant spec/plan/data model. Append gaps under a new Convergence section in this file rather than fixing them silently during that pass; report “Converged” only with no gaps and stop for review.

## Dependencies & Execution Order

`T001 -> T004-T010 -> T011-T016 -> T017-T021 -> T022-T026 -> T027-T029`.

Phase 1 implementation is limited to T001-T016. T017 and later require phase-scoped clarification
and the team lead's phase approval. T022 must not start until the Phase 5 clarification is recorded and approved.

## Phase 7: Convergence

- [x] T030 Reject undeclared provider JSON fields in `PlanProposal` and `AnticipatedNextStep` per approved proposal constraint (partial)
- [x] T031 Retry one corrective schema-only prompt for an invalid provider response before provider failover in `src/cipher_lens/services/planning.py` per T018 (missing)
- [x] T032 Define the team-lead-approved rate-limit threshold and enforce it through a concrete auditable policy in the proposal gate per FR-001 and plan delivery sequence (missing)
- [x] T033 Preserve optional `anticipated_next_steps` in the proposal audit detail so the preview has audit visibility per approved implementation constraints (missing)
- [x] T034 Load the documented local `.env` provider configuration before resolving provider slots, with tests, per approved provider configuration constraint (missing)
- [x] T035 Update `Project-Context.md` to accurately record Phase 2 implementation, Python 3.13 verification, and outstanding convergence work per Constitution V (partial)

## Phase 8: Convergence

- [x] T036 Replace the caller-supplied approval flag with a persisted, auditable approval decision verified before any active-validation adapter start per FR-011 and Constitution I (partial)
- [x] T037 Define and implement a scope-safe ZAP target URL scheme policy so HTTPS services are not silently sent as `http://` per T020 daemon integration decision (missing)

## Phase 9: Convergence

- [x] T038 Handle malformed Nmap/Nikto XML and ZAP JSON by recording an auditable parse failure and setting the linked scan run to `failed` per edge-case requirements and Constitution III (partial)

## Phase 10: Convergence

- [x] T039 Persist the approved proposal rationale when each live adapter creates its scan run, so T021 can display the real evidence-grounded rationale rather than an empty-state substitute per FR-003 and FR-004 (partial)
- [x] T040 Implement Tier 1 native tool vulnerability extraction in `src/cipher_lens/adapters/nikto.py`, `src/cipher_lens/adapters/zap.py`, and `src/cipher_lens/adapters/nmap.py` to parse evidenced CVE/CWE tokens and verified product/version strings without network calls
- [x] T041 Implement Tier 2 NIST NVD API 2.0 lookup service in `src/cipher_lens/services/nvd.py` with 50 req/30s rate limiting, in-memory caching, apiKey authentication, and strict gating to scanner-captured product/version
- [x] T042 Wire two-tier CVE/CVSS enrichment into Result Ingestion in `src/cipher_lens/services/findings.py` with comprehensive unit test coverage in `tests/unit/test_nvd.py`
- [x] T043 Implement cross-platform POSIX compatibility in `src/cipher_lens/adapters/nmap.py` replacing top-level Windows-only `ctypes.windll` with runtime Linux root/privilege detection (`os.geteuid() == 0`)

## Phase 11: Production Hardening & Multi-Tool Planning (Convergence)

- [x] T044 [P1] [FIX] Make scan subprocess lifecycle and polling rerun-safe in `src/cipher_lens/adapters/nikto.py`, `src/cipher_lens/adapters/nmap.py`, and `src/cipher_lens/ui/assessment_page.py`. Persist process metadata (`pid`, `output_path`, `deadline`) to disk so scans survive Streamlit reruns and browser reloads without being falsely marked as "Scan process was interrupted by page reload". Update `_recover_orphaned_scans` to poll active processes and ingest completed results instead of failing active scans. Add regression test in `tests/unit/test_assessment_page.py`.
- [x] T045 [P2] [FEATURE] Expand planning prompt in `src/cipher_lens/services/planning.py` to ingest the truthful 7-tool catalog with real statuses (`Live`, `Import-only`, `Planned`) from `src/cipher_lens/services/integrations.py`. Enable the LLM to reference import-only tools (e.g. Burp Suite Community) in `rationale` and `anticipated_next_steps` with manual guidance, while strictly enforcing that only Live tools can be selected in the executable `tool` field. Add unit tests in `tests/unit/test_planning.py`.
- [x] T046 [P3] [UI] Surface pre-approval ZAP site-tree warm-up checklist in `src/cipher_lens/ui/audit_page.py` above the active-validation approval button, guiding the analyst to confirm daemon reachability and proxy-browse SPA routes before unleashing active scans.

## Phase 12: ZAP Active Validation Bridge, Loopback Normalization & Nikto Severity Classification

- [x] T047 [P1] [FIX] Implement intelligent loopback alias resolution in `src/cipher_lens/adapters/zap.py`. Before invoking `/JSON/ascan/action/scan/`, inspect `/JSON/core/view/sites/`. If `target_url` (e.g. `http://127.0.0.1:3000`) is not in ZAP's sites list but its loopback counterpart (`http://localhost:3000`) is present, target the populated site tree entry. Capture and report exact error messages from ZAP REST responses instead of failing with an unhandled `KeyError`.
- [x] T048 [P1] [FIX] Make approval scheme verification flexible in `src/cipher_lens/persistence/repositories.py`. When an approval record has `scheme is None`, allow it to match requests with scheme `http` or `https` instead of failing strict tuple equality.
- [x] T049 [P2] [OBSERVABILITY] Add explicit console failure logging in `_execute_and_collect_scan` in `src/cipher_lens/ui/assessment_page.py` to print exact validation block reasons and adapter start failures to stdout.
- [x] T050 [P2] [FEATURE] Implement native OWASP/CWE/CVSS vulnerability classification for Nikto findings in `src/cipher_lens/adapters/nikto.py`. Map web misconfigurations (missing security headers X-Frame-Options, CSP, HSTS, cookie secure/HttpOnly flags, info leaks) to respective CWEs, severities (Critical/High/Medium/Low), and CVSS baseline scores per SECREF documentation.
- [x] T051 [P1] [TEST] Add regression tests for ZAP loopback site-tree alias resolution, scheme wildcard verification in approvals, and Nikto finding severity/CVSS extraction.
