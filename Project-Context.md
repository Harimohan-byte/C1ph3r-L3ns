# CIPHER LENS - Project Context

Last updated: 8 November 2026 (IST)  
Current status: **Phase 1 through Phase 6 (T001–T039) are 100% complete, verified with 61 passing tests, fresh Graphify graph (557 nodes, 1694 edges, 18 communities), zero convergence gaps, and clean client-ready documentation; ready for final push and demonstration.**

## Product in one sentence

CIPHER LENS is a conversational VAPT assistant for explicitly authorized lab targets that turns an analyst request into a scoped, evidence-backed assessment plan, correlated findings, human-approved validation decisions, and a client-ready report.

## Non-negotiable product rules

- Operate only within explicitly registered and authorized lab scope.
- Require explicit analyst approval before any active or offensive validation; never autonomously exploit a target.
- Ground all conclusions and scores in real imported or live-tool evidence.
- Preserve evidence, timestamps, source tools, confidence, validation status, and audit history.
- Keep developer rules, stage labels, and implementation notes out of client-facing screens.

## Stage ledger

| Stage | Status | Outcome |
| --- | --- | --- |
| 0 - Foundation | Complete | Read and summarized the official brief; selected Mono UI guidance; installed Spec Kit and Graphify project support; created durable project rules and source-control exclusions. |
| 1 - Product definition | Complete | Master specification, constitution, technical research, data model, interface contract, validation guide, and proposed MVP sequence prepared and verified. |
| 2 - Core application | Complete | Phase 1 persistence, Phase 2 AI proposals/gates, Phase 3 scope workspace, Phase 4 scanner adapters/status workspace, and Phase 5 finding correlation, approvals state machine, 7-tool matrix, and PDF reporting are complete and verified. |
| 3 - Demonstrable workflow | Complete | Full assessment-to-report lifecycle verified end-to-end via integration test suite; all 61 tests pass. |
| 4 - Verification & Release | Complete | Phase 6 cross-cutting verification complete: Graphify architecture regenerated, Spec Kit cross-artifact alignment verified with 0 gaps, client-ready quickstart and README validated. |
| 5 - Hardening & Planning | Complete | Phase 11 T044-T046 complete: rerun-safe scan lifecycle (.meta.json, PID poll, non-destructive recovery), 7-tool aware planning prompt with strict Live tool selection enforcement, and ZAP pre-approval warm-up checklist. 88/88 tests pass. |

## Implemented features

- Complete Markdown interpretation of the supplied problem statement.
- Repository-scoped Mono design guidance for accessible, compact, evidence-dense UI decisions.
- Repository-scoped Spec Kit workflow skills for specification, planning, tasks, implementation, analysis, and convergence.
- Repository-scoped Graphify guidance for efficient codebase navigation once source code exists.
- Persistent project operating rules, including safety, audit, UI-language, and documentation requirements.
- Base ignore rules for secrets, dependencies, generated graphs, scan artifacts, and reports.
- Master product specification and complete pre-implementation plan for the authorized VAPT agent.
- Project constitution defining mandatory safety, evidence, auditability, integration honesty, and handoff rules.
- Phase 1 persistence core: SQLite tables for scopes, scan runs, evidence, findings, approvals, and audit events.
- Phase 1 safety controls: strict target/port validation, normalized `is_in_scope(target, port, action)`, persistent scope registration, and append-only audit events.
- Phase 1 Mono-styled Streamlit scope workspace, including authorization attestation, accessible feedback, empty state, and saved-scope display.
- Phase 1 Graphify visual report: 158 nodes, 317 edges, and confirmed registration-to-audit dependency path. The current code-only `graph.json` was refreshed after Phase 2 to 364 nodes and 1,055 edges; its HTML visual report has not yet been regenerated, so `graph.html` and `GRAPH_REPORT.md` remain the Phase 1 snapshot.
- Phase 2 typed Nmap profile and plan-proposal models reject undeclared LLM fields and free-form arguments.
- Phase 2 provider gateway supports two ordered OpenAI-compatible slots, a bounded two-attempt schema cap (`SCHEMA_ATTEMPT_CAP = 2`, including one corrective retry) per provider, auditable failover, and deterministic local fallback.
- Phase 2 deterministic proposal gate applies schema, scope, profile, and a 45-second per normalized `(target, action)` in-memory rate limit before approval or adapter access; `RATE_LIMIT_WINDOW_SECONDS = 45` is the configurable default and each rate check is audited.
- Phase 2 loads optional local `.env` provider configuration without overriding real process environment settings.
- T019 common adapter contract: shared validate/start/poll/parse lifecycle, 300-second/2-second overridable defaults, declared scan states, approval wait state, common finding type, and immutable raw-artifact hashing/persistence helper.
- T019 environment check: Nmap and Nikto are not available on PATH; no ZAP service is reachable at `127.0.0.1:8080`. No tool was launched.
- T020 adapters: Nmap fixed-profile XML execution, Nikto fixed XML execution, and ZAP REST daemon lifecycle paths. All validate through scope/rate/approval gates and require a single-use validation ticket before start.
- T020 evidence: each parser stores raw XML/JSON locally with SHA-256 and SQLite evidence reference; Nmap preserves observed `--reason` data in evidence-backed findings.
- T036 approval boundary: active validation verifies a persisted exact-request approval with actor, rationale, timestamp, audit event, and a 15-minute expiry; caller-supplied approval booleans are removed.
- T037 ZAP target policy: each ZAP request requires explicit `http` or `https`, which is included in validation and approval audit records before target URL construction.
- T038 parser safety: malformed Nmap/Nikto XML or ZAP JSON is preserved as immutable evidence, then marks its scan run failed and records an auditable parse-failure event.
- T021 read-only assessment workspace: scope-filtered persisted run timeline, rationale, status, adapter error/recovery guidance, and approval-status display. It has no execution or approval controls.
- T039 evidence-grounded scan records: live adapters require and persist the approved rationale and non-binding anticipated-next-steps preview at scan creation; T021 displays both without treating previews as executable.
- T022 finding normalization, correlation, and priority: implemented in `src/cipher_lens/services/findings.py` and `src/cipher_lens/domain/findings.py`. Preserves all evidence provenance, consolidates duplicates on `(asset, cve)` or `(asset, title/cwe)` without losing distinct assets, normalizes severities into standard enums, computes deterministic priority scores without AI hallucination, provides stable sort ordering, and persists to SQLite with auditable event logging.
- T023 approval state machine and searchable audit history: implemented in `src/cipher_lens/services/approvals.py` and `src/cipher_lens/ui/audit_page.py`. Models strict state transitions (pending -> approved/rejected/cancelled, approved -> completed/expired/cancelled), enforces 15-minute approval expiry, requires decision actor and rationale, validates scope before request creation, provides searchable/filterable audit timeline, and registers the Audit trail & approvals workspace.
- T024 honest seven-tool integration matrix: implemented in `src/cipher_lens/services/integrations.py` and `src/cipher_lens/ui/integrations_page.py`. Evaluates real local availability for Nmap, Nikto, and ZAP, declares truthful Import-only / Planned states for Nessus, OpenVAS, Burp Community, and Metasploit, and clearly documents operational limitations and safety boundaries.
- T025 deterministic VAPT PDF reporting: implemented in `src/cipher_lens/services/reporting.py` and `src/cipher_lens/ui/report_page.py`. Compiles all 6 required report sections (executive summary, methodology, severity distribution, detailed findings with provenance hashes, impact & remediation, limitations & approvals) and renders downloadable professional PDF snapshots.
- T026 end-to-end assessment lifecycle verification: implemented in `tests/integration/test_assessment_to_report.py`. Validates scope registration, proposal/gate decision, scan runs, findings deduplication and priority, human approval state machine, immutable audit trail, and PDF generation with 100% evidence traceability.
- T027 visual architecture graph & safety trace: regenerated with Python 3.13 `.venv` Graphify to 557 nodes, 1,694 edges across 18 communities; updated `graph.html` and `GRAPH_REPORT.md`; confirmed through graph path analysis that every adapter path routes through `is_in_scope()` and audit `record()`, with zero bypass paths.
- T028 final Spec Kit cross-artifact analysis: non-destructive review across `spec.md`, `plan.md`, `data-model.md`, `contracts/api.md`, and `tasks.md` confirmed 100% requirement coverage, complete task completion, zero contradictions, and full adherence to the project Constitution.
- T029 clean-client quickstart & README verification: updated `README.md` into a client-ready, professional guide covering environment setup, `.env.example` configurations, test commands, graceful handling of missing local scanner tools, and workspace walkthroughs without internal developer jargon; verified Streamlit application entry resilience and 61/61 test suite passing.

## Current project tree

| Path | Role |
| --- | --- |
| `PROBLEM-STATEMENT.pdf` | Original hackathon brief supplied by the team lead. |
| `PROBLEM-STATEMENT.md` | Structured, readable project requirements derived from the brief. |
| `Project-Context.md` | This implementation ledger, tree map, and next-goal tracker. |
| `AGENTS.md` | Persistent project rules for Codex and Graphify navigation guidance. |
| `.gitignore` | Excludes secrets, generated artifacts, and local evidence from version control. |
| `Working.md` | Existing empty workspace placeholder; purpose to be decided before implementation. |
| `.agents/skills/mono/SKILL.md` | Agent-facing Mono UI guidance. |
| `.agents/skills/mono/DESIGN.md` | Human-facing Mono design rationale and references. |
| `.agents/skills/speckit-constitution/SKILL.md` | Establishes project principles. |
| `.agents/skills/speckit-specify/SKILL.md` | Creates feature specifications. |
| `.agents/skills/speckit-plan/SKILL.md` | Converts approved specifications into implementation plans. |
| `.agents/skills/speckit-tasks/SKILL.md` | Breaks a plan into executable tasks. |
| `.agents/skills/speckit-implement/SKILL.md` | Guides controlled implementation. |
| `.agents/skills/speckit-converge/SKILL.md` | Assesses finished work and records remaining tasks. |
| `.agents/skills/speckit-clarify/SKILL.md` | Optional ambiguity-reduction workflow. |
| `.agents/skills/speckit-analyze/SKILL.md` | Optional cross-artifact consistency review. |
| `.agents/skills/speckit-checklist/SKILL.md` | Optional acceptance-checklist workflow. |
| `.codex/skills/graphify/SKILL.md` | Project-local Graphify instructions. |
| `.codex/skills/graphify/references/` | Graphify reference material installed with its guidance. |
| `.codex/skills/graphify/.graphify_version` | Graphify skill version marker. |
| `.codex/hooks.json` | Local hook registration for Graphify freshness checks. |
| `.specify/init-options.json` | Spec Kit initialization record. |
| `.specify/integration.json` | Selected Spec Kit/Codex integration settings. |
| `.specify/integrations/codex.manifest.json` | Codex integration manifest. |
| `.specify/integrations/speckit.manifest.json` | Spec Kit workflow manifest. |
| `.specify/memory/constitution.md` | Project constitution template awaiting team decisions. |
| `.specify/memory/.constitution-template.json` | Constitution template metadata. |
| `.specify/scripts/powershell/check-prerequisites.ps1` | Checks prerequisites for Spec Kit workflow stages. |
| `.specify/scripts/powershell/common.ps1` | Shared Spec Kit PowerShell helpers. |
| `.specify/scripts/powershell/create-new-feature.ps1` | Creates a Spec Kit feature workspace. |
| `.specify/scripts/powershell/resolve-template.ps1` | Resolves workflow templates. |
| `.specify/scripts/powershell/setup-plan.ps1` | Sets up a feature planning artifact. |
| `.specify/scripts/powershell/setup-tasks.ps1` | Sets up task artifacts. |
| `.specify/templates/checklist-template.md` | Template for acceptance checklists. |
| `.specify/templates/constitution-template.md` | Template for team project principles. |
| `.specify/templates/plan-template.md` | Template for implementation plans. |
| `.specify/templates/spec-template.md` | Template for feature specifications. |
| `.specify/templates/tasks-template.md` | Template for implementation tasks. |
| `.specify/workflows/speckit/workflow.yml` | Spec Kit workflow definition. |
| `.specify/workflows/workflow-registry.json` | Installed workflow registry. |
| `.specify/.gitignore` | Spec Kit internal exclusions. |
| `src/cipher_lens/app.py` | Streamlit application entry point. |
| `src/cipher_lens/config.py` | Local data, SQLite, `.env`, and provider-slot configuration. |
| `src/cipher_lens/domain/models.py` | Pydantic models for scope, audit, typed profiles, proposals, and finding re-exports. |
| `src/cipher_lens/domain/findings.py` | Normalized finding, severity, validation status, and provenance domain models. |
| `src/cipher_lens/domain/proposals.py` | Stable public imports for Phase 2 proposal types. |
| `src/cipher_lens/adapters/base.py` | Fail-closed shared adapter contract, common lifecycle types, and raw-evidence helper. |
| `src/cipher_lens/adapters/nmap.py` | Fixed-profile, scoped Nmap XML adapter with non-shell execution. |
| `src/cipher_lens/adapters/nikto.py` | Fixed-bundle, scoped Nikto XML adapter with non-shell execution. |
| `src/cipher_lens/adapters/zap.py` | Scoped ZAP REST adapter with explicit daemon-unavailable handling. |
| `src/cipher_lens/domain/validation.py` | Rejecting IPv4/hostname and port/range validators. |
| `src/cipher_lens/domain/scope.py` | Central normalized scope gate for all future adapter paths. |
| `src/cipher_lens/persistence/schema.py` | SQLite schema for all MVP entities. |
| `src/cipher_lens/persistence/repositories.py` | SQLite persistence and connection lifecycle. |
| `src/cipher_lens/services/audit.py` | Append-only audit service. |
| `src/cipher_lens/services/scope_registration.py` | Validated, audited scope-registration workflow. |
| `src/cipher_lens/services/planning.py` | Provider failover, schema retry, deterministic fallback, and auditable proposal gates. |
| `src/cipher_lens/services/findings.py` | Finding normalization, deduplication, provenance retention, and deterministic priority. |
| `src/cipher_lens/services/approvals.py` | Durable exact-request active-validation approval creation and audit logging. |
| `src/cipher_lens/services/integrations.py` | Honest capability checks and metadata for the seven core security tools. |
| `src/cipher_lens/services/reporting.py` | Deterministic VAPT PDF report generation engine with complete evidence traceability. |
| `src/cipher_lens/ui/mono.py` | Shared compact/high-contrast Mono Streamlit tokens. |
| `src/cipher_lens/ui/scope_page.py` | Authorization-aware scope registration page. |
| `src/cipher_lens/ui/assessment_page.py` | Read-only Mono activity and approval-status workspace. |
| `src/cipher_lens/ui/audit_page.py` | Human approval state machine and searchable audit timeline workspace. |
| `src/cipher_lens/ui/integrations_page.py` | Truthful seven-tool integration status and capability directory. |
| `src/cipher_lens/ui/report_page.py` | Executive VAPT report preview and PDF download interface. |
| `tests/unit/test_scope.py` | Scope validation, normalization, exclusion, action, persistence tests. |
| `tests/unit/test_planning.py` | Proposal validation, failover, retry, rate-limit, and local configuration tests. |
| `tests/unit/test_findings.py` | Finding normalization, deduplication, provenance retention, and priority scoring tests. |
| `tests/unit/test_audit_page.py` | Approval state machine, transition rejection, expiry, and audit search tests. |
| `tests/unit/test_integrations.py` | Seven-tool matrix, truthful status, and availability checks tests. |
| `tests/unit/test_reporting.py` | ReportLab PDF compilation, severity distribution, and no-data tests. |
| `tests/unit/test_adapter_contract.py` | Contract validation order, approval blocking, and raw-evidence persistence tests. |
| `tests/unit/test_live_adapters.py` | Live-adapter unavailable-state, fixed-bundle, and ZAP approval-boundary tests. |
| `tests/integration/test_scope_registration.py` | Persistent registration and audit round-trip test. |
| `tests/integration/test_assessment_to_report.py` | Complete end-to-end assessment lifecycle to PDF report verification. |
| `specs/001-authorized-vapt-agent/spec.md` | Master product specification and measurable acceptance criteria. |
| `specs/001-authorized-vapt-agent/plan.md` | Draft full-project architecture, delivery sequence, and integration strategy. |
| `specs/001-authorized-vapt-agent/research.md` | Technical and free-tier decision record. |
| `specs/001-authorized-vapt-agent/data-model.md` | Assessment, evidence, finding, approval, audit, and report model. |
| `specs/001-authorized-vapt-agent/contracts/api.md` | Draft server interface contract. |
| `specs/001-authorized-vapt-agent/quickstart.md` | End-to-end validation scenarios for the approved MVP. |
| `specs/001-authorized-vapt-agent/checklists/requirements.md` | Specification quality verification. |

## Next three goals - pending your approval

1. **Interactive Assessment Plan Generator in UI**: Expose the existing `propose_and_gate` service in the UI (e.g. under Saved Scopes) so analysts can enter a natural-language assessment request and view the gated plan proposal with evidence-grounded rationale in real time.
2. **Multi-Tool Demonstration Fixtures & Import**: Add realistic sample scan exports under `sample-data/` (Nmap XML, Nikto XML, and ZAP JSON) and an analyst import interface in the workspace to demonstrate live cross-tool deduplication and correlation without requiring live external scanners installed.
3. **Live Demonstration Rehearsal**: Rehearse the complete 7-step hackathon live-demo checklist from `PROBLEM-STATEMENT.md` (Scope -> Plan -> Scans -> Correlation -> Human Approval -> PDF Report -> Integration Matrix).

## Required project workflow tools

| Resource | Mandatory use in this project |
| --- | --- |
| Spec Kit | Use the constitution, specification, plan, task, implementation, analysis, checklist, and convergence workflows whenever their stage applies. |
| Awesome Design Skills - Mono | Use for every UI decision: compact evidence density, high contrast, semantic components, keyboard-first interaction, and clear empty/loading/error states. |
| Graphify | Once application source exists, query the local graph before broad code searches and refresh it after code changes. |

## Per-phase operating protocol

- Before a new implementation phase, run the Spec Kit clarification workflow only for that phase,
  record accepted answers in the feature specification, and do not guess unresolved decisions.
- Implement only the approved phase tasks in dependency order and update `tasks.md` as tasks finish.
- At phase end, run a read-only convergence comparison. Append identified gaps to a `Convergence`
  section in `tasks.md`; do not silently fix them. Report a phase as converged only when no gaps
  remain, then stop for team-lead review before the next phase.

## Verification record

| Check | Result |
| --- | --- |
| Supplied brief reviewed | Complete - all 10 pages read and key tables visually verified. |
| Mono skill installed in repository | Complete - `.agents/skills/mono/`. |
| Spec Kit installed and initialized for Codex | Complete - `specify` version 1.3.2. |
| Graphify installed and registered for Codex | Complete - `graphify` version 0.9.103. |
| Secrets and generated artifact exclusions added | Complete - root `.gitignore`. |
| Phase 1 direct domain verification | Complete - valid scope persistence, normalization, exclusion/action denial, audit persistence, and invalid-input rejection passed. |
| Phase 1 Python compilation | Complete - `src/` compiled without errors. |
| Phase 1 Graphify checkpoint | Complete - `graphify-out/graph.html`, `graph.json`, and `GRAPH_REPORT.md` generated from code only; scope-registration to audit path confirmed. |
| Graphify repair and refreshed code graph | Complete - Graphify 0.9.103 is installed in the project Python 3.13 `.venv`, avoiding the broken global `uv` trampoline. `graphify-out/graph.json` was refreshed after T021/T039 to 385 nodes and 1,115 edges. The Phase 1 HTML/report were not regenerated; final visual-graph review remains T027. |
| T020 adapter safety-graph trace | Pass - Nmap, Nikto, and ZAP `start()` paths consume validation tickets; tickets originate only from `validate()`, which calls `is_in_scope()` and audit `record()` before subprocess/ZAP API access. No adapter bypass edge was found. |
| Python 3.13 project environment | Complete - clean standard `.venv` rebuilt with Python 3.13.7 after removing an incompatible prior Python 3.12 binary. |
| Phase 1 through T038 pytest suite | Complete - 26 tests passed under the rebuilt Python 3.13 `.venv`. |
| T020/T036/T037/T038 convergence | Complete - scoped adapter and safety implementation satisfies the approved specification, plan, and tasks. |
| T021/T039 implementation verification | Complete - 28 tests passed under the Python 3.13 `.venv`; scoped convergence is clean. |
| T022 findings normalization and correlation verification | Complete - 41 tests passed under Python 3.13 `.venv`; Graphify refreshed to 454 nodes and 1,325 edges. |
| T023 approval state machine and audit workspace verification | Complete - 50 tests passed under Python 3.13 `.venv`; Graphify refreshed to 493 nodes and 1,479 edges. |
| T024 seven-tool integration matrix verification | Complete - 56 tests passed under Python 3.13 `.venv`; honest Live/Import-only/Planned statuses and limitations verified. |
| T025 deterministic VAPT PDF report verification | Complete - 60 tests passed under Python 3.13 `.venv`; ReportLab PDF compilation, severity distribution, and empty-state verified. |
| T026 end-to-end assessment lifecycle verification | Complete - 61 tests passed under Python 3.13 `.venv`; complete registration-to-PDF report lifecycle with 100% evidence traceability verified. |
| T027 visual architecture graph & safety trace | Complete - Graphify 0.9.103 regenerated code graph to 557 nodes and 1,694 edges across 18 communities; `graph.html` and `GRAPH_REPORT.md` refreshed; path tracing confirmed `ToolAdapter.validate() -> is_in_scope()` and `ToolAdapter._audit() -> record()` on all paths with zero bypasses. |
| T028 Spec Kit cross-artifact consistency analysis | Complete - non-destructive analysis across `spec.md`, `plan.md`, `data-model.md`, `contracts/api.md`, and `tasks.md` confirmed 100% requirements coverage (FR-001 to FR-014), complete task mapping, and zero constitutional or architectural conflicts. |
| T029 Clean-client quickstart & README verification | Complete - professional, client-ready `README.md` verified; standard `.venv` setup and pytest execution verified; Streamlit import path resilience verified; graceful handling of missing external scanners verified. |
| T040 Tier 1 native tool CVE/CWE extraction | Complete - `nikto.py` and `zap.py` extract native evidenced CVE/CWE tokens from `<references>`, `<description>`, and `cweid` fields without network access. |
| T041 Tier 2 NIST NVD API 2.0 lookup service | Complete - `src/cipher_lens/services/nvd.py` implements authenticated NVD 2.0 lookup with 50 req/30s rate limiting, in-memory cache, and strict gating to scanner-verified `product` and `version`. |
| T042 Result Ingestion CVE/CVSS enrichment & test suite | Complete - `ingest_and_store_findings()` integrates multi-tier enrichment; 11 comprehensive tests in `tests/unit/test_nvd.py` verify gating, zero-cost operation, cache deduplication, and severity elevation. |
| T043 Cross-platform POSIX root/privilege handling | Complete - replaced top-level `ctypes.windll` import in `nmap.py` with runtime OS branch (`os.geteuid() == 0` for Linux, safe `windll` guard for Windows). |
| Complete 72-test suite verification | Complete - 72/72 tests passed under Python 3.13 `.venv` (`pytest -v`). |
| Python runtime pinning mandate | Established - environment must be explicitly pinned to Python 3.12 or 3.13 (`python3.12 -m venv` or `python3.13 -m venv`), never bare `python3` (which resolves to unreleased Python 3.14 on cutting-edge Kali Linux rolling releases, breaking binary wheel installs). |
| Retroactive T004-T010 Spec Kit analysis | Complete - read-only cross-artifact review found no foundation-phase contradiction or remediation task. |

## Handoff note

For a new model, account, or session: read this file, then `PROBLEM-STATEMENT.md`, then `AGENTS.md`. The repository-scoped skill folders are portable once committed; local executables and API keys are deliberately machine/account-specific and must be installed/configured separately.
