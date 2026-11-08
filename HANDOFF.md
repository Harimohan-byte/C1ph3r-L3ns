# Cipher Lens — Agent Handoff

Read these files in this exact order before changing anything. This is the smallest set that restores the approved architecture, safety policy, current work ledger, and UI system.

1. `Project-Context.md` — current checkpoint, verified environment, project tree, graph findings, and next goals.
2. `AGENTS.md` — repository-specific working instructions and safety boundaries.
3. `specs/001-authorized-vapt-agent/tasks.md` — authoritative task status, detailed remaining-task acceptance criteria, and execution order.
4. `specs/001-authorized-vapt-agent/spec.md` — approved product behavior and recorded clarification decisions; do not invent unsettled policy.
5. `specs/001-authorized-vapt-agent/plan.md` — approved architecture, tool boundaries, and delivery strategy.
6. `specs/001-authorized-vapt-agent/data-model.md` — persistent records, state semantics, and evidence/finding shape.
7. `specs/001-authorized-vapt-agent/contracts/api.md` — planning, adapter, and approval service contract.
8. `src/cipher_lens/app.py` — Streamlit entry point, navigation state, and page registration.
9. `src/cipher_lens/ui/mono.py` — mandatory shared UI tokens, hero component, validation presentation, and accessibility rules.
10. `src/cipher_lens/ui/scope_page.py` and `src/cipher_lens/ui/assessment_page.py` — existing page conventions; extend rather than replace them.
11. `src/cipher_lens/adapters/base.py`, `src/cipher_lens/services/planning.py`, and `src/cipher_lens/services/approvals.py` — lifecycle, proposal, gate, and durable approval rules.
12. `src/cipher_lens/adapters/nmap.py`, `src/cipher_lens/adapters/nikto.py`, and `src/cipher_lens/adapters/zap.py` — concrete safety paths and evidence behavior.

## Current verified state

- Last completed task: **T046**. T001–T046 are checkpointed, verified, and converged.
- Baseline: **88/88 tests pass** (`python -m pytest -v`).
- Canonical runtime: **Python 3.12 or 3.13 explicitly pinned** (`python3.12 -m venv` or `python3.13 -m venv`). Never use bare `python3` on Kali Linux rolling releases, which resolves to experimental/alpha Python 3.14 lacking binary wheels for ReportLab and Streamlit.
- Rerun-resilient subprocess execution: Nmap and Nikto persist `.meta.json` with PID, output path, and timeout deadline so running scans survive Streamlit widget reruns and browser reloads; `_recover_orphaned_scans` polls active processes and ingests completed artifacts instead of marking runs interrupted.
- Planning LLM 7-tool catalog awareness: Full capability and truthful integration statuses (`Live`, `Import-only`, `Planned`) for all 7 tools are fed into the system prompt; executable `tool` selection is strictly constrained to Live tools (`nmap`, `nikto`, `zap`), while `rationale` can cite Import-only tools (e.g. Burp Suite Community) with manual instructions.
- Pre-approval ZAP warm-up checklist: Interactive guidance rendered above active-validation approval button to verify daemon reachability and recommend proxy-browsing SPA routes before active scanning.

## Non-negotiable rules

- argument-list subprocess only
- regex-before-scope-check
- typed scan-profile enums not free-form flags
- AI-proposes-first/deterministic-validates-second ordering
- audit logging from Phase 1 onward
- human approval gate for active validation

## Mandatory operating procedure

1. Before a new implementation phase, run phase-scoped clarification (no more than five critical questions), record accepted decisions in `spec.md`, and do not guess unresolved policy.
2. Implement only approved tasks in dependency order; mark `tasks.md` immediately as each task lands. At phase end run a read-only convergence comparison against spec/plan/data model. Append gaps as new tasks only; never silently fix code during convergence. Report convergence only with an empty gap list, then stop for review.
3. Query Graphify before broad structural code searches and refresh it after code changes. Use the project-local `.venv` Graphify executable.
4. Every UI page must call the shared `apply_tokens()` and `heading()` helpers in `src/cipher_lens/ui/mono.py`. Do not add page-local CSS except where a reviewed shared component cannot express the need.

## UI system — mandatory for all present and future pages

This is a custom Neon + Bento direction, replacing the original terminal-heavy Mono appearance while preserving its WCAG 2.2 AA, visible focus, and 44px target requirements.

- Shared source of truth: `src/cipher_lens/ui/mono.py`. Tokens: lime accent `#BBF351`, cream main surface `#FFF5E6`, dark-teal/ink label and heading tone `#064E56`, and near-black sidebar/navigation rail. Use clean sans-serif text; reserve monospace for actual technical output, hashes, and raw evidence.
- Use soft, rounded bento cards with clear spacing and hierarchy. Do not reintroduce dense terminal panels, low-contrast grey labels, or ad-hoc per-page colors.
- All page headers use `heading()` only. It renders one unified landscape hero card using the root `Logo-landscape.png` as the card's CSS background image. It must contain **no** `st.image()` call and **no** `<img>` tag. Its approved aspect ratio is explicitly `2898 / 621`; update this shared token only when the team lead replaces the artwork and approves new dimensions. The text sits directly over the clear left side; no secondary text box or separate logo panel exists.
- `1.png` is a visual reference only and must never be embedded. `Cipher-Lens-logo-1.png` is not the active hero asset. Preserve and commit `Logo-landscape.png` with the client-facing UI when the UI checkpoint is approved.
- Forms use the shared label token and bold 700 weight. Catch Pydantic validation failures at the UI boundary with `friendly_validation_message()` and `inline_error()`; raw `ValidationError`, field codes, and documentation URLs must never reach an analyst.
- Scope registration already shows a succinct success summary, then after about 1.75 seconds sets Streamlit navigation state to **Assessment status** and reruns. Keep registration repeatable by navigating back; do not turn it into a one-way flow.
- The current Assessment status page is read-only. Do not add start, approve, reject, or other execution controls to it before the appropriate approved task/state machine exists.

## Do not re-do

- Do not re-run, re-plan, or re-implement the completed Phase 1–Phase 4 checkpoint: T001–T021 and T030–T039.
- Do not rerun Phase 1 Graphify or its analyzer pass merely to reproduce prior results.
- Do not start T022 until its phase-scoped clarification is complete and the team lead approves implementation.
- Do not alter safety behavior to make unavailable local tools appear operational.

## Graph note

Graphify 0.9.103 is installed in the project Python 3.13 `.venv`. `graphify-out/graph.json` was refreshed after T021/T039 (385 nodes, 1,115 edges) and includes planning, model, adapter, and status-workspace nodes. Nmap, Nikto, and ZAP start paths require a validation ticket issued only after `is_in_scope()` and audit `record()`. `graphify-out/graph.html` and `GRAPH_REPORT.md` are still the Phase 1 visual snapshot; T027 is the final visual graph-review task.
