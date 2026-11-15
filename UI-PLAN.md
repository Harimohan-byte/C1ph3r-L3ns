# CIPHER LENS — UI Redesign & Embarko Deployment Plan (Authoritative)

**Branch**: `feature/ui-redesign`  
**Rollback Hash on `main`**: `4aeb949320f184777b7743c5e197ad73ffefae76`  
**Status**: In Progress  
**Last Updated**: 2026-11-15  

---

## 1. Executive Summary & Design System

Cipher-Lens is transitioning from a legacy Streamlit interface to a custom, dark glassmorphic cyber-aesthetic web application (FastAPI + React 18 + TypeScript + Vite + Tailwind + Framer Motion) ahead of hosting on Embarko.

### Locked Brand Foundation (Directly Sampled from Final Logo)
* **Background Base:** `#0F0D18` (Obsidian near-black with faint violet undertone)
* **Card Surface:** `#171324` (Elevated dark slate-violet)
* **Card Hover Surface:** `#1F1A30`
* **Primary Accent / Glow:** `#7D58FD` (Electric indigo-violet)
* **Secondary Accent / Sensor:** `#30E1DB` (Cold cyan-teal)
* **Text Primary:** `#ECE9F7` (Cool off-white, high contrast)
* **Text Secondary / Muted:** `#8A86A3` (Desaturated violet-grey)
* **Danger / Critical:** `#FF4D6D` (Vivid magenta-red)
* **Warning / Gated:** `#FFB454` (Warm amber, isolated for alerts)
* **Success / Approved:** `#30E1DB` (Cold cyan-teal)
* **Typography:** Fraunces / Playfair (Serif headlines), Plus Jakarta Sans / Inter (UI text), JetBrains Mono (Terminal/telemetry)
* **Logo Artwork:** Eye-in-C icon + wordmark (fixed artwork, central cyan eye pulses during active scanning/reasoning)

---

## 2. Deployment Architecture (Single-Process Embarko Container)

```text
┌────────────────────────────────────────────────────────┐
│               React 18 + Vite Frontend                 │
│  - Top-center floating glass navigation                │
│  - 3 AI response modes: conversational/advisory/scan   │
│  - Kinetic approval gate with laser sweep              │
└───────────────────────────▲────────────────────────────┘
                            │ Compiled to frontend/dist/
┌───────────────────────────▼────────────────────────────┐
│              FastAPI Unified Entrypoint                │
│  - Root main.py binds to 0.0.0.0:$PORT                 │
│  - Mounts /api/v1/ REST endpoints                      │
│  - Serves static assets at / with SPA fallback         │
└───────────────────────────▲────────────────────────────┘
                            │ Pure Python In-Process Calls
┌───────────────────────────▼────────────────────────────┐
│         Existing Services, Adapters, & SQLite DB       │
│  (100% Unchanged: planning, approvals, adapters, repo) │
└────────────────────────────────────────────────────────┘
```

---

## 3. Phased Implementation Roadmap

### Phase 1: Setup & Foundational Infrastructure
- [ ] **T001**: Add `fastapi>=0.115` and `uvicorn>=0.32` to `requirements.txt`.
- [ ] **T002**: Implement FastAPI server in `src/cipher_lens/api/main.py` exposing typed REST endpoints for all existing services without modifying database or business logic.
- [ ] **T003**: Scaffold React 18 + Vite + TypeScript application in `frontend/` with Tailwind CSS, Lucide icons, and Framer Motion.
- [ ] **T004**: Configure locked brand design tokens in `frontend/tailwind.config.js` and `frontend/src/index.css`.
- [ ] **T005**: Create typed API client (`frontend/src/services/api.ts`) and global Zustand store (`frontend/src/store/useScopeStore.ts`).

### Phase 2: Navigation & Brand Telemetry (User Story 1 - P1)
- [ ] **T006**: Implement `BrandLogo.tsx` with fixed eye-in-C logo and pulsing cyan sensor glow state.
- [ ] **T007**: Implement floating glass `TopNav.tsx` with raise-on-hover elevation, electric violet under-glow, active gliding pill, and active scope badge.
- [ ] **T008**: Implement `PageTransition.tsx` wrapper for modular fade + parallax transitions.

### Phase 3: Scope Registration & Perimeter Calibration (User Story 2 - P1)
- [ ] **T009**: Implement `ScopeView.tsx` with target onboarding form (Domain/IP/CIDR, description, exclusions).
- [ ] **T010**: Implement `PerimeterEffect.tsx` for violet laser boundary calibration animation upon scope creation.
- [ ] **T011**: Implement registered scopes list table with active scope switcher, statistics counters, and deletion modal.

### Phase 4: Assessment Workspace, Three AI Modes & Approval Gate (User Story 3 & 4 - P1)
- [ ] **T012**: Implement `AssessmentView.tsx` with target selector header and assessment metrics.
- [ ] **T013**: Implement `PromptBar.tsx` for submitting objectives to C1PH3R with quick action chips.
- [ ] **T014**: Implement `ConversationalCard.tsx` (Mode 1: cyber chat bubble, C1PH3R persona, clickable follow-up chips).
- [ ] **T015**: Implement `AdvisoryCard.tsx` (Mode 2: strategic intelligence dossier, key risks, methodology, tool action chips).
- [ ] **T016**: Implement `ScanProposalCard.tsx` (Mode 3: terminal preview, command highlight, scope safety verdict).
- [ ] **T017**: Implement `ApprovalGate.tsx` with kinetic laser unlock animation, state transitions (`PENDING`, `APPROVED`, `REJECTED`), and live execution trigger.
- [ ] **T018**: Implement `FindingsTable.tsx` with severity badges, CVSS score pills, and remediation detail drawer.

### Phase 5: Audit Trail, Integrations & VAPT Reporting (User Story 5 - P2)
- [ ] **T019**: Implement `AuditView.tsx` with filterable timeline, cryptographic hash inspection, and approval logs.
- [ ] **T020**: Implement `IntegrationsView.tsx` with tool status cards and truthful capability tags (Live / Import-only / Planned).
- [ ] **T021**: Implement `ReportView.tsx` with executive summary, finding severity breakdown, and one-click PDF download.

### Phase 6: Single-Process Container & Embarko Packaging
- [ ] **T022**: Build production frontend (`npm run build` to `frontend/dist`).
- [ ] **T023**: Implement root `main.py` entrypoint launching FastAPI and mounting `frontend/dist` with dynamic `$PORT` binding on `0.0.0.0`.
- [ ] **T024**: Run full existing backend regression test suite (`pytest tests/`) and verify 100% pass rate.
- [ ] **T025**: Execute end-to-end manual verification of all three AI response modes and all 5 workspaces.

---

## 4. Regression & Failure Mode Verification Protocol

Before declaring completion, verify:
1. **Button Handlers:** Explicit event handling ensures zero dead clicks.
2. **Text Contrast:** Check `#8A86A3` on `#171324` (guaranteed > 4.5:1 ratio).
3. **Z-Index Layering:** Glow effects strictly use `pointer-events: none`.
4. **Animation Performance:** GPU transforms maintain 60+ FPS with 100+ findings loaded.
5. **Full Test Suite:** All `pytest tests/` pass identically.

