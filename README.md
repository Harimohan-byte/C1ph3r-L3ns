# CIPHER LENS

**CIPHER LENS** is a local-first conversational AI assistant for Vulnerability Assessment and Penetration Testing (VAPT) designed exclusively for explicitly authorized lab targets. It provides end-to-end guidance from authorized scope registration through evidence-grounded planning, scanner coordination, human-in-the-loop validation approvals, and client-ready VAPT reporting.

---

## Key Capabilities

- **Authorized Scope Enforcement**: Define target IP addresses, hostnames, port ranges, and permitted action classes. Requests outside the declared boundary are rejected prior to execution.
- **Evidence-Grounded Planning**: Proposes structured assessment steps with transparent rationale derived directly from observed scan findings.
- **Human-in-the-Loop Approval Gateway**: Active or intrusive validation activities require explicit analyst approval with durable 15-minute expiration windows.
- **Multi-Tool Finding Normalization**: Ingests, normalizes, deduplicates, and prioritizes findings across network and web security tools while retaining full provenance and raw artifact SHA-256 fingerprints.
- **Truthful Integration Directory**: Transparently indicates tool operational status (`Live`, `Import-only`, or `Planned`) for industry tools including Nmap, OWASP ZAP, Nikto, Nessus, OpenVAS, Burp Suite Community, and Metasploit.
- **Deterministic VAPT PDF Reporting**: Compiles an executive summary, methodology, asset distribution, detailed findings with evidence hashes, remediation guidance, and complete human approval logs into a professional report.

---

## Quickstart Guide

### 1. Prerequisites

- **Python**: Python 3.13 is recommended (Python 3.11+ supported).
- **Git**: For cloning and repository management.
- **Optional Local Scanners**: Nmap, Nikto, and OWASP ZAP for local live scanning. If these tools are not locally installed or running, CIPHER LENS operates in Import-only mode gracefully without errors.

### 2. Environment Setup

Clone the repository and set up a virtual environment:

```powershell
# Windows (PowerShell)
py -3.13 -m venv .venv
.\.venv\Scripts\Activate.ps1
python -m pip install --upgrade pip
python -m pip install -r requirements.txt
```

```bash
# Linux / macOS
python3 -m venv .venv
source .venv/bin/activate
pip install --upgrade pip
pip install -r requirements.txt
```

### 3. Local Configuration (Optional)

Copy the sample environment file to configure local paths and provider slots:

```powershell
Copy-Item .env.example .env
```

Configuration variables in `.env`:
- `CIPHER_LENS_DATA_DIR`: Base directory for SQLite databases, raw XML/JSON evidence, and reports (defaults to `./data`).
- `PROVIDER_1_BASE_URL` / `PROVIDER_1_API_KEY` / `PROVIDER_1_MODEL`: Primary OpenAI-compatible model provider slot.
- `PROVIDER_2_BASE_URL` / `PROVIDER_2_API_KEY` / `PROVIDER_2_MODEL`: Secondary model provider slot for auditable failover.
- `ZAP_BASE_URL`: Base address of the local OWASP ZAP daemon (defaults to `http://127.0.0.1:8080`).

> **Note**: When no model provider slots are configured, CIPHER LENS automatically uses its deterministic, rule-based local planning engine.

### 4. Running the Application

Launch the Streamlit web interface:

```bash
streamlit run src/cipher_lens/app.py
```

Open your web browser and navigate to `http://localhost:8501`.

### 5. Running the Test Suite

Execute the complete test suite:

```bash
pytest
```

---

## Application Workspaces

The sidebar navigation provides access to five core operational workspaces:

1. **Authorized Scope**: Register assessment target boundaries, ports, allowed action classes, exclusions, and analyst authorization attestations.
2. **Assessment Status**: Monitor active and completed scan runs, view rationale, track execution timelines, and inspect adapter recovery guidance.
3. **Audit Trail & Approvals**: Review pending approval requests for active validation tasks, execute approved decisions, and search the immutable audit log.
4. **Tool Integrations**: Review real-time availability, licensing models, and capabilities for the seven core security tool adapters.
5. **VAPT Report**: Review executive summary metrics, examine finding severity distribution, and download the full deterministic PDF report.

---

## Safety & Governance Principles

1. **Strict Lab Boundaries**: All assessment requests are validated against registered scope rules before any network activity or command execution.
2. **Mandatory Human Control**: The assistant never performs autonomous exploitation. Active validation actions are blocked until a human analyst grants an auditable approval.
3. **No Fabricated Evidence**: Severity scores, CVEs, and conclusions must be backed by imported or captured tool evidence. AI models never invent findings.
4. **Immutable Audit Trail**: All actions, approvals, rejections, scan starts, and imports are permanently recorded in an append-only SQLite audit log.
5. **Rate-Limiting Protection**: To prevent denial-of-service against lab services, scans enforce a minimum 45-second window per target-action pair.
