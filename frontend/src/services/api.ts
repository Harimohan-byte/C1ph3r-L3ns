import {
  Approval,
  AuditEvent,
  Finding,
  PlanningOutcome,
  ReportMetrics,
  Scope,
  ToolCapability,
} from '../types';

const BASE_URL = '/api/v1';

async function fetchJson<T>(url: string, options?: RequestInit): Promise<T> {
  const res = await fetch(url, {
    headers: {
      'Content-Type': 'application/json',
      ...options?.headers,
    },
    ...options,
  });

  if (!res.ok) {
    let errorDetail = `Request failed: ${res.status} ${res.statusText}`;
    try {
      const errJson = await res.json();
      if (errJson.detail) errorDetail = errJson.detail;
    } catch {}
    throw new Error(errorDetail);
  }

  return res.json();
}

export const api = {
  // Scopes
  async listScopes(): Promise<Scope[]> {
    return fetchJson<Scope[]>(`${BASE_URL}/scopes`);
  },

  async createScope(data: {
    target: string;
    allowed_ports: string;
    excluded_ports?: string;
    excluded_endpoints?: string;
    engagement_note: string;
    authorized_lab_attested: boolean;
    allowed_actions: string[];
  }): Promise<Scope> {
    return fetchJson<Scope>(`${BASE_URL}/scopes`, {
      method: 'POST',
      body: JSON.stringify(data),
    });
  },

  async deleteScope(scopeId: string): Promise<void> {
    await fetchJson(`${BASE_URL}/scopes/${scopeId}`, { method: 'DELETE' });
  },

  async resetSystem(): Promise<void> {
    await fetchJson(`${BASE_URL}/system/reset`, { method: 'POST' });
  },

  // Planning & Execution
  async createPlan(scopeId: string, request: string): Promise<PlanningOutcome> {
    return fetchJson<PlanningOutcome>(`${BASE_URL}/planning/plan`, {
      method: 'POST',
      body: JSON.stringify({ scope_id: scopeId, request }),
    });
  },

  async executeScan(data: {
    scope_id: string;
    tool: string;
    target: string;
    port?: number;
    profile?: string;
    action_type?: string;
    rationale?: string;
  }): Promise<{
    status: string;
    message?: string;
    run_id?: string;
    stdout?: string;
    stderr?: string;
    findings_count?: number;
    findings?: Finding[];
  }> {
    return fetchJson(`${BASE_URL}/planning/execute`, {
      method: 'POST',
      body: JSON.stringify(data),
    });
  },

  // Approvals
  async listApprovals(scopeId?: string): Promise<Approval[]> {
    const url = scopeId ? `${BASE_URL}/approvals?scope_id=${scopeId}` : `${BASE_URL}/approvals`;
    return fetchJson<Approval[]>(url);
  },

  async createApproval(data: {
    scope_id: string;
    tool: string;
    target: string;
    port: number;
    action: string;
    command_preview: string;
    rationale: string;
    requested_by: string;
  }): Promise<Approval> {
    return fetchJson<Approval>(`${BASE_URL}/approvals`, {
      method: 'POST',
      body: JSON.stringify(data),
    });
  },

  async transitionApproval(
    approvalId: string,
    toStatus: string,
    decisionReason = 'Approved by operator',
    actor = 'security-lead'
  ): Promise<Approval> {
    return fetchJson<Approval>(`${BASE_URL}/approvals/${approvalId}/transition`, {
      method: 'POST',
      body: JSON.stringify({
        to_status: toStatus,
        decision_reason: decisionReason,
        actor,
      }),
    });
  },

  // Audit
  async listAuditTimeline(scopeId?: string): Promise<AuditEvent[]> {
    const url = scopeId ? `${BASE_URL}/audit/timeline?scope_id=${scopeId}` : `${BASE_URL}/audit/timeline`;
    return fetchJson<AuditEvent[]>(url);
  },

  // Integrations
  async listIntegrations(): Promise<ToolCapability[]> {
    return fetchJson<ToolCapability[]>(`${BASE_URL}/integrations`);
  },

  // Findings
  async listFindings(scopeId?: string): Promise<Finding[]> {
    const url = scopeId ? `${BASE_URL}/findings?scope_id=${scopeId}` : `${BASE_URL}/findings`;
    return fetchJson<Finding[]>(url);
  },

  async updateFinding(findingId: string, status: string, notes?: string): Promise<Finding> {
    return fetchJson<Finding>(`${BASE_URL}/findings/${findingId}`, {
      method: 'PATCH',
      body: JSON.stringify({ status, notes }),
    });
  },

  // Reports
  async getReportMetrics(scopeId: string): Promise<ReportMetrics> {
    return fetchJson<ReportMetrics>(`${BASE_URL}/reports/metrics?scope_id=${scopeId}`);
  },

  getPdfUrl(scopeId: string): string {
    return `${BASE_URL}/reports/pdf?scope_id=${scopeId}`;
  },
};

