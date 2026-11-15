export type ActionClass = 'recon' | 'active_validation' | 'configuration_audit';

export interface Scope {
  id: string;
  target: string;
  canonical_target: string;
  allowed_ports: string;
  excluded_ports: string;
  excluded_endpoints: string;
  engagement_note: string;
  authorized_lab_attested: boolean;
  allowed_actions: ActionClass[];
  created_at?: string;
}

export interface ConversationalPayload {
  message: string;
  suggested_follow_ups: string[];
}

export interface AdvisoryToolRecommendation {
  tool: string;
  rationale: string;
  priority: string;
}

export interface AdvisoryPayload {
  analysis?: string;
  strategic_guidance?: string;
  directional_guidance?: string;
  relevant_ports?: number[];
  key_risks?: string[];
  methodology_notes?: string[];
  recommended_tools: AdvisoryToolRecommendation[];
}

export interface ScopeValidation {
  is_in_scope: boolean;
  reason: string;
  violates_exclusions?: boolean;
}

export interface PlanProposal {
  tool: string;
  target: string;
  action_type: string;
  command_preview: string;
  reasoning: string;
  risk_assessment: string;
  requires_approval: boolean;
  scope_validation?: ScopeValidation;
  port?: number;
  profile?: string;
}

export interface AgentResponse {
  response_type: 'conversational' | 'advisory' | 'scan_proposal';
  conversational?: ConversationalPayload;
  advisory?: AdvisoryPayload;
  scan_proposal?: PlanProposal;
}

export interface PlanningOutcome {
  status: 'approved' | 'rejected' | 'blocked' | 'awaiting_approval';
  agent_response?: AgentResponse;
  plan_proposal?: PlanProposal;
  error?: string;
  source?: string;
}

export type ApprovalStatus = 'pending' | 'approved' | 'rejected' | 'escalated' | 'revoked';

export interface Approval {
  id: string;
  scope_id: string;
  tool: string;
  target: string;
  action: string;
  command_preview?: string;
  status: ApprovalStatus;
  requested_at?: string;
  decided_at?: string;
  decision_reason?: string;
  actor?: string;
  requested_by?: string;
}

export interface AuditEvent {
  id: string;
  timestamp: string;
  actor: string;
  event_type: string;
  entity_type: string;
  entity_id?: string;
  scope_id?: string;
  detail: Record<string, any>;
}

export interface FindingProvenance {
  source_tool: string;
  original_severity?: string;
  raw_identifier?: string;
  confidence?: string;
}

export interface Finding {
  id: string;
  scan_run_id: string;
  canonical_title: string;
  affected_asset: string;
  severity: 'critical' | 'high' | 'medium' | 'low' | 'info';
  cvss?: number;
  cve?: string;
  cwe?: string;
  description: string;
  validation_status: 'confirmed' | 'unvalidated' | 'false_positive';
  priority_score?: number;
  provenance?: FindingProvenance[];
}

export interface ToolCapability {
  name: string;
  status: 'Live' | 'Import-only' | 'Planned' | 'Unsupported';
  expected_role: string;
  coverage_type: string;
  declared_mode: string;
  availability_details: string;
  is_available: boolean;
  limitations: string;
  supported_formats: string[];
  last_verified: string;
}

export interface ReportMetrics {
  scope: Scope | string;
  runs_count: number;
  findings_count: number;
  approvals_count: number;
  distribution: {
    critical: number;
    high: number;
    medium: number;
    low: number;
    info: number;
  };
  generated_at: string;
}
