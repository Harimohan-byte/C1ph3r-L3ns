import React, { useState, useEffect } from 'react';
import {
  Activity,
  Shield,
  Crosshair,
  AlertCircle,
  FileCheck2,
  RefreshCw,
} from 'lucide-react';
import { useScopeStore } from '../../store/useScopeStore';
import { api } from '../../services/api';
import { Finding, PlanningOutcome } from '../../types';
import { PromptBar } from './PromptBar';
import { ConversationalCard } from './ConversationalCard';
import { AdvisoryCard } from './AdvisoryCard';
import { ScanProposalCard } from './ScanProposalCard';
import { FindingsTable } from './FindingsTable';

export const AssessmentView: React.FC = () => {
  const {
    activeScopeId,
    getActiveScope,
    scopes,
    setActiveScopeId,
    promptInput,
    setPromptInput,
    setIsScanning,
    setActiveWorkspace,
  } = useScopeStore();

  const activeScope = getActiveScope();

  const [loadingPlan, setLoadingPlan] = useState(false);
  const [outcome, setOutcome] = useState<PlanningOutcome | null>(null);
  const [isApproved, setIsApproved] = useState(false);
  const [executing, setExecuting] = useState(false);
  const [executionResult, setExecutionResult] = useState<{
    status: string;
    message?: string;
    findings_count?: number;
  } | null>(null);

  const [findings, setFindings] = useState<Finding[]>([]);
  const [loadingFindings, setLoadingFindings] = useState(false);

  // Load findings for active scope
  const loadFindings = async () => {
    if (!activeScopeId) return;
    setLoadingFindings(true);
    try {
      const data = await api.listFindings(activeScopeId);
      setFindings(data);
    } catch (err) {
      console.error('Failed to load findings:', err);
    } finally {
      setLoadingFindings(false);
    }
  };

  useEffect(() => {
    loadFindings();
    setOutcome(null);
    setIsApproved(false);
    setExecutionResult(null);
  }, [activeScopeId]);

  const handleConsult = async (queryText: string) => {
    if (!activeScopeId) return;
    setLoadingPlan(true);
    setIsScanning(true);
    setExecutionResult(null);
    setIsApproved(false);

    try {
      const planOutcome = await api.createPlan(activeScopeId, queryText);
      setOutcome(planOutcome);

      // If it doesn't require human approval or is already approved
      if (planOutcome.plan_proposal && !planOutcome.plan_proposal.requires_approval) {
        setIsApproved(true);
      }
    } catch (err: any) {
      alert(`Consultation error: ${err.message}`);
    } finally {
      setLoadingPlan(false);
      setIsScanning(false);
    }
  };

  const handleApprove = async () => {
    if (!activeScopeId || !outcome?.plan_proposal) return;
    try {
      // Create and auto-approve in backend
      const prop = outcome.plan_proposal;
      const appr = await api.createApproval({
        scope_id: activeScopeId,
        tool: prop.tool,
        target: prop.target,
        port: prop.port || 80,
        action: prop.action_type || 'active_validation',
        command_preview: prop.command_preview,
        rationale: prop.reasoning,
        requested_by: 'operator',
      });

      await api.transitionApproval(appr.id, 'approved', 'Operator authorized via assessment gate', 'operator');
      setIsApproved(true);
    } catch (err: any) {
      alert(`Approval error: ${err.message}`);
    }
  };

  const handleExecute = async () => {
    if (!activeScopeId || !outcome?.plan_proposal) return;
    const prop = outcome.plan_proposal;

    setExecuting(true);
    setIsScanning(true);

    try {
      const result = await api.executeScan({
        scope_id: activeScopeId,
        tool: prop.tool,
        target: prop.target,
        port: prop.port || 80,
        profile: prop.profile || 'quick_recon',
        action_type: prop.action_type,
        rationale: prop.reasoning,
      });

      setExecutionResult({
        status: result.status,
        message: result.message,
        findings_count: result.findings_count,
      });

      // Reload findings
      await loadFindings();
    } catch (err: any) {
      setExecutionResult({
        status: 'failed',
        message: err.message,
      });
    } finally {
      setExecuting(false);
      setIsScanning(false);
    }
  };

  if (!activeScope) {
    return (
      <div className="max-w-4xl mx-auto px-6 py-20 text-center">
        <div className="w-16 h-16 rounded-2xl bg-[#7D58FD]/10 border border-[#7D58FD]/30 flex items-center justify-center text-[#30E1DB] mx-auto mb-4 shadow-glow-cyan-sm">
          <Crosshair className="w-8 h-8" />
        </div>
        <h2 className="text-2xl font-display font-semibold text-[#ECE9F7] mb-2">
          No Scope Calibrated
        </h2>
        <p className="text-sm text-[#8A86A3] max-w-md mx-auto mb-6">
          To run security scans, consult C1PH3R, or inspect vulnerabilities, first calibrate an authorized target boundary.
        </p>
        <button
          onClick={() => setActiveWorkspace('scope')}
          className="px-6 py-3 rounded-xl font-medium text-sm text-white bg-gradient-to-r from-[#7D58FD] to-[#5a36db] shadow-glow-violet hover:shadow-[0_0_24px_rgba(125,88,253,0.5)] transition-all"
        >
          Calibrate Target Perimeter →
        </button>
      </div>
    );
  }

  const agentResponse = outcome?.agent_response;
  const isConversational = agentResponse?.response_type === 'conversational';
  const isAdvisory = agentResponse?.response_type === 'advisory';
  const isScanProposal = agentResponse?.response_type === 'scan_proposal' || !!outcome?.plan_proposal;

  return (
    <div className="w-full max-w-[1700px] mx-auto px-6 lg:px-12 py-8 space-y-8">
      {/* Target Status Header Card */}
      <div className="glass-panel rounded-2xl p-6 flex flex-col md:flex-row items-start md:items-center justify-between gap-4">
        <div className="flex items-center gap-4">
          <div className="w-12 h-12 rounded-xl bg-[#7D58FD]/15 border border-[#7D58FD]/30 flex items-center justify-center text-[#30E1DB] shadow-glow-cyan-sm">
            <Shield className="w-6 h-6" />
          </div>
          <div>
            <div className="flex items-center gap-2.5">
              <h1 className="text-xl font-mono font-bold text-[#ECE9F7]">
                {activeScope.target}
              </h1>
              <span className="text-xs font-mono px-2.5 py-0.5 rounded bg-[#30E1DB]/15 text-[#30E1DB] border border-[#30E1DB]/30 font-bold">
                AUTHORIZED
              </span>
            </div>
            <p className="text-sm text-[#8A86A3] mt-1">
              Allowed Ports: <span className="font-mono text-[#ECE9F7]">{activeScope.allowed_ports}</span> | Actions: {activeScope.allowed_actions.join(', ')}
            </p>
          </div>
        </div>

        {/* Scope Switcher Dropdown */}
        <div className="flex items-center gap-3 w-full md:w-auto">
          <select
            value={activeScopeId || ''}
            onChange={(e) => setActiveScopeId(e.target.value)}
            className="w-full md:w-64 px-4 py-2.5 rounded-xl bg-[#0F0D18] border border-[#7D58FD]/30 text-sm font-mono text-[#ECE9F7] focus:outline-none focus:border-[#7D58FD]"
          >
            {scopes.map((s) => (
              <option key={s.id} value={s.id}>
                {s.target}
              </option>
            ))}
          </select>
          <button
            onClick={loadFindings}
            className="p-2.5 rounded-xl bg-[#171324] border border-[#7D58FD]/30 text-[#8A86A3] hover:text-[#ECE9F7] transition-colors"
            title="Refresh findings"
          >
            <RefreshCw className={`w-4 h-4 ${loadingFindings ? 'animate-spin' : ''}`} />
          </button>
        </div>
      </div>

      {/* Main AI Consultation Prompt Bar */}
      <PromptBar
        input={promptInput}
        setInput={setPromptInput}
        onSubmit={handleConsult}
        loading={loadingPlan}
      />

      {/* Three AI Response Modes Render Dispatch */}
      {outcome && (
        <div className="space-y-6">
          {/* Mode 1: Conversational Card */}
          {isConversational && agentResponse?.conversational && (
            <ConversationalCard
              payload={agentResponse.conversational}
              onSelectFollowUp={(chip) => {
                setPromptInput(chip);
                handleConsult(chip);
              }}
            />
          )}

          {/* Mode 2: Advisory Card */}
          {isAdvisory && agentResponse?.advisory && (
            <AdvisoryCard
              payload={agentResponse.advisory}
              onSelectTool={(tool, rationale) => {
                const query = `Plan ${tool} assessment: ${rationale}`;
                setPromptInput(query);
                handleConsult(query);
              }}
            />
          )}

          {/* Mode 3: Scan Proposal Card */}
          {isScanProposal && (outcome.plan_proposal || agentResponse?.scan_proposal) && (
            <ScanProposalCard
              proposal={(outcome.plan_proposal || agentResponse?.scan_proposal)!}
              isApproved={isApproved}
              onApprove={handleApprove}
              onExecute={handleExecute}
              executing={executing}
              executionResult={executionResult}
            />
          )}
        </div>
      )}

      {/* Consolidated Findings Table */}
      <FindingsTable
        findings={findings}
        onUpdateStatus={async (id, newStatus) => {
          try {
            await api.updateFinding(id, newStatus);
            await loadFindings();
          } catch (err: any) {
            alert(err.message || 'Failed to update finding');
          }
        }}
      />
    </div>
  );
};

