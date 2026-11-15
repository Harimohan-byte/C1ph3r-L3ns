import React, { useState } from 'react';
import { Terminal, Shield, Copy, Check, AlertCircle, Play } from 'lucide-react';
import { PlanProposal } from '../../types';
import { ApprovalGate } from './ApprovalGate';

interface ScanProposalCardProps {
  proposal: PlanProposal;
  isApproved: boolean;
  onApprove: () => void;
  onReject?: () => void;
  onExecute: () => void;
  executing: boolean;
  executionResult?: {
    status: string;
    message?: string;
    findings_count?: number;
  } | null;
}

export const ScanProposalCard: React.FC<ScanProposalCardProps> = ({
  proposal,
  isApproved,
  onApprove,
  onReject,
  onExecute,
  executing,
  executionResult,
}) => {
  const [copied, setCopied] = useState(false);

  const handleCopy = () => {
    navigator.clipboard.writeText(proposal.command_preview);
    setCopied(true);
    setTimeout(() => setCopied(false), 2000);
  };

  return (
    <div className="space-y-4">
      {/* Proposal Summary Card */}
      <div className="glass-panel rounded-2xl p-6 border-l-4 border-l-[#7D58FD]">
        <div className="flex flex-col sm:flex-row items-start sm:items-center justify-between gap-2 pb-4 border-b border-[#7D58FD]/15 mb-5">
          <div className="flex items-center gap-3.5">
            <div className="w-10 h-10 rounded-xl bg-[#7D58FD]/15 border border-[#7D58FD]/40 flex items-center justify-center text-[#7D58FD] shadow-glow-violet-sm">
              <Terminal className="w-5 h-5" />
            </div>
            <div>
              <h3 className="text-base font-semibold text-[#ECE9F7] flex items-center gap-2">
                Operational Scan Proposal
                <span className="text-xs font-mono px-2.5 py-0.5 rounded-full bg-[#7D58FD]/25 text-[#ECE9F7] uppercase font-bold">
                  {proposal.tool} ({proposal.action_type})
                </span>
              </h3>
              <p className="text-sm text-[#8A86A3]">
                Target: <span className="font-mono text-[#ECE9F7]">{proposal.target}</span>
              </p>
            </div>
          </div>

          {/* Scope Safety Verification Badge */}
          <div className="flex items-center gap-1.5 px-3 py-1.5 rounded-full text-xs font-mono bg-[#30E1DB]/10 border border-[#30E1DB]/30 text-[#30E1DB]">
            <Shield className="w-3.5 h-3.5" />
            <span>PERIMETER VERIFIED</span>
          </div>
        </div>

        {/* Command Terminal Preview */}
        <div className="mb-5">
          <div className="flex items-center justify-between px-4 py-2 bg-[#0F0D18] rounded-t-xl border border-b-0 border-[#7D58FD]/25 text-xs font-mono text-[#8A86A3]">
            <span>COMMAND EXECUTION PREVIEW</span>
            <button
              onClick={handleCopy}
              className="flex items-center gap-1.5 text-xs text-[#8A86A3] hover:text-[#ECE9F7] transition-colors"
            >
              {copied ? (
                <>
                  <Check className="w-3.5 h-3.5 text-[#30E1DB]" />
                  <span className="text-[#30E1DB]">Copied</span>
                </>
              ) : (
                <>
                  <Copy className="w-3.5 h-3.5" />
                  <span>Copy</span>
                </>
              )}
            </button>
          </div>
          <div className="p-4 bg-[#0A0812] rounded-b-xl border border-[#7D58FD]/25 font-mono text-sm text-[#30E1DB] overflow-x-auto shadow-inner">
            <code>$ {proposal.command_preview}</code>
          </div>
        </div>

        {/* Reasoning & Risk Grid */}
        <div className="grid grid-cols-1 md:grid-cols-2 gap-4 text-sm">
          <div className="p-4 rounded-xl bg-[#0F0D18]/70 border border-[#7D58FD]/20">
            <span className="font-semibold text-[#ECE9F7] block mb-1">Analyst Objective Rationale:</span>
            <p className="text-[#8A86A3] leading-relaxed text-sm">{proposal.reasoning}</p>
          </div>
          <div className="p-4 rounded-xl bg-[#0F0D18]/70 border border-[#FFB454]/20">
            <span className="font-semibold text-[#FFB454] block mb-1">Operational Risk Evaluation:</span>
            <p className="text-[#8A86A3] leading-relaxed text-sm">{proposal.risk_assessment}</p>
          </div>
        </div>

        {/* Passive Recon Direct Execution */}
        {!proposal.requires_approval && (
          <div className="mt-5 pt-4 border-t border-[#7D58FD]/15 flex items-center justify-between">
            <div className="text-sm text-[#8A86A3]">
              Passive reconnaissance does not require human gate approval.
            </div>
            <button
              onClick={onExecute}
              disabled={executing}
              className="px-6 py-3 rounded-xl text-sm font-semibold text-white bg-gradient-to-r from-[#7D58FD] to-[#5a36db] hover:from-[#8d6bff] shadow-glow-violet transition-all flex items-center gap-2"
            >
              {executing ? (
                <span className="w-4 h-4 border-2 border-white/30 border-t-white rounded-full animate-spin" />
              ) : (
                <Play className="w-4 h-4 fill-current text-[#30E1DB]" />
              )}
              <span>EXECUTE RECON SCAN</span>
            </button>
          </div>
        )}
      </div>

      {/* Human Approval Gate if required */}
      {proposal.requires_approval && (
        <ApprovalGate
          proposal={proposal}
          isApproved={isApproved}
          onApprove={onApprove}
          onReject={onReject}
          onExecute={onExecute}
          executing={executing}
          executionResult={executionResult}
        />
      )}
    </div>
  );
};

