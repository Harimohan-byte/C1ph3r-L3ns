import React, { useState } from 'react';
import { motion, AnimatePresence } from 'framer-motion';
import { Lock, Unlock, ShieldAlert, CheckCircle2, Play, XCircle } from 'lucide-react';
import { PlanProposal } from '../../types';

interface ApprovalGateProps {
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

export const ApprovalGate: React.FC<ApprovalGateProps> = ({
  proposal,
  isApproved,
  onApprove,
  onReject,
  onExecute,
  executing,
  executionResult,
}) => {
  const [laserFired, setLaserFired] = useState(false);

  const handleApproveClick = () => {
    setLaserFired(true);
    setTimeout(() => {
      onApprove();
    }, 400);
  };

  return (
    <div
      className={`relative overflow-hidden rounded-2xl border p-6 transition-all duration-300 ${
        isApproved
          ? 'bg-[#171324] border-[#30E1DB]/60 shadow-[0_0_24px_rgba(48,225,219,0.2)]'
          : 'bg-[#171324] border-[#FFB454]/50 shadow-[0_0_20px_rgba(255,180,84,0.15)]'
      }`}
    >
      {/* Laser Sweep Unlock Animation */}
      <AnimatePresence>
        {laserFired && (
          <motion.div
            initial={{ left: '-100%' }}
            animate={{ left: '100%' }}
            exit={{ opacity: 0 }}
            transition={{ duration: 0.6, ease: 'easeOut' }}
            className="absolute top-0 bottom-0 w-32 bg-gradient-to-r from-transparent via-[#30E1DB] to-transparent opacity-80 blur-sm pointer-events-none z-20"
          />
        )}
      </AnimatePresence>

      <div className="flex flex-col sm:flex-row items-start sm:items-center justify-between gap-4 mb-4">
        <div className="flex items-center gap-3">
          <div
            className={`w-10 h-10 rounded-xl flex items-center justify-center transition-all ${
              isApproved
                ? 'bg-[#30E1DB]/15 text-[#30E1DB] border border-[#30E1DB]/40 shadow-glow-cyan-sm'
                : 'bg-[#FFB454]/15 text-[#FFB454] border border-[#FFB454]/40'
            }`}
          >
            {isApproved ? <Unlock className="w-5 h-5" /> : <Lock className="w-5 h-5" />}
          </div>
          <div>
            <h4 className="text-base font-semibold text-[#ECE9F7] flex items-center gap-2">
              Human In-The-Loop Approval Gate
              <span
                className={`text-xs font-mono px-2.5 py-0.5 rounded-full font-bold uppercase ${
                  isApproved
                    ? 'bg-[#30E1DB]/20 text-[#30E1DB] border border-[#30E1DB]/40'
                    : 'bg-[#FFB454]/20 text-[#FFB454] border border-[#FFB454]/40'
                }`}
              >
                {isApproved ? 'UNLOCKED / AUTHORIZED' : 'SAFETY LOCKED — APPROVAL REQUIRED'}
              </span>
            </h4>
            <p className="text-sm text-[#8A86A3]">
              {isApproved
                ? 'Action authorized by operator. Ready for live execution.'
                : 'Active scan profile triggers automated safety gate per Constitution Principle I.'}
            </p>
          </div>
        </div>

        {/* Action Controls */}
        <div className="flex items-center gap-2.5 w-full sm:w-auto">
          {!isApproved ? (
            <>
              {onReject && (
                <button
                  onClick={onReject}
                  className="px-4 py-2.5 rounded-xl text-sm font-semibold text-[#FF4D6D] border border-[#FF4D6D]/30 hover:bg-[#FF4D6D]/10 transition-all flex items-center gap-1.5"
                >
                  <XCircle className="w-4 h-4" />
                  Reject
                </button>
              )}
              <button
                onClick={handleApproveClick}
                className="px-6 py-2.5 rounded-xl text-sm font-semibold text-[#0F0D18] bg-[#30E1DB] hover:bg-[#49f2ec] shadow-glow-cyan transition-all flex items-center gap-2 font-mono"
              >
                <CheckCircle2 className="w-4 h-4 text-[#0F0D18]" />
                AUTHORIZE ACTION
              </button>
            </>
          ) : (
            <button
              onClick={onExecute}
              disabled={executing}
              className="w-full sm:w-auto px-7 py-3 rounded-xl text-sm font-semibold text-white bg-gradient-to-r from-[#7D58FD] to-[#5a36db] hover:from-[#8d6bff] hover:to-[#6c48e8] shadow-glow-violet disabled:opacity-50 transition-all flex items-center justify-center gap-2"
            >
              {executing ? (
                <>
                  <span className="w-4 h-4 border-2 border-white/30 border-t-white rounded-full animate-spin" />
                  <span>Executing Scan...</span>
                </>
              ) : (
                <>
                  <Play className="w-4 h-4 fill-current text-[#30E1DB]" />
                  <span>EXECUTE {proposal.tool.toUpperCase()} SCAN</span>
                </>
              )}
            </button>
          )}
        </div>
      </div>

      {/* Execution Feedback Banner */}
      {executionResult && (
        <div
          className={`mt-4 p-3.5 rounded-xl border text-sm flex items-center justify-between ${
            executionResult.status === 'completed'
              ? 'bg-[#30E1DB]/10 border-[#30E1DB]/30 text-[#ECE9F7]'
              : 'bg-[#FF4D6D]/10 border-[#FF4D6D]/30 text-[#FF4D6D]'
          }`}
        >
          <div className="flex items-center gap-2">
            <CheckCircle2 className="w-4 h-4 text-[#30E1DB]" />
            <span>
              Execution {executionResult.status}: {executionResult.message || 'Scan completed successfully.'}
            </span>
          </div>
          {executionResult.findings_count !== undefined && (
            <span className="font-mono text-[11px] px-2 py-0.5 rounded bg-[#30E1DB]/20 text-[#30E1DB] font-bold">
              {executionResult.findings_count} Findings Ingested
            </span>
          )}
        </div>
      )}
    </div>
  );
};

