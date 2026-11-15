import React, { useState, useEffect } from 'react';
import {
  FileCheck2,
  Shield,
  Search,
  CheckCircle2,
  XCircle,
  AlertTriangle,
  Clock,
  User,
  Fingerprint,
} from 'lucide-react';
import { api } from '../../services/api';
import { useScopeStore } from '../../store/useScopeStore';
import { Approval, AuditEvent } from '../../types';

export const AuditView: React.FC = () => {
  const activeScopeId = useScopeStore((state) => state.activeScopeId);
  const [approvals, setApprovals] = useState<Approval[]>([]);
  const [timeline, setTimeline] = useState<AuditEvent[]>([]);
  const [loading, setLoading] = useState(false);
  const [search, setSearch] = useState('');

  const loadData = async () => {
    setLoading(true);
    try {
      const [apprList, events] = await Promise.all([
        api.listApprovals(activeScopeId || undefined),
        api.listAuditTimeline(activeScopeId || undefined),
      ]);
      setApprovals(apprList);
      setTimeline(events);
    } catch (err) {
      console.error('Failed to load audit data:', err);
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    loadData();
  }, [activeScopeId]);

  const handleDecision = async (approvalId: string, decision: 'approved' | 'rejected') => {
    const reason = prompt(`Enter reason for ${decision}:`, decision === 'approved' ? 'Authorized by security lead' : 'Outside test scope');
    if (reason === null) return;

    try {
      await api.transitionApproval(approvalId, decision, reason, 'security-lead');
      await loadData();
    } catch (err: any) {
      alert(`Transition error: ${err.message}`);
    }
  };

  const filteredEvents = timeline.filter((e) =>
    e.event_type.toLowerCase().includes(search.toLowerCase()) ||
    e.actor.toLowerCase().includes(search.toLowerCase()) ||
    JSON.stringify(e.detail).toLowerCase().includes(search.toLowerCase())
  );

  return (
    <div className="w-full max-w-[1700px] mx-auto px-6 lg:px-12 py-8 space-y-8">
      {/* Header */}
      <div className="text-center mb-8">
        <div className="inline-flex items-center gap-2 px-3.5 py-1.5 rounded-full bg-[#7D58FD]/10 border border-[#7D58FD]/30 text-[#30E1DB] text-sm font-mono mb-4">
          <Fingerprint className="w-4 h-4" />
          IMMUTABLE COMPLIANCE LEDGER
        </div>
        <h1 className="text-3xl md:text-4xl font-display font-semibold text-[#ECE9F7] tracking-tight mb-2">
          Audit Trail & Governance Approvals
        </h1>
        <p className="text-sm md:text-base text-[#8A86A3] max-w-3xl mx-auto font-sans leading-relaxed">
          Cryptographically recorded timeline of every scope definition, tool execution, AI proposal, and human decision.
        </p>
      </div>

      {/* Human Approvals Management Card */}
      <div className="glass-panel rounded-2xl p-6">
        <div className="flex items-center justify-between pb-4 border-b border-[#7D58FD]/15 mb-5">
          <h2 className="text-lg font-semibold text-[#ECE9F7] flex items-center gap-2.5">
            <FileCheck2 className="w-5 h-5 text-[#30E1DB]" />
            Human In-The-Loop Approval Decisions
            <span className="text-xs font-mono px-2.5 py-0.5 rounded bg-[#7D58FD]/20 text-[#ECE9F7]">
              {approvals.length} Records
            </span>
          </h2>
          <span className="text-xs font-mono text-[#8A86A3]">Constitution Principle III</span>
        </div>

        {approvals.length === 0 ? (
          <div className="text-center py-6 text-sm text-[#8A86A3]">
            No pending or decided approval requests on record.
          </div>
        ) : (
          <div className="space-y-3">
            {approvals.map((appr) => (
              <div
                key={appr.id}
                className="p-4 rounded-xl border border-[#7D58FD]/20 bg-[#0F0D18]/60 flex flex-col sm:flex-row items-start sm:items-center justify-between gap-4"
              >
                <div>
                  <div className="flex items-center gap-2.5 mb-1.5">
                    <span className="text-sm font-mono font-bold uppercase text-[#ECE9F7]">
                      {appr.tool} ({appr.action})
                    </span>
                    <span
                      className={`text-xs font-mono px-2.5 py-0.5 rounded font-bold uppercase border ${
                        appr.status === 'approved'
                          ? 'bg-[#30E1DB]/20 text-[#30E1DB] border-[#30E1DB]/40'
                          : appr.status === 'rejected'
                          ? 'bg-[#FF4D6D]/20 text-[#FF4D6D] border-[#FF4D6D]/40'
                          : 'bg-[#FFB454]/20 text-[#FFB454] border-[#FFB454]/40'
                      }`}
                    >
                      {appr.status}
                    </span>
                  </div>
                  <div className="text-sm font-mono text-[#8A86A3]">
                    Target: {appr.target} | Requested: {appr.requested_by || 'operator'}
                  </div>
                  {appr.decision_reason && (
                    <div className="text-xs text-[#8A86A3] mt-1">
                      Reason: <span className="text-[#ECE9F7]">{appr.decision_reason}</span>
                    </div>
                  )}
                </div>

                {appr.status === 'pending' && (
                  <div className="flex items-center gap-2.5">
                    <button
                      onClick={() => handleDecision(appr.id, 'rejected')}
                      className="px-3.5 py-2 rounded-lg text-xs font-mono text-[#FF4D6D] border border-[#FF4D6D]/30 hover:bg-[#FF4D6D]/10 transition-colors"
                    >
                      Reject
                    </button>
                    <button
                      onClick={() => handleDecision(appr.id, 'approved')}
                      className="px-4.5 py-2 rounded-lg text-xs font-mono font-semibold text-[#0F0D18] bg-[#30E1DB] hover:bg-[#4df7f1] transition-all"
                    >
                      Approve
                    </button>
                  </div>
                )}
              </div>
            ))}
          </div>
        )}
      </div>

      {/* Append-Only Audit Event Timeline */}
      <div className="glass-panel rounded-2xl p-6">
        <div className="flex flex-col sm:flex-row items-start sm:items-center justify-between gap-4 pb-4 border-b border-[#7D58FD]/15 mb-5">
          <h2 className="text-base font-semibold text-[#ECE9F7] flex items-center gap-2">
            <Clock className="w-5 h-5 text-[#7D58FD]" />
            Chronological Audit Timeline
            <span className="text-xs font-mono px-2 py-0.5 rounded bg-[#7D58FD]/20 text-[#ECE9F7]">
              {filteredEvents.length} Events
            </span>
          </h2>

          <div className="relative w-full sm:w-64">
            <Search className="w-3.5 h-3.5 absolute left-3 top-2.5 text-[#8A86A3]" />
            <input
              type="text"
              value={search}
              onChange={(e) => setSearch(e.target.value)}
              placeholder="Filter timeline events..."
              className="w-full pl-8 pr-3 py-1.5 rounded-xl bg-[#0F0D18]/80 border border-[#7D58FD]/25 text-xs text-[#ECE9F7] placeholder-[#8A86A3]/50 focus:outline-none focus:border-[#7D58FD]"
            />
          </div>
        </div>

        {filteredEvents.length === 0 ? (
          <div className="text-center py-8 text-xs text-[#8A86A3]">
            No audit events found.
          </div>
        ) : (
          <div className="space-y-3 font-mono text-xs">
            {filteredEvents.map((ev) => (
              <div
                key={ev.id}
                className="p-3 rounded-xl border border-[#7D58FD]/15 bg-[#0F0D18]/50 flex flex-col md:flex-row md:items-center justify-between gap-2"
              >
                <div className="flex items-center gap-3">
                  <span className="text-[10px] text-[#8A86A3] whitespace-nowrap">
                    {ev.timestamp ? new Date(ev.timestamp).toLocaleTimeString() : 'Recent'}
                  </span>
                  <span className="px-2 py-0.5 rounded text-[10px] font-bold uppercase bg-[#7D58FD]/20 text-[#30E1DB] border border-[#7D58FD]/30">
                    {ev.event_type}
                  </span>
                  <span className="text-[#ECE9F7] truncate max-w-md">
                    {JSON.stringify(ev.detail)}
                  </span>
                </div>

                <div className="flex items-center gap-2 text-[10px] text-[#8A86A3] flex-shrink-0">
                  <User className="w-3 h-3" />
                  <span>{ev.actor}</span>
                </div>
              </div>
            ))}
          </div>
        )}
      </div>
    </div>
  );
};

