import React, { useState, useEffect } from 'react';
import { FileText, Download, ShieldCheck, AlertCircle, BarChart3, CheckCircle } from 'lucide-react';
import { useScopeStore } from '../../store/useScopeStore';
import { api } from '../../services/api';
import { ReportMetrics } from '../../types';

export const ReportView: React.FC = () => {
  const { activeScopeId, getActiveScope, setActiveWorkspace } = useScopeStore();
  const activeScope = getActiveScope();

  const [metrics, setMetrics] = useState<ReportMetrics | null>(null);
  const [loading, setLoading] = useState(false);

  useEffect(() => {
    if (!activeScopeId) return;
    setLoading(true);
    api.getReportMetrics(activeScopeId)
      .then((data) => setMetrics(data))
      .catch((err) => console.error('Failed to load metrics:', err))
      .finally(() => setLoading(false));
  }, [activeScopeId]);

  if (!activeScope) {
    return (
      <div className="max-w-4xl mx-auto px-6 py-20 text-center">
        <FileText className="w-12 h-12 text-[#8A86A3] mx-auto mb-4 opacity-50" />
        <h2 className="text-xl font-display font-semibold text-[#ECE9F7] mb-2">
          No Scope Selected
        </h2>
        <p className="text-sm text-[#8A86A3] mb-6">
          Calibrate a target perimeter to view assessment analytics and compile executive PDF reports.
        </p>
        <button
          onClick={() => setActiveWorkspace('scope')}
          className="px-5 py-2.5 rounded-xl text-xs font-semibold text-white bg-[#7D58FD] hover:bg-[#6c48e8] transition-all"
        >
          Select Scope →
        </button>
      </div>
    );
  }

  const dist = metrics?.distribution || { critical: 0, high: 0, medium: 0, low: 0, info: 0 };
  const totalFindings = metrics?.findings_count || 0;

  return (
    <div className="w-full max-w-[1700px] mx-auto px-6 lg:px-12 py-8 space-y-8">
      {/* Header */}
      <div className="text-center mb-8">
        <div className="inline-flex items-center gap-2 px-3.5 py-1.5 rounded-full bg-[#7D58FD]/10 border border-[#7D58FD]/30 text-[#30E1DB] text-sm font-mono mb-4">
          <ShieldCheck className="w-4 h-4" />
          EXECUTIVE POSTURE & TECHNICAL REPORTING
        </div>
        <h1 className="text-3xl md:text-4xl font-display font-semibold text-[#ECE9F7] tracking-tight mb-2">
          VAPT Executive & Technical Report
        </h1>
        <p className="text-sm md:text-base text-[#8A86A3] max-w-3xl mx-auto font-sans leading-relaxed">
          Comprehensive compliance-grade Vulnerability Assessment & Penetration Testing report generated with evidence-backed provenance.
        </p>
      </div>

      {/* Metrics Overview Cards */}
      <div className="grid grid-cols-2 md:grid-cols-4 gap-4">
        <div className="glass-panel rounded-2xl p-5 border-l-4 border-l-[#FF4D6D]">
          <span className="text-sm font-mono uppercase text-[#8A86A3] block mb-1">Critical Issues</span>
          <span className="text-3xl font-mono font-bold text-[#FF4D6D]">{dist.critical}</span>
        </div>
        <div className="glass-panel rounded-2xl p-5 border-l-4 border-l-[#FFB454]">
          <span className="text-sm font-mono uppercase text-[#8A86A3] block mb-1">High Severity</span>
          <span className="text-3xl font-mono font-bold text-[#FFB454]">{dist.high}</span>
        </div>
        <div className="glass-panel rounded-2xl p-5 border-l-4 border-l-[#7D58FD]">
          <span className="text-sm font-mono uppercase text-[#8A86A3] block mb-1">Medium Severity</span>
          <span className="text-3xl font-mono font-bold text-[#ECE9F7]">{dist.medium}</span>
        </div>
        <div className="glass-panel rounded-2xl p-5 border-l-4 border-l-[#30E1DB]">
          <span className="text-sm font-mono uppercase text-[#8A86A3] block mb-1">Total Confirmed</span>
          <span className="text-3xl font-mono font-bold text-[#30E1DB]">{totalFindings}</span>
        </div>
      </div>

      {/* Main Report Action Card */}
      <div className="glass-panel rounded-2xl p-8 flex flex-col md:flex-row items-center justify-between gap-6 relative overflow-hidden">
        <div className="space-y-2 max-w-xl">
          <h2 className="text-xl font-semibold text-[#ECE9F7] flex items-center gap-2">
            <FileText className="w-5 h-5 text-[#30E1DB]" />
            Generate Client-Ready PDF Report
          </h2>
          <p className="text-sm text-[#8A86A3] leading-relaxed">
            Exports a finalized, executive-level PDF report for target <span className="font-mono text-[#ECE9F7]">{activeScope.target}</span>. Includes severity distribution charts, scope boundaries, attack surface summaries, and remediation instructions.
          </p>
          <div className="text-xs font-mono text-[#30E1DB] pt-1">
            ✓ ReportLab 4.0 Pure Python Engine | Client-Appropriate Language
          </div>
        </div>

        <a
          href={api.getPdfUrl(activeScope.id)}
          download
          className="px-8 py-4 rounded-xl text-sm font-semibold text-white bg-gradient-to-r from-[#7D58FD] to-[#5a36db] hover:from-[#8d6bff] shadow-glow-violet transition-all flex items-center gap-2.5 flex-shrink-0"
        >
          <Download className="w-4 h-4 text-[#30E1DB]" />
          <span>DOWNLOAD VAPT REPORT (PDF)</span>
        </a>
      </div>
    </div>
  );
};

