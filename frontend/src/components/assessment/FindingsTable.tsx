import React, { useState } from 'react';
import {
  ShieldAlert,
  Search,
  Filter,
  ExternalLink,
  ChevronRight,
  ChevronDown,
  CheckCircle,
  HelpCircle,
} from 'lucide-react';
import { Finding } from '../../types';

interface FindingsTableProps {
  findings: Finding[];
  onUpdateStatus?: (findingId: string, status: string) => void;
}

export const FindingsTable: React.FC<FindingsTableProps> = ({
  findings,
  onUpdateStatus,
}) => {
  const [search, setSearch] = useState('');
  const [selectedSeverity, setSelectedSeverity] = useState<string>('all');
  const [expandedId, setExpandedId] = useState<string | null>(null);

  const filtered = findings.filter((f) => {
    const matchesSearch =
      f.canonical_title.toLowerCase().includes(search.toLowerCase()) ||
      f.affected_asset.toLowerCase().includes(search.toLowerCase()) ||
      (f.cve && f.cve.toLowerCase().includes(search.toLowerCase()));

    const matchesSeverity =
      selectedSeverity === 'all' || f.severity.toLowerCase() === selectedSeverity.toLowerCase();

    return matchesSearch && matchesSeverity;
  });

  const getSeverityBadge = (sev: string) => {
    switch (sev.toLowerCase()) {
      case 'critical':
        return 'bg-[#FF4D6D]/20 text-[#FF4D6D] border-[#FF4D6D]/40';
      case 'high':
        return 'bg-[#FF4D6D]/15 text-[#FF4D6D] border-[#FF4D6D]/30';
      case 'medium':
        return 'bg-[#FFB454]/15 text-[#FFB454] border-[#FFB454]/30';
      case 'low':
        return 'bg-[#7D58FD]/20 text-[#ECE9F7] border-[#7D58FD]/40';
      default:
        return 'bg-[#8A86A3]/15 text-[#8A86A3] border-[#8A86A3]/30';
    }
  };

  return (
    <div className="glass-panel rounded-2xl p-6">
      <div className="flex flex-col sm:flex-row items-start sm:items-center justify-between gap-4 pb-5 border-b border-[#7D58FD]/15 mb-5">
        <div>
          <h3 className="text-lg font-semibold text-[#ECE9F7] flex items-center gap-2.5">
            <ShieldAlert className="w-5 h-5 text-[#30E1DB]" />
            Consolidated Security Findings
            <span className="text-xs font-mono px-2.5 py-0.5 rounded-full bg-[#7D58FD]/20 text-[#ECE9F7]">
              {filtered.length} of {findings.length}
            </span>
          </h3>
          <p className="text-sm text-[#8A86A3] mt-1">
            Normalized across Nmap, Nikto, OWASP ZAP, Metasploit, Nuclei, Sqlmap, and Wireshark.
          </p>
        </div>

        {/* Filter Controls */}
        <div className="flex items-center gap-3 w-full sm:w-auto">
          <div className="relative flex-1 sm:w-60">
            <Search className="w-4 h-4 absolute left-3 top-3 text-[#8A86A3]" />
            <input
              type="text"
              value={search}
              onChange={(e) => setSearch(e.target.value)}
              placeholder="Filter findings..."
              className="w-full pl-9 pr-3 py-2 rounded-xl bg-[#0F0D18]/80 border border-[#7D58FD]/25 text-sm text-[#ECE9F7] placeholder-[#8A86A3]/50 focus:outline-none focus:border-[#7D58FD]"
            />
          </div>

          <select
            value={selectedSeverity}
            onChange={(e) => setSelectedSeverity(e.target.value)}
            className="px-3.5 py-2 rounded-xl bg-[#0F0D18]/80 border border-[#7D58FD]/25 text-sm text-[#ECE9F7] focus:outline-none focus:border-[#7D58FD]"
          >
            <option value="all">All Severities</option>
            <option value="critical">Critical</option>
            <option value="high">High</option>
            <option value="medium">Medium</option>
            <option value="low">Low</option>
            <option value="info">Info</option>
          </select>
        </div>
      </div>

      {/* Findings List Table */}
      {filtered.length === 0 ? (
        <div className="text-center py-10">
          <CheckCircle className="w-8 h-8 text-[#30E1DB] mx-auto mb-2 opacity-50" />
          <p className="text-base text-[#ECE9F7]">No findings matching filter criteria.</p>
          <p className="text-sm text-[#8A86A3] mt-1">Execute a scan or import vulnerability reports.</p>
        </div>
      ) : (
        <div className="space-y-2">
          {filtered.map((finding) => {
            const isExpanded = expandedId === finding.id;

            return (
              <div
                key={finding.id}
                className="rounded-xl border border-[#7D58FD]/15 bg-[#0F0D18]/50 hover:border-[#7D58FD]/35 transition-all overflow-hidden"
              >
                <div
                  onClick={() => setExpandedId(isExpanded ? null : finding.id)}
                  className="p-4 flex items-center justify-between gap-4 cursor-pointer select-none"
                >
                  <div className="flex items-center gap-3.5 flex-1 min-w-0">
                    <span
                      className={`text-xs font-mono px-2.5 py-0.5 rounded font-bold uppercase border ${getSeverityBadge(
                        finding.severity
                      )}`}
                    >
                      {finding.severity}
                    </span>
                    <div className="truncate">
                      <span className="text-sm font-semibold text-[#ECE9F7] hover:text-[#30E1DB] transition-colors block truncate">
                        {finding.canonical_title}
                      </span>
                      <span className="text-xs font-mono text-[#8A86A3]">
                        {finding.affected_asset}
                      </span>
                    </div>
                  </div>

                  <div className="flex items-center gap-3 flex-shrink-0">
                    {finding.cvss && (
                      <span className="text-xs font-mono px-2 py-0.5 rounded bg-[#171324] text-[#ECE9F7] border border-[#7D58FD]/20">
                        CVSS {finding.cvss.toFixed(1)}
                      </span>
                    )}
                    {finding.cve && (
                      <span className="text-xs font-mono px-2 py-0.5 rounded bg-[#30E1DB]/10 text-[#30E1DB] border border-[#30E1DB]/20">
                        {finding.cve}
                      </span>
                    )}
                    {isExpanded ? (
                      <ChevronDown className="w-4 h-4 text-[#8A86A3]" />
                    ) : (
                      <ChevronRight className="w-4 h-4 text-[#8A86A3]" />
                    )}
                  </div>
                </div>

                {/* Expanded Details Drawer */}
                {isExpanded && (
                  <div className="px-5 pb-5 pt-3 border-t border-[#7D58FD]/15 bg-[#171324]/60 space-y-4 text-sm">
                    <div>
                      <span className="text-xs font-mono uppercase text-[#8A86A3] block mb-1">
                        Technical Description
                      </span>
                      <p className="text-[#ECE9F7] leading-relaxed whitespace-pre-line text-sm">
                        {finding.description}
                      </p>
                    </div>

                    <div className="grid grid-cols-1 md:grid-cols-3 gap-3 pt-2">
                      <div className="p-3 rounded-lg bg-[#0F0D18] border border-[#7D58FD]/15">
                        <span className="text-xs text-[#8A86A3] block">Validation Status</span>
                        <span className="text-sm font-mono font-semibold text-[#30E1DB]">
                          {finding.validation_status}
                        </span>
                      </div>
                      <div className="p-3 rounded-lg bg-[#0F0D18] border border-[#7D58FD]/15">
                        <span className="text-xs text-[#8A86A3] block">Evidence Provenance</span>
                        <span className="text-sm font-mono text-[#ECE9F7]">
                          {finding.provenance && finding.provenance.length > 0
                            ? finding.provenance.map((p) => p.source_tool).join(', ')
                            : 'Direct Scanner'}
                        </span>
                      </div>
                      <div className="p-3 rounded-lg bg-[#0F0D18] border border-[#7D58FD]/15">
                        <span className="text-xs text-[#8A86A3] block">Remediation Action</span>
                        <div className="flex gap-2 mt-1.5">
                          {['confirmed', 'false_positive'].map((st) => (
                            <button
                              key={st}
                              onClick={(e) => {
                                e.stopPropagation();
                                onUpdateStatus?.(finding.id, st);
                              }}
                              className="px-2.5 py-1 rounded text-xs font-mono border border-[#7D58FD]/30 hover:border-[#30E1DB] text-[#ECE9F7] hover:bg-[#7D58FD]/10 transition-colors"
                            >
                              Mark {st}
                            </button>
                          ))}
                        </div>
                      </div>
                    </div>
                  </div>
                )}
              </div>
            );
          })}
        </div>
      )}
    </div>
  );
};

