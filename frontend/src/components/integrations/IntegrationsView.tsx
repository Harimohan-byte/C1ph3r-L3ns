import React, { useState, useEffect } from 'react';
import { Cpu, CheckCircle2, AlertCircle, Wrench, RefreshCw, Info } from 'lucide-react';
import { api } from '../../services/api';
import { ToolCapability } from '../../types';

export const IntegrationsView: React.FC = () => {
  const [tools, setTools] = useState<ToolCapability[]>([]);
  const [loading, setLoading] = useState(false);

  const loadIntegrations = async () => {
    setLoading(true);
    try {
      const data = await api.listIntegrations();
      setTools(data);
    } catch (err) {
      console.error('Failed to load integrations:', err);
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    loadIntegrations();
  }, []);

  const getStatusBadge = (status: string) => {
    switch (status) {
      case 'Live':
        return 'bg-[#30E1DB]/20 text-[#30E1DB] border-[#30E1DB]/40 shadow-glow-cyan-sm';
      case 'Import-only':
        return 'bg-[#7D58FD]/20 text-[#ECE9F7] border-[#7D58FD]/40';
      case 'Planned':
        return 'bg-[#FFB454]/20 text-[#FFB454] border-[#FFB454]/40';
      default:
        return 'bg-[#8A86A3]/20 text-[#8A86A3] border-[#8A86A3]/40';
    }
  };

  return (
    <div className="w-full max-w-[1700px] mx-auto px-6 lg:px-12 py-8 space-y-8">
      {/* Header */}
      <div className="text-center mb-8">
        <div className="inline-flex items-center gap-2 px-3.5 py-1.5 rounded-full bg-[#7D58FD]/10 border border-[#7D58FD]/30 text-[#30E1DB] text-sm font-mono mb-4">
          <Cpu className="w-4 h-4" />
          HONEST INTEGRATION MATRIX
        </div>
        <h1 className="text-3xl md:text-4xl font-display font-semibold text-[#ECE9F7] tracking-tight mb-3">
          Security Tool Integrations
        </h1>
        <p className="text-sm md:text-base text-[#8A86A3] max-w-3xl mx-auto font-sans leading-relaxed">
          Truthful capability declaration across all seven security adapters. Every scanner is explicitly labelled Live, Import-only, Planned, or Unsupported per Constitution Principle IV.
        </p>
      </div>

      {/* Tools Grid - 4 columns on large landscape screens covers all 7 tools in exactly 2 rows */}
      <div className="grid grid-cols-1 md:grid-cols-2 xl:grid-cols-4 gap-6">
        {tools.map((tool) => (
          <div
            key={tool.name}
            className="glass-panel rounded-2xl p-6 flex flex-col justify-between border-t-2 border-t-[#7D58FD] hover:border-t-[#30E1DB] transition-all"
          >
            <div>
              <div className="flex items-center justify-between gap-2 mb-3">
                <h3 className="text-lg font-mono font-bold uppercase text-[#ECE9F7]">
                  {tool.name}
                </h3>
                <span
                  className={`text-xs font-mono px-2.5 py-0.5 rounded font-bold uppercase border ${getStatusBadge(
                    tool.status
                  )}`}
                >
                  {tool.status}
                </span>
              </div>

              <div className="text-sm font-semibold text-[#30E1DB] mb-2.5">
                {tool.expected_role}
              </div>

              <p className="text-sm text-[#8A86A3] leading-relaxed mb-4">
                {tool.availability_details}
              </p>

              {tool.limitations && (
                <div className="p-3.5 rounded-xl bg-[#0F0D18]/70 border border-[#7D58FD]/15 mb-4 text-xs text-[#8A86A3]">
                  <span className="font-semibold text-[#FFB454] block mb-1 flex items-center gap-1.5">
                    <Info className="w-3.5 h-3.5" /> Operational Constraints:
                  </span>
                  {tool.limitations}
                </div>
              )}
            </div>

            <div className="pt-3.5 border-t border-[#7D58FD]/15 flex items-center justify-between text-xs font-mono text-[#8A86A3]">
              <span>Coverage: {tool.coverage_type}</span>
              <span>Mode: {tool.declared_mode}</span>
            </div>
          </div>
        ))}
      </div>
    </div>
  );
};

