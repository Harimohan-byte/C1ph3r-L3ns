import React from 'react';
import { Compass, AlertTriangle, CheckSquare, Wrench, ArrowRight } from 'lucide-react';
import { AdvisoryPayload } from '../../types';

interface AdvisoryCardProps {
  payload: AdvisoryPayload;
  onSelectTool: (tool: string, rationale: string) => void;
}

export const AdvisoryCard: React.FC<AdvisoryCardProps> = ({
  payload,
  onSelectTool,
}) => {
  return (
    <div className="glass-panel rounded-2xl p-6 border-l-4 border-l-[#7D58FD] relative overflow-hidden">
      {/* Background glow */}
      <div className="absolute top-0 right-0 w-64 h-64 bg-[#7D58FD]/10 rounded-full blur-3xl pointer-events-none" />

      {/* Header */}
      <div className="flex items-center gap-3.5 mb-5">
        <div className="w-10 h-10 rounded-xl bg-[#7D58FD]/15 border border-[#7D58FD]/40 flex items-center justify-center text-[#7D58FD] shadow-glow-violet-sm">
          <Compass className="w-5 h-5" />
        </div>
        <div>
          <h3 className="text-base font-semibold text-[#ECE9F7] flex items-center gap-2">
            Strategic Assessment Advisory
            <span className="text-xs font-mono px-2.5 py-0.5 rounded-full bg-[#7D58FD]/20 text-[#ECE9F7] border border-[#7D58FD]/40 font-bold">
              ADVISORY DOSSIER
            </span>
          </h3>
          <p className="text-sm text-[#8A86A3]">Executive Threat Modeling & Technical Guidance</p>
        </div>
      </div>

      {/* Strategic Guidance Body */}
      <div className="text-base text-[#ECE9F7] leading-relaxed whitespace-pre-line mb-6 font-sans">
        {payload.strategic_guidance || payload.analysis || payload.directional_guidance}
      </div>

      <div className="grid grid-cols-1 md:grid-cols-2 gap-6 mb-6">
        {/* Key Risks */}
        {payload.key_risks && payload.key_risks.length > 0 && (
          <div className="p-4 rounded-xl bg-[#0F0D18]/70 border border-[#FF4D6D]/20">
            <div className="text-sm font-semibold text-[#FF4D6D] uppercase tracking-wider mb-2.5 flex items-center gap-1.5">
              <AlertTriangle className="w-4 h-4" />
              Identified Threat Vectors
            </div>
            <ul className="space-y-2 text-sm text-[#ECE9F7]">
              {payload.key_risks.map((risk, idx) => (
                <li key={idx} className="flex items-start gap-2">
                  <span className="text-[#FF4D6D] mt-0.5">•</span>
                  <span>{risk}</span>
                </li>
              ))}
            </ul>
          </div>
        )}

        {/* Methodology Notes */}
        {payload.methodology_notes && payload.methodology_notes.length > 0 && (
          <div className="p-4 rounded-xl bg-[#0F0D18]/70 border border-[#7D58FD]/20">
            <div className="text-sm font-semibold text-[#30E1DB] uppercase tracking-wider mb-2.5 flex items-center gap-1.5">
              <CheckSquare className="w-4 h-4" />
              Methodology Alignment
            </div>
            <ul className="space-y-2 text-sm text-[#ECE9F7]">
              {payload.methodology_notes.map((note, idx) => (
                <li key={idx} className="flex items-start gap-2">
                  <span className="text-[#30E1DB] mt-0.5">✓</span>
                  <span>{note}</span>
                </li>
              ))}
            </ul>
          </div>
        )}
      </div>

      {/* Recommended Integrated Tools */}
      {payload.recommended_tools && payload.recommended_tools.length > 0 && (
        <div className="pt-4 border-t border-[#7D58FD]/15">
          <div className="text-sm font-mono text-[#8A86A3] mb-3 flex items-center gap-1.5">
            <Wrench className="w-4 h-4 text-[#7D58FD]" />
            Recommended Operational Tools:
          </div>
          <div className="grid grid-cols-1 sm:grid-cols-2 md:grid-cols-3 gap-3">
            {payload.recommended_tools.map((rec, idx) => (
              <div
                key={idx}
                className="p-3.5 rounded-xl bg-[#171324] border border-[#7D58FD]/25 hover:border-[#7D58FD] flex flex-col justify-between transition-all"
              >
                <div>
                  <div className="flex items-center justify-between mb-1.5">
                    <span className="text-sm font-mono font-bold uppercase text-[#ECE9F7]">
                      {rec.tool}
                    </span>
                    <span className="text-xs font-mono px-2 py-0.5 rounded bg-[#7D58FD]/20 text-[#30E1DB]">
                      {rec.priority || 'RECOMMENDED'}
                    </span>
                  </div>
                  <p className="text-xs text-[#8A86A3] mb-3 leading-relaxed">
                    {rec.rationale}
                  </p>
                </div>
                <button
                  onClick={() => onSelectTool(rec.tool, rec.rationale)}
                  className="w-full py-2 rounded-lg text-xs font-medium bg-[#7D58FD]/20 border border-[#7D58FD]/40 text-[#ECE9F7] hover:bg-[#7D58FD] hover:text-white transition-all flex items-center justify-center gap-1.5"
                >
                  <span>Propose {rec.tool.toUpperCase()} Plan</span>
                  <ArrowRight className="w-3.5 h-3.5" />
                </button>
              </div>
            ))}
          </div>
        </div>
      )}
    </div>
  );
};
