import React from 'react';
import { Bot, MessageSquare, ArrowRight } from 'lucide-react';
import { ConversationalPayload } from '../../types';

interface ConversationalCardProps {
  payload: ConversationalPayload;
  onSelectFollowUp: (prompt: string) => void;
}

export const ConversationalCard: React.FC<ConversationalCardProps> = ({
  payload,
  onSelectFollowUp,
}) => {
  return (
    <div className="glass-panel rounded-2xl p-6 border-l-4 border-l-[#30E1DB] relative overflow-hidden">
      {/* Subtle background glow */}
      <div className="absolute top-0 right-0 w-64 h-64 bg-[#30E1DB]/5 rounded-full blur-3xl pointer-events-none" />

      {/* Header with C1PH3R Persona */}
      <div className="flex items-center gap-3.5 mb-4">
        <div className="w-10 h-10 rounded-xl bg-[#30E1DB]/10 border border-[#30E1DB]/30 flex items-center justify-center text-[#30E1DB] shadow-glow-cyan-sm">
          <Bot className="w-5 h-5" />
        </div>
        <div>
          <h3 className="text-base font-semibold text-[#ECE9F7] flex items-center gap-2">
            C1PH3R Security Advisor
            <span className="text-xs font-mono px-2.5 py-0.5 rounded-full bg-[#30E1DB]/15 text-[#30E1DB] font-bold">
              CONVERSATIONAL MODE
            </span>
          </h3>
          <p className="text-sm text-[#8A86A3]">Autonomous Cyber Advisory & Threat Analysis</p>
        </div>
      </div>

      {/* Conversational Text */}
      <div className="text-base text-[#ECE9F7] leading-relaxed whitespace-pre-line mb-6 font-sans">
        {payload.message}
      </div>

      {/* Interactive Follow-up Chips */}
      {payload.suggested_follow_ups && payload.suggested_follow_ups.length > 0 && (
        <div className="pt-4 border-t border-[#7D58FD]/15">
          <div className="text-sm font-mono text-[#8A86A3] mb-3 flex items-center gap-1.5">
            <MessageSquare className="w-4 h-4 text-[#30E1DB]" />
            Suggested Discussion Vectors:
          </div>
          <div className="flex flex-wrap gap-2.5">
            {payload.suggested_follow_ups.map((chip, idx) => (
              <button
                key={idx}
                onClick={() => onSelectFollowUp(chip)}
                className="group flex items-center gap-2 px-4 py-2 rounded-xl bg-[#171324] border border-[#7D58FD]/30 text-sm text-[#ECE9F7] hover:border-[#30E1DB] hover:bg-[#1F1A30] hover:text-[#30E1DB] transition-all"
              >
                <span>💬 {chip}</span>
                <ArrowRight className="w-3.5 h-3.5 text-[#7D58FD] group-hover:text-[#30E1DB] group-hover:translate-x-0.5 transition-all" />
              </button>
            ))}
          </div>
        </div>
      )}
    </div>
  );
};

