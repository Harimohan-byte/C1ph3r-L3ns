import React from 'react';
import { Send, Sparkles, Terminal, Compass, ShieldAlert } from 'lucide-react';

interface PromptBarProps {
  input: string;
  setInput: (val: string) => void;
  onSubmit: (text: string) => void;
  loading: boolean;
  disabled?: boolean;
}

const STARTER_PROMPTS = [
  { label: 'Who are you?', text: 'Who are you?', icon: Sparkles },
  { label: 'Initial Port Discovery', text: 'Perform initial port and service discovery on the target application.', icon: Terminal },
  { label: 'Web VAPT Guidance', text: 'What is our strategic security assessment methodology for this target?', icon: Compass },
  { label: 'Check Critical CVEs', text: 'Analyze web server configurations and probe for known high-severity vulnerabilities.', icon: ShieldAlert },
];

export const PromptBar: React.FC<PromptBarProps> = ({
  input,
  setInput,
  onSubmit,
  loading,
  disabled = false,
}) => {
  const handleSubmit = (e: React.FormEvent) => {
    e.preventDefault();
    if (!input.trim() || loading || disabled) return;
    onSubmit(input.trim());
  };

  return (
    <div className="w-full space-y-3">
      {/* Quick Objective Chips */}
      <div className="flex items-center gap-2 overflow-x-auto pb-1 text-sm">
        <span className="text-[#8A86A3] font-mono flex items-center gap-1.5 flex-shrink-0 text-sm">
          <Sparkles className="w-4 h-4 text-[#30E1DB]" />
          Objectives:
        </span>
        {STARTER_PROMPTS.map((p, idx) => {
          const Icon = p.icon;
          return (
            <button
              key={idx}
              type="button"
              disabled={disabled || loading}
              onClick={() => {
                setInput(p.text);
                onSubmit(p.text);
              }}
              className="flex items-center gap-2 px-3.5 py-1.5 rounded-full bg-[#171324] border border-[#7D58FD]/25 text-[#ECE9F7] hover:border-[#7D58FD] hover:bg-[#1F1A30] hover:text-[#30E1DB] transition-all flex-shrink-0 font-sans text-sm"
            >
              <Icon className="w-3.5 h-3.5 text-[#7D58FD]" />
              <span>{p.label}</span>
            </button>
          );
        })}
      </div>

      {/* Main Glass Cyber Prompt Bar */}
      <form onSubmit={handleSubmit} className="relative flex items-center">
        <input
          type="text"
          value={input}
          onChange={(e) => setInput(e.target.value)}
          disabled={disabled || loading}
          placeholder="Ask C1PH3R anything (e.g. propose next scan, advise on CVE mitigations, discuss findings)..."
          className="w-full pl-5 pr-32 py-4 rounded-2xl bg-[#171324]/90 backdrop-blur-xl border border-[#7D58FD]/35 text-[#ECE9F7] text-base placeholder-[#8A86A3]/60 focus:outline-none focus:border-[#7D58FD] focus:ring-2 focus:ring-[#7D58FD]/40 shadow-glow-violet-sm transition-all"
        />
        <button
          type="submit"
          disabled={!input.trim() || loading || disabled}
          className="absolute right-2.5 px-5 py-2.5 rounded-xl text-sm font-semibold text-white bg-gradient-to-r from-[#7D58FD] to-[#5a36db] hover:from-[#8d6bff] hover:to-[#6c48e8] disabled:opacity-40 shadow-glow-violet transition-all flex items-center gap-2"
        >
          {loading ? (
            <span className="w-4 h-4 border-2 border-white/30 border-t-white rounded-full animate-spin" />
          ) : (
            <>
              <span>Consult</span>
              <Send className="w-4 h-4 text-[#30E1DB]" />
            </>
          )}
        </button>
      </form>
    </div>
  );
};

