import React from 'react';
import { motion } from 'framer-motion';
import {
  Shield,
  Activity,
  FileCheck2,
  Cpu,
  FileText,
  Crosshair,
  AlertCircle,
} from 'lucide-react';
import { BrandLogo } from './BrandLogo';
import { useScopeStore, WorkspaceTab } from '../../store/useScopeStore';

interface NavItem {
  id: WorkspaceTab;
  label: string;
  icon: React.ElementType;
}

const NAV_ITEMS: NavItem[] = [
  { id: 'scope', label: 'Authorized Scope', icon: Shield },
  { id: 'assessment', label: 'Assessment Workspace', icon: Activity },
  { id: 'audit', label: 'Audit & Approvals', icon: FileCheck2 },
  { id: 'integrations', label: 'Integrations', icon: Cpu },
  { id: 'report', label: 'VAPT Report', icon: FileText },
];

export const TopNav: React.FC = () => {
  const {
    activeWorkspace,
    setActiveWorkspace,
    getActiveScope,
    isScanning,
  } = useScopeStore();

  const activeScope = getActiveScope();

  return (
    <header className="sticky top-0 z-50 w-full px-6 py-4 flex items-center justify-between pointer-events-none">
      {/* Left: Brand Logo & Sensor Indicator */}
      <div className="flex items-center gap-3 pointer-events-auto">
        <BrandLogo sensorActive={isScanning} size="md" />
        {isScanning && (
          <span className="flex items-center gap-1.5 px-2.5 py-0.5 rounded-full text-xs font-mono font-medium bg-[#30E1DB]/10 text-[#30E1DB] border border-[#30E1DB]/30 shadow-glow-cyan-sm">
            <span className="w-1.5 h-1.5 rounded-full bg-[#30E1DB] animate-pulse" />
            TELEMETRY ACTIVE
          </span>
        )}
      </div>

      {/* Center: Floating Glass Navigation Bar */}
      <nav className="nav-glass-pill px-2 py-1.5 rounded-full flex items-center gap-1 pointer-events-auto transition-all">
        {NAV_ITEMS.map((item) => {
          const isActive = activeWorkspace === item.id;
          const Icon = item.icon;

          return (
            <button
              key={item.id}
              onClick={() => setActiveWorkspace(item.id)}
              className={`relative px-4 py-2 rounded-full text-sm font-medium tracking-wide flex items-center gap-2 transition-all duration-200 select-none ${
                isActive
                  ? 'text-[#ECE9F7] font-semibold'
                  : 'text-[#8A86A3] hover:text-[#ECE9F7] hover:-translate-y-0.5 hover:shadow-[0_4px_16px_-2px_rgba(125,88,253,0.5)]'
              }`}
              style={{
                transitionTimingFunction: 'cubic-bezier(0.16, 1, 0.3, 1)',
              }}
            >
              {/* Active Gliding Background Pill */}
              {isActive && (
                <motion.div
                  layoutId="activeTabPill"
                  className="absolute inset-0 rounded-full bg-[#7D58FD]/25 border border-[#7D58FD]/60 shadow-[0_0_16px_rgba(125,88,253,0.4)]"
                  transition={{ type: 'spring', stiffness: 450, damping: 32 }}
                />
              )}

              <span className="relative z-10 flex items-center gap-1.5">
                <Icon className={`w-4 h-4 ${isActive ? 'text-[#30E1DB]' : 'text-current'}`} />
                <span>{item.label}</span>
              </span>
            </button>
          );
        })}
      </nav>

      {/* Right: Active Target Perimeter Pill */}
      <div className="flex items-center gap-3 pointer-events-auto">
        <button
          onClick={() => setActiveWorkspace('scope')}
          className={`flex items-center gap-2 px-3 py-1.5 rounded-full text-xs font-mono transition-all border ${
            activeScope
              ? 'bg-[#171324] border-[#7D58FD]/30 text-[#ECE9F7] hover:border-[#7D58FD]/70 hover:shadow-glow-violet-sm'
              : 'bg-[#171324] border-[#FFB454]/40 text-[#FFB454] hover:bg-[#1F1A30]'
          }`}
          title="Click to manage authorized targets"
        >
          {activeScope ? (
            <>
              <Crosshair className="w-3.5 h-3.5 text-[#30E1DB]" />
              <span className="font-semibold text-white truncate max-w-[140px]">
                {activeScope.target}
              </span>
              <span className="text-[10px] px-1.5 py-0.2 rounded bg-[#30E1DB]/20 text-[#30E1DB] font-semibold">
                ACTIVE
              </span>
            </>
          ) : (
            <>
              <AlertCircle className="w-3.5 h-3.5 text-[#FFB454]" />
              <span>No Scope Calibrated</span>
            </>
          )}
        </button>
      </div>
    </header>
  );
};

