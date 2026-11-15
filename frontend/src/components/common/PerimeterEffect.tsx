import React from 'react';
import { motion, AnimatePresence } from 'framer-motion';
import { useScopeStore } from '../../store/useScopeStore';

export const PerimeterEffect: React.FC = () => {
  const perimeterActive = useScopeStore((state) => state.perimeterActive);

  return (
    <AnimatePresence>
      {perimeterActive && (
        <motion.div
          initial={{ opacity: 0 }}
          animate={{ opacity: 1 }}
          exit={{ opacity: 0 }}
          transition={{ duration: 0.3 }}
          className="fixed inset-0 z-50 pointer-events-none flex items-center justify-center"
        >
          {/* Laser Perimeter Line */}
          <div className="absolute inset-4 rounded-2xl border-2 border-[#7D58FD] shadow-[0_0_30px_rgba(125,88,253,0.8),inset_0_0_30px_rgba(125,88,253,0.4)]" />

          {/* Corner Tech Brackets in Cyan */}
          <div className="absolute top-4 left-4 w-8 h-8 border-t-2 border-l-2 border-[#30E1DB] shadow-glow-cyan-sm" />
          <div className="absolute top-4 right-4 w-8 h-8 border-t-2 border-r-2 border-[#30E1DB] shadow-glow-cyan-sm" />
          <div className="absolute bottom-4 left-4 w-8 h-8 border-b-2 border-l-2 border-[#30E1DB] shadow-glow-cyan-sm" />
          <div className="absolute bottom-4 right-4 w-8 h-8 border-b-2 border-r-2 border-[#30E1DB] shadow-glow-cyan-sm" />

          {/* HUD Calibration Readout */}
          <motion.div
            initial={{ scale: 0.9, opacity: 0 }}
            animate={{ scale: 1, opacity: 1 }}
            exit={{ scale: 1.05, opacity: 0 }}
            transition={{ duration: 0.25 }}
            className="px-6 py-3 rounded-xl bg-[#171324]/90 backdrop-blur-xl border border-[#30E1DB]/60 shadow-glow-cyan text-center"
          >
            <div className="text-[10px] font-mono tracking-widest text-[#30E1DB] mb-1 font-bold">
              [ SAFETY PROTOCOL ACTIVE ]
            </div>
            <div className="text-sm font-mono font-semibold text-[#ECE9F7]">
              AUTHORIZED SCOPE PERIMETER CALIBRATED
            </div>
          </motion.div>
        </motion.div>
      )}
    </AnimatePresence>
  );
};

