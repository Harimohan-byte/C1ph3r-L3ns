import React from 'react';
import { motion, AnimatePresence } from 'framer-motion';

interface PageTransitionProps {
  children: React.ReactNode;
  transitionKey: string;
}

/**
 * Modular Page Transition Wrapper
 * 
 * NOTE: This component encapsulates all view transitions.
 * It currently implements a GPU-accelerated directional fade + parallax push
 * (240ms with cubic-bezier easing). It is fully swappable for a custom
 * glass-morph wipe or 3D camera drift without modifying any view logic.
 */
export const PageTransition: React.FC<PageTransitionProps> = ({
  children,
  transitionKey,
}) => {
  return (
    <AnimatePresence mode="wait">
      <motion.div
        key={transitionKey}
        initial={{ opacity: 0, y: 12, scale: 0.995 }}
        animate={{ opacity: 1, y: 0, scale: 1 }}
        exit={{ opacity: 0, y: -8, scale: 0.995 }}
        transition={{
          duration: 0.24,
          ease: [0.16, 1, 0.3, 1], // Custom snappy ease-out
        }}
        className="w-full h-full"
      >
        {children}
      </motion.div>
    </AnimatePresence>
  );
};

