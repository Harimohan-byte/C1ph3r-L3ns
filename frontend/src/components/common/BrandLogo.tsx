import React from 'react';

interface BrandLogoProps {
  sensorActive?: boolean;
  size?: 'sm' | 'md' | 'lg';
  className?: string;
}

export const BrandLogo: React.FC<BrandLogoProps> = ({
  sensorActive = false,
  size = 'md',
  className = '',
}) => {
  const sizeClasses = {
    sm: 'h-8',
    md: 'h-10',
    lg: 'h-14',
  };

  return (
    <div className={`relative flex items-center select-none ${className}`}>
      {/* Sensor telemetry glow behind the eye when scanning */}
      {sensorActive && (
        <span
          className="absolute left-[8px] top-[10px] w-6 h-6 rounded-full bg-[#30E1DB] blur-md animate-ping opacity-75 pointer-events-none"
          title="Security Telemetry Active"
        />
      )}

      {/* Main Official Brand Logo */}
      <img
        src="/logo.png"
        alt="CIPHER LENS"
        className={`${sizeClasses[size]} w-auto object-contain transition-all duration-300 ${
          sensorActive
            ? 'filter drop-shadow-[0_0_16px_rgba(48,225,219,0.7)]'
            : 'filter drop-shadow-[0_0_12px_rgba(125,88,253,0.3)] hover:drop-shadow-[0_0_18px_rgba(125,88,253,0.55)]'
        }`}
      />
    </div>
  );
};

