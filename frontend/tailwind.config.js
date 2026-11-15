/** @type {import('tailwindcss').Config} */
export default {
  content: [
    "./index.html",
    "./src/**/*.{js,ts,jsx,tsx}",
  ],
  theme: {
    extend: {
      colors: {
        cl: {
          bg: "#0F0D18",
          card: "#171324",
          hover: "#1F1A30",
          violet: "#7D58FD",
          cyan: "#30E1DB",
          text: "#ECE9F7",
          muted: "#8A86A3",
          danger: "#FF4D6D",
          warning: "#FFB454",
          success: "#30E1DB",
        },
      },
      fontFamily: {
        display: ['Fraunces', 'Playfair Display', 'Georgia', 'serif'],
        sans: ['Plus Jakarta Sans', 'Inter', 'system-ui', 'sans-serif'],
        mono: ['JetBrains Mono', 'Fira Code', 'monospace'],
      },
      boxShadow: {
        'glow-violet': '0 0 24px rgba(125, 88, 253, 0.35)',
        'glow-violet-sm': '0 0 12px rgba(125, 88, 253, 0.25)',
        'glow-cyan': '0 0 20px rgba(48, 225, 219, 0.45)',
        'glow-cyan-sm': '0 0 10px rgba(48, 225, 219, 0.3)',
      },
      animation: {
        'sensor-pulse': 'sensorPulse 2s ease-in-out infinite',
        'perimeter-trace': 'perimeterTrace 1.5s cubic-bezier(0.16, 1, 0.3, 1) forwards',
        'laser-sweep': 'laserSweep 0.8s ease-out forwards',
      },
      keyframes: {
        sensorPulse: {
          '0%, 100%': { transform: 'scale(1)', filter: 'drop-shadow(0 0 6px rgba(48, 225, 219, 0.4))' },
          '50%': { transform: 'scale(1.12)', filter: 'drop-shadow(0 0 20px rgba(48, 225, 219, 0.85))' },
        },
        laserSweep: {
          '0%': { transform: 'translateX(-100%)', opacity: '0' },
          '50%': { opacity: '1' },
          '100%': { transform: 'translateX(100%)', opacity: '0' },
        },
      },
    },
  },
  plugins: [],
}

