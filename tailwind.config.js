/** @type {import('tailwindcss').Config} */
export default {
  content: ['./src/**/*.{html,js,svelte,ts}'],
  darkMode: 'class',
  theme: {
    extend: {
      colors: {
        // Zero-trust theme colors
        trust: {
          high: '#22c55e',    // green-500
          medium: '#eab308',  // yellow-500
          low: '#f97316',     // orange-500
          critical: '#ef4444' // red-500
        },
        severity: {
          critical: '#dc2626',
          high: '#ea580c',
          medium: '#ca8a04',
          low: '#16a34a',
          info: '#2563eb'
        }
      },
      animation: {
        'pulse-slow': 'pulse 3s cubic-bezier(0.4, 0, 0.6, 1) infinite',
        'attack-line': 'attack-line 2s linear forwards'
      },
      keyframes: {
        'attack-line': {
          '0%': { strokeDashoffset: '1000' },
          '100%': { strokeDashoffset: '0' }
        }
      }
    }
  },
  plugins: []
};
