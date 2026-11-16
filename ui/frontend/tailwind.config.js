/** @type {import('tailwindcss').Config} */
export default {
  content: [
    "./index.html",
    "./src/**/*.{js,ts,jsx,tsx}",
  ],
  theme: {
    extend: {
      colors: {
        primary: {
          50: '#f0f9ff',
          100: '#e0f2fe',
          200: '#bae6fd',
          300: '#7dd3fc',
          400: '#38bdf8',
          500: '#0ea5e9',
          600: '#0284c7',
          700: '#0369a1',
          800: '#075985',
          900: '#0c4a6e',
        },
        severity: {
          p1: '#dc2626',
          p2: '#ea580c',
          p3: '#ca8a04',
          p4: '#16a34a',
        },
        status: {
          new: '#3b82f6',
          validated: '#22c55e',
          reported: '#f59e0b',
          duplicate: '#a855f7',
          false_positive: '#ef4444',
          fixed: '#22c55e',
          paid: '#eab308',
        },
      },
      fontFamily: {
        sans: ['Inter', 'system-ui', 'sans-serif'],
        mono: ['JetBrains Mono', 'Fira Code', 'monospace'],
      },
    },
  },
  plugins: [],
}