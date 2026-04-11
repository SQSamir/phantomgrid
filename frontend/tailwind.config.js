/** @type {import('tailwindcss').Config} */
export default {
  content: ['./index.html', './src/**/*.{js,ts,jsx,tsx}'],
  theme: {
    extend: {
      colors: {
        surface: {
          900: '#0d0d1a',
          800: '#12122a',
          700: '#1a1a3a',
          600: '#22224a',
        },
      },
    },
  },
  plugins: [],
};
