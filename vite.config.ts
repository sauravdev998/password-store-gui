import { defineConfig } from 'vite'
import react from '@vitejs/plugin-react'
import tailwindcss from '@tailwindcss/vite'

// https://vite.dev/config/
export default defineConfig({
  plugins: [react(), tailwindcss()],

  // Tauri owns the terminal output; don't let Vite wipe it.
  clearScreen: false,
  server: {
    port: 1420,
    strictPort: true,
    watch: {
      // The Rust core is watched by cargo, not Vite.
      ignored: ['**/src-tauri/**'],
    },
  },
  // Only TAURI_ENV_* and VITE_* reach the frontend bundle.
  envPrefix: ['VITE_', 'TAURI_ENV_'],
})
