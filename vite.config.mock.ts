import { resolve } from 'node:path'
import { defineConfig } from 'vite'
import react from '@vitejs/plugin-react'
import tailwindcss from '@tailwindcss/vite'

/**
 * The frontend with a stubbed core, for click-testing in a plain browser.
 *
 * `pnpm dev:mock`, then open http://localhost:1421/. See `src/lib/mockInvoke.ts`
 * for what the stub does and does not stand in for — in short, it exercises the
 * webview and says nothing about the Rust core or `PLAN.md` §4.
 *
 * Identical to `vite.config.ts` but for the alias, so `src/lib/commands.ts` is
 * exercised unchanged and every component reaches the stub through the same
 * typed wrappers it uses in the real app. A different port from the Tauri dev
 * server, so both can run at once without one silently serving the other.
 */
export default defineConfig({
  plugins: [react(), tailwindcss()],

  resolve: {
    alias: [
      {
        find: /^@tauri-apps\/api\/core$/,
        replacement: resolve(import.meta.dirname, 'src/lib/mockInvoke.ts'),
      },
    ],
  },

  server: {
    port: 1421,
    strictPort: true,
    watch: {
      // The Rust core is watched by cargo, not Vite — and is not running here.
      ignored: ['**/src-tauri/**'],
    },
  },
})
