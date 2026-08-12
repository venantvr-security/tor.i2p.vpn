import { defineConfig } from 'vite'
import vue from '@vitejs/plugin-vue'

// Le bundle est embarqué dans le binaire Rust par rust-embed, qui lit `web/dist`.
// En développement, `npm run dev` proxifie l'API vers la passerelle locale.
export default defineConfig({
  plugins: [vue()],
  build: {
    outDir: 'dist',
    emptyOutDir: true,
    // Un Raspberry Pi sert ces fichiers : on garde le bundle compact et sans
    // fichiers de sourcemap inutiles en production.
    sourcemap: false,
    chunkSizeWarningLimit: 700,
  },
  server: {
    port: 5173,
    proxy: {
      '/api': {
        target: process.env.TIV_DEV_API ?? 'http://127.0.0.1:8080',
        changeOrigin: false,
      },
    },
  },
})
