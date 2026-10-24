import { defineConfig } from "vite";
import react from "@vitejs/plugin-react";

// Dev: `npm run dev` proxies /api to the FastAPI server on :8000.
// Build: output goes to ../api/static so FastAPI serves the console itself.
// The Docker image (api/Dockerfile) overrides this with `vite build --outDir /out --emptyOutDir`
// and copies the result to /app/static; keep outDir here for the local workflow.
export default defineConfig({
  plugins: [react()],
  server: { proxy: { "/api": "http://127.0.0.1:8000" } },
  build: { outDir: "../api/static", emptyOutDir: true },
});
