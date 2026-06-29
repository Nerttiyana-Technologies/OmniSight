import { defineConfig } from "vite";
import react from "@vitejs/plugin-react";

// `base` lets the static build live under a GitHub Pages project path
// (e.g. /OmniSight/). Defaults to "/" for local dev and root deploys.
const base = process.env.VITE_BASE || "/";

export default defineConfig({
  base,
  plugins: [react()],
  server: {
    port: 5173,
    proxy: {
      "/api": { target: "http://localhost:4000", changeOrigin: true },
      "/health": { target: "http://localhost:4000", changeOrigin: true },
    },
  },
});
