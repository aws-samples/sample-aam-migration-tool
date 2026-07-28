import { defineConfig } from "vite";
import react from "@vitejs/plugin-react";

// Dev server proxies API calls to the Flask backend on :5000 so the UI
// can be developed with hot reload while the Python API runs separately.
// `npm run build` emits static assets that Flask serves from web/dist.
export default defineConfig({
  plugins: [react()],
  server: {
    port: 5173,
    proxy: {
      "/api": "http://127.0.0.1:5000",
    },
  },
  build: {
    outDir: "dist",
  },
});
