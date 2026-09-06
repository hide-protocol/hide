import react from "@vitejs/plugin-react";
import { defineConfig } from "vite";

export default defineConfig({
  plugins: [react()],
  // Tauri serves the built files from disk; a fixed port keeps `tauri dev` working.
  clearScreen: false,
  server: { port: 5173, strictPort: true },
  build: {
    target: "chrome110",
    sourcemap: false,
    chunkSizeWarningLimit: 700,
  },
});
