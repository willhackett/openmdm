import { defineConfig } from "vite";

// The Go binary embeds web/dist and serves index.html for every unknown path,
// so assets are root-absolute and the router uses real paths.
export default defineConfig({
  base: "/",
  esbuild: { jsx: "automatic", jsxImportSource: "preact" },
  build: { outDir: "dist", emptyOutDir: true, sourcemap: false },
});
