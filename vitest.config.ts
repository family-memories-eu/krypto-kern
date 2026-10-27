import { fileURLToPath } from "node:url";
import { defineConfig } from "vitest/config";

// Same settings as the app: Node environment (WebCrypto at globalThis.crypto),
// the "@/*" -> "src/*" alias, and headroom for real AES-GCM over large chunks.
export default defineConfig({
  resolve: { alias: { "@": fileURLToPath(new URL("./src", import.meta.url)) } },
  test: {
    environment: "node",
    include: ["src/**/*.test.ts"],
    testTimeout: 30000,
  },
});
