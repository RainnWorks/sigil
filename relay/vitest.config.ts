import { defineWorkersConfig } from "@cloudflare/vitest-pool-workers/config";

// Runs the suite inside workerd (via Miniflare), so the Durable Object,
// WebSocket, and storage behaviour under test is the real runtime, not a mock.
// No Cloudflare account is needed for `vitest run`; only `wrangler deploy` is.
export default defineWorkersConfig({
  test: {
    // The Bun suite (bun/) runs under `bun test`, not workerd; keep it out.
    include: ["test/**/*.test.ts"],
    poolOptions: {
      workers: {
        // Every test uses a unique random mailbox id, so per-test storage
        // isolation is unnecessary; disabling it sidesteps a known pool-workers
        // crash when a hibernatable WebSocket is still open at a test boundary.
        isolatedStorage: false,
        wrangler: { configPath: "./wrangler.jsonc" },
      },
    },
  },
});
