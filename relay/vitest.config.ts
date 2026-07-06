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
        // isolation is unnecessary; disabling it also keeps a mailbox's
        // Durable Object instance (and its in-memory queues) stable across
        // the several requests one test makes against the same mailbox id.
        isolatedStorage: false,
        wrangler: { configPath: "./wrangler.jsonc" },
        // Overrides production's wrangler.jsonc (which sets no LONG_POLL_MS
        // at all, so it falls back to shared/protocol's real ~25s) with a
        // tiny value just for this suite, so a long-poll GET on an empty
        // slot times out in milliseconds instead of seconds.
        miniflare: { bindings: { LONG_POLL_MS: "150" } },
      },
    },
  },
});
