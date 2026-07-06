/**
 * Node-only loader for the protocol test scripts (self-test, verify-vectors).
 * Uses the CJS build of libsodium-wrappers via createRequire, because its ESM
 * entry re-imports "./libsodium.mjs" from a sibling package and fails to resolve
 * under Bun/Node without a bundler. Never imported by the app bundle.
 */
import { createRequire } from "node:module";

import { setSodium, type Sodium } from "./sodium";

export async function loadSodiumForTests(): Promise<Sodium> {
  const require = createRequire(import.meta.url);
  const s = require("libsodium-wrappers") as Sodium & { ready: Promise<void> };
  await s.ready;
  setSodium(s);
  return s;
}
