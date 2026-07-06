import type { Env } from "../src/index";

declare module "cloudflare:test" {
  // Bindings declared in wrangler.jsonc, surfaced to `env` in tests.
  interface ProvidedEnv extends Env {}
}
