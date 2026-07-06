// Docker HEALTHCHECK probe: exits 0 if GET /health responds ok, 1 otherwise.
// Kept tiny and dependency-free, like the rest of the Bun variant. Wrapped in
// an async function (rather than top-level await) so this file needs no
// `export {}` to be treated as a module.
async function main(): Promise<void> {
  const port = process.env.PORT ?? "8787";
  try {
    const r = await fetch(`http://127.0.0.1:${port}/health`);
    process.exit(r.ok ? 0 : 1);
  } catch {
    process.exit(1);
  }
}

void main();
