// Wrangler's bundler is configured (see wrangler.jsonc's "rules") to treat
// .html imports as raw text modules, so ../landing.html's default export is
// its file contents as a string. This ambient declaration is only what makes
// that import typecheck; the actual behavior comes from the bundler rule.
declare module "*.html" {
  const content: string;
  export default content;
}
