// Print the Sparkle public key that matches a Sparkle private key file.
//
// Sparkle's own `generate_keys -p` reads the login keychain, which a CI runner
// does not have, so this derives the key from the exported file instead. That
// file is the base64 of the 32-byte Ed25519 seed (see `generate_keys -x`), and
// an Ed25519 public key is a pure function of its seed.
//
// Usage: node sparkle-public-key.mjs <private-key-file>
//
// It prints the public key and nothing else. The private key never leaves this
// process.
import { readFileSync } from "node:fs";
import { createPrivateKey, createPublicKey } from "node:crypto";

const file = process.argv[2];
if (!file) {
  console.error("usage: sparkle-public-key.mjs <private-key-file>");
  process.exit(2);
}

const seed = Buffer.from(readFileSync(file, "utf8").trim(), "base64");
if (seed.length !== 32) {
  console.error(`expected a 32-byte seed, got ${seed.length} bytes`);
  process.exit(1);
}

// PKCS#8 wrapper for a raw Ed25519 seed, then SPKI, whose last 32 bytes are the key.
const pkcs8 = Buffer.concat([Buffer.from("302e020100300506032b657004220420", "hex"), seed]);
const spki = createPublicKey(createPrivateKey({ key: pkcs8, format: "der", type: "pkcs8" }))
  .export({ format: "der", type: "spki" });
console.log(spki.subarray(spki.length - 32).toString("base64"));
