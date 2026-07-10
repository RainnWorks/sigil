/**
 * The pairing checksum (six words) and the routing mailbox id, mirroring
 * crates/sigil-proto/src/fingerprint.rs. Both are domain-separated Blake2b512 hashes
 * of the two pinned identities, absorbed in sorted order so the result does not
 * depend on which device is "a" and which is "b".
 */
import { concatBytes } from "./bytes";
import { type PeerIdentity } from "./identity";
import { type Sodium } from "./sodium";
import { WORDS } from "./words";

const FINGERPRINT_DOMAIN = new TextEncoder().encode("sigil.fingerprint.v1");
const MAILBOX_DOMAIN = new TextEncoder().encode("sigil.mailbox.v1");

/** The two 32-byte halves as one 64-byte string, fixed field order. */
function identityBytes(p: PeerIdentity): Uint8Array {
  return concatBytes(p.verifying, p.agreement);
}

/** Lexicographic byte compare, matching Rust's `[u8; 64]` ordering. */
function lexLessOrEqual(a: Uint8Array, b: Uint8Array): boolean {
  for (let i = 0; i < a.length; i++) {
    if (a[i]! < b[i]!) return true;
    if (a[i]! > b[i]!) return false;
  }
  return true;
}

function absorbCanonical(a: PeerIdentity, b: PeerIdentity): Uint8Array {
  const ab = identityBytes(a);
  const bb = identityBytes(b);
  return lexLessOrEqual(ab, bb) ? concatBytes(ab, bb) : concatBytes(bb, ab);
}

/** Six words confirming both devices pinned the same key pair. */
export function fingerprintWords(
  sodium: Sodium,
  a: PeerIdentity,
  b: PeerIdentity,
): [string, string, string, string, string, string] {
  const digest = sodium.crypto_generichash(
    64,
    concatBytes(FINGERPRINT_DOMAIN, absorbCanonical(a, b)),
  );
  return [
    WORDS[digest[0]!]!,
    WORDS[digest[1]!]!,
    WORDS[digest[2]!]!,
    WORDS[digest[3]!]!,
    WORDS[digest[4]!]!,
    WORDS[digest[5]!]!,
  ];
}

/** The routing mailbox for this pairing: 32 bytes, carries no identity. */
export function mailboxId(sodium: Sodium, a: PeerIdentity, b: PeerIdentity): Uint8Array {
  const digest = sodium.crypto_generichash(
    64,
    concatBytes(MAILBOX_DOMAIN, absorbCanonical(a, b)),
  );
  return digest.slice(0, 32);
}
