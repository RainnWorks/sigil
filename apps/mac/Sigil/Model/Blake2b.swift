//  Blake2b.swift
//  BLAKE2b-256, unkeyed, per RFC 7693. The one hash primitive CryptoKit does not
//  ship and the one the daemon side uses: the wrapped-keystore file carries a
//  `pub_digest` the daemon recomputes with the Rust `blake2` crate (Blake2b256)
//  before it will accept provisioned material, so this must agree with that crate
//  byte for byte or every provision is refused. Substituting SHA-256 here would
//  be a silent contract break, not an implementation detail, which is why the
//  algorithm is vendored rather than swapped.
//
//  One-shot only, over material already held in memory (a keystore file is a few
//  hundred bytes). No streaming, no keyed mode, no personalization: the contract
//  needs exactly `blake2b(bytes, 32)` and unused modes are unaudited surface.
//
//  Verified against RFC 7693's appendix vector and against Python hashlib's
//  blake2b(digest_size: 32) for the empty input, "abc", and multi-block inputs
//  spanning the 128-byte block boundary. `Blake2b.selfTestPasses` re-checks two
//  of those vectors at runtime and is asserted by the keystore service before it
//  writes any digest a daemon will verify.

import Foundation

enum Blake2b {
    /// BLAKE2b with a 32-byte digest, no key. The contract digest.
    static func hash256(_ message: some Collection<UInt8>) -> [UInt8] {
        hash(Array(message), digestLength: 32)
    }

    /// Lowercase hex of `hash256`, the form the wrapped file and the wire carry.
    static func hex256(_ message: some Collection<UInt8>) -> String {
        hash256(message).map { String(format: "%02x", $0) }.joined()
    }

    /// The keystore v2 digest, defined once for both sides of the contract:
    ///
    ///     BLAKE2b-256( "sigil.keystore.v2"
    ///                  || u64-le len(se_pub) || se_pub
    ///                  || u64-le len(material) || material )
    ///
    /// The domain tag stops this hash colliding with any other use of BLAKE2b in
    /// the system, and the length prefixes stop a shorter public key plus a
    /// longer material (or the reverse) hashing to the same bytes. Binding
    /// `se_pub` into the digest is what ties the material to the key that wrapped
    /// it: swapping in an attacker's public key changes the digest the daemon
    /// expects, so a re-wrap under a different key cannot pass as the original.
    static func keystoreDigest(sePub: Data, material: Data) -> String {
        var input = Data("sigil.keystore.v2".utf8)
        input.append(littleEndian: UInt64(sePub.count))
        input.append(sePub)
        input.append(littleEndian: UInt64(material.count))
        input.append(material)
        return hex256(input)
    }

    // MARK: - RFC 7693

    private static let iv: [UInt64] = [
        0x6a09_e667_f3bc_c908, 0xbb67_ae85_84ca_a73b, 0x3c6e_f372_fe94_f82b, 0xa54f_f53a_5f1d_36f1,
        0x510e_527f_ade6_82d1, 0x9b05_688c_2b3e_6c1f, 0x1f83_d9ab_fb41_bd6b, 0x5be0_cd19_137e_2179,
    ]

    /// The message-word schedule. Twelve rounds: the ten distinct permutations
    /// followed by rounds 0 and 1 again, as the spec prescribes for BLAKE2b.
    private static let sigma: [[Int]] = [
        [0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15],
        [14, 10, 4, 8, 9, 15, 13, 6, 1, 12, 0, 2, 11, 7, 5, 3],
        [11, 8, 12, 0, 5, 2, 15, 13, 10, 14, 3, 6, 7, 1, 9, 4],
        [7, 9, 3, 1, 13, 12, 11, 14, 2, 6, 5, 10, 4, 0, 15, 8],
        [9, 0, 5, 7, 2, 4, 10, 15, 14, 1, 11, 12, 6, 8, 3, 13],
        [2, 12, 6, 10, 0, 11, 8, 3, 4, 13, 7, 5, 15, 14, 1, 9],
        [12, 5, 1, 15, 14, 13, 4, 10, 0, 7, 6, 3, 9, 2, 8, 11],
        [13, 11, 7, 14, 12, 1, 3, 9, 5, 0, 15, 4, 8, 6, 2, 10],
        [6, 15, 14, 9, 11, 3, 0, 8, 12, 2, 13, 7, 1, 4, 10, 5],
        [10, 2, 8, 4, 7, 6, 1, 5, 15, 11, 9, 14, 3, 12, 13, 0],
        [0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15],
        [14, 10, 4, 8, 9, 15, 13, 6, 1, 12, 0, 2, 11, 7, 5, 3],
    ]

    private static let blockLength = 128

    private static func hash(_ message: [UInt8], digestLength: Int) -> [UInt8] {
        // Parameter block, unkeyed: digest length in byte 0, key length 0 in byte
        // 1, fanout and depth 1 in bytes 2 and 3.
        var h = iv
        h[0] ^= 0x0101_0000 ^ UInt64(digestLength)

        // Every block but the last is compressed as non-final. `counter` is the
        // number of message bytes consumed INCLUDING the block being compressed,
        // which is why it advances before each call rather than after.
        var counter = UInt64(0)
        var offset = 0
        while message.count - offset > blockLength {
            counter &+= UInt64(blockLength)
            compress(&h, block(of: message, at: offset), counter, final: false)
            offset += blockLength
        }

        // The final block is zero-padded to 128 bytes and counts only the real
        // bytes in it. Empty input takes this path too: one all-zero final block
        // with the counter still at zero.
        let remaining = message.count - offset
        counter &+= UInt64(remaining)
        compress(&h, block(of: message, at: offset), counter, final: true)

        var digest = [UInt8]()
        digest.reserveCapacity(digestLength)
        for word in h {
            for shift in stride(from: 0, to: 64, by: 8) where digest.count < digestLength {
                digest.append(UInt8(truncatingIfNeeded: word >> UInt64(shift)))
            }
        }
        return digest
    }

    /// The 16 little-endian words at `offset`, zero-padded past the end.
    private static func block(of message: [UInt8], at offset: Int) -> [UInt64] {
        var words = [UInt64](repeating: 0, count: 16)
        for i in 0..<blockLength {
            let index = offset + i
            guard index < message.count else { break }
            words[i / 8] |= UInt64(message[index]) << UInt64((i % 8) * 8)
        }
        return words
    }

    private static func compress(_ h: inout [UInt64], _ m: [UInt64], _ counter: UInt64, final: Bool) {
        var v = [UInt64](repeating: 0, count: 16)
        for i in 0..<8 { v[i] = h[i] }
        for i in 0..<8 { v[8 + i] = iv[i] }
        v[12] ^= counter
        // v[13] takes the high half of the 128-bit counter, which a keystore file
        // can never reach; XORing zero keeps the spec shape visible.
        v[13] ^= 0
        if final { v[14] = ~v[14] }

        for round in 0..<12 {
            let s = sigma[round]
            mix(&v, 0, 4, 8, 12, m[s[0]], m[s[1]])
            mix(&v, 1, 5, 9, 13, m[s[2]], m[s[3]])
            mix(&v, 2, 6, 10, 14, m[s[4]], m[s[5]])
            mix(&v, 3, 7, 11, 15, m[s[6]], m[s[7]])
            mix(&v, 0, 5, 10, 15, m[s[8]], m[s[9]])
            mix(&v, 1, 6, 11, 12, m[s[10]], m[s[11]])
            mix(&v, 2, 7, 8, 13, m[s[12]], m[s[13]])
            mix(&v, 3, 4, 9, 14, m[s[14]], m[s[15]])
        }

        for i in 0..<8 { h[i] ^= v[i] ^ v[8 + i] }
    }

    private static func mix(_ v: inout [UInt64], _ a: Int, _ b: Int, _ c: Int, _ d: Int,
                            _ x: UInt64, _ y: UInt64) {
        v[a] = v[a] &+ v[b] &+ x
        v[d] = (v[d] ^ v[a]).rotatedRight(32)
        v[c] = v[c] &+ v[d]
        v[b] = (v[b] ^ v[c]).rotatedRight(24)
        v[a] = v[a] &+ v[b] &+ y
        v[d] = (v[d] ^ v[a]).rotatedRight(16)
        v[c] = v[c] &+ v[d]
        v[b] = (v[b] ^ v[c]).rotatedRight(63)
    }

    // MARK: - Self test

    /// Two known-answer vectors, checked at runtime before the app writes a digest
    /// the daemon will verify. A wrong digest is not a visible bug on this side:
    /// the wrap succeeds, the file looks fine, and every provision is refused with
    /// a mismatch that reads like daemon trouble. Checking here names the real
    /// cause instead.
    static var selfTestPasses: Bool {
        hex256([]) == "0e5751c026e543b2e8ab2eb06099daa1d1e5df47778f7787faab45cdf12fe3a8"
            && hex256(Array("abc".utf8))
                == "bddd813c634239723171ef3fee98579b94964e3bb1cb3e427262c8c068d52319"
    }
}

private extension UInt64 {
    func rotatedRight(_ n: UInt64) -> UInt64 { (self >> n) | (self << (64 - n)) }
}

private extension Data {
    /// Append a length as eight little-endian bytes, the contract's framing for
    /// every length prefix in the digest input.
    mutating func append(littleEndian value: UInt64) {
        for shift in stride(from: 0, to: 64, by: 8) {
            append(UInt8(truncatingIfNeeded: value >> UInt64(shift)))
        }
    }
}
