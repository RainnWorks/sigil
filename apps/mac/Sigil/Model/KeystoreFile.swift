//  KeystoreFile.swift
//  The daemon's keystore file as it sits on disk at `~/.sigil/keystore.json`, in
//  its two shapes. Mirrors the Rust side (crates/sigil/src/keystore.rs) the way
//  SSHKeyStore.swift mirrors sshagent.rs: the app reads and writes the same file
//  the daemon reads, so the format lives in one reviewable place.
//
//    v1 (plaintext) `{"blobs":{"<label>":"<base64>"}}` is the portable store. It holds
//        the daemon identity key and this Mac's threshold share. Neither opens a
//        secret alone, but a copy of the file impersonates this daemon from
//        anywhere.
//    v2 (wrapped)   `{"v":2,"pub_digest":"<hex>","se_pub":"<base64 SPKI DER>",
//                     "ciphertext":"<base64>"}` is the same v1 bytes encrypted to
//        a Secure Enclave key that exists only on this physical Mac.
//
//  The v1 bytes are OPAQUE here. This file never parses the blobs map, never
//  looks at a label, and never re-serializes: wrapping encrypts the file's exact
//  bytes, unwrapping writes those exact bytes back, and the digest is computed
//  over that same byte string (see `Blake2b.keystoreDigest`). Byte-for-byte
//  handling is what lets the daemon verify the digest it recomputes, and what
//  makes de-adoption a true restore rather than a re-render that could drift
//  from what the daemon wrote.
//
//  The keystore is READ-WRITE at runtime, so v2 is not a one-way migration: when
//  pairing changes the material, the daemon can no longer write its own file and
//  hands the new bytes back to be re-wrapped through exactly the same path.

import Foundation

enum KeystoreFile {
    /// The wrapped (v2) envelope. Field names are the wire contract; the daemon
    /// parses this same JSON.
    struct Wrapped: Codable, Equatable, Sendable {
        /// Always 2. A file without a `v` is v1 plaintext. There is deliberately
        /// no `se_wrapped` flag: `v == 2` already means wrapped, and a second
        /// boolean saying the same thing is one more field that could disagree.
        var v: Int
        /// Lowercase hex. See `Blake2b.keystoreDigest`: domain-tagged and length
        /// -prefixed over both `se_pub` and the material, never the bare material.
        var pubDigest: String
        /// Base64 of the wrapping public key as SubjectPublicKeyInfo DER. Carried
        /// so the daemon can bind the material to the key that wrapped it, and so
        /// a reader can tell which key a file needs without asking the Enclave.
        var sePub: String
        /// Base64 of the `SecKeyCreateEncryptedData` ECIES output.
        var ciphertext: String

        enum CodingKeys: String, CodingKey {
            case v
            case pubDigest = "pub_digest"
            case sePub = "se_pub"
            case ciphertext
        }

        init(pubDigest: String, sePub: Data, ciphertext: Data) {
            self.v = 2
            self.pubDigest = pubDigest
            self.sePub = sePub.base64EncodedString()
            self.ciphertext = ciphertext.base64EncodedString()
        }

        /// The ECIES bytes, or nil when the base64 is corrupt.
        var ciphertextData: Data? { Data(base64Encoded: ciphertext) }
        /// The SPKI DER bytes, or nil when the base64 is corrupt.
        var sePubData: Data? { Data(base64Encoded: sePub) }
    }

    /// What is actually at the path right now.
    enum Contents: Equatable, Sendable {
        /// No file. The daemon has not stored anything yet, so there is nothing
        /// to protect and nothing to repair.
        case absent
        /// v1: the exact file bytes, ready to wrap.
        case plaintext(Data)
        /// v2: already wrapped.
        case wrapped(Wrapped)
        /// Present but neither shape parses. Never guessed at and never
        /// overwritten: a file we cannot read is a file we must not clobber.
        case unreadable(String)
    }

    /// `$SIGIL_HOME/keystore.json`, else `~/.sigil/keystore.json`. Same
    /// resolution order the daemon uses, minus the process-local default, so both
    /// sides land on one file.
    static func defaultPath() -> String {
        let env = ProcessInfo.processInfo.environment
        let home: String
        if let sigilHome = env["SIGIL_HOME"], !sigilHome.isEmpty {
            home = sigilHome
        } else {
            home = (NSHomeDirectory() as NSString).appendingPathComponent(".sigil")
        }
        return (home as NSString).appendingPathComponent("keystore.json")
    }

    // There is no older filename to probe. `keystore.json` is the canonical path
    // and always was the one holding the live pairing; the `dev-keystore.json`
    // spelling the rename was supposed to migrate from never existed on a real
    // install. A probe for it would only be a second way to be wrong about which
    // file matters.

    static func read(at path: String) -> Contents {
        guard let data = FileManager.default.contents(atPath: path) else { return .absent }
        // A v2 file is the narrow case: it decodes as the envelope AND says v == 2.
        // Anything else that is still valid JSON is v1 material, kept verbatim.
        if let wrapped = try? JSONDecoder().decode(Wrapped.self, from: data), wrapped.v == 2 {
            return .wrapped(wrapped)
        }
        guard (try? JSONSerialization.jsonObject(with: data)) != nil else {
            return .unreadable("not JSON")
        }
        return .plaintext(data)
    }

    /// Replace the file with the wrapped envelope, durably. See `writeAtomically`
    /// for why the fsync is not optional here.
    static func writeWrapped(_ wrapped: Wrapped, to path: String) throws {
        let encoder = JSONEncoder()
        encoder.outputFormatting = [.sortedKeys]
        try writeAtomically(try encoder.encode(wrapped), to: path)
    }

    /// Restore the plaintext material, byte for byte, as de-adoption does.
    static func writePlaintext(_ material: Data, to path: String) throws {
        try writeAtomically(material, to: path)
    }

    /// Write to a sibling temp file created 0600, fsync it, then rename over the
    /// target and fsync the directory.
    ///
    /// Both fsyncs are load-bearing rather than caution. Every caller acks
    /// something the moment this returns: adoption tells the daemon the file is
    /// protected, a commit tells it the new material is safe, an unwrap tells the
    /// CLI the file is plaintext again. If the rename is still only in the page
    /// cache when power is lost, the daemon's view and the disk's disagree in the
    /// one direction that loses material. Renaming without syncing the directory
    /// entry has the same failure: the file contents survive under a name nothing
    /// points at.
    private static func writeAtomically(_ data: Data, to path: String) throws {
        let directory = (path as NSString).deletingLastPathComponent
        try FileManager.default.createDirectory(atPath: directory, withIntermediateDirectories: true,
                                                attributes: [.posixPermissions: 0o700])
        let temp = (directory as NSString)
            .appendingPathComponent(".keystore.\(UUID().uuidString).tmp")
        guard FileManager.default.createFile(atPath: temp, contents: data,
                                             attributes: [.posixPermissions: 0o600]) else {
            throw KeystoreFileError.write("could not write \(temp)")
        }
        do {
            try fsyncPath(temp, flags: O_WRONLY)
            guard rename(temp, path) == 0 else {
                throw KeystoreFileError.write(
                    "could not replace \(path): \(String(cString: strerror(errno)))")
            }
            // The rename itself is a directory mutation, so the durability of the
            // new name lives in the directory, not the file.
            try fsyncPath(directory, flags: O_RDONLY)
        } catch {
            try? FileManager.default.removeItem(atPath: temp)
            throw error
        }
    }

    private static func fsyncPath(_ path: String, flags: Int32) throws {
        let fd = open(path, flags)
        guard fd >= 0 else {
            throw KeystoreFileError.write("could not open \(path) to sync: \(String(cString: strerror(errno)))")
        }
        defer { close(fd) }
        // F_FULLFSYNC is the only call that reaches the platter on macOS; plain
        // fsync(2) returns once the drive has merely accepted the write. Fall
        // back to fsync where the filesystem does not implement it (some network
        // and virtual filesystems return ENOTSUP).
        if fcntl(fd, F_FULLFSYNC) == -1 && fsync(fd) != 0 {
            throw KeystoreFileError.write("could not sync \(path): \(String(cString: strerror(errno)))")
        }
    }
}

enum KeystoreFileError: LocalizedError, Equatable {
    case write(String)

    var errorDescription: String? {
        switch self {
        case .write(let detail): return detail
        }
    }
}
