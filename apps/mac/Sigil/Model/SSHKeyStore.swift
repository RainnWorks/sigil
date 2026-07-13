//  SSHKeyStore.swift
//  The served-SSH-key store, as it sits on disk at `~/.sigil/ssh-keys.json`.
//  These Codable models mirror crates/sigil/src/sshagent.rs (`SshKeyEntry`,
//  `SshFileEntry`, `SshKeyConfig`) field for field, so the app reads the same
//  file the daemon serves from. Reads decode this file directly; every WRITE goes
//  through the `sigil ssh …` CLI, which owns all validation, so nothing here
//  authors or mutates the store.
//
//  The Mac only ever holds PUBLIC material: the OpenSSH public-key line, the
//  1Password coordinates that locate the private key, and the client-side host
//  routing metadata. Private keys are fetched per-signature by the daemon and
//  never touch this surface.

import Foundation
import CryptoKit

/// One 1Password-backed SSH identity on disk. The private key is fetched per
/// signature from `op://<vault>/<item>/<field>`; only the public line is stored.
/// Mirrors `sshagent::SshKeyEntry`.
struct SshKeyEntry: Codable, Equatable, Sendable {
    var publicKey: String
    var vault: String
    var item: String
    var field: String
    var comment: String
    var hosts: [String]

    enum CodingKeys: String, CodingKey {
        case publicKey = "public_key"
        case vault, item, field, comment, hosts
    }

    init(publicKey: String, vault: String, item: String,
         field: String = "private key", comment: String = "", hosts: [String] = []) {
        self.publicKey = publicKey
        self.vault = vault
        self.item = item
        self.field = field
        self.comment = comment
        self.hosts = hosts
    }

    init(from decoder: Decoder) throws {
        let c = try decoder.container(keyedBy: CodingKeys.self)
        publicKey = try c.decode(String.self, forKey: .publicKey)
        vault = try c.decode(String.self, forKey: .vault)
        item = try c.decode(String.self, forKey: .item)
        // serde defaults: field -> "private key", comment/hosts -> empty.
        field = try c.decodeIfPresent(String.self, forKey: .field) ?? "private key"
        comment = try c.decodeIfPresent(String.self, forKey: .comment) ?? ""
        hosts = try c.decodeIfPresent([String].self, forKey: .hosts) ?? []
    }
}

/// One local-file-backed SSH identity on disk. The public key comes from the
/// sibling `<path>.pub`; the private key is read only at sign time. Mirrors
/// `sshagent::SshFileEntry`.
struct SshFileEntry: Codable, Equatable, Sendable {
    var path: String
    var comment: String
    var hosts: [String]

    enum CodingKeys: String, CodingKey { case path, comment, hosts }

    init(path: String, comment: String = "", hosts: [String] = []) {
        self.path = path
        self.comment = comment
        self.hosts = hosts
    }

    init(from decoder: Decoder) throws {
        let c = try decoder.container(keyedBy: CodingKeys.self)
        path = try c.decode(String.self, forKey: .path)
        comment = try c.decodeIfPresent(String.self, forKey: .comment) ?? ""
        hosts = try c.decodeIfPresent([String].self, forKey: .hosts) ?? []
    }
}

/// The whole `~/.sigil/ssh-keys.json`: 1Password keys and local key files. The
/// on-disk shape mirrors `sshagent::SshKeyConfig`; an absent file decodes as an
/// empty store. Named `SshKeyStore` (not `SshKeyConfig`) so it never blurs with
/// the if-this-then-that `SigilConfig` the Rules screen edits.
struct SshKeyStore: Codable, Equatable, Sendable {
    var keys: [SshKeyEntry]
    var files: [SshFileEntry]

    init(keys: [SshKeyEntry] = [], files: [SshFileEntry] = []) {
        self.keys = keys
        self.files = files
    }

    init(from decoder: Decoder) throws {
        let c = try decoder.container(keyedBy: CodingKeys.self)
        keys = try c.decodeIfPresent([SshKeyEntry].self, forKey: .keys) ?? []
        files = try c.decodeIfPresent([SshFileEntry].self, forKey: .files) ?? []
    }

    enum CodingKeys: String, CodingKey { case keys, files }

    var isEmpty: Bool { keys.isEmpty && files.isEmpty }

    /// The two on-disk lists flattened into one display list: 1Password keys
    /// first, then file keys, each resolved to the fields the pane renders.
    var served: [SshServedKey] {
        keys.map(SshServedKey.init(onePassword:)) + files.map(SshServedKey.init(file:))
    }
}

/// One served key, resolved for display. Unifies a 1Password entry and a file
/// entry so the pane lists them together: a source, a bright label, the mono ref
/// (`op://…` or a path), the fingerprint when derivable, and the routed hosts.
struct SshServedKey: Identifiable, Equatable, Sendable {
    enum Source: Equatable, Sendable {
        case onePassword
        case file

        var label: String { self == .onePassword ? "1Password" : "Key file" }
    }

    let id: String
    let source: Source
    /// Brightest line: the 1Password item, or the key file's name.
    let label: String
    /// The mono reference: `op://<vault>/<item>/<field>` or the file path.
    let ref: String
    /// The `SHA256:…` fingerprint when it could be derived from the public-key
    /// line, else nil (a file key stores only its path here, so it shows the ref).
    let fingerprint: String?
    let comment: String
    /// Hosts routed through Sigil for this key. Empty means served, not routed.
    let hosts: [String]
    /// The token `sigil ssh remove <arg>` matches on: the 1Password item name for
    /// a 1Password key, or the file path for a file key. The CLI `ssh_remove`
    /// filters both `keys` (by item) and `files` (by path), so Remove works for
    /// either source (see CLIDaemonClient.removeSshKey).
    let removeItem: String

    var isRouted: Bool { !hosts.isEmpty }

    init(onePassword e: SshKeyEntry) {
        id = "op:\(e.vault)/\(e.item)/\(e.field)"
        source = .onePassword
        label = e.item
        ref = "op://\(e.vault)/\(e.item)/\(e.field)"
        fingerprint = SshServedKey.fingerprint(fromOpenSSHLine: e.publicKey)
        comment = e.comment
        hosts = e.hosts
        removeItem = e.item
    }

    init(file e: SshFileEntry) {
        id = "file:\(e.path)"
        source = .file
        label = (e.path as NSString).lastPathComponent
        ref = e.path
        // Only the path is stored for a file key, not its `.pub` line, so we do
        // not read a fingerprint here; the ref is the identifying content.
        fingerprint = nil
        comment = e.comment
        hosts = e.hosts
        removeItem = e.path
    }

    /// The OpenSSH `SHA256:<base64-no-pad>` fingerprint of a public-key line,
    /// matching what `ssh-keygen -lf` and the daemon's `ssh_key` render: SHA-256
    /// over the base64-decoded key blob (the second whitespace field). Returns nil
    /// if the line has no decodable blob, so the caller falls back to the ref.
    static func fingerprint(fromOpenSSHLine line: String) -> String? {
        let fields = line.split(whereSeparator: { $0 == " " || $0 == "\t" })
        guard fields.count >= 2, let blob = Data(base64Encoded: String(fields[1])) else {
            return nil
        }
        let digest = Data(SHA256.hash(data: blob))
        let b64 = digest.base64EncodedString().replacingOccurrences(of: "=", with: "")
        return "SHA256:\(b64)"
    }
}

/// The editor sheet's working copy. A key is either a 1Password reference or a
/// local file; both carry an optional comment and the hosts to route. The CLI
/// validates on save (ed25519, dedupe, safe host tokens), so this only gathers
/// input and gates the obviously-incomplete cases.
struct SSHKeyDraft {
    enum Source: Hashable { case onePassword, file }

    var source: Source = .onePassword

    // 1Password branch.
    var vault = ""
    var item = ""
    var field = "private key"
    var publicKey = ""

    // Key-file branch.
    var path = ""

    // Both branches.
    var comment = ""
    var hosts: [String] = []

    /// The live `op://<vault>/<item>/<field>` preview, with the default field
    /// filled in so the preview never shows an empty trailing segment.
    var opReference: String {
        let f = field.trimmed.isEmpty ? "private key" : field.trimmed
        return "op://\(vault.trimmed)/\(item.trimmed)/\(f)"
    }
}
