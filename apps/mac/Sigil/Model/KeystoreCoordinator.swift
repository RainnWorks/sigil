//  KeystoreCoordinator.swift
//  The Mac half of keystore wrapping, as one small state machine.
//
//  The daemon is portable and unsigned, so it cannot hold a Secure Enclave key.
//  The signed app can. That asymmetry is the whole feature: the app wraps the
//  daemon's keystore file to an Enclave key that exists only on this physical
//  Mac, and hands the plaintext material back to the running daemon over the
//  control socket. The file at rest becomes ciphertext that a copy taken off this
//  machine cannot open; the daemon in memory is exactly as capable as before.
//
//  Three flows:
//
//    ADOPT     a v1 plaintext file is encrypted and replaced with v2, written and
//              synced BEFORE the plaintext copy is released, then provisioned to
//              the daemon from the copy still in memory.
//    PROVISION on every connection to the daemon: read v2, decrypt in the
//              Enclave, push the material, scrub the buffer. Silent, no prompt.
//              The daemon accepts this once per lifetime, so the trigger is the
//              subscription connecting, not a timer: a daemon that restarted is
//              precisely a connection that dropped and was remade.
//    DE-ADOPT  `sigil keystore unwrap` asks, through the daemon, for the file to
//              go back to plaintext. This is the ONE path that takes a Touch ID,
//              because it is the one path that lowers protection. The plaintext
//              is written and synced BEFORE the wrapping key is destroyed: a
//              crash in the other order would leave ciphertext no one can open.
//
//  The key's absence is also the record that an unwrap was sanctioned. If the
//  wrapping key is still here but the file on disk has gone back to plaintext,
//  nothing sanctioned did that, and the app says so loudly rather than quietly
//  re-wrapping over the evidence.
//
//  That question has THREE answers, not two. The keychain can say yes, say no, or
//  refuse to answer (locked, unavailable, an entitlement the running build does
//  not carry). Only a clear no licenses an adopt, because adopting is what
//  overwrites the evidence the check exists to find. "Could not determine"
//  therefore raises the alarm alongside a confirmed downgrade rather than being
//  rounded down to absence.
//
//  Fails closed and stays honest: no state here ever writes plaintext as a
//  fallback, no unknown is read as a benign known, and a Mac that cannot wrap
//  says so rather than quietly leaving the file bare while the UI implies
//  otherwise.

import Foundation
import Observation

/// What is protecting the keystore right now, as the UI must tell it.
enum KeystoreProtection: Equatable, Sendable {
    /// Not looked at yet.
    case checking
    /// No keystore file. The daemon has stored nothing, so there is nothing to
    /// protect. Not a problem, and not a state to nag about.
    case absent(path: String)
    /// Wrapped on disk and the daemon holds the material for this run.
    case sealed(path: String)
    /// Wrapped on disk, but the daemon does not have the material: it is
    /// fail-closed until this app provisions it. The one state that is genuinely
    /// wrong while the app is running.
    case sealedUnprovisioned(path: String, reason: String)
    /// Plaintext on disk, with the reason: no Enclave on this Mac, a daemon that
    /// was not up to receive the material, or a de-adoption the user just asked
    /// for. Honest, not alarming: this is exactly the protection the file had
    /// before the feature existed.
    case plaintext(path: String, reason: String)
    /// Plaintext on disk while the wrapping key still exists. No sanctioned path
    /// produces this, so it is reported as what it is and never papered over.
    case downgraded(path: String)
    /// Plaintext on disk, and the keychain would not say whether the wrapping key
    /// is still there. From here that is indistinguishable from `downgraded`, and
    /// it is treated as one: the only other move is to adopt, which would erase
    /// the evidence before anyone read it.
    case downgradeUnverified(path: String, reason: String)
    /// Something failed: the wrap, the decrypt, or the write.
    case failed(path: String, reason: String)

    var path: String {
        switch self {
        case .checking: return ""
        case .absent(let p), .sealed(let p), .downgraded(let p): return p
        case .sealedUnprovisioned(let p, _), .plaintext(let p, _), .failed(let p, _),
             .downgradeUnverified(let p, _): return p
        }
    }

    /// Whether the daemon is currently unable to work because of this layer.
    var blocksDaemon: Bool {
        switch self {
        case .sealedUnprovisioned, .failed: return true
        // The two downgrade states do not block anything: the file is plaintext,
        // which is precisely what makes them a security fact rather than an
        // outage. They are loud for a different reason.
        case .checking, .absent, .sealed, .plaintext, .downgraded, .downgradeUnverified: return false
        }
    }

    /// Whether this is a state the human must look at now, rather than a fact
    /// about the machine they can read whenever. Exhaustive on purpose: a new
    /// state has to answer this question rather than inherit a quiet default.
    var isAlarm: Bool {
        switch self {
        case .downgraded, .downgradeUnverified: return true
        case .checking, .absent, .sealed, .sealedUnprovisioned, .plaintext, .failed: return false
        }
    }
}

@MainActor
@Observable
final class KeystoreCoordinator {
    private(set) var state: KeystoreProtection = .checking
    /// Set once, on the launch that first wrapped the file. The adoption is
    /// surfaced as a single line in the Status pane, not a ceremony: the user did
    /// not ask for a migration and nothing about their workflow changed.
    private(set) var adoptionNotice: String?

    private let wrapper: KeystoreWrapper
    /// Guards against two syncs overlapping (launch and a reconnect landing
    /// together).
    private var syncing = false
    /// A fixtures coordinator holds its state still and touches nothing.
    private let inert: Bool

    init(path: String = KeystoreFile.defaultPath(),
         wrapKey: any KeystoreWrapKey = SecureEnclaveWrapKey()) {
        self.wrapper = KeystoreWrapper(path: path, wrapKey: wrapKey)
        self.inert = false
    }

    /// Previews and fixtures: a fixed state. Reads no file, mints no key, and
    /// stays on whatever state it was built with, so a preview of the sealed pane
    /// cannot flip to "absent" just because the developer's Mac has no keystore.
    init(previewState: KeystoreProtection, adoptionNotice: String? = nil) {
        self.state = previewState
        self.adoptionNotice = adoptionNotice
        self.wrapper = KeystoreWrapper(path: previewState.path,
                                       wrapKey: UnavailableWrapKey(reason: "fixtures"))
        self.inert = true
    }

    /// Bring the file and the daemon into agreement. Safe to call repeatedly: at
    /// launch, on every reconnection, and behind the Retry control.
    func sync(daemon: DaemonClient) async {
        guard !inert, !syncing else { return }
        syncing = true
        defer { syncing = false }

        switch await wrapper.read() {
        case .absent:
            state = .absent(path: wrapper.path)

        case .unreadable(let why):
            state = .failed(path: wrapper.path, reason: "The keystore file could not be read (\(why)). It has been left untouched.")

        case .plaintext(let material):
            // Plaintext plus a surviving wrapping key is the downgrade signal.
            // Re-wrapping here would destroy the only evidence that the file was
            // replaced, so this stops and says so.
            //
            // A keychain that throws is NOT a keychain that said no. Swallowing
            // the throw would send a real downgrade down the adopt path, where a
            // daemon that happens to be down renders it as the calm "left as it
            // is" line and the alarm never fires. Only an answered no continues.
            do {
                if try await wrapper.keyExists() {
                    state = .downgraded(path: wrapper.path)
                    return
                }
            } catch {
                state = .downgradeUnverified(path: wrapper.path, reason: Self.reason(error))
                return
            }
            await adopt(material: material, daemon: daemon)

        case .wrapped(let envelope):
            await provision(from: envelope, daemon: daemon)
        }
    }

    /// Wrap a downgraded file back up, from the Status pane's explicit control.
    /// Separate from `sync` on purpose: recovering from a downgrade is a decision
    /// the human makes after seeing the alarm, never something that happens on a
    /// reconnect while they are not looking.
    ///
    /// Both alarm states qualify, which is what keeps the control that the alarm
    /// puts on screen from being a button that does nothing. If the keychain is
    /// still refusing to answer, the wrap throws on the same lookup and this
    /// lands on `.failed` with the reason, which is the honest outcome; it cannot
    /// mint a second key over a first one it could not read.
    func rewrapAfterDowngrade(daemon: DaemonClient) async {
        guard !inert, state.isAlarm else { return }
        guard case .plaintext(let material) = await wrapper.read() else {
            await sync(daemon: daemon)
            return
        }
        await adopt(material: material, daemon: daemon)
    }

    /// ADOPT: wrap a v1 file, then provision from the copy still in memory. The
    /// ordering is load-bearing: the v2 file is written and synced before the
    /// plaintext is released, so a crash between the two leaves protected-but
    /// -unprovisioned (recoverable on the next connection) rather than a daemon
    /// holding material whose file was never protected.
    private func adopt(material: Data, daemon: DaemonClient) async {
        // Never adopt against a daemon we cannot immediately hand the material
        // to. Wrapping is otherwise a way to turn a working install into a
        // fail-closed one and walk away: the file would be ciphertext, the daemon
        // would hold nothing, and the next gated command would fail with no
        // obvious cause. Waiting for the next sync costs nothing.
        guard await daemon.daemonRunning() else {
            state = .plaintext(
                path: wrapper.path,
                reason: "The daemon is not running, so the keystore has been left as it is. It is wrapped once the daemon is up to receive it.")
            return
        }

        var plaintext = material
        defer { KeystoreWrapper.scrub(&plaintext) }

        do {
            try await wrapper.wrap(plaintext)
        } catch {
            // Only a Mac that cannot do Enclave crypto is "plaintext, and that is
            // that". A write or digest failure is a real fault and reads as one.
            state = (error as? WrapKeyError).map(Self.isUnsupported) == true
                ? .plaintext(path: wrapper.path, reason: Self.reason(error))
                : .failed(path: wrapper.path, reason: Self.reason(error))
            return
        }
        adoptionNotice = "Wrapped to this Mac's Secure Enclave. A copy of the file taken off this Mac, in a backup or a disk image, can no longer be opened."
        await push(plaintext, daemon: daemon)
    }

    /// PROVISION: open the v2 file and hand the material to the daemon. Silent,
    /// because the wrapping key asks for no presence.
    private func provision(from envelope: KeystoreFile.Wrapped, daemon: DaemonClient) async {
        var plaintext: Data
        do {
            plaintext = try await wrapper.open(envelope)
        } catch {
            state = .failed(path: wrapper.path, reason: Self.openFailureReason(error))
            return
        }
        defer { KeystoreWrapper.scrub(&plaintext) }
        await push(plaintext, daemon: daemon)
    }

    private func push(_ material: Data, daemon: DaemonClient) async {
        do {
            switch try await daemon.provisionKeystore(material: material) {
            case .ok:
                state = .sealed(path: wrapper.path)
            case .failed(let lines):
                // Surfaced and left alone. The daemon takes a provision once per
                // lifetime and refuses on a digest mismatch or an unrecognized
                // caller, none of which a retry loop would fix; retrying would
                // only bury the reason under noise.
                state = .sealedUnprovisioned(
                    path: wrapper.path,
                    reason: lines.isEmpty ? "The daemon refused the keystore material." : lines.joined(separator: "; "))
            }
        } catch {
            state = .sealedUnprovisioned(path: wrapper.path, reason: Self.reason(error))
        }
    }

    /// The app-directed channel, live for the whole session: connection events
    /// (which drive provisioning) and de-adoption requests.
    func watchKeystoreEvents(daemon: DaemonClient) async {
        guard !inert else { return }
        for await event in daemon.subscribeKeystoreEvents() {
            switch event {
            case .connected:
                await sync(daemon: daemon)
            case .unwrap(let nonce):
                await handleUnwrap(nonce: nonce, daemon: daemon)
            }
        }
    }

    /// DE-ADOPT: Touch ID, write the plaintext, sync it, and only then destroy the
    /// wrapping key. Any other order can lose the material to a crash.
    private func handleUnwrap(nonce: String, daemon: DaemonClient) async {
        // The only presence check in this feature. Wrapping and unwrapping are
        // silent; turning the protection OFF is not.
        if let refusal = await LocalPresence.confirm(
            reason: "unwrap the Sigil keystore back to plaintext on this Mac") {
            _ = try? await daemon.reportKeystoreUnwrap(nonce: nonce, ok: false, reason: refusal)
            return
        }

        do {
            guard case .wrapped(let envelope) = await wrapper.read() else {
                _ = try? await daemon.reportKeystoreUnwrap(
                    nonce: nonce, ok: false, reason: "the keystore is not wrapped")
                return
            }
            var plaintext = try await wrapper.open(envelope)
            defer { KeystoreWrapper.scrub(&plaintext) }
            try await wrapper.restorePlaintext(plaintext)
            // Only now, with the plaintext durably on disk, is the key safe to
            // destroy. Its absence is what marks this unwrap as sanctioned, so a
            // later launch does not read the plaintext file as a downgrade.
            try await wrapper.deleteKey()
            state = .plaintext(
                path: wrapper.path,
                reason: "Unwrapped on request. The keystore is a 0600 file again and the wrapping key is gone.")
            adoptionNotice = nil
            _ = try? await daemon.reportKeystoreUnwrap(nonce: nonce, ok: true, reason: "")
        } catch {
            let reason = Self.reason(error)
            state = .failed(path: wrapper.path, reason: reason)
            _ = try? await daemon.reportKeystoreUnwrap(nonce: nonce, ok: false, reason: reason)
        }
    }

    private static func isUnsupported(_ error: WrapKeyError) -> Bool {
        if case .unsupported = error { return true }
        return false
    }

    private static func reason(_ error: Error) -> String {
        (error as? LocalizedError)?.errorDescription ?? error.localizedDescription
    }

    /// A missing wrapping key is not a transient failure and must not read like
    /// one: the material is gone with it, and the only way forward is a re-pair.
    private static func openFailureReason(_ error: Error) -> String {
        if let wrapError = error as? WrapKeyError, wrapError == .keyMissing {
            return "Sealed to a Secure Enclave key this Mac no longer has. The material cannot be recovered; pair again to rebuild it."
        }
        return reason(error)
    }
}

/// The blocking half: file I/O, the Enclave, and the digest. A plain Sendable
/// struct rather than an actor, so its `async` methods run off the main actor and
/// the coordinator above stays a pure state machine.
private struct KeystoreWrapper: Sendable {
    let path: String
    let wrapKey: any KeystoreWrapKey

    func read() async -> KeystoreFile.Contents { KeystoreFile.read(at: path) }

    func keyExists() async throws -> Bool { try wrapKey.keyExists() }

    func deleteKey() async throws { try wrapKey.deleteKey() }

    /// Encrypt `material` and replace the file with the v2 envelope, durably. The
    /// write is synced before this returns, so every caller may treat a return as
    /// "it is on disk" when it acks to the daemon.
    ///
    /// Takes arbitrary material rather than reading the file itself, which is what
    /// makes it the ready-made write-back path: if the daemon ever mutates the
    /// keystore, a commit is this call plus a fetch verb. Today nothing needs
    /// that. The production daemon never writes the keystore (every mutation is
    /// CLI-side, and those are refused up front while the store is wrapped), so
    /// the commit flow is deferred and only adoption calls this.
    func wrap(_ material: Data) async throws {
        // A wrong digest would not fail here; it would fail at every future
        // provision, looking like daemon trouble. Check the primitive before
        // committing a digest to disk.
        guard Blake2b.selfTestPasses else {
            throw KeystoreFileError.write("the BLAKE2b implementation failed its own vectors")
        }
        try wrapKey.ensureKeyExists()
        // The public key comes back from the same call that encrypted, so the
        // digest can never bind material to a key other than the one used.
        let (ciphertext, sePub) = try wrapKey.encrypt(material)
        let digest = Blake2b.keystoreDigest(sePub: sePub, material: material)
        try KeystoreFile.writeWrapped(
            KeystoreFile.Wrapped(pubDigest: digest, sePub: sePub, ciphertext: ciphertext), to: path)
    }

    /// Decrypt a v2 envelope and confirm it is the material the digest names.
    func open(_ envelope: KeystoreFile.Wrapped) async throws -> Data {
        guard let ciphertext = envelope.ciphertextData else {
            throw KeystoreFileError.write("the wrapped keystore's ciphertext is not valid base64")
        }
        guard let sePub = envelope.sePubData else {
            throw KeystoreFileError.write("the wrapped keystore's public key is not valid base64")
        }
        let material = try wrapKey.decrypt(ciphertext)
        // ECIES already authenticates the ciphertext, so this catches the other
        // thing: an envelope whose digest or public key field was edited. Refusing
        // here means the daemon never sees material the app itself does not
        // believe, and the daemon checks the same digest independently.
        guard Blake2b.keystoreDigest(sePub: sePub, material: material) == envelope.pubDigest else {
            throw KeystoreFileError.write("the wrapped keystore's digest does not match its contents")
        }
        return material
    }

    func restorePlaintext(_ material: Data) async throws {
        try KeystoreFile.writePlaintext(material, to: path)
    }

    /// Overwrite a material buffer once we are done with it.
    ///
    /// Best effort, and named that way on purpose: Swift's `Data` is
    /// copy-on-write with no zeroizing guarantee, so this overwrites the buffer
    /// this app holds and cannot promise the runtime kept no other copy. The wire
    /// path was moved to raw bytes precisely so there is no base64 `String` copy
    /// to worry about as well. Nothing here should be read as clean zeroization;
    /// the guarantee that matters is the one on disk.
    static func scrub(_ data: inout Data) {
        guard !data.isEmpty else { return }
        data.resetBytes(in: 0..<data.count)
    }
}
