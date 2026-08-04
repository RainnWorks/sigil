//  KeystoreWrapKey.swift
//  The Secure Enclave seam, and the only place in the app that touches the
//  Keychain or the Enclave. Everything above it (KeystoreCoordinator, the views)
//  sees a small protocol, which is what keeps SE access reviewable in one file
//  and mockable everywhere else.
//
//  The key: a P-256 private key generated inside the Secure Enclave, non
//  exportable by construction, tagged `works.rainn.sigil.keystore-wrap`, minted
//  once and reused. Its access control carries `.privateKeyUsage` and NOTHING
//  else: no `.biometryCurrentSet`, no `.userPresence`. That is deliberate and is
//  the whole ergonomic bargain of this layer. Unwrapping is SILENT, so the app
//  provisions the daemon at launch with no prompt and the human never trades a
//  Touch ID tap for something that is not an approval. Approvals are unaffected:
//  they still require the phone, always, and this key can no more approve a
//  request than the file it protects can.
//
//  What that buys, precisely: it removes AT-REST exfiltration. The keystore file
//  becomes ciphertext only this physical Mac can open, so the copies that leave a
//  machine without anyone attacking it (Time Machine and other backups, a
//  cloud-synced home directory, a disk image, a drive sold or repaired) are inert
//  elsewhere. What it does not buy: any runtime protection. The daemon's material
//  stays readable by anything running as this user, by design, and such code can
//  ask the Enclave to decrypt exactly as the app does. Device binding, not access
//  control, and the UI copy says so in those words.
//
//  DEVICE-GATED. None of this can be exercised in a headless build: the Enclave
//  refuses a process whose code signature carries no keychain-access-group
//  entitlement, and an unsigned binary asking for a data-protection keychain item
//  is killed by amfid rather than merely refused. Compilation proves the API
//  usage type-checks; only a signed, installed .app proves the runtime path.

import CryptoKit
import Foundation
import LocalAuthentication
import Security

/// Wrap and unwrap the keystore material. A protocol so the coordinator and its
/// previews never reach for `Sec*` directly.
protocol KeystoreWrapKey: Sendable {
    /// Encrypt to the wrapping key, minting it on first use. Returns the
    /// ciphertext and the SubjectPublicKeyInfo DER of the key it used, because
    /// the digest binds both and the caller must never pair one with the other's
    /// bytes by accident.
    func encrypt(_ plaintext: Data) throws -> (ciphertext: Data, sePub: Data)
    /// Decrypt with the wrapping key. Never mints: a missing key means this
    /// ciphertext can no longer be opened on this Mac, which is a different and
    /// much louder fact than a decrypt failure.
    func decrypt(_ ciphertext: Data) throws -> Data
    /// Mint the key if it does not exist yet, so adoption can fail before it
    /// starts rewriting a file rather than halfway through.
    func ensureKeyExists() throws
    /// Whether the wrapping key is on this Mac. A true here against a plaintext
    /// file on disk is the downgrade signal: something removed the protection
    /// without going through the sanctioned unwrap, which deletes the key.
    func keyExists() throws -> Bool
    /// Destroy the wrapping key. Only ever called by a sanctioned unwrap, and
    /// only after the plaintext is on disk and synced.
    func deleteKey() throws
}

enum WrapKeyError: LocalizedError, Equatable {
    /// No Secure Enclave, or the platform refused to make an Enclave key.
    case unsupported(String)
    /// The tagged key is not in the keychain, so existing ciphertext is unopenable.
    case keyMissing
    case keychain(String, OSStatus)
    case crypto(String)

    var errorDescription: String? {
        switch self {
        case .unsupported(let detail):
            return "no Secure Enclave available: \(detail)"
        case .keyMissing:
            return "the Secure Enclave wrapping key is gone from this Mac"
        case .keychain(let op, let status):
            let message = SecCopyErrorMessageString(status, nil) as String? ?? "OSStatus \(status)"
            return "keychain \(op) failed: \(message)"
        case .crypto(let detail):
            return detail
        }
    }
}

struct SecureEnclaveWrapKey: KeystoreWrapKey {
    /// The application tag both halves of the contract name. Stable forever: a
    /// changed tag orphans every wrapped file on the machine.
    static let applicationTag = "works.rainn.sigil.keystore-wrap"

    /// ECIES cofactor key agreement, X9.63 KDF with SHA-256, AES-GCM. Pinned to
    /// one constant and never chosen at runtime.
    ///
    /// The contract names "ECIES cofactor X963 SHA256 AES-GCM"; this is the
    /// variable-IV member of that family, and the choice is forced rather than
    /// preferred. The Secure Enclave supports only the variable-IV ECIES
    /// variants; the fixed-IV constant of the same name is a legacy software-key
    /// algorithm the Enclave refuses. Both are AES-GCM, so the contract's actual
    /// requirement (authenticated encryption, never a non-GCM variant) holds:
    /// tampered ciphertext fails to open instead of yielding garbage material.
    /// `encrypt` verifies support before use rather than trusting this comment.
    private static let algorithm: SecKeyAlgorithm = .eciesEncryptionCofactorVariableIVX963SHA256AESGCM

    var tag: String = SecureEnclaveWrapKey.applicationTag

    func ensureKeyExists() throws {
        _ = try loadOrCreatePrivateKey()
    }

    func encrypt(_ plaintext: Data) throws -> (ciphertext: Data, sePub: Data) {
        let privateKey = try loadOrCreatePrivateKey()
        guard let publicKey = SecKeyCopyPublicKey(privateKey) else {
            throw WrapKeyError.crypto("could not derive the wrapping public key")
        }
        // Refuse rather than silently fall back to whatever the platform does
        // support. A wrapped file is only as good as the algorithm that made it,
        // so an Enclave that will not do this exact one is an honest failure.
        guard SecKeyIsAlgorithmSupported(privateKey, .decrypt, Self.algorithm) else {
            throw WrapKeyError.unsupported(
                "this Mac's Secure Enclave does not support ECIES cofactor X9.63 SHA-256 AES-GCM")
        }
        var error: Unmanaged<CFError>?
        guard let ciphertext = SecKeyCreateEncryptedData(
            publicKey, Self.algorithm, plaintext as CFData, &error) as Data? else {
            throw WrapKeyError.crypto(Self.describe(error, fallback: "encrypt failed"))
        }
        return (ciphertext, try Self.spki(of: publicKey))
    }

    func decrypt(_ ciphertext: Data) throws -> Data {
        guard let privateKey = try loadPrivateKey() else { throw WrapKeyError.keyMissing }
        var error: Unmanaged<CFError>?
        guard let plaintext = SecKeyCreateDecryptedData(
            privateKey, Self.algorithm, ciphertext as CFData, &error) as Data? else {
            throw WrapKeyError.crypto(Self.describe(error, fallback: "decrypt failed"))
        }
        return plaintext
    }

    func keyExists() throws -> Bool {
        try loadPrivateKey() != nil
    }

    func deleteKey() throws {
        let status = SecItemDelete(baseQuery as CFDictionary)
        guard status == errSecSuccess || status == errSecItemNotFound else {
            throw WrapKeyError.keychain("delete", status)
        }
    }

    /// The public key as SubjectPublicKeyInfo DER, which is what the v2 file and
    /// the digest carry. `SecKeyCopyExternalRepresentation` gives the bare X9.63
    /// point (04 || X || Y), so CryptoKit does the ASN.1 rather than this file
    /// hand-rolling a structure it would then have to be trusted on.
    private static func spki(of publicKey: SecKey) throws -> Data {
        var error: Unmanaged<CFError>?
        guard let x963 = SecKeyCopyExternalRepresentation(publicKey, &error) as Data? else {
            throw WrapKeyError.crypto(describe(error, fallback: "could not export the wrapping public key"))
        }
        do {
            return try P256.Signing.PublicKey(x963Representation: x963).derRepresentation
        } catch {
            throw WrapKeyError.crypto("the wrapping public key is not a P-256 point: \(error.localizedDescription)")
        }
    }

    // MARK: - Keychain

    /// The query that identifies our one key. No `kSecAttrAccessGroup`: with the
    /// data-protection keychain an item defaults to the first group in the app's
    /// `keychain-access-groups` entitlement, which is exactly the app's own group
    /// (see Sigil.entitlements). Naming it here would mean hardcoding the team
    /// prefix that the build resolves.
    private var baseQuery: [String: Any] {
        [
            kSecClass as String: kSecClassKey,
            kSecAttrKeyType as String: kSecAttrKeyTypeECSECPrimeRandom,
            kSecAttrApplicationTag as String: Data(tag.utf8),
            kSecAttrTokenID as String: kSecAttrTokenIDSecureEnclave,
            kSecUseDataProtectionKeychain as String: true,
        ]
    }

    private func loadPrivateKey() throws -> SecKey? {
        var query = baseQuery
        query[kSecReturnRef as String] = true
        var item: CFTypeRef?
        let status = SecItemCopyMatching(query as CFDictionary, &item)
        switch status {
        case errSecSuccess:
            // A conditional cast to a CoreFoundation type always succeeds, so the
            // type is checked the CF way before the reference is trusted.
            guard let item, CFGetTypeID(item) == SecKeyGetTypeID() else {
                throw WrapKeyError.keychain("lookup", status)
            }
            return unsafeDowncast(item as AnyObject, to: SecKey.self)
        case errSecItemNotFound:
            return nil
        default:
            throw WrapKeyError.keychain("lookup", status)
        }
    }

    private func loadOrCreatePrivateKey() throws -> SecKey {
        if let existing = try loadPrivateKey() { return existing }

        var accessError: Unmanaged<CFError>?
        // `.privateKeyUsage` alone: the key may be used, and using it prompts for
        // nothing. `WhenUnlockedThisDeviceOnly` keeps it off backups and out of
        // any sync, which is what makes the wrapped file device-bound.
        guard let access = SecAccessControlCreateWithFlags(
            kCFAllocatorDefault,
            kSecAttrAccessibleWhenUnlockedThisDeviceOnly,
            [.privateKeyUsage],
            &accessError) else {
            throw WrapKeyError.crypto(Self.describe(accessError, fallback: "access control failed"))
        }

        let attributes: [String: Any] = [
            kSecAttrKeyType as String: kSecAttrKeyTypeECSECPrimeRandom,
            kSecAttrKeySizeInBits as String: 256,
            kSecAttrTokenID as String: kSecAttrTokenIDSecureEnclave,
            kSecUseDataProtectionKeychain as String: true,
            kSecPrivateKeyAttrs as String: [
                kSecAttrIsPermanent as String: true,
                kSecAttrApplicationTag as String: Data(tag.utf8),
                kSecAttrAccessControl as String: access,
            ] as [String: Any],
        ]

        var error: Unmanaged<CFError>?
        guard let key = SecKeyCreateRandomKey(attributes as CFDictionary, &error) else {
            throw WrapKeyError.crypto(Self.describe(error, fallback: "could not mint the wrapping key"))
        }
        return key
    }

    // There is deliberately no "does this Mac have an Enclave" predicate. Every
    // probe worth writing is either a lie (a software key reports ECIES support
    // whether or not an Enclave exists) or the real thing (minting an Enclave
    // key), so the mint IS the probe: a machine without one fails at
    // `loadOrCreatePrivateKey` and the coordinator renders that as an honest
    // unsupported state rather than a broken one.

    private static func describe(_ error: Unmanaged<CFError>?, fallback: String) -> String {
        guard let error else { return fallback }
        return (error.takeRetainedValue() as Error).localizedDescription
    }
}

/// A fill for machines and previews with no Enclave. Never pretends to encrypt:
/// there is no fake-crypto path in this app, so a state that cannot wrap says so
/// instead of producing bytes that look protected.
struct UnavailableWrapKey: KeystoreWrapKey {
    var reason: String
    func ensureKeyExists() throws { throw WrapKeyError.unsupported(reason) }
    func encrypt(_ plaintext: Data) throws -> (ciphertext: Data, sePub: Data) {
        throw WrapKeyError.unsupported(reason)
    }
    func decrypt(_ ciphertext: Data) throws -> Data { throw WrapKeyError.unsupported(reason) }
    /// False, never a throw: "is there a key" must answer on a Mac that cannot
    /// have one, or the downgrade check would read a missing Enclave as an alarm.
    func keyExists() throws -> Bool { false }
    func deleteKey() throws {}
}

// MARK: - Presence

/// The one place in this feature that asks for a human. De-adoption downgrades
/// the file back to plaintext, so it takes a live Touch ID even though wrapping
/// and unwrapping never do.
enum LocalPresence {
    /// Ask for Touch ID (falling back to the login password only where no
    /// biometry is enrolled, so this is never a dead end on a Mac without a
    /// sensor). Returns nil on success, or a calm reason on refusal or failure.
    static func confirm(reason: String) async -> String? {
        let context = LAContext()
        var policyError: NSError?
        let policy: LAPolicy = context.canEvaluatePolicy(
            .deviceOwnerAuthenticationWithBiometrics, error: &policyError)
            ? .deviceOwnerAuthenticationWithBiometrics
            : .deviceOwnerAuthentication
        do {
            let ok = try await context.evaluatePolicy(policy, localizedReason: reason)
            return ok ? nil : "not confirmed"
        } catch {
            return (error as? LAError).map(describe) ?? error.localizedDescription
        }
    }

    private static func describe(_ error: LAError) -> String {
        switch error.code {
        case .userCancel, .appCancel, .systemCancel: return "cancelled"
        case .userFallback: return "cancelled"
        case .biometryNotEnrolled: return "no Touch ID enrolled on this Mac"
        case .biometryNotAvailable: return "no Touch ID on this Mac"
        case .biometryLockout: return "Touch ID is locked out; unlock with your password first"
        default: return "not confirmed"
        }
    }
}
