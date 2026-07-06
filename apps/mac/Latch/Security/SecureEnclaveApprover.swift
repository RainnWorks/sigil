//  SecureEnclaveApprover.swift
//  Real Touch ID + Secure Enclave implementation of LocalApprovalService.
//
//  NEEDS VERIFICATION — this code is written against the confirmed current API
//  shape (see apps/mac/RESEARCH.md) but CANNOT be exercised on the build box:
//  the Secure Enclave requires real Apple-silicon hardware with an enrolled
//  biometric (not a VM, not the Simulator). Two things in particular must be
//  confirmed on device:
//
//    1. Biometric-gated ECIES decrypt round-trips: a DEK encrypted to the SE
//       public key via P-256 ECIES is recoverable ONLY after a live Touch ID,
//       and the private key never leaves the Enclave.
//    2. The envelope format matches rust-core's `wrap_dek_for`. The Enclave does
//       P-256 ECIES, NOT X25519 crypto_box. If rust-core wraps the Mac's second
//       recipient with X25519, the formats do not meet and one side must change;
//       the SE cannot move off P-256. This is the load-bearing cross-seam item.
//
//  Confirm on device with the app's DEBUG "Run SE self-test" action, which mints
//  the key, encrypts a known DEK to it, and decrypts under Touch ID.

import Foundation
import LocalAuthentication
import Security

/// SE-backed approver. The private key is created with `.privateKeyUsage +
/// .biometryCurrentSet`, so it is unusable without a live Touch ID and is
/// invalidated if the enrolled biometric set changes.
final class SecureEnclaveApprover: LocalApprovalService, @unchecked Sendable {
    /// Keychain tag for the SE private key. One key per install.
    private let keyTag = "co.rowm.sigil.local-approval.p256".data(using: .utf8)!

    var biometricsAvailable: Bool {
        let ctx = LAContext()
        var err: NSError?
        let ok = ctx.canEvaluatePolicy(.deviceOwnerAuthenticationWithBiometrics, error: &err)
        // Secure Enclave presence is implied on Apple silicon; the biometry
        // check is the meaningful gate for whether Touch ID can be presented.
        return ok
    }

    var macApprovalsEnabled: Bool { (try? loadPrivateKey()) != nil }

    // MARK: enable / disable

    func enableMacApprovals() throws -> MacEnclaveKey {
        if let existing = try? loadPrivateKey() {
            return try publicKey(of: existing)
        }
        var acError: Unmanaged<CFError>?
        guard let access = SecAccessControlCreateWithFlags(
            kCFAllocatorDefault,
            kSecAttrAccessibleWhenUnlockedThisDeviceOnly,
            [.privateKeyUsage, .biometryCurrentSet],
            &acError
        ) else {
            throw LocalApprovalError.unavailable("access control: \(cfError(acError))")
        }

        let attributes: [String: Any] = [
            kSecAttrKeyType as String: kSecAttrKeyTypeECSECPrimeRandom,
            kSecAttrKeySizeInBits as String: 256,
            kSecAttrTokenID as String: kSecAttrTokenIDSecureEnclave,
            kSecPrivateKeyAttrs as String: [
                kSecAttrIsPermanent as String: true,
                kSecAttrApplicationTag as String: keyTag,
                kSecAttrAccessControl as String: access,
            ],
        ]

        var error: Unmanaged<CFError>?
        guard let priv = SecKeyCreateRandomKey(attributes as CFDictionary, &error) else {
            throw LocalApprovalError.unavailable("SE key generation failed: \(cfError(error))")
        }
        return try publicKey(of: priv)
    }

    func disableMacApprovals() throws {
        let query: [String: Any] = [
            kSecClass as String: kSecClassKey,
            kSecAttrApplicationTag as String: keyTag,
            kSecAttrKeyType as String: kSecAttrKeyTypeECSECPrimeRandom,
        ]
        let status = SecItemDelete(query as CFDictionary)
        guard status == errSecSuccess || status == errSecItemNotFound else {
            throw LocalApprovalError.unavailable("could not delete SE key: \(status)")
        }
    }

    // MARK: approve

    func approve(wrappedDEK: Data, reason: String) async throws -> UnwrappedDEK {
        let context = LAContext()
        context.localizedReason = reason
        // The Enclave demands the biometric before it will operate on the key;
        // passing the context makes the Touch ID sheet carry our reason.
        let priv = try loadPrivateKey(context: context)

        let algorithm: SecKeyAlgorithm = .eciesEncryptionCofactorVariableIVX963SHA256AESGCM
        guard SecKeyIsAlgorithmSupported(priv, .decrypt, algorithm) else {
            throw LocalApprovalError.decrypt("SE key does not support the ECIES algorithm")
        }
        var error: Unmanaged<CFError>?
        guard let plain = SecKeyCreateDecryptedData(priv, algorithm, wrappedDEK as CFData, &error) as Data? else {
            let e = cfError(error)
            if e.localizedCaseInsensitiveContains("cancel") { throw LocalApprovalError.userCancelled }
            throw LocalApprovalError.biometryFailed(e)
        }
        return UnwrappedDEK(bytes: plain)
    }

    // MARK: helpers

    private func loadPrivateKey(context: LAContext? = nil) throws -> SecKey {
        var query: [String: Any] = [
            kSecClass as String: kSecClassKey,
            kSecAttrApplicationTag as String: keyTag,
            kSecAttrKeyType as String: kSecAttrKeyTypeECSECPrimeRandom,
            kSecReturnRef as String: true,
        ]
        if let context { query[kSecUseAuthenticationContext as String] = context }
        var item: CFTypeRef?
        let status = SecItemCopyMatching(query as CFDictionary, &item)
        guard status == errSecSuccess, let item else {
            throw LocalApprovalError.noMacEnvelope
        }
        // SecItemCopyMatching returns a SecKey for a key-class item.
        return item as! SecKey
    }

    private func publicKey(of priv: SecKey) throws -> MacEnclaveKey {
        guard let pub = SecKeyCopyPublicKey(priv) else {
            throw LocalApprovalError.unavailable("could not derive SE public key")
        }
        var error: Unmanaged<CFError>?
        guard let data = SecKeyCopyExternalRepresentation(pub, &error) as Data? else {
            throw LocalApprovalError.unavailable("could not export SE public key: \(cfError(error))")
        }
        // For EC public keys this is the ANSI X9.63 (0x04 || X || Y) form.
        return MacEnclaveKey(x963PublicKey: data)
    }

    private func cfError(_ e: Unmanaged<CFError>?) -> String {
        guard let e = e?.takeRetainedValue() else { return "unknown error" }
        return CFErrorCopyDescription(e) as String? ?? "unknown error"
    }
}
