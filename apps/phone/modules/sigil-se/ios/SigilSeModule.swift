// The phone half of Sigil v2 threshold decryption: a non-exportable P-256
// key-agreement key `f` resident in the Secure Enclave, gated by the current
// biometric set (Face ID). The private scalar never leaves the enclave; the only
// value that ever exits is a per-request ECDH partial `Z_F = x(f·E)`, which the
// Mac combines with its own share to open one account's token.
//
// Design: docs/design/threshold-v2.md (scheme §3/§5/§6; R2 on-curve validation;
// NV-1 non-exportability + biometric gating; NV-2/NV-7 ECDH output shape). This
// module is the real Secure-Enclave key-agreement the design calls "the crux".

import CryptoKit
import ExpoModulesCore
import Foundation
import LocalAuthentication
import Security

/// Keychain service under which the opaque, SE-wrapped key blobs are stored. The
/// blob is `SecureEnclave.P256.KeyAgreement.PrivateKey.dataRepresentation`: it is
/// itself enclave-wrapped, so it is not usable off this device and reveals no
/// scalar. The biometric gate lives on the SE key's own access control, enforced
/// at key-agreement time, not on this keychain item.
private let kSigilSeService = "works.rainn.sigil.se.share"

// MARK: - Errors (mapped to JS promise rejections with stable codes)

internal final class SecureEnclaveUnavailableException: Exception {
  override var reason: String {
    "Secure Enclave is not available on this device (Simulator or unsupported hardware)"
  }
}

internal final class AccessControlException: Exception {
  override var reason: String {
    "Could not create the biometric access control for the Secure Enclave key"
  }
}

internal final class InvalidPointException: Exception {
  override var reason: String {
    // R2 / NV-6: the validating X9.63 decoder rejected E as off-curve, on the
    // twist, the identity, or the wrong length, BEFORE any key-agreement.
    "The supplied P-256 point E is not a valid on-curve X9.63 encoding"
  }
}

internal final class MissingKeyException: Exception {
  override var reason: String {
    "No Secure Enclave share key is stored for the requested key id"
  }
}

internal final class KeyAgreementException: GenericException<String> {
  override var reason: String {
    // A user cancel, a failed Face ID, or an invalidated key all land here;
    // fail closed with no partial.
    "Secure Enclave key-agreement failed or was denied: \(param)"
  }
}

internal final class KeychainException: GenericException<OSStatus> {
  override var reason: String {
    "Keychain operation failed with OSStatus \(param)"
  }
}

// MARK: - Module

public final class SigilSeModule: Module {
  public func definition() -> ModuleDefinition {
    Name("SigilSe")

    // Whether this device has a usable Secure Enclave. False on the Simulator, so
    // the JS layer can fail loudly rather than mint a phantom share.
    Function("isAvailable") { () -> Bool in
      SecureEnclave.isAvailable
    }

    // Whether a share key blob is stored under `keyId` (cheap; no biometric).
    Function("hasShareKey") { (keyId: String) -> Bool in
      loadBlob(keyId) != nil
    }

    // Pairing: mint `f` in the Secure Enclave under `.privateKeyUsage +
    // .biometryCurrentSet`, persist its opaque wrapped blob under `keyId`, and
    // return F = f.publicKey in ANSI X9.63 uncompressed form (65 bytes), base64.
    // The Mac pins F and seals account tokens to it. Minting itself does not
    // prompt Face ID; the biometric is required on every later key-agreement.
    AsyncFunction("generateShareKey") { (keyId: String) -> String in
      guard SecureEnclave.isAvailable else { throw SecureEnclaveUnavailableException() }

      var acError: Unmanaged<CFError>?
      guard
        let access = SecAccessControlCreateWithFlags(
          kCFAllocatorDefault,
          kSecAttrAccessibleWhenUnlockedThisDeviceOnly,
          [.privateKeyUsage, .biometryCurrentSet],
          &acError
        )
      else {
        throw AccessControlException()
      }

      let key = try SecureEnclave.P256.KeyAgreement.PrivateKey(accessControl: access)
      try saveBlob(keyId, key.dataRepresentation)
      return key.publicKey.x963Representation.base64EncodedString()
    }

    // Per request: reconstruct `f` from its stored blob, on-curve-validate E, and
    // key-agree inside the enclave to produce the RAW 32-byte X-coordinate
    // x(f·E). The key-agreement is the Face-ID gate (the SE key's
    // `.biometryCurrentSet` access control fires here), so this biometric IS what
    // mints the per-request material. Returns base64 of the raw X-coordinate.
    //
    // The ECDH-output shaping (NV-2: "raw-x" identity vs "x963-sha256" KDF) is
    // applied in TS (src/protocol/threshold.ts `shapeEcdh`), so both Rust and TS
    // hand-roll the identical X9.63 formula and the x963 path's byte-parity rests
    // only on the raw-ECDH agreement (NV-3), not on CryptoKit's KDF matching
    // Rust's. The enclave here does exactly one thing: the guarded raw ECDH.
    AsyncFunction("computePartial") {
      (keyId: String, ephemeralPubBase64: String, reason: String) -> String in
      guard SecureEnclave.isAvailable else { throw SecureEnclaveUnavailableException() }

      guard let eData = Data(base64Encoded: ephemeralPubBase64) else {
        throw InvalidPointException()
      }
      // R2 / NV-6, load-bearing: the validating CryptoKit decoder rejects
      // off-curve / twist / identity / wrong-length points here, BEFORE `f` is
      // ever multiplied against E. Never hand a raw/unvalidated point to the SE.
      let ePub: P256.KeyAgreement.PublicKey
      do {
        ePub = try P256.KeyAgreement.PublicKey(x963Representation: eData)
      } catch {
        throw InvalidPointException()
      }

      guard let blob = loadBlob(keyId) else { throw MissingKeyException() }

      // `reason` is the generic Face-ID prompt string ("Approve request"); the
      // provider-blind phone no longer names an account here (R5 removed). Passcode
      // fallback is disabled so key release is strictly biometric.
      let context = LAContext()
      if !reason.isEmpty {
        context.localizedFallbackTitle = ""
      }

      let shared: SharedSecret
      do {
        let key = try SecureEnclave.P256.KeyAgreement.PrivateKey(
          dataRepresentation: blob,
          authenticationContext: context
        )
        // Face ID fires on this call (the key's access control gates the op).
        shared = try key.sharedSecretFromKeyAgreement(with: ePub)
      } catch {
        throw KeyAgreementException(String(describing: error))
      }

      // The raw 32-byte big-endian X-coordinate, verbatim from the enclave. This
      // equals p256's `diffie_hellman(...).raw_secret_bytes()` on the Mac (NV-3).
      let rawX = shared.withUnsafeBytes { Data($0) }
      return rawX.base64EncodedString()
    }

    // Remove a stored share blob (unpair / re-key). Since `f` is enclave-resident
    // and non-exportable, deleting the blob permanently retires the share.
    Function("deleteShareKey") { (keyId: String) in
      deleteBlob(keyId)
    }
  }
}

// MARK: - Keychain blob storage (opaque, ThisDeviceOnly)

private func baseQuery(_ keyId: String) -> [String: Any] {
  [
    kSecClass as String: kSecClassGenericPassword,
    kSecAttrService as String: kSigilSeService,
    kSecAttrAccount as String: keyId,
  ]
}

private func saveBlob(_ keyId: String, _ data: Data) throws {
  SecItemDelete(baseQuery(keyId) as CFDictionary)
  var add = baseQuery(keyId)
  add[kSecValueData as String] = data
  add[kSecAttrAccessible as String] = kSecAttrAccessibleWhenUnlockedThisDeviceOnly
  let status = SecItemAdd(add as CFDictionary, nil)
  guard status == errSecSuccess else { throw KeychainException(status) }
}

private func loadBlob(_ keyId: String) -> Data? {
  var query = baseQuery(keyId)
  query[kSecReturnData as String] = true
  query[kSecMatchLimit as String] = kSecMatchLimitOne
  var out: CFTypeRef?
  let status = SecItemCopyMatching(query as CFDictionary, &out)
  guard status == errSecSuccess else { return nil }
  return out as? Data
}

private func deleteBlob(_ keyId: String) {
  SecItemDelete(baseQuery(keyId) as CFDictionary)
}
