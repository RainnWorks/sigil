#!/usr/bin/env swift
//  se-selftest.swift
//  On-device confirmation of the Secure Enclave local-approval seam. This is the
//  command RESEARCH.md points at for the NEEDS VERIFICATION items: it cannot pass
//  on a VM, the Simulator, or a machine without an enrolled biometric.
//
//  It mints the SE P-256 key (biometry-gated), exports the X9.63 public key,
//  encrypts a known 32-byte DEK to it with P-256 ECIES, then decrypts under a
//  live Touch ID and asserts the round-trip. If this passes on real hardware,
//  the SE half of SecureEnclaveApprover is confirmed; the remaining open item is
//  whether rust-core's Mac-envelope format matches this ECIES scheme.
//
//  Run:  swift apps/mac/Tools/se-selftest.swift

import Foundation
import LocalAuthentication
import Security

let tag = "co.rowm.latch.selftest.p256".data(using: .utf8)!

func cfErr(_ e: Unmanaged<CFError>?) -> String {
    guard let e = e?.takeRetainedValue() else { return "unknown" }
    return CFErrorCopyDescription(e) as String? ?? "unknown"
}

// 1. Access control: private-key usage gated by the current biometric set.
var acErr: Unmanaged<CFError>?
guard let access = SecAccessControlCreateWithFlags(
    kCFAllocatorDefault, kSecAttrAccessibleWhenUnlockedThisDeviceOnly,
    [.privateKeyUsage, .biometryCurrentSet], &acErr) else {
    print("FAIL access control: \(cfErr(acErr))"); exit(1)
}

// Clean any prior self-test key.
SecItemDelete([kSecClass: kSecClassKey, kSecAttrApplicationTag: tag,
               kSecAttrKeyType: kSecAttrKeyTypeECSECPrimeRandom] as CFDictionary)

// 2. Mint the SE key.
let attrs: [String: Any] = [
    kSecAttrKeyType as String: kSecAttrKeyTypeECSECPrimeRandom,
    kSecAttrKeySizeInBits as String: 256,
    kSecAttrTokenID as String: kSecAttrTokenIDSecureEnclave,
    kSecPrivateKeyAttrs as String: [
        kSecAttrIsPermanent as String: true,
        kSecAttrApplicationTag as String: tag,
        kSecAttrAccessControl as String: access,
    ],
]
var keyErr: Unmanaged<CFError>?
guard let priv = SecKeyCreateRandomKey(attrs as CFDictionary, &keyErr) else {
    print("FAIL SE keygen: \(cfErr(keyErr)) (need real Apple-silicon + enrolled biometric)"); exit(1)
}
guard let pub = SecKeyCopyPublicKey(priv),
      let pubData = SecKeyCopyExternalRepresentation(pub, nil) as Data? else {
    print("FAIL public key export"); exit(1)
}
print("OK  SE P-256 key minted; X9.63 pubkey = \(pubData.count) bytes (0x\(pubData.prefix(1).map { String(format: "%02x", $0) }.joined()) lead)")

// 3. Encrypt a known DEK to the public key with ECIES.
let algo: SecKeyAlgorithm = .eciesEncryptionCofactorVariableIVX963SHA256AESGCM
let dek = Data((0..<32).map { UInt8($0) })
var encErr: Unmanaged<CFError>?
guard let ct = SecKeyCreateEncryptedData(pub, algo, dek as CFData, &encErr) as Data? else {
    print("FAIL ECIES encrypt: \(cfErr(encErr))"); exit(1)
}
print("OK  ECIES sealed DEK -> \(ct.count) bytes")

// 4. Decrypt under a live Touch ID.
let ctx = LAContext()
ctx.localizedReason = "Latch self-test: unwrap the DEK"
let query: [String: Any] = [
    kSecClass as String: kSecClassKey, kSecAttrApplicationTag as String: tag,
    kSecAttrKeyType as String: kSecAttrKeyTypeECSECPrimeRandom,
    kSecReturnRef as String: true, kSecUseAuthenticationContext as String: ctx,
]
var item: CFTypeRef?
guard SecItemCopyMatching(query as CFDictionary, &item) == errSecSuccess, let item else {
    print("FAIL load SE key"); exit(1)
}
let loaded = item as! SecKey
var decErr: Unmanaged<CFError>?
guard let pt = SecKeyCreateDecryptedData(loaded, algo, ct as CFData, &decErr) as Data? else {
    print("FAIL ECIES decrypt (Touch ID): \(cfErr(decErr))"); exit(1)
}
print(pt == dek ? "PASS round-trip: DEK recovered only after a live Touch ID" : "FAIL round-trip mismatch")
SecItemDelete([kSecClass: kSecClassKey, kSecAttrApplicationTag: tag,
               kSecAttrKeyType: kSecAttrKeyTypeECSECPrimeRandom] as CFDictionary)
exit(pt == dek ? 0 : 1)
