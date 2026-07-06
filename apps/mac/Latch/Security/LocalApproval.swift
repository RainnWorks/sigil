//  LocalApproval.swift
//  The Touch ID + Secure Enclave seam, isolated behind a protocol exactly like
//  the Rust keystore_macos seam. The app never touches the Keychain or the
//  Enclave outside this file. Two implementations: a real SE-backed one (marked
//  NEEDS VERIFICATION, since the Enclave cannot be exercised on this build box)
//  and a mock for previews and non-hardware runs.
//
//  What "local approval" means (brief): approving at the Mac requires a live
//  Touch ID that unwraps the DEK inside the Secure Enclave. There is no code
//  path that yields the DEK without a biometric. Hardened mode never mints the
//  Mac envelope, so the phone stays strictly required.

import Foundation

/// The Enclave-held public key the daemon wraps the DEK to when Mac approvals
/// are enabled. ANSI X9.63 (0x04 || X || Y) representation of a P-256 point.
struct MacEnclaveKey: Equatable, Sendable {
    /// X9.63 uncompressed public key bytes, handed to the daemon to wrap against.
    var x963PublicKey: Data
}

/// The result of a local approval: the recovered DEK, held only long enough to
/// hand to the daemon. Zeroized by the caller after use.
struct UnwrappedDEK: Sendable {
    var bytes: Data
}

enum LocalApprovalError: LocalizedError {
    case unavailable(String)
    case userCancelled
    case biometryFailed(String)
    case noMacEnvelope
    case decrypt(String)

    var errorDescription: String? {
        switch self {
        case .unavailable(let s): return s
        case .userCancelled: return "cancelled"
        case .biometryFailed(let s): return s
        case .noMacEnvelope: return "No Mac approval envelope. Approve on iPhone."
        case .decrypt(let s): return s
        }
    }
}

/// The whole local-approval surface. The app calls these; the impl decides
/// whether a real Enclave or a mock answers.
protocol LocalApprovalService: Sendable {
    /// True iff this Mac has usable Touch ID + Secure Enclave.
    var biometricsAvailable: Bool { get }

    /// Mint (or fetch) the Secure Enclave key for local approvals and return its
    /// public half for the daemon to wrap the DEK against. Enabling Mac approvals.
    func enableMacApprovals() throws -> MacEnclaveKey

    /// Drop the Mac envelope: hardened, phone-only. The SE key is deleted.
    func disableMacApprovals() throws

    /// Whether a Mac envelope currently exists (Mac approvals enabled).
    var macApprovalsEnabled: Bool { get }

    /// Perform a biometric-gated unwrap of the DEK the daemon sealed to the SE
    /// key. `reason` is the Touch ID prompt line (e.g. "Approve graphql-api for
    /// Rowm work"). The DEK is only recoverable after a live Touch ID.
    func approve(wrappedDEK: Data, reason: String) async throws -> UnwrappedDEK
}
