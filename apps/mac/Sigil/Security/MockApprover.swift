//  MockApprover.swift
//  A LocalApprovalService for previews and non-hardware runs. It simulates the
//  Touch ID prompt latency and returns a fixed DEK, so the menubar approve flow
//  is fully exercisable without the Enclave. It never claims a real biometric
//  happened; it exists to render and drive the UI.

import Foundation

final class MockApprover: LocalApprovalService, @unchecked Sendable {
    private let lock = NSLock()
    private var enabled: Bool
    /// When true, approve() throws userCancelled, to exercise the cancel path.
    var simulateCancel = false
    var biometricsAvailable: Bool

    init(macApprovalsEnabled: Bool = true, biometricsAvailable: Bool = true) {
        self.enabled = macApprovalsEnabled
        self.biometricsAvailable = biometricsAvailable
    }

    var macApprovalsEnabled: Bool {
        lock.lock(); defer { lock.unlock() }
        return enabled
    }

    func enableMacApprovals() throws -> MacEnclaveKey {
        lock.lock(); enabled = true; lock.unlock()
        // A fixed 65-byte X9.63 P-256 point (0x04 || 32 || 32), values are dummy.
        var bytes = Data([0x04])
        bytes.append(Data(repeating: 0xA1, count: 32))
        bytes.append(Data(repeating: 0xB2, count: 32))
        return MacEnclaveKey(x963PublicKey: bytes)
    }

    func disableMacApprovals() throws {
        lock.lock(); enabled = false; lock.unlock()
    }

    func approve(wrappedDEK: Data, reason: String) async throws -> UnwrappedDEK {
        guard macApprovalsEnabled else { throw LocalApprovalError.noMacEnvelope }
        try? await Task.sleep(for: .milliseconds(700))  // Touch ID sheet latency
        if simulateCancel { throw LocalApprovalError.userCancelled }
        return UnwrappedDEK(bytes: Data(repeating: 0x2A, count: 32))
    }
}
