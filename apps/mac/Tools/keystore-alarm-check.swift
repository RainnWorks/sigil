//  keystore-alarm-check.swift
//  A headless check on the two decisions in the keystore layer that must never
//  fail open, run against the app's real sources rather than a copy of them:
//
//    1. KeystoreCoordinator.sync, when the file on disk is plaintext. The
//       wrapping key's survival is the tamper evidence, and "the keychain would
//       not answer" must raise the alarm rather than be read as "there is no
//       key" and adopted over.
//    2. LocalPresence.fallback(for:), which decides whether the login password
//       may stand in for Touch ID on the de-adoption path. Only a Mac that
//       cannot do biometry may fall back. A locked-out sensor may not, or an
//       attacker gets to lower the bar by failing Touch ID five times.
//
//  Both are ordinary logic and neither needs an Enclave, a keychain, or a
//  sensor, which is why they can be checked here at all. What CANNOT be checked
//  here, and belongs on the device checklist instead: that a real Enclave
//  produces these errors, that a real Touch ID lockout surfaces as
//  LAErrorBiometryLockout rather than some other code, and every line of
//  SecureEnclaveWrapKey, which an unsigned binary cannot reach at all.
//
//  Nothing runs this automatically. There is no test target in project.yml, and
//  this file is deliberately outside `Sigil/` so it joins no build:
//
//    cd apps/mac && swiftc -swift-version 6 -o /tmp/keystore-alarm-check \
//      Sigil/Model/*.swift Sigil/Design/*.swift Tools/keystore-alarm-check.swift \
//      && /tmp/keystore-alarm-check

import Foundation
import LocalAuthentication

@main
struct KeystoreAlarmCheck {
    static func main() async {
        var failures = 0
        failures += await checkDowngradeIsNeverAssumedAway()
        failures += checkOnlyMissingHardwareMayFallBack()
        print(failures == 0 ? "\nall pass" : "\n\(failures) FAILED")
        exit(failures == 0 ? 0 : 1)
    }

    // MARK: - 1. the downgrade check has three answers

    /// A wrapping key that answers yes, no, or refuses to say. The third is the
    /// one that matters: errSecInteractionNotAllowed, errSecNotAvailable and a
    /// missing entitlement all arrive as a throw, not as a false.
    private struct StubWrapKey: KeystoreWrapKey {
        enum Answer { case yes, no, refuses }
        var answer: Answer

        func ensureKeyExists() throws {}
        func encrypt(_ plaintext: Data) throws -> (ciphertext: Data, sePub: Data) { (Data(), Data()) }
        func decrypt(_ ciphertext: Data) throws -> Data { Data() }
        func deleteKey() throws {}
        func keyExists() throws -> Bool {
            switch answer {
            case .yes: return true
            case .no: return false
            case .refuses: throw WrapKeyError.keychain("lookup", errSecInteractionNotAllowed)
            }
        }
    }

    @MainActor
    private static func checkDowngradeIsNeverAssumedAway() async -> Int {
        var failures = 0
        let dir = NSTemporaryDirectory() + "sigil-keystore-alarm-\(getpid())"
        try? FileManager.default.createDirectory(atPath: dir, withIntermediateDirectories: true)
        defer { try? FileManager.default.removeItem(atPath: dir) }
        let path = dir + "/keystore.json"

        func sync(_ answer: StubWrapKey.Answer, daemonRunning: Bool) async -> KeystoreProtection {
            // A v1 plaintext keystore, written fresh for each case.
            try? KeystoreFile.writePlaintext(Data("{\"v\":1,\"material\":\"x\"}".utf8), to: path)
            let coordinator = KeystoreCoordinator(path: path, wrapKey: StubWrapKey(answer: answer))
            await coordinator.sync(daemon: MockDaemonClient(scenario: .armedIdle, running: daemonRunning))
            return coordinator.state
        }

        func expect(_ label: String, _ state: KeystoreProtection,
                    _ predicate: (KeystoreProtection) -> Bool) {
            let ok = predicate(state)
            print("\(ok ? "ok  " : "FAIL") \(label)\n       \(state)")
            if !ok { failures += 1 }
        }

        func downgraded(_ s: KeystoreProtection) -> Bool {
            if case .downgraded = s { return true }
            return false
        }
        func unverified(_ s: KeystoreProtection) -> Bool {
            if case .downgradeUnverified = s { return true }
            return false
        }

        expect("a surviving key over a plaintext file is the alarm",
               await sync(.yes, daemonRunning: true), downgraded)
        expect("and stays the alarm with the daemon down",
               await sync(.yes, daemonRunning: false), downgraded)
        expect("a keychain that will not answer is also an alarm",
               await sync(.refuses, daemonRunning: true), unverified)
        // The specific fail-open this check exists for: swallowing the throw sent
        // this down the adopt path, where a daemon that happens to be down
        // renders a real downgrade as the calm "left as it is" line.
        expect("and with the daemon down, where it used to read as benign",
               await sync(.refuses, daemonRunning: false), unverified)
        expect("an answered no is the only thing that adopts",
               await sync(.no, daemonRunning: true), { !$0.isAlarm })
        return failures
    }

    // MARK: - 2. the password may only stand in for absent hardware

    private static func checkOnlyMissingHardwareMayFallBack() -> Int {
        var failures = 0

        func expect(_ label: String, _ code: LAError.Code?, mayFallBack: Bool) {
            let error = code.map { NSError(domain: LAErrorDomain, code: $0.rawValue) }
            check(label, LocalPresence.fallback(for: error), mayFallBack: mayFallBack)
        }

        func check(_ label: String, _ got: LocalPresence.BiometryUnavailable, mayFallBack: Bool) {
            let fellBack = got == .fallBackToPassword
            let ok = fellBack == mayFallBack
            print("\(ok ? "ok  " : "FAIL") \(label)\n       \(got)")
            if !ok { failures += 1 }
        }

        expect("no sensor on this Mac: the password is all there is",
               .biometryNotAvailable, mayFallBack: true)
        expect("no finger enrolled: still the only device-owner check there is",
               .biometryNotEnrolled, mayFallBack: true)
        // Inducible by anyone holding the Mac, so it must not be a way through.
        expect("locked out by repeated failures: refuse",
               .biometryLockout, mayFallBack: false)
        expect("Touch ID keyboard unpaired: refuse",
               .biometryNotPaired, mayFallBack: false)
        expect("Touch ID keyboard disconnected: refuse",
               .biometryDisconnected, mayFallBack: false)
        expect("no login password set: nothing to confirm with",
               .passcodeNotSet, mayFallBack: false)
        expect("an LAError we do not recognize: refuse",
               .invalidContext, mayFallBack: false)
        expect("unavailable with no error at all: refuse",
               nil, mayFallBack: false)
        check("an error from some other domain: refuse",
              LocalPresence.fallback(for: NSError(domain: NSOSStatusErrorDomain, code: -7)),
              mayFallBack: false)
        return failures
    }
}
