// A minimal LocalAuthentication presence check for the daemon's pairing gate.
//
// LAContext.evaluatePolicy forces a live biometric (Touch ID / Apple Watch)
// prompt and needs NO keychain item, NO Secure Enclave key, and NO entitlement,
// so it works from the unsigned, portable daemon. This replaces the old presence
// check that minted a persistent Secure Enclave keychain key (which an unsigned
// binary cannot create: errSecMissingEntitlement / amfid SIGKILL).
//
// The policy is deviceOwnerAuthenticationWithBiometrics: biometry only, no
// passcode fallback, so "presence" always means a fresh finger/watch, matching
// the security intent of the pairing gate.

#import <Foundation/Foundation.h>
#import <LocalAuthentication/LocalAuthentication.h>

// Result codes returned to Rust. Kept small and stable; Rust maps them to a
// KeystoreError.
//   1  = present (biometric succeeded)
//   0  = declined / failed / cancelled
//  -1  = biometrics unavailable or not enrolled (canEvaluatePolicy false)
int sigil_la_verify_presence(const char *reason_utf8) {
    @autoreleasepool {
        LAContext *ctx = [[LAContext alloc] init];
        // No passcode fallback: a live biometric or nothing.
        ctx.localizedFallbackTitle = @"";
        LAPolicy policy = LAPolicyDeviceOwnerAuthenticationWithBiometrics;

        NSError *canErr = nil;
        if (![ctx canEvaluatePolicy:policy error:&canErr]) {
            NSLog(@"sigil presence: canEvaluatePolicy failed: %@", canErr);
            // Encode the LAError code so Rust can log it: -1000 + code (codes are
            // small negatives like -6 biometryNotAvailable, -7 notEnrolled).
            return canErr ? (int)(-1000 + canErr.code) : -1;
        }

        NSString *reason = reason_utf8 != NULL
            ? [NSString stringWithUTF8String:reason_utf8]
            : @"Sigil needs your presence";
        if (reason == nil || reason.length == 0) {
            reason = @"Sigil needs your presence";
        }

        // evaluatePolicy is asynchronous (a reply block). The daemon calls this
        // from a worker thread, never the main queue, so blocking that thread on
        // a semaphore until the prompt resolves is safe.
        __block int result = 0;
        dispatch_semaphore_t sem = dispatch_semaphore_create(0);
        [ctx evaluatePolicy:policy
            localizedReason:reason
                      reply:^(BOOL success, NSError *error) {
                        result = success ? 1 : 0;
                        dispatch_semaphore_signal(sem);
                      }];
        dispatch_semaphore_wait(sem, DISPATCH_TIME_FOREVER);
        return result;
    }
}
