// Peer code-identity check: does the process on the other end of our unix
// socket satisfy a code-signing requirement?
//
// This is the enforcement behind the keystore contract's "only the signed Sigil
// app may hand the daemon its material". A pid alone proves nothing (pids
// recycle, and any same-UID process can connect to a 0600 socket), so we ask
// the kernel's code-signing machinery what that pid actually IS, and match it
// against a requirement string the caller supplies.
//
// SecCodeCopyGuestWithAttributes with kSecGuestAttributePid resolves a live pid
// to its SecCode; SecCodeCheckValidityWithErrors then validates the signature
// AND evaluates the requirement, so an unsigned, ad-hoc-signed, or
// wrong-team binary fails. Both are the documented, non-deprecated path.
//
// Honest limit, carried in the Rust caller's docs too: this answers "what is
// that pid now". A pid could in principle be recycled between the check and a
// later use of the same connection. We check at accept time on a connection
// that stays open, which is the tightest binding this API offers.

#include <CoreFoundation/CoreFoundation.h>
#include <Security/Security.h>

// Same check, but keyed on the peer's AUDIT TOKEN rather than its pid. An audit
// token identifies a specific process instance and is never reused, so unlike a
// pid it cannot be recycled onto a different process between the moment the
// kernel handed it to us and the moment we ask about it. This is Apple's
// documented way to identify the far end of a unix socket.
//
// Return codes are identical to the pid variant below.
int sigil_audit_satisfies_requirement(const void *token, size_t token_len,
                                      const char *requirement) {
    if (requirement == NULL || token == NULL) {
        return -1;
    }
    CFStringRef req_str = CFStringCreateWithCString(NULL, requirement, kCFStringEncodingUTF8);
    if (req_str == NULL) {
        return -1;
    }
    SecRequirementRef req = NULL;
    OSStatus st = SecRequirementCreateWithString(req_str, kSecCSDefaultFlags, &req);
    CFRelease(req_str);
    if (st != errSecSuccess || req == NULL) {
        if (req != NULL) {
            CFRelease(req);
        }
        return -1;
    }

    CFDataRef token_data = CFDataCreate(NULL, (const UInt8 *)token, (CFIndex)token_len);
    if (token_data == NULL) {
        CFRelease(req);
        return -3;
    }
    const void *keys[] = {kSecGuestAttributeAudit};
    const void *values[] = {token_data};
    CFDictionaryRef attrs = CFDictionaryCreate(NULL, keys, values, 1,
                                               &kCFTypeDictionaryKeyCallBacks,
                                               &kCFTypeDictionaryValueCallBacks);
    CFRelease(token_data);
    if (attrs == NULL) {
        CFRelease(req);
        return -3;
    }

    SecCodeRef code = NULL;
    st = SecCodeCopyGuestWithAttributes(NULL, attrs, kSecCSDefaultFlags, &code);
    CFRelease(attrs);
    if (st != errSecSuccess || code == NULL) {
        if (code != NULL) {
            CFRelease(code);
        }
        CFRelease(req);
        return -2;
    }

    st = SecCodeCheckValidityWithErrors(code, kSecCSDefaultFlags, req, NULL);
    CFRelease(code);
    CFRelease(req);
    return (st == errSecSuccess) ? 0 : 1;
}

// 0  = the peer satisfies the requirement
// 1  = the peer does NOT satisfy it (unsigned, ad-hoc, wrong team, tampered)
// -1 = the requirement string did not compile
// -2 = the pid could not be resolved to a code object
// -3 = an unexpected API failure
int sigil_peer_satisfies_requirement(int pid, const char *requirement) {
    if (requirement == NULL) {
        return -1;
    }
    CFStringRef req_str = CFStringCreateWithCString(NULL, requirement, kCFStringEncodingUTF8);
    if (req_str == NULL) {
        return -1;
    }
    SecRequirementRef req = NULL;
    OSStatus st = SecRequirementCreateWithString(req_str, kSecCSDefaultFlags, &req);
    CFRelease(req_str);
    if (st != errSecSuccess || req == NULL) {
        if (req != NULL) {
            CFRelease(req);
        }
        return -1;
    }

    // Resolve the pid to its code object.
    pid_t p = (pid_t)pid;
    CFNumberRef pid_num = CFNumberCreate(NULL, kCFNumberIntType, &p);
    if (pid_num == NULL) {
        CFRelease(req);
        return -3;
    }
    const void *keys[] = {kSecGuestAttributePid};
    const void *values[] = {pid_num};
    CFDictionaryRef attrs = CFDictionaryCreate(NULL, keys, values, 1,
                                               &kCFTypeDictionaryKeyCallBacks,
                                               &kCFTypeDictionaryValueCallBacks);
    CFRelease(pid_num);
    if (attrs == NULL) {
        CFRelease(req);
        return -3;
    }

    SecCodeRef code = NULL;
    st = SecCodeCopyGuestWithAttributes(NULL, attrs, kSecCSDefaultFlags, &code);
    CFRelease(attrs);
    if (st != errSecSuccess || code == NULL) {
        if (code != NULL) {
            CFRelease(code);
        }
        CFRelease(req);
        return -2;
    }

    st = SecCodeCheckValidityWithErrors(code, kSecCSDefaultFlags, req, NULL);
    CFRelease(code);
    CFRelease(req);
    if (st == errSecSuccess) {
        return 0;
    }
    return 1;
}
