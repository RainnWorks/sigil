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
#include <stdint.h>
#include <string.h>

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

// The platform code identity of the executable at `path`: its cdhash
// (kSecCodeInfoUnique), the digest of the CodeDirectory that the signature
// commits to and that the kernel enforces against the pages it maps.
//
// This is a MEASUREMENT, not an authorization: nothing here decides whether a
// binary may do anything. It exists so the lease grant key names an ancestor by
// what the platform says it is rather than by a hash we compute ourselves.
//
// Only a signature with a signer yields one. An ad-hoc signature (flags &
// kSecCodeSignatureAdhoc) has no signer at all: its cdhash is a digest of the
// binary and nothing more, exactly as strong as the caller's own content hash
// and no stronger, so calling it a signing identity would overstate it. Ad-hoc
// is reported as absent and the caller falls back to (and separately tags) its
// own hash. A platform binary carries no certificate chain either, but the
// kernel's trust cache vouches for it, so it counts.
//
// Deliberately does NOT call SecStaticCodeCheckValidity: on this platform it
// costs up to ~200ms on a large signed binary, and (measured) it still returns
// success for a Mach-O whose text pages were altered under an intact
// CodeDirectory. The tamper-evidence comes from the kernel refusing to execute
// such a binary at all, not from a userspace re-check. See the Rust caller's
// docs for the honest statement of what that does and does not buy.
//
// >0 = number of cdhash bytes written to `out`
//  0 = no platform identity (unsigned, ad-hoc, or no cdhash in the signature)
// -1 = bad arguments
// -2 = the path is not a code object
// -3 = signing information unavailable
// -4 = `out` is too small for the cdhash
int sigil_cdhash_for_path(const char *path, unsigned char *out, size_t out_len) {
    if (path == NULL || out == NULL) {
        return -1;
    }
    CFStringRef path_str = CFStringCreateWithCString(NULL, path, kCFStringEncodingUTF8);
    if (path_str == NULL) {
        return -1;
    }
    CFURLRef url = CFURLCreateWithFileSystemPath(NULL, path_str, kCFURLPOSIXPathStyle, false);
    CFRelease(path_str);
    if (url == NULL) {
        return -1;
    }

    SecStaticCodeRef code = NULL;
    OSStatus st = SecStaticCodeCreateWithPath(url, kSecCSDefaultFlags, &code);
    CFRelease(url);
    if (st != errSecSuccess || code == NULL) {
        if (code != NULL) {
            CFRelease(code);
        }
        return -2;
    }

    CFDictionaryRef info = NULL;
    st = SecCodeCopySigningInformation(code, kSecCSDefaultFlags, &info);
    CFRelease(code);
    if (st != errSecSuccess || info == NULL) {
        if (info != NULL) {
            CFRelease(info);
        }
        // An unsigned binary answers here rather than erroring; either way there
        // is no platform identity to report.
        return (st == errSecCSUnsigned) ? 0 : -3;
    }

    uint32_t flags = 0;
    CFNumberRef flags_num = (CFNumberRef)CFDictionaryGetValue(info, kSecCodeInfoFlags);
    if (flags_num != NULL) {
        CFNumberGetValue(flags_num, kCFNumberSInt32Type, &flags);
    }
    CFDataRef unique = (CFDataRef)CFDictionaryGetValue(info, kSecCodeInfoUnique);
    if (unique == NULL || (flags & kSecCodeSignatureAdhoc) != 0) {
        CFRelease(info);
        return 0;
    }

    CFIndex len = CFDataGetLength(unique);
    if (len <= 0) {
        CFRelease(info);
        return 0;
    }
    if ((size_t)len > out_len) {
        CFRelease(info);
        return -4;
    }
    memcpy(out, CFDataGetBytePtr(unique), (size_t)len);
    CFRelease(info);
    return (int)len;
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
