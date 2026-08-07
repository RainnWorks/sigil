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

// The code identity of the image RUNNING as `pid`, in one resolution: its
// executable path and its cdhash (kSecCodeInfoUnique), plus whether the
// signature has a signer.
//
// This is a MEASUREMENT, not an authorization: nothing here decides whether a
// process may do anything. It exists so the lease grant key names an ancestor by
// what the platform says that RUNNING PROCESS is.
//
// Keyed on the live pid, never on a path. SecCodeCopyGuestWithAttributes with
// kSecGuestAttributePid resolves the pid to the code object the kernel is
// actually running, and SecCodeCheckValidityWithErrors then asks the platform
// whether that image is still intact. That check is the load-bearing part:
// kSecCodeInfoUnique is returned WITHOUT any validity check, so on its own a
// cdhash is only whatever the CodeDirectory claims. Measured on this platform:
// replace the file at a running process's path (in place or by rename) and the
// signing information happily reports the substituted binary's cdhash while the
// validity check turns into -67034 errSecCSStaticCodeChanged. So anything but
// errSecSuccess is reported here as "could not measure", and the caller must not
// coalesce on it. This is the same machinery sigil_peer_satisfies_requirement
// uses for the keystore gate.
//
// `*adhoc_out` distinguishes a signature with a signer from an ad-hoc one (flags
// & kSecCodeSignatureAdhoc). An ad-hoc signature has no signer at all: its
// cdhash is a digest of the binary and nothing more, so the caller tags it as a
// separate KIND of measurement rather than as a signing identity. A platform
// binary carries no certificate chain either, but the kernel's trust cache
// vouches for it, so it counts as signed.
//
// What the validity check catches is SUBSTITUTION: an image whose identity is
// not the one the kernel executed. It is not a page check. Measured: patching
// bytes under an intact CodeDirectory leaves the cdhash where it was and the
// check still succeeds, because the identity genuinely did not move; the kernel
// is what refuses to RUN a page-tampered image. A static re-validation would not
// close that either -- with default flags SecStaticCodeCheckValidity passes a
// page-tampered Mach-O, and the strict flags that refuse one
// (kSecCSCheckAllArchitectures | kSecCSStrictValidate) cost ~200ms per binary.
//
// >0 = number of cdhash bytes written to `out`; `path_out` holds the running
//      image's executable path and `*adhoc_out` is 0 (signer) or 1 (ad-hoc)
//  0 = the image validated but reports no cdhash
// -1 = bad arguments
// -2 = the pid does not resolve to a live guest (exited, or its image is gone)
// -3 = signing information unavailable
// -4 = `out` or `path_out` is too small
// -5 = the running image did not validate: it was swapped after exec
//      (-67034), or it is unsigned, or the platform refused for another reason
int sigil_guest_measure(int pid, unsigned char *out, size_t out_len, char *path_out,
                        size_t path_len, int *adhoc_out) {
    if (out == NULL || path_out == NULL || adhoc_out == NULL || path_len == 0) {
        return -1;
    }

    pid_t p = (pid_t)pid;
    CFNumberRef pid_num = CFNumberCreate(NULL, kCFNumberIntType, &p);
    if (pid_num == NULL) {
        return -3;
    }
    const void *keys[] = {kSecGuestAttributePid};
    const void *values[] = {pid_num};
    CFDictionaryRef attrs = CFDictionaryCreate(NULL, keys, values, 1,
                                               &kCFTypeDictionaryKeyCallBacks,
                                               &kCFTypeDictionaryValueCallBacks);
    CFRelease(pid_num);
    if (attrs == NULL) {
        return -3;
    }

    SecCodeRef code = NULL;
    OSStatus st = SecCodeCopyGuestWithAttributes(NULL, attrs, kSecCSDefaultFlags, &code);
    CFRelease(attrs);
    if (st != errSecSuccess || code == NULL) {
        if (code != NULL) {
            CFRelease(code);
        }
        return -2;
    }

    // The whole point of the dynamic path: does the platform still vouch for the
    // image this pid is running? A post-exec swap of the file answers -67034 here
    // and answers the substituted binary's cdhash below, so this must gate.
    st = SecCodeCheckValidityWithErrors(code, kSecCSDefaultFlags, NULL, NULL);
    if (st != errSecSuccess) {
        CFRelease(code);
        return -5;
    }

    CFDictionaryRef info = NULL;
    st = SecCodeCopySigningInformation((SecStaticCodeRef)code, kSecCSDefaultFlags, &info);
    CFRelease(code);
    if (st != errSecSuccess || info == NULL) {
        if (info != NULL) {
            CFRelease(info);
        }
        return -3;
    }

    // The path comes off the SAME guest object as the measurement, so the two can
    // never describe different processes (a pid recycled between two independent
    // lookups would).
    CFURLRef exe = (CFURLRef)CFDictionaryGetValue(info, kSecCodeInfoMainExecutable);
    if (exe == NULL ||
        !CFURLGetFileSystemRepresentation(exe, true, (UInt8 *)path_out, (CFIndex)path_len)) {
        CFRelease(info);
        return -4;
    }

    uint32_t flags = 0;
    CFNumberRef flags_num = (CFNumberRef)CFDictionaryGetValue(info, kSecCodeInfoFlags);
    if (flags_num != NULL) {
        CFNumberGetValue(flags_num, kCFNumberSInt32Type, &flags);
    }
    *adhoc_out = (flags & kSecCodeSignatureAdhoc) != 0 ? 1 : 0;

    CFDataRef unique = (CFDataRef)CFDictionaryGetValue(info, kSecCodeInfoUnique);
    if (unique == NULL) {
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
