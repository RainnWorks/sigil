//! Build script: on macOS, compile the tiny LocalAuthentication ObjC shim
//! (`src/presence.m`) and link the frameworks it needs. The shim gives the
//! daemon a Touch-ID presence check via `LAContext.evaluatePolicy`, which needs
//! no keychain entitlement and so works from the unsigned binary (a Secure
//! Enclave key does not; it requires app-bundle signing). On non-macOS targets
//! this is a no-op.

fn main() {
    #[cfg(target_os = "macos")]
    {
        println!("cargo:rerun-if-changed=src/presence.m");
        let mut build = cc::Build::new();
        build
            .file("src/presence.m")
            .flag("-fobjc-arc")
            .flag("-Wno-unused-parameter");
        // Pin Apple's ar. A dev machine may have GNU binutils `ar` ahead of
        // Apple's on PATH, which produces a GNU-format static archive that Apple's
        // linker rejects ("invalid control bits"). /usr/bin/ar is the system ar.
        if std::path::Path::new("/usr/bin/ar").exists() {
            build.archiver("/usr/bin/ar");
        }
        build.compile("sigil_presence");
        println!("cargo:rustc-link-lib=framework=LocalAuthentication");
        println!("cargo:rustc-link-lib=framework=Foundation");
    }
}
