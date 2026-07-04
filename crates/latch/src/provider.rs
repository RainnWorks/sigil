//! The secret-provider seam.
//!
//! The daemon's core is generic: "run this command with the approved credential
//! injected so the command resolves its own secrets." The SOURCE of secrets is
//! pluggable. 1Password (`op` plus a service-account token) is provider #1;
//! bitwarden, aws-vault, doppler, and a plain env-file are future fills of this
//! same trait. The approval protocol ([`latch_proto::request`]) and the approver
//! (phone / softphone) are provider-blind: they carry opaque references and a
//! display hint, never provider mechanics.
//!
//! ## The invariant that shapes this seam
//!
//! Secret VALUES never enter daemon memory (brief invariant #2). So a provider
//! does **not** `fetch(refs) -> secret bytes` into the daemon. Instead it injects
//! a CREDENTIAL (for `op`, the service-account token) into the child's
//! environment, and the child streams the resolved secrets straight to the
//! caller's fd. That is why the trait below splits into:
//!
//! * [`SecretProvider::kind`] / [`SecretProvider::describe`] — build the
//!   provider-agnostic display for the approval screen (implemented now); and
//! * `prepare_env` / `probe` — inject the credential and enumerate what it can
//!   serve. **NEEDS-BUILD** as a general trait method: today the daemon's spawn
//!   path ([`crate::daemon`] `spawn_op`) is the `op` provider's inject step,
//!   hard-coding `OP_SERVICE_ACCOUNT_TOKEN`, and [`crate::secrets::probe_vaults`]
//!   is its probe. When provider #2 lands, lift those two into this trait
//!   (`prepare_env(&self, dek) -> Vec<(String, String)>` and
//!   `probe(&self, dek) -> Vec<String>`) so the daemon spawn path stops naming
//!   `op`. The env-injection contract must keep secret values out of daemon RAM.

use latch_proto::{RequestKind, SecretRef};

/// A pluggable source of secrets. See the module docs for the memory invariant
/// that shapes it.
pub trait SecretProvider: Send + Sync {
    /// Stable provider id, surfaced in [`SecretRef::provider`], e.g. "1password".
    fn id(&self) -> &str;

    /// The display hint for a command. A hint only; it never selects mechanism.
    fn kind(&self, command: &[String]) -> RequestKind;

    /// Describe the secrets `command` will resolve, as provider-agnostic
    /// [`SecretRef`]s for the approval screen. This is where the provider's own
    /// reference syntax is parsed; the approver never does this.
    fn describe(&self, command: &[String]) -> Vec<SecretRef>;
}

/// Provider #1: 1Password via `op` and a service-account token.
///
/// It understands `op://…` references and injects the token so the `op` child
/// resolves and streams the secret itself (never through the daemon).
#[derive(Debug, Default, Clone, Copy)]
pub struct OpProvider;

impl OpProvider {
    pub const ID: &'static str = "1password";
}

impl SecretProvider for OpProvider {
    fn id(&self) -> &str {
        Self::ID
    }

    fn kind(&self, _command: &[String]) -> RequestKind {
        // Both `op read` and `op item get` are secret reads for display purposes;
        // the readout well renders the refs the same way.
        RequestKind::SecretRead
    }

    fn describe(&self, command: &[String]) -> Vec<SecretRef> {
        command.iter().filter_map(|arg| op_reference(arg)).collect()
    }
}

/// Parse one argv token into a [`SecretRef`] if it carries an `op://` reference.
///
/// 1Password references are `op://<vault>/<item>/<field>` (optionally
/// `op://<account>/<vault>/<item>[/<section>]/<field>`). We keep the raw
/// reference opaque and build display `segments` from its path; this is display
/// metadata only (no secret value), so a partial parse is acceptable.
fn op_reference(arg: &str) -> Option<SecretRef> {
    let start = arg.find("op://")?;
    let rest = &arg[start..];
    // Stop at whitespace: the reference is one token.
    let reference = rest.split_whitespace().next().unwrap_or(rest).to_string();
    let path = &reference["op://".len()..];
    let segments: Vec<String> = path
        .split('/')
        .filter(|p| !p.is_empty())
        .map(str::to_string)
        .collect();
    if segments.is_empty() {
        return None;
    }
    // The brightest label is the item where present (second segment), else the
    // last segment.
    let label = segments
        .get(1)
        .or_else(|| segments.last())
        .cloned()
        .unwrap_or_default();
    Some(SecretRef {
        provider: OpProvider::ID.to_string(),
        reference,
        segments,
        label,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn describe_extracts_op_references_only() {
        let p = OpProvider;
        let refs = p.describe(&[
            "op".into(),
            "read".into(),
            "op://Engineering/.env/password".into(),
        ]);
        assert_eq!(refs.len(), 1);
        let r = &refs[0];
        assert_eq!(r.provider, "1password");
        assert_eq!(r.reference, "op://Engineering/.env/password");
        assert_eq!(r.segments, vec!["Engineering", ".env", "password"]);
        assert_eq!(r.label, ".env");
    }

    #[test]
    fn describe_is_empty_without_a_reference() {
        assert!(OpProvider
            .describe(&["op".into(), "vault".into(), "list".into()])
            .is_empty());
    }

    #[test]
    fn kind_is_a_display_hint() {
        assert_eq!(
            OpProvider.kind(&["op".into(), "read".into()]),
            RequestKind::SecretRead
        );
    }
}
