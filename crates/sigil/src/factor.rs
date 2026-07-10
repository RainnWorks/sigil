//! The approving-factor policy: what actually gates a secret at arm time.
//!
//! This closes the finding recorded in `docs/security-claims.md` residual #1.
//! The local control-socket approver is **not** an adversarial gate: the request
//! id it waits on is same-UID readable, so a rogue same-UID peer (the exact
//! adversary Sigil exists to stop) could self-approve. So the daemon must decide,
//! before it will serve any gated request, which real approving factor it has:
//!
//! * [`Factor::Phone`] — a paired phone reachable over a [`Transport`]. Its
//!   approval is a sealed, signed [`ApprovalResponse`] a same-UID peer cannot
//!   forge. The real shipping gate.
//! * [`Factor::Biometric`] — a verified hardware keystore
//!   ([`Keystore::is_biometric`](crate::keystore::Keystore::is_biometric)). The
//!   Secure Enclave unwrap *is* the biometric.
//! * [`Factor::DevInsecure`] — neither of the above, but the operator explicitly
//!   passed `--dev-insecure` (or `SIGIL_DEV_INSECURE=1`). Only here do
//!   `SIGIL_DEV_AUTOAPPROVE` and the bare control-socket approval function, and
//!   only here does the daemon print the loud warning below.
//! * [`Factor::NoFactor`] — none of the above. The daemon **fails closed**: it
//!   arms (so `status`, pairing, and diagnostics work) but refuses every gated
//!   request. It is never silently self-approvable.
//!
//! [`Transport`]: sigil_proto::Transport
//! [`ApprovalResponse`]: sigil_proto::ApprovalResponse

/// The approving factor the daemon resolved at arm time.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Factor {
    /// A paired phone reachable over a transport (the real gate).
    Phone,
    /// A verified hardware biometric keystore (Secure Enclave).
    Biometric,
    /// No real factor, but `--dev-insecure` was given: dev auto-approve and the
    /// control socket are enabled, with a loud warning on every start.
    DevInsecure,
    /// No real factor and no `--dev-insecure`: every gated request fails closed.
    NoFactor,
}

impl Factor {
    /// A short label for the arm banner.
    pub fn label(self) -> &'static str {
        match self {
            Factor::Phone => "paired phone (sealed remote approval)",
            Factor::Biometric => "hardware biometric (Secure Enclave)",
            Factor::DevInsecure => "DEV-INSECURE (same-UID self-approval)",
            Factor::NoFactor => "none, gated requests fail closed",
        }
    }

    /// Whether this factor is a real adversarial gate (immune to same-UID
    /// self-approval). Dev-insecure and no-factor are not.
    pub fn is_real(self) -> bool {
        matches!(self, Factor::Phone | Factor::Biometric)
    }
}

/// The three signals the arm-time policy reads. Kept as plain data so the policy
/// is a pure function, unit-testable without a keystore or a relay.
#[derive(Debug, Clone, Copy)]
pub struct ArmInputs {
    /// `--dev-insecure` flag or `SIGIL_DEV_INSECURE=1`.
    pub dev_insecure: bool,
    /// A persisted phone pairing exists and a transport can be built to it.
    pub phone_paired: bool,
    /// The host keystore reports a real hardware biometric.
    pub biometric: bool,
}

/// Resolve the approving factor. A real factor (phone, then biometric) always
/// wins over the dev path, so `--dev-insecure` on a properly paired daemon does
/// not weaken it. Without any real factor, the dev switch is the only thing that
/// keeps the daemon from failing closed.
pub fn resolve(inputs: &ArmInputs) -> Factor {
    if inputs.phone_paired {
        Factor::Phone
    } else if inputs.biometric {
        Factor::Biometric
    } else if inputs.dev_insecure {
        Factor::DevInsecure
    } else {
        Factor::NoFactor
    }
}

/// True if the operator asked for the insecure dev path, via the `--dev-insecure`
/// argument or `SIGIL_DEV_INSECURE` set to a truthy value.
pub fn dev_insecure_requested(args: &[String]) -> bool {
    if args.iter().any(|a| a == "--dev-insecure") {
        return true;
    }
    matches!(std::env::var("SIGIL_DEV_INSECURE"), Ok(v) if v == "1" || v == "true")
}

/// The loud, multi-line warning that must appear on every start under
/// [`Factor::DevInsecure`]. It names the concrete risk (same-UID self-approval)
/// so a dev config can never be mistaken for a safe one. Returned as a string so
/// its content is testable; [`warn_dev_insecure`] is what actually prints it.
pub const DEV_INSECURE_WARNING: &str = "\n\
!! ============================================================ !!\n\
!!  SIGIL IS RUNNING IN --dev-insecure MODE                     !!\n\
!! ------------------------------------------------------------ !!\n\
!!  No paired phone and no hardware biometric are configured,   !!\n\
!!  so the ONLY approving factor is the local control socket    !!\n\
!!  (and SIGIL_DEV_AUTOAPPROVE, if set).                        !!\n\
!!                                                              !!\n\
!!  RISK: any process running as YOUR user can approve its own  !!\n\
!!  secret requests (same-UID self-approval). A rogue agent     !!\n\
!!  such as a compromised `claude` or `op` is exactly the       !!\n\
!!  adversary Sigil exists to stop, and this mode does not.     !!\n\
!!                                                              !!\n\
!!  Use this ONLY for local development. Pair a phone or        !!\n\
!!  provision a Secure Enclave biometric for a real gate.       !!\n\
!! ============================================================ !!\n";

/// Print [`DEV_INSECURE_WARNING`] to stderr. Called on every start under
/// [`Factor::DevInsecure`].
pub fn warn_dev_insecure() {
    eprintln!("{DEV_INSECURE_WARNING}");
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn phone_is_the_top_factor_even_with_dev_insecure() {
        // A real factor must never be downgraded by the presence of the dev flag.
        let f = resolve(&ArmInputs {
            dev_insecure: true,
            phone_paired: true,
            biometric: true,
        });
        assert_eq!(f, Factor::Phone);
        assert!(f.is_real());
    }

    #[test]
    fn biometric_wins_when_no_phone() {
        let f = resolve(&ArmInputs {
            dev_insecure: true,
            phone_paired: false,
            biometric: true,
        });
        assert_eq!(f, Factor::Biometric);
        assert!(f.is_real());
    }

    #[test]
    fn dev_insecure_only_applies_without_a_real_factor() {
        let f = resolve(&ArmInputs {
            dev_insecure: true,
            phone_paired: false,
            biometric: false,
        });
        assert_eq!(f, Factor::DevInsecure);
        assert!(!f.is_real());
    }

    #[test]
    fn no_factor_and_no_dev_flag_is_the_fail_closed_default() {
        let f = resolve(&ArmInputs {
            dev_insecure: false,
            phone_paired: false,
            biometric: false,
        });
        assert_eq!(f, Factor::NoFactor);
        assert!(!f.is_real());
    }

    #[test]
    fn dev_insecure_warning_names_the_same_uid_risk() {
        // The warning must be unmistakable about what it gives up.
        assert!(DEV_INSECURE_WARNING.contains("--dev-insecure"));
        assert!(DEV_INSECURE_WARNING.contains("same-UID self-approval"));
        assert!(DEV_INSECURE_WARNING.contains("ONLY for local development"));
        // Multi-line, per the requirement.
        assert!(DEV_INSECURE_WARNING.lines().count() > 5);
    }

    #[test]
    fn dev_insecure_flag_is_detected_from_args() {
        assert!(dev_insecure_requested(&["--dev-insecure".to_string()]));
        assert!(dev_insecure_requested(&[
            "daemon".to_string(),
            "--dev-insecure".to_string()
        ]));
        assert!(!dev_insecure_requested(&["daemon".to_string()]));
    }
}
