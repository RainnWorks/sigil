//! `latch-softphone`: the headless reference approver as a command-line tool.
//!
//! Two subcommands:
//!
//! * `pair --qr <base64url> [--policy approve|deny|lease] [--now <unix-ms>]`
//!   Scan a real daemon's QR string, print the phone's `PairingResponse` (as a
//!   base64url line the daemon verifies) to stdout and the six SAS words to
//!   stderr. This is the phone-to-Mac message of the handshake; completing the
//!   pairing (SAS confirm + DEK delivery) needs the daemon on a shared
//!   transport, which today is the in-process `LocalRelay` — so cross-process
//!   pairing waits on the network relay transport (a second `Transport` impl).
//!
//! * `demo [--policy approve|deny|lease]`
//!   Run the entire remote loop in one process against an in-memory relay: mint
//!   a QR on a mock daemon, pair a softphone to it, seal one `ApprovalRequest`,
//!   have the softphone apply the policy, and show the daemon recover (or not)
//!   the DEK from the sealed response. This is the runnable, human-inspectable
//!   demonstration of the protocol.
//!
//! Arg parsing is hand-rolled (no `clap`), matching the `latch` CLI house style.

use std::time::Duration;

use anyhow::{bail, Context};
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine;

use latch_proto::envelope::Envelope;
use latch_proto::identity::DeviceIdentity;
use latch_proto::pairing::{DaemonPairing, Dek};
use latch_proto::{
    now_ms, ApprovalRequest, Direction, LocalRelay, Provenance, RequestKind, RiskLevel, SecretRef,
    Transport,
};
use latch_softphone::{Pairing, Policy};

fn main() -> anyhow::Result<()> {
    let args: Vec<String> = std::env::args().skip(1).collect();
    match args.first().map(String::as_str) {
        Some("pair") => cmd_pair(&args[1..]),
        Some("demo") => cmd_demo(&args[1..]),
        Some("-h") | Some("--help") | None => {
            print_help();
            Ok(())
        }
        Some(other) => {
            eprintln!("latch-softphone: unknown command '{other}'\n");
            print_help();
            std::process::exit(2);
        }
    }
}

fn print_help() {
    eprintln!(
        "latch-softphone: headless reference approver\n\
         \n\
         USAGE:\n\
         \x20 latch-softphone pair --qr <base64url> [--policy approve|deny|lease] [--now <ms>]\n\
         \x20 latch-softphone demo [--policy approve|deny|lease]\n\
         \n\
         pair  scan a daemon QR, print the pairing response + SAS words\n\
         demo  run the whole pair + approve loop in-process against a local relay"
    );
}

/// Parse `--flag value` pairs into a small lookup. Unknown flags are an error.
fn parse_flags(args: &[String], allowed: &[&str]) -> anyhow::Result<Vec<(String, String)>> {
    let mut out = Vec::new();
    let mut it = args.iter();
    while let Some(a) = it.next() {
        let Some(name) = a.strip_prefix("--") else {
            bail!("unexpected argument '{a}' (expected --flag value)");
        };
        if !allowed.contains(&name) {
            bail!("unknown flag '--{name}'");
        }
        let value = it
            .next()
            .with_context(|| format!("flag '--{name}' needs a value"))?;
        out.push((name.to_string(), value.clone()));
    }
    Ok(out)
}

fn flag<'a>(flags: &'a [(String, String)], name: &str) -> Option<&'a str> {
    flags
        .iter()
        .find(|(k, _)| k == name)
        .map(|(_, v)| v.as_str())
}

fn parse_policy(flags: &[(String, String)]) -> anyhow::Result<Policy> {
    match flag(flags, "policy").unwrap_or("approve") {
        "approve" => Ok(Policy::Approve),
        "deny" => Ok(Policy::Deny),
        "lease" => Ok(Policy::Lease(Duration::from_secs(15 * 60))),
        other => bail!("unknown policy '{other}' (use approve|deny|lease)"),
    }
}

fn cmd_pair(args: &[String]) -> anyhow::Result<()> {
    let flags = parse_flags(args, &["qr", "policy", "now"])?;
    let qr = flag(&flags, "qr").context("pair needs --qr <base64url>")?;
    let policy = parse_policy(&flags)?;
    let now = match flag(&flags, "now") {
        Some(v) => v.parse().context("--now must be unix ms")?,
        None => now_ms(),
    };

    let identity = DeviceIdentity::generate();
    let (pairing, response) = Pairing::scan(identity, qr, now, policy)
        .context("scanning the QR and building the pairing response")?;

    // The response is the phone -> Mac message; the daemon verifies its tag.
    let json = serde_json::to_vec(&response).context("serializing pairing response")?;
    println!("{}", URL_SAFE_NO_PAD.encode(json));

    eprintln!("SAS words (compare against the Mac's screen):");
    eprintln!("  {}", pairing.sas_words().join(" "));
    eprintln!(
        "\nNext: the daemon verifies this response, you confirm the SAS on both\n\
         screens, and the daemon seals the DEK to this phone. Completing that\n\
         step across processes needs the network relay transport."
    );
    Ok(())
}

fn cmd_demo(args: &[String]) -> anyhow::Result<()> {
    let flags = parse_flags(args, &["policy"])?;
    let policy = parse_policy(&flags)?;
    let policy_label = flag(&flags, "policy").unwrap_or("approve").to_string();
    let now = now_ms();

    println!("latch-softphone demo · policy = {policy_label}");
    println!("--------------------------------------------------");

    // 0. Mock daemon mints a QR.
    let daemon_id = DeviceIdentity::generate();
    let daemon_id_keep = DeviceIdentity {
        signing: daemon_id.signing.clone(),
        agreement: daemon_id.agreement.clone(),
    };
    let (mut daemon, payload) =
        DaemonPairing::mint(daemon_id, vec!["lan://latch.local:4823".to_string()], now);
    let qr = payload.to_qr_string().context("qr encode")?;
    println!("1. daemon minted QR ({} chars)", qr.len());

    // 1. Softphone scans and responds.
    let phone_id = DeviceIdentity::generate();
    let (mut pairing, resp) = Pairing::scan(phone_id, &qr, now + 500, policy)?;
    println!(
        "2. softphone scanned, SAS = {}",
        pairing.sas_words().join(" ")
    );

    // 2. Daemon verifies, both confirm SAS, daemon delivers the DEK.
    daemon.receive_response(&resp, now + 1_000)?;
    assert_eq!(daemon.sas_words().unwrap(), pairing.sas_words());
    daemon.confirm()?;
    pairing.confirm()?;
    let dek = Dek::generate();
    let dek_hex = hex(dek.as_bytes());
    let dek_env = daemon.deliver_dek(&dek, 1)?;
    let phone = pairing.receive_dek(&dek_env)?;
    println!(
        "3. paired · mailbox {} · DEK delivered",
        &hex(&phone.mailbox())[..16]
    );

    // 3. Daemon seals one approval request into the phone's inbox.
    let relay = LocalRelay::new();
    let mailbox = phone.mailbox();
    let request = ApprovalRequest {
        request_id: "demo-req-1".into(),
        kind: RequestKind::SecretRead,
        command: vec![
            "op".into(),
            "read".into(),
            "op://Engineering/.env/password".into(),
        ],
        secrets: vec![SecretRef {
            provider: "1password".into(),
            reference: "op://Engineering/.env/password".into(),
            segments: vec!["Engineering".into(), ".env".into(), "password".into()],
            label: ".env".into(),
        }],
        ssh: None,
        provenance: Provenance {
            process_chain: vec!["zsh".into(), "claude".into(), "op".into()],
            cwd: "/Projects/rowm".into(),
            machine: "demo-mac".into(),
            requested_at: now,
        },
        risk: RiskLevel::Routine,
        reason: None,
        expires_at: now + 90_000,
        timeout_ms: 90_000,
    };
    let req_env = Envelope::seal(
        &request,
        mailbox,
        2,
        &daemon_id_keep.signing,
        &phone.phone_identity(),
    )
    .context("seal request")?;
    relay.send(mailbox, Direction::ToPhone, &req_env)?;
    println!(
        "4. daemon sealed request '{}' -> phone inbox",
        request.request_id
    );

    // 4. Softphone serves one turn: opens, decides, seals the response.
    let (handled, decision) = phone
        .serve_once(&relay, Duration::from_millis(500))?
        .context("softphone received no request")?;
    println!(
        "5. softphone decided {decision:?} for '{}'",
        handled.request_id
    );

    // 5. Daemon reads the response and (on approve) recovers the DEK.
    let resp_env = relay
        .recv(mailbox, Direction::ToDaemon, Duration::from_millis(500))?
        .context("no response from softphone")?;
    let mut guard = latch_proto::ReplayGuard::new();
    let response: latch_proto::ApprovalResponse = resp_env
        .open(
            &phone.phone_identity(),
            &daemon_id_keep.agreement,
            &mut guard,
        )
        .context("open response")?;
    match response.dek() {
        Some(recovered) => {
            let ok = hex(recovered.as_bytes()) == dek_hex;
            println!(
                "6. daemon recovered DEK from the response: {} (matches delivered DEK: {ok})",
                &hex(recovered.as_bytes())[..16]
            );
            println!("\nRESULT: approve path complete. The daemon could now decrypt the token.");
        }
        None => {
            println!("6. response carried no DEK (denied); daemon fails closed, no secret served.");
            println!("\nRESULT: deny path complete. Nothing released.");
        }
    }

    let _ = decision;
    Ok(())
}

fn hex(bytes: &[u8]) -> String {
    let mut s = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        s.push_str(&format!("{b:02x}"));
    }
    s
}
