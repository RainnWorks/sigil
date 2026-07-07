//! The SSH agent: an RFC 9987 unix-socket listener that serves Tom's 1Password
//! SSH keys and gates every signature through the same phone approval loop as an
//! `op` secret release.
//!
//! ## What this is
//!
//! The SSH agent protocol (RFC 9987, plus OpenSSH's `PROTOCOL.agent` for the
//! `session-bind@openssh.com` extension) is a length-prefixed binary protocol
//! over a unix socket: each message is `uint32 length` then `byte type` then
//! type-specific fields, where every variable field is an SSH `string`
//! (`uint32 len` + bytes). We hand-roll the `string`/`u32` helpers ([`Reader`] /
//! [`Writer`]) in the same spirit as the envelope serde rather than pulling in
//! `ssh-encoding`.
//!
//! A real client (`ssh`, `git`, `ssh-add -l`) needs exactly two request types:
//!
//! * `REQUEST_IDENTITIES (11) -> IDENTITIES_ANSWER (12)` — "what keys do you
//!   have?"; we answer with each served public key's wire blob + comment.
//! * `SIGN_REQUEST (13) -> SIGN_RESPONSE (14)` — the approval-worthy event; we
//!   gate it on the phone, fetch the private key per-signature, sign, and wipe.
//!
//! We also accept and record `session-bind@openssh.com` (the server host key, for
//! the approval screen's destination line). Everything else — add/remove/lock,
//! other extensions — is refused with `SSH_AGENT_FAILURE (5)`. `ssh-add <file>`
//! failing cleanly is correct: our keys come from 1Password, not pushed in.
//!
//! ## Custody (v1) and the residual it carries
//!
//! Unlike an `op` secret release — where the secret never enters daemon memory
//! (the `op` child streams straight to the caller's fd) — the agent is the one
//! doing the crypto, so **the private key must be in daemon RAM for the duration
//! of one signature**. On an approved `SIGN_REQUEST` the daemon fetches the key
//! (`op read "op://<shared-vault>/<item>/private key?ssh-format=openssh"`) into a
//! [`Zeroizing`] buffer, decodes with [`ssh_key`], signs, and zeroizes at once.
//! Because the service-account token can read the *whole* key, a compromise at
//! the moment of an approved request leaks durable signing power, not one
//! signature — strictly worse than the secret case, and the reason v2 moves keys
//! into the Secure Enclave. See `docs/design/ssh-agent.md` §4.
//!
//! The key MUST live in a service-account-visible shared vault (Engineering/…),
//! never Personal (the SA cannot see Personal at all).

use std::io::{self, Read, Write};
use std::os::unix::net::UnixStream;
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};
use zeroize::Zeroizing;

use crate::secrets::Token;

// --- RFC 9987 message types -------------------------------------------------

/// Generic failure / refusal. The reply for anything we do not implement.
const SSH_AGENT_FAILURE: u8 = 5;
/// Generic success. The ack for a `session-bind` we accepted.
const SSH_AGENT_SUCCESS: u8 = 6;
/// Client -> agent: "list your identities".
const SSH2_AGENTC_REQUEST_IDENTITIES: u8 = 11;
/// Agent -> client: the identity list.
const SSH2_AGENT_IDENTITIES_ANSWER: u8 = 12;
/// Client -> agent: "sign this data with this key".
const SSH2_AGENTC_SIGN_REQUEST: u8 = 13;
/// Agent -> client: the signature.
const SSH2_AGENT_SIGN_RESPONSE: u8 = 14;
/// Client -> agent: a vendor extension (we accept only `session-bind`).
const SSH_AGENTC_EXTENSION: u8 = 27;

/// The OpenSSH extension that carries the server host key on the agent
/// connection, sent before the sign request by OpenSSH >= 8.9.
const SESSION_BIND: &[u8] = b"session-bind@openssh.com";

/// Reject any agent message whose framed body is larger than this. A real
/// request (sign data is a session-id transcript) is a few hundred bytes;
/// this is a generous ceiling that stops a hostile client forcing a large
/// allocation.
const MAX_MESSAGE_LEN: usize = 256 * 1024;

// --- hand-rolled SSH wire helpers -------------------------------------------

/// A cursor over an agent message body, decoding SSH `u32`/`string`/`bool`
/// fields. Every read is bounds-checked and returns `None` on a short buffer, so
/// a truncated or hostile message fails closed to a refusal rather than panicking.
struct Reader<'a> {
    buf: &'a [u8],
    pos: usize,
}

impl<'a> Reader<'a> {
    fn new(buf: &'a [u8]) -> Self {
        Self { buf, pos: 0 }
    }

    fn take(&mut self, n: usize) -> Option<&'a [u8]> {
        let end = self.pos.checked_add(n)?;
        let slice = self.buf.get(self.pos..end)?;
        self.pos = end;
        Some(slice)
    }

    fn u32(&mut self) -> Option<u32> {
        let b = self.take(4)?;
        Some(u32::from_be_bytes([b[0], b[1], b[2], b[3]]))
    }

    /// An SSH `string`: a `u32` length then that many bytes.
    fn string(&mut self) -> Option<&'a [u8]> {
        let n = self.u32()? as usize;
        self.take(n)
    }
}

/// Builds an agent message body, then frames it with the leading `u32` length.
#[derive(Default)]
struct Writer {
    buf: Vec<u8>,
}

impl Writer {
    fn u8(&mut self, v: u8) {
        self.buf.push(v);
    }

    fn u32(&mut self, v: u32) {
        self.buf.extend_from_slice(&v.to_be_bytes());
    }

    /// An SSH `string`: a `u32` length then the bytes.
    fn string(&mut self, s: &[u8]) {
        self.u32(s.len() as u32);
        self.buf.extend_from_slice(s);
    }

    /// Prepend the `u32` frame length and yield the wire bytes.
    fn frame(self) -> Vec<u8> {
        let mut out = Vec::with_capacity(4 + self.buf.len());
        out.extend_from_slice(&(self.buf.len() as u32).to_be_bytes());
        out.extend_from_slice(&self.buf);
        out
    }
}

/// A one-byte-type reply message (`FAILURE` / `SUCCESS`), framed.
fn single(msg_type: u8) -> Vec<u8> {
    let mut w = Writer::default();
    w.u8(msg_type);
    w.frame()
}

/// Read one framed agent message body (type byte + payload), or `None` at a
/// clean EOF (the client hung up). Enforces [`MAX_MESSAGE_LEN`].
fn read_message<R: Read>(stream: &mut R) -> io::Result<Option<Vec<u8>>> {
    let mut len = [0u8; 4];
    match stream.read_exact(&mut len) {
        Ok(()) => {}
        Err(e) if e.kind() == io::ErrorKind::UnexpectedEof => return Ok(None),
        Err(e) => return Err(e),
    }
    let n = u32::from_be_bytes(len) as usize;
    if n == 0 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "empty agent message",
        ));
    }
    if n > MAX_MESSAGE_LEN {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "agent message exceeds maximum length",
        ));
    }
    let mut body = vec![0u8; n];
    stream.read_exact(&mut body)?;
    Ok(Some(body))
}

// --- served identities and the backend seam ---------------------------------

/// One SSH identity Sigil serves: the public-key wire blob and comment for
/// `IDENTITIES_ANSWER`, plus the 1Password reference used to fetch the private
/// key per-signature and the display fields for the approval screen.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ServedIdentity {
    /// The SSH public-key wire blob (e.g. `"ssh-ed25519"` + 32-byte point). This
    /// is what a client matches its target against and what we compare a
    /// `SIGN_REQUEST`'s `key_blob` to.
    pub key_blob: Vec<u8>,
    /// Human label shown by `ssh-add -l`.
    pub comment: String,
    /// The op reference for the private key, e.g.
    /// `op://Engineering/GitHub/private key`. The `?ssh-format=openssh` query is
    /// appended at fetch time. Must resolve inside a shared, SA-visible vault.
    pub key_ref: String,
    /// The item label, shown brightest on the approval screen.
    pub label: String,
    /// The public key's `SHA256:…` fingerprint, for `sigil ssh list`.
    pub fingerprint: String,
}

/// The best-effort destination for the approval screen, derived from the
/// `session-bind` host key. Honest by construction: either a name we actually
/// found in `~/.ssh/known_hosts`, or the host-key fingerprint — never a
/// fabricated hostname (the agent protocol carries no hostname).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct HostContext {
    pub host: String,
}

/// The daemon-side capability the listener needs, kept as a trait so the wire
/// protocol is unit-testable against a fake signer with no `op`, keystore, or
/// phone. The daemon `Core` implements it (identities from config;
/// [`approve_and_sign`](SshBackend::approve_and_sign) via the approval gate +
/// per-signature `op` fetch + ed25519 sign).
pub trait SshBackend: Send + Sync {
    /// The identities to advertise in `IDENTITIES_ANSWER`.
    fn identities(&self) -> Vec<ServedIdentity>;

    /// Gate `data` on the phone (showing `id.label`, the derived `host`, and a
    /// hash of the data — never the raw bytes), and on approval fetch the private
    /// key, sign, and wipe. Returns the SSH signature blob
    /// (`string algorithm` + `string signature`) on approval, or `None` on
    /// denial or any failure (fail closed: no signature without an approval).
    fn approve_and_sign(&self, req: SignRequest<'_>) -> Option<Vec<u8>>;
}

/// One approval-gated signing request handed to the backend.
pub struct SignRequest<'a> {
    /// The identity whose private key to sign with.
    pub id: &'a ServedIdentity,
    /// The exact bytes to sign, opaque to us and signed verbatim.
    pub data: &'a [u8],
    /// The derived destination for the approval screen.
    pub host: &'a HostContext,
    /// The kernel-verified pid of the process on the other end of the socket
    /// (the `ssh`/`git` that connected), for caller-scoped bookkeeping. `None`
    /// if the peer pid could not be read.
    pub caller_pid: Option<i32>,
}

// --- the pluggable key source (signer) seam ---------------------------------

/// A pluggable SSH key SOURCE. SSH is a distinct integration — its event is a
/// signature, not an env injection — but the *key source* is as pluggable as the
/// [`SecretProvider`](crate::provider::SecretProvider) seam is for secrets. Sigil
/// stays the universal phone-gate regardless of where the key lives: the daemon
/// applies the approval gate, then delegates the key-source-specific signing to
/// the owning signer here.
///
/// Shipping impls:
/// * [`OpSshSigner`] (the default) — fetch the key from 1Password per signature
///   via the service account, sign, zeroize. The honest residual: the key is in
///   daemon RAM for one signature (see the module custody note).
/// * [`FileSshSigner`] — sign from a local `~/.ssh/id_*` file, for users who do
///   not keep their keys in 1Password. Proves the seam is real, not op-shaped.
///
/// Future impls are additive: a Secure-Enclave-resident signer (v2, key never
/// leaves hardware) or a proxy-to-another-agent signer plug in here without
/// touching the wire listener or the phone gate.
pub trait SshSigner: Send + Sync {
    /// The identities this source can serve, for `IDENTITIES_ANSWER`.
    fn identities(&self) -> Vec<ServedIdentity>;

    /// Whether the daemon must decrypt a stored account token before this signer
    /// can sign (true for [`OpSshSigner`]: the SA token authenticates the fetch;
    /// false for [`FileSshSigner`]: the key is a local file).
    fn needs_account(&self) -> bool;

    /// Produce the SSH signature blob (`string algorithm` + `string signature`)
    /// over `data` with `id`'s key. Called **after** the daemon's phone approval.
    /// `credential` is the decrypted account token when [`needs_account`] is true,
    /// else `None`. Returns `None` on any failure (fail closed).
    ///
    /// [`needs_account`]: SshSigner::needs_account
    fn sign(&self, id: &ServedIdentity, data: &[u8], credential: Option<&Token>)
        -> Option<Vec<u8>>;

    /// True if this signer serves `key_blob` (so the daemon can route a sign
    /// request to its owning signer).
    fn owns(&self, key_blob: &[u8]) -> bool {
        self.identities().iter().any(|i| i.key_blob == key_blob)
    }
}

/// The default signer: fetch-per-signature from 1Password via the service
/// account. Holds the resolved op identities and the `op` binary to shell out to
/// (`None` uses PATH discovery; tests point it at a fake `op`).
pub struct OpSshSigner {
    identities: Vec<ServedIdentity>,
    op_path: Option<PathBuf>,
}

impl OpSshSigner {
    pub fn new(identities: Vec<ServedIdentity>, op_path: Option<PathBuf>) -> Self {
        Self {
            identities,
            op_path,
        }
    }
}

impl SshSigner for OpSshSigner {
    fn identities(&self) -> Vec<ServedIdentity> {
        self.identities.clone()
    }

    fn needs_account(&self) -> bool {
        true
    }

    fn sign(
        &self,
        id: &ServedIdentity,
        data: &[u8],
        credential: Option<&Token>,
    ) -> Option<Vec<u8>> {
        let token = credential?;
        let op = self.op_path.clone().or_else(crate::paths::find_real_op)?;
        // fetch_and_sign holds the key in a Zeroizing buffer for the one
        // signature and wipes it (the v1 custody exception; see module docs).
        fetch_and_sign(&op, token, &id.key_ref, data)
    }
}

/// A file-based signer: sign from a local OpenSSH private key file (e.g.
/// `~/.ssh/id_ed25519`). The second reference impl, for users who do not keep
/// their SSH keys in 1Password. Needs no account credential.
///
/// The private key is read into a [`Zeroizing`] buffer for the one signature and
/// wiped, matching the op signer's custody discipline; v1 serves unencrypted
/// ed25519 keys only (a passphrase-encrypted key fails to decode and fails
/// closed to no signature).
pub struct FileSshSigner {
    /// (served identity, private-key file path) pairs.
    keys: Vec<(ServedIdentity, PathBuf)>,
}

impl FileSshSigner {
    pub fn new(keys: Vec<(ServedIdentity, PathBuf)>) -> Self {
        Self { keys }
    }
}

impl SshSigner for FileSshSigner {
    fn identities(&self) -> Vec<ServedIdentity> {
        self.keys.iter().map(|(id, _)| id.clone()).collect()
    }

    fn needs_account(&self) -> bool {
        false
    }

    fn sign(
        &self,
        id: &ServedIdentity,
        data: &[u8],
        _credential: Option<&Token>,
    ) -> Option<Vec<u8>> {
        let (_, path) = self.keys.iter().find(|(i, _)| i.key_blob == id.key_blob)?;
        let pem = Zeroizing::new(std::fs::read(path).ok()?);
        sign_openssh_ed25519(&pem, data)
    }
}

// --- the connection handler -------------------------------------------------

/// Serve one agent connection until the client hangs up. Reads the peer pid once
/// (kernel-verified, never client-claimed) and drives the request loop; a single
/// connection may carry a `session-bind` then a `SIGN_REQUEST`, so per-connection
/// state (the bound host key) lives here.
pub fn handle_connection(backend: &dyn SshBackend, mut stream: UnixStream) -> io::Result<()> {
    let caller_pid = crate::lease::peer_pid(std::os::fd::AsRawFd::as_raw_fd(&stream));
    let mut bound_hostkey: Option<Vec<u8>> = None;
    while let Some(body) = read_message(&mut stream)? {
        let reply = respond(backend, &body, &mut bound_hostkey, caller_pid);
        stream.write_all(&reply)?;
    }
    Ok(())
}

/// Dispatch one message body to its reply bytes. Pure over the backend and the
/// per-connection bound host key, so it is directly testable.
fn respond(
    backend: &dyn SshBackend,
    body: &[u8],
    bound_hostkey: &mut Option<Vec<u8>>,
    caller_pid: Option<i32>,
) -> Vec<u8> {
    let Some((&msg_type, payload)) = body.split_first() else {
        return single(SSH_AGENT_FAILURE);
    };
    match msg_type {
        SSH2_AGENTC_REQUEST_IDENTITIES => identities_answer(backend),
        SSH2_AGENTC_SIGN_REQUEST => sign(backend, payload, bound_hostkey.as_deref(), caller_pid),
        SSH_AGENTC_EXTENSION => extension(payload, bound_hostkey),
        // add/remove/lock/unlock and any other type: we serve 1Password keys and
        // hold no lock of our own, so refuse. `ssh-add <file>` failing here is
        // the correct, clean outcome.
        _ => single(SSH_AGENT_FAILURE),
    }
}

/// `IDENTITIES_ANSWER`: `u32 nkeys` then, per key, `string key_blob` +
/// `string comment`.
fn identities_answer(backend: &dyn SshBackend) -> Vec<u8> {
    let ids = backend.identities();
    let mut w = Writer::default();
    w.u8(SSH2_AGENT_IDENTITIES_ANSWER);
    w.u32(ids.len() as u32);
    for id in &ids {
        w.string(&id.key_blob);
        w.string(id.comment.as_bytes());
    }
    w.frame()
}

/// `SIGN_REQUEST`: `string key_blob`, `string data`, `u32 flags`. For ed25519
/// the flags are ignored (they select the RSA hash only). We match the key blob
/// to a served identity, derive the destination, gate + sign, and reply
/// `SIGN_RESPONSE` (`string signature`) or `FAILURE`.
fn sign(
    backend: &dyn SshBackend,
    payload: &[u8],
    bound_hostkey: Option<&[u8]>,
    caller_pid: Option<i32>,
) -> Vec<u8> {
    let mut r = Reader::new(payload);
    let (Some(key_blob), Some(data)) = (r.string(), r.string()) else {
        return single(SSH_AGENT_FAILURE);
    };
    // flags are present on the wire but ignored for ed25519; read-and-drop.
    let _flags = r.u32().unwrap_or(0);

    let ids = backend.identities();
    let Some(id) = ids.iter().find(|i| i.key_blob == key_blob) else {
        // We were asked to sign with a key we do not serve.
        return single(SSH_AGENT_FAILURE);
    };
    let host = derive_host(bound_hostkey);
    match backend.approve_and_sign(SignRequest {
        id,
        data,
        host: &host,
        caller_pid,
    }) {
        Some(sig_blob) => {
            let mut w = Writer::default();
            w.u8(SSH2_AGENT_SIGN_RESPONSE);
            w.string(&sig_blob);
            w.frame()
        }
        None => single(SSH_AGENT_FAILURE),
    }
}

/// `EXTENSION`: `string extension_name` then extension-specific fields. We
/// accept only `session-bind@openssh.com`, recording its host key for the
/// approval screen and acking with `SUCCESS`. Every other extension is refused
/// with `FAILURE`, which is protocol-legal and clients tolerate.
fn extension(payload: &[u8], bound_hostkey: &mut Option<Vec<u8>>) -> Vec<u8> {
    let mut r = Reader::new(payload);
    let Some(name) = r.string() else {
        return single(SSH_AGENT_FAILURE);
    };
    if name == SESSION_BIND {
        // session-bind@openssh.com: string hostkey, string session-id,
        // string signature, bool is_forwarding. We only need the host key; we do
        // not verify the host's signature here (the client already validated the
        // host against known_hosts before binding — we use the key solely to
        // label the approval screen, and fall back to a fingerprint regardless).
        if let Some(hostkey) = r.string() {
            *bound_hostkey = Some(hostkey.to_vec());
            return single(SSH_AGENT_SUCCESS);
        }
    }
    single(SSH_AGENT_FAILURE)
}

// --- host derivation --------------------------------------------------------

/// Derive the destination shown on the approval screen from the `session-bind`
/// host key, best-effort and honest:
///
/// * no `session-bind` (a client that does not send it) -> a plain marker;
/// * host key found in `~/.ssh/known_hosts` -> that hostname;
/// * otherwise -> the host key's `SHA256:…` fingerprint.
///
/// Trust caveat: the host key is supplied by the (untrusted, same-UID) client and
/// we do not verify the host's signature over it, so a malicious client can name
/// any destination — including a real, public host key like github.com's. The
/// host line is therefore *advisory context*, not a security boundary. The gate
/// is the approval itself: the human should treat an unexpected signature request
/// as the signal, and the key label + data fingerprint are the load-bearing
/// fields. v2 (SE-resident keys) does not change this; it is inherent to the
/// agent protocol carrying no authenticated hostname.
fn derive_host(bound_hostkey: Option<&[u8]>) -> HostContext {
    match bound_hostkey {
        None => HostContext {
            host: "(host not bound)".to_string(),
        },
        Some(blob) => {
            if let Some(name) = known_hosts_lookup(blob, &known_hosts_path()) {
                HostContext { host: name }
            } else {
                HostContext {
                    host: hostkey_fingerprint(blob),
                }
            }
        }
    }
}

/// `~/.ssh/known_hosts`, overridable with `SIGIL_KNOWN_HOSTS` (tests).
fn known_hosts_path() -> PathBuf {
    if let Some(p) = std::env::var_os("SIGIL_KNOWN_HOSTS") {
        return PathBuf::from(p);
    }
    std::env::var_os("HOME")
        .map(|h| PathBuf::from(h).join(".ssh").join("known_hosts"))
        .unwrap_or_else(|| PathBuf::from("/dev/null"))
}

/// Reverse-lookup a host-key wire blob to a hostname in a known_hosts file.
///
/// Returns the first host pattern whose base64 key matches `blob`. Hashed
/// entries (`|1|…`) cannot be reversed and are skipped; marker lines
/// (`@cert-authority`, `@revoked`) have the marker stripped; the first
/// comma-separated pattern is returned with any `[host]:port` brackets removed.
fn known_hosts_lookup(blob: &[u8], path: &Path) -> Option<String> {
    use base64::engine::general_purpose::STANDARD as B64;
    use base64::Engine;
    let want = B64.encode(blob);
    let contents = std::fs::read_to_string(path).ok()?;
    for line in contents.lines() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        let mut fields = line.split_whitespace();
        let mut first = fields.next()?;
        // A marker line (@cert-authority / @revoked) shifts the columns by one.
        if first.starts_with('@') {
            first = fields.next()?;
        }
        let hosts = first;
        // Skip hashed host entries: they cannot be reversed to a name.
        if hosts.starts_with("|1|") {
            continue;
        }
        let _keytype = fields.next()?;
        let key_b64 = fields.next()?;
        if key_b64 == want {
            let pattern = hosts.split(',').next().unwrap_or(hosts);
            return Some(normalize_host_pattern(pattern));
        }
    }
    None
}

/// Strip a `[host]:port` wrapper down to `host`; leave a bare host untouched.
fn normalize_host_pattern(pattern: &str) -> String {
    if let Some(rest) = pattern.strip_prefix('[') {
        if let Some((host, _port)) = rest.split_once("]:") {
            return host.to_string();
        }
    }
    pattern.to_string()
}

/// The `SHA256:…` fingerprint of a host-key wire blob, matching the form
/// OpenSSH shows. Uses `ssh-key`'s own fingerprint when the blob parses as a
/// known key type, else a direct SHA-256 over the blob in the same rendering.
fn hostkey_fingerprint(blob: &[u8]) -> String {
    if let Ok(pk) = ssh_key::PublicKey::from_bytes(blob) {
        return pk.fingerprint(ssh_key::HashAlg::Sha256).to_string();
    }
    sha256_fingerprint(blob)
}

/// `SHA256:<base64-no-pad>` over arbitrary bytes, the OpenSSH fingerprint
/// rendering. Used for the data-to-sign hash and as a host-key fallback.
pub fn sha256_fingerprint(bytes: &[u8]) -> String {
    use base64::engine::general_purpose::STANDARD_NO_PAD as B64;
    use base64::Engine;
    use sha2::{Digest, Sha256};
    let digest = Sha256::digest(bytes);
    format!("SHA256:{}", B64.encode(digest))
}

// --- fetch-per-signature: op read -> decode -> ed25519 sign -> zeroize -------

/// Fetch the OpenSSH private key for `reference` via the service account and
/// produce the SSH signature blob over `data`, holding the key material for the
/// one signature only.
///
/// This is the v1 custody exception (see the module docs): the key lands in a
/// [`Zeroizing`] buffer, is decoded, signs, and is wiped when the buffer drops
/// at the end of this function. It is never written to disk and never logged.
///
/// Returns the inner signature blob (`string algorithm` + `string signature`),
/// ready to be wrapped as the `SIGN_RESPONSE`'s single `string` field, or `None`
/// on any failure (missing `op`, a non-ed25519 key, a decode/sign error).
pub fn fetch_and_sign(op: &Path, token: &[u8], reference: &str, data: &[u8]) -> Option<Vec<u8>> {
    let pem = op_read_openssh_key(op, token, reference)?;
    sign_openssh_ed25519(&pem, data)
}

/// Run `op read "<reference>?ssh-format=openssh"` with the service-account token
/// injected, capturing stdout into a [`Zeroizing`] buffer so the key material
/// never lands in an un-wiped allocation. Returns `None` on a non-zero exit or a
/// spawn failure (fail closed).
fn op_read_openssh_key(op: &Path, token: &[u8], reference: &str) -> Option<Zeroizing<Vec<u8>>> {
    use std::process::{Command, Stdio};

    // `op` accepts the format as a query parameter on the reference. Appending it
    // here keeps the stored reference clean (`.../private key`).
    let reference = format!("{reference}?ssh-format=openssh");
    let token = std::str::from_utf8(token).ok()?;

    let mut child = Command::new(op)
        .args(["read", &reference])
        .env("OP_SERVICE_ACCOUNT_TOKEN", token)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()
        .ok()?;

    // Read stdout ourselves into a wiped buffer rather than `Command::output`,
    // whose captured `Vec` would not be zeroized.
    let mut pem = Zeroizing::new(Vec::new());
    child.stdout.take()?.read_to_end(&mut pem).ok()?;
    let status = child.wait().ok()?;
    if !status.success() || pem.is_empty() {
        return None;
    }
    Some(pem)
}

/// Decode an `-----BEGIN OPENSSH PRIVATE KEY-----` body and sign `data` with it,
/// producing the SSH signature blob. ed25519-only: a key of any other type
/// yields `None` (we neither advertise nor sign other types in v1).
fn sign_openssh_ed25519(pem: &[u8], data: &[u8]) -> Option<Vec<u8>> {
    use signature::Signer;

    // The decoded key's secret scalar lives inside `ssh_key::PrivateKey`, which
    // (with ed25519-dalek underneath) zeroizes its key material on drop; `key`
    // drops at the end of this function, right after the one signature. The
    // source PEM in the caller's `Zeroizing` buffer is wiped there too.
    let key = ssh_key::PrivateKey::from_openssh(pem).ok()?;
    if key.algorithm() != ssh_key::Algorithm::Ed25519 {
        return None;
    }
    let sig: ssh_key::Signature = key.try_sign(data).ok()?;
    Some(encode_signature(&sig))
}

/// Hand-encode an [`ssh_key::Signature`] as the SSH wire blob
/// `string algorithm_name` + `string raw_signature`, using our own writer rather
/// than the `ssh-encoding` `Encode` impl (keeps the wire construction in one
/// place). For ed25519 this is `"ssh-ed25519"` + the 64-byte signature.
fn encode_signature(sig: &ssh_key::Signature) -> Vec<u8> {
    let mut w = Writer::default();
    w.string(sig.algorithm().as_str().as_bytes());
    w.string(sig.as_bytes());
    // The frame length prefix is not part of a nested signature blob, so take the
    // body only.
    w.buf
}

// --- the served-key config (`~/.sigil/ssh-keys.json`) -----------------------

/// One configured SSH identity on disk. Holds only public material and 1Password
/// coordinates — never key bytes — so the store stays inert like the account
/// catalogue. The public key line is what we advertise; the vault/item locate
/// the private key to fetch per-signature.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct SshKeyEntry {
    /// The OpenSSH public-key line, e.g. `ssh-ed25519 AAAA… comment`.
    pub public_key: String,
    /// The vault holding the SSH Key item (must be SA-visible / shared).
    pub vault: String,
    /// The item name.
    pub item: String,
    /// The private-key field name (`op` calls it `private key`).
    #[serde(default = "default_field")]
    pub field: String,
    /// Optional comment override; the public-key line's own comment is used when
    /// this is empty.
    #[serde(default)]
    pub comment: String,
}

fn default_field() -> String {
    "private key".to_string()
}

/// One configured file-based SSH identity on disk: a path to a local OpenSSH
/// private key (e.g. `~/.ssh/id_ed25519`). The public key is read from the
/// sibling `<path>.pub` for `IDENTITIES_ANSWER`; the private key is read only at
/// sign time. This is the [`FileSshSigner`] source — proof the signer seam is
/// pluggable, not 1Password-bound.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct SshFileEntry {
    /// Path to the OpenSSH private key file. `<path>.pub` must exist.
    pub path: String,
    /// Optional comment override; the `.pub` line's own comment is used when empty.
    #[serde(default)]
    pub comment: String,
}

/// The persisted list of served SSH identities, at `~/.sigil/ssh-keys.json`.
/// Two sources: `keys` (fetched from 1Password per signature) and `files` (local
/// key files). Each becomes a distinct [`SshSigner`] at arm time.
#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct SshKeyConfig {
    #[serde(default)]
    pub keys: Vec<SshKeyEntry>,
    #[serde(default)]
    pub files: Vec<SshFileEntry>,
}

impl SshKeyConfig {
    /// `~/.sigil/ssh-keys.json`, or `$SIGIL_HOME/ssh-keys.json` (tests).
    pub fn path() -> Option<PathBuf> {
        crate::paths::sigil_home().map(|h| h.join("ssh-keys.json"))
    }

    /// Load the config, returning an empty one if the file is absent.
    pub fn load() -> io::Result<Self> {
        let Some(path) = Self::path() else {
            return Ok(Self::default());
        };
        match std::fs::read(&path) {
            Ok(bytes) => serde_json::from_slice(&bytes)
                .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e)),
            Err(e) if e.kind() == io::ErrorKind::NotFound => Ok(Self::default()),
            Err(e) => Err(e),
        }
    }

    /// Persist the config, parent dir 0700 and file 0600 (public data, but kept
    /// consistent with the rest of `~/.sigil`).
    pub fn save(&self) -> io::Result<()> {
        use std::os::unix::fs::PermissionsExt;
        let path = Self::path().ok_or_else(|| io::Error::other("no SIGIL_HOME/HOME for config"))?;
        if let Some(dir) = path.parent() {
            std::fs::create_dir_all(dir)?;
            std::fs::set_permissions(dir, std::fs::Permissions::from_mode(0o700))?;
        }
        let json = serde_json::to_vec_pretty(self)
            .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))?;
        std::fs::write(&path, json)?;
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600))?;
        Ok(())
    }

    /// Resolve every entry to a [`ServedIdentity`], parsing its public-key line
    /// into the wire blob and fingerprint. Non-ed25519 or unparseable entries are
    /// dropped (with a stderr note) rather than failing the whole agent: v1
    /// serves ed25519 only.
    pub fn served_identities(&self) -> Vec<ServedIdentity> {
        self.keys
            .iter()
            .filter_map(|e| match resolve_identity(e) {
                Some(id) => Some(id),
                None => {
                    eprintln!(
                        "sigil sshagent: skipping key op://{}/{} (not a usable ed25519 public key)",
                        e.vault, e.item
                    );
                    None
                }
            })
            .collect()
    }

    /// Resolve every file entry to a `(served identity, private-key path)` pair,
    /// reading each `<path>.pub` for the public blob. Unparseable / non-ed25519 /
    /// missing-`.pub` entries are dropped with a stderr note (v1 ed25519 only).
    pub fn file_keys(&self) -> Vec<(ServedIdentity, PathBuf)> {
        self.files
            .iter()
            .filter_map(|e| match resolve_file_identity(e) {
                Some(id) => Some((id, PathBuf::from(&e.path))),
                None => {
                    eprintln!(
                        "sigil sshagent: skipping file key {} (need an ed25519 key with a sibling .pub)",
                        e.path
                    );
                    None
                }
            })
            .collect()
    }
}

/// Parse one config entry's public-key line into a served identity. Returns
/// `None` if the line does not parse or is not ed25519 (v1 serves ed25519 only).
/// Public so `sigil ssh add` can validate an entry before persisting it.
pub fn resolve_identity(e: &SshKeyEntry) -> Option<ServedIdentity> {
    let pk = ssh_key::PublicKey::from_openssh(&e.public_key).ok()?;
    if pk.algorithm() != ssh_key::Algorithm::Ed25519 {
        return None;
    }
    let key_blob = pk.to_bytes().ok()?;
    let comment = if e.comment.is_empty() {
        pk.comment().to_string()
    } else {
        e.comment.clone()
    };
    Some(ServedIdentity {
        key_blob,
        comment,
        key_ref: format!("op://{}/{}/{}", e.vault, e.item, e.field),
        label: e.item.clone(),
        fingerprint: pk.fingerprint(ssh_key::HashAlg::Sha256).to_string(),
    })
}

/// Resolve a file entry's sibling `<path>.pub` into a served identity, without
/// reading the private key. Returns `None` if the `.pub` is missing/unparseable
/// or not ed25519 (v1 serves ed25519 only). For a file identity `key_ref` holds
/// the file path (display only; the [`FileSshSigner`] signs from the file, not an
/// op reference). Public so `sigil ssh add-file` can validate before persisting.
pub fn resolve_file_identity(e: &SshFileEntry) -> Option<ServedIdentity> {
    let pub_path = format!("{}.pub", e.path);
    let line = std::fs::read_to_string(&pub_path).ok()?;
    let pk = ssh_key::PublicKey::from_openssh(line.trim()).ok()?;
    if pk.algorithm() != ssh_key::Algorithm::Ed25519 {
        return None;
    }
    let key_blob = pk.to_bytes().ok()?;
    let comment = if e.comment.is_empty() {
        pk.comment().to_string()
    } else {
        e.comment.clone()
    };
    // A readable label from the file stem (e.g. "id_ed25519").
    let label = Path::new(&e.path)
        .file_name()
        .and_then(|s| s.to_str())
        .unwrap_or(&e.path)
        .to_string();
    Some(ServedIdentity {
        key_blob,
        comment,
        key_ref: e.path.clone(),
        label,
        fingerprint: pk.fingerprint(ssh_key::HashAlg::Sha256).to_string(),
    })
}

// --- socket path ------------------------------------------------------------

/// Where the agent listens. `SIGIL_SSH_SOCK` overrides with a full path;
/// otherwise it sits beside the daemon socket at `<runtime_dir>/ssh-agent.sock`,
/// resolved from the SAME authoritative [`crate::local::runtime_dir`] the daemon
/// socket uses (zero environment, stable across the GUI/shell/launchd), so the
/// two sockets can never land in different directories. This is the value a user
/// points `SSH_AUTH_SOCK` at.
pub fn socket_path() -> PathBuf {
    if let Some(p) = std::env::var_os("SIGIL_SSH_SOCK") {
        return PathBuf::from(p);
    }
    crate::local::runtime_dir().join("ssh-agent.sock")
}

#[cfg(test)]
mod tests {
    use super::*;
    use signature::Signer;
    use std::os::fd::AsRawFd;

    /// Cryptographically verify a raw ed25519 agent signature against a served
    /// public key. Uses ed25519-dalek directly (ssh-key's `PublicKey::verify` is
    /// for namespaced SshSig, not the raw agent-protocol signature).
    fn verify_ed25519(pubkey: &ssh_key::PublicKey, data: &[u8], raw_sig: &[u8]) {
        use ed25519_dalek::{Signature, Verifier, VerifyingKey};
        let pk_bytes = pubkey.key_data().ed25519().expect("ed25519 public key").0;
        let vk = VerifyingKey::from_bytes(&pk_bytes).expect("valid verifying key");
        let sig = Signature::from_slice(raw_sig).expect("64-byte signature");
        vk.verify(data, &sig).expect("the signature verifies");
    }

    // --- wire helpers -------------------------------------------------------

    #[test]
    fn reader_and_writer_round_trip_strings_and_u32() {
        let mut w = Writer::default();
        w.u32(0xdead_beef);
        w.string(b"ssh-ed25519");
        w.string(&[]); // empty string is legal
        let body = w.buf;

        let mut r = Reader::new(&body);
        assert_eq!(r.u32(), Some(0xdead_beef));
        assert_eq!(r.string(), Some(&b"ssh-ed25519"[..]));
        assert_eq!(r.string(), Some(&b""[..]));
        assert_eq!(r.string(), None, "reader is exhausted");
    }

    #[test]
    fn reader_rejects_a_short_string() {
        // A length claiming 8 bytes with only 2 present must not panic or read OOB.
        let body = [0u8, 0, 0, 8, 1, 2];
        let mut r = Reader::new(&body);
        assert_eq!(r.string(), None);
    }

    #[test]
    fn frame_prefixes_the_length() {
        let framed = single(SSH_AGENT_FAILURE);
        assert_eq!(framed, vec![0, 0, 0, 1, SSH_AGENT_FAILURE]);
    }

    // --- a fake backend for the wire tests ----------------------------------

    /// Generate an in-test ed25519 identity and hold its private key so the fake
    /// backend can actually sign (and the test can verify).
    struct FakeBackend {
        key: ssh_key::PrivateKey,
        identity: ServedIdentity,
        approve: bool,
        last_host: std::sync::Mutex<Option<String>>,
    }

    impl FakeBackend {
        fn new(approve: bool) -> Self {
            let key =
                ssh_key::PrivateKey::random(&mut rand_core::OsRng, ssh_key::Algorithm::Ed25519)
                    .unwrap();
            let pk = key.public_key();
            let identity = ServedIdentity {
                key_blob: pk.to_bytes().unwrap(),
                comment: "tom@sigil-test".to_string(),
                key_ref: "op://Engineering/Test/private key".to_string(),
                label: "Test".to_string(),
                fingerprint: pk.fingerprint(ssh_key::HashAlg::Sha256).to_string(),
            };
            Self {
                key,
                identity,
                approve,
                last_host: std::sync::Mutex::new(None),
            }
        }
    }

    impl SshBackend for FakeBackend {
        fn identities(&self) -> Vec<ServedIdentity> {
            vec![self.identity.clone()]
        }
        fn approve_and_sign(&self, req: SignRequest<'_>) -> Option<Vec<u8>> {
            *self.last_host.lock().unwrap() = Some(req.host.host.clone());
            if !self.approve {
                return None;
            }
            let sig: ssh_key::Signature = self.key.try_sign(req.data).unwrap();
            Some(encode_signature(&sig))
        }
    }

    fn request_identities_msg() -> Vec<u8> {
        vec![SSH2_AGENTC_REQUEST_IDENTITIES]
    }

    fn sign_request_msg(key_blob: &[u8], data: &[u8]) -> Vec<u8> {
        let mut w = Writer::default();
        w.u8(SSH2_AGENTC_SIGN_REQUEST);
        w.string(key_blob);
        w.string(data);
        w.u32(0);
        // respond() takes the body (type + payload) without the frame prefix.
        w.buf
    }

    // --- identities answer --------------------------------------------------

    #[test]
    fn request_identities_answers_with_the_served_key() {
        let backend = FakeBackend::new(true);
        let reply = respond(&backend, &request_identities_msg(), &mut None, None);

        // Strip the frame prefix, then parse the answer.
        let (len, body) = reply.split_at(4);
        assert_eq!(
            u32::from_be_bytes(len.try_into().unwrap()) as usize,
            body.len()
        );
        let mut r = Reader::new(&body[1..]);
        assert_eq!(body[0], SSH2_AGENT_IDENTITIES_ANSWER);
        assert_eq!(r.u32(), Some(1), "one identity");
        assert_eq!(r.string(), Some(&backend.identity.key_blob[..]));
        assert_eq!(r.string(), Some(&b"tom@sigil-test"[..]));
    }

    // --- sign happy path: the signature verifies ----------------------------

    #[test]
    fn sign_request_produces_a_signature_that_verifies() {
        let backend = FakeBackend::new(true);
        let data = b"session-id-transcript-bytes";
        let reply = respond(
            &backend,
            &sign_request_msg(&backend.identity.key_blob, data),
            &mut None,
            None,
        );

        // Parse SIGN_RESPONSE -> string signature -> string algo + string sig.
        let body = &reply[4..];
        assert_eq!(body[0], SSH2_AGENT_SIGN_RESPONSE);
        let mut r = Reader::new(&body[1..]);
        let sig_blob = r.string().expect("signature field");
        let mut sr = Reader::new(sig_blob);
        assert_eq!(sr.string(), Some(&b"ssh-ed25519"[..]));
        let raw = sr.string().expect("raw signature");
        assert_eq!(raw.len(), 64, "ed25519 signature is 64 bytes");

        // Verify against the served public key.
        verify_ed25519(backend.key.public_key(), data, raw);
    }

    #[test]
    fn sign_request_for_an_unknown_key_is_refused() {
        let backend = FakeBackend::new(true);
        let reply = respond(
            &backend,
            &sign_request_msg(b"not-our-key", b"data"),
            &mut None,
            None,
        );
        assert_eq!(reply, single(SSH_AGENT_FAILURE));
    }

    #[test]
    fn a_denied_sign_request_yields_failure_and_no_signature() {
        let backend = FakeBackend::new(false); // backend denies
        let reply = respond(
            &backend,
            &sign_request_msg(&backend.identity.key_blob, b"data"),
            &mut None,
            None,
        );
        assert_eq!(reply, single(SSH_AGENT_FAILURE), "a denial fails closed");
    }

    // --- refusals -----------------------------------------------------------

    #[test]
    fn add_remove_lock_and_unknown_extensions_are_refused() {
        let backend = FakeBackend::new(true);
        for msg_type in [17u8, 18, 19, 22, 23, 25, 99] {
            let reply = respond(&backend, &[msg_type], &mut None, None);
            assert_eq!(
                reply,
                single(SSH_AGENT_FAILURE),
                "message type {msg_type} must be refused"
            );
        }
        // An unknown extension is refused too.
        let mut w = Writer::default();
        w.u8(SSH_AGENTC_EXTENSION);
        w.string(b"query@openssh.com");
        let reply = respond(&backend, &w.buf, &mut None, None);
        assert_eq!(reply, single(SSH_AGENT_FAILURE));
    }

    // --- session-bind capture + host derivation -----------------------------

    /// Build a session-bind EXTENSION body carrying `hostkey`.
    fn session_bind_msg(hostkey: &[u8]) -> Vec<u8> {
        let mut w = Writer::default();
        w.u8(SSH_AGENTC_EXTENSION);
        w.string(SESSION_BIND);
        w.string(hostkey); // hostkey
        w.string(b"session-id"); // session identifier
        w.string(b"sig"); // signature
        w.u8(0); // is_forwarding (bool)
        w.buf
    }

    #[test]
    fn session_bind_is_accepted_recorded_and_used_for_host_derivation() {
        // A synthetic known_hosts mapping a host key to a name.
        let host_key =
            ssh_key::PrivateKey::random(&mut rand_core::OsRng, ssh_key::Algorithm::Ed25519)
                .unwrap();
        let host_blob = host_key.public_key().to_bytes().unwrap();

        let dir = std::env::temp_dir().join(format!("sigil-kh-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let kh = dir.join("known_hosts");
        let line = host_key.public_key().to_openssh().unwrap(); // "ssh-ed25519 AAAA..."
        std::fs::write(&kh, format!("github.example.com {line}\n")).unwrap();

        // known_hosts_lookup finds the name.
        assert_eq!(
            known_hosts_lookup(&host_blob, &kh).as_deref(),
            Some("github.example.com")
        );

        // The handler records the host key and hands the derived name to the sign.
        let backend = FakeBackend::new(true);
        let mut bound = None;
        let reply = respond(&backend, &session_bind_msg(&host_blob), &mut bound, None);
        assert_eq!(reply, single(SSH_AGENT_SUCCESS), "session-bind is acked");
        assert_eq!(bound.as_deref(), Some(&host_blob[..]), "host key recorded");

        // With SIGIL_KNOWN_HOSTS pointed at the synthetic file, a sign derives it.
        let _lock = crate::TEST_ENV_LOCK
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        let prev = std::env::var_os("SIGIL_KNOWN_HOSTS");
        std::env::set_var("SIGIL_KNOWN_HOSTS", &kh);
        respond(
            &backend,
            &sign_request_msg(&backend.identity.key_blob, b"data"),
            &mut bound,
            None,
        );
        assert_eq!(
            backend.last_host.lock().unwrap().as_deref(),
            Some("github.example.com")
        );
        match prev {
            Some(v) => std::env::set_var("SIGIL_KNOWN_HOSTS", v),
            None => std::env::remove_var("SIGIL_KNOWN_HOSTS"),
        }
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn unknown_host_key_falls_back_to_a_fingerprint_not_a_fake_name() {
        // A host key absent from an empty known_hosts derives to SHA256:… .
        let host_key =
            ssh_key::PrivateKey::random(&mut rand_core::OsRng, ssh_key::Algorithm::Ed25519)
                .unwrap();
        let host_blob = host_key.public_key().to_bytes().unwrap();
        let ctx = derive_host_with(Some(&host_blob), Path::new("/nonexistent/known_hosts"));
        assert!(
            ctx.host.starts_with("SHA256:"),
            "honest fingerprint, not a name"
        );
        // It matches ssh-key's own fingerprint of the same key.
        assert_eq!(
            ctx.host,
            host_key
                .public_key()
                .fingerprint(ssh_key::HashAlg::Sha256)
                .to_string()
        );
    }

    #[test]
    fn no_session_bind_yields_an_honest_unbound_marker() {
        let ctx = derive_host(None);
        assert_eq!(ctx.host, "(host not bound)");
    }

    /// Test seam: derive with an explicit known_hosts path (avoids env mutation).
    fn derive_host_with(bound_hostkey: Option<&[u8]>, kh: &Path) -> HostContext {
        match bound_hostkey {
            None => derive_host(None),
            Some(blob) => match known_hosts_lookup(blob, kh) {
                Some(name) => HostContext { host: name },
                None => HostContext {
                    host: hostkey_fingerprint(blob),
                },
            },
        }
    }

    #[test]
    fn hashed_known_hosts_entries_are_skipped() {
        let host_key =
            ssh_key::PrivateKey::random(&mut rand_core::OsRng, ssh_key::Algorithm::Ed25519)
                .unwrap();
        let host_blob = host_key.public_key().to_bytes().unwrap();
        let dir = std::env::temp_dir().join(format!("sigil-kh-hash-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let kh = dir.join("known_hosts");
        // A hashed entry cannot be reversed even though its key would match.
        let line = host_key.public_key().to_openssh().unwrap();
        let (_algo, b64) = line.split_once(' ').unwrap();
        let b64 = b64.rsplit(' ').next().unwrap_or(b64);
        std::fs::write(&kh, format!("|1|abcd|efgh ssh-ed25519 {b64}\n")).unwrap();
        assert_eq!(known_hosts_lookup(&host_blob, &kh), None);
        std::fs::remove_dir_all(&dir).ok();
    }

    // --- marker-line handling ----------------------------------------------

    #[test]
    fn cert_authority_marker_line_is_parsed() {
        let host_key =
            ssh_key::PrivateKey::random(&mut rand_core::OsRng, ssh_key::Algorithm::Ed25519)
                .unwrap();
        let host_blob = host_key.public_key().to_bytes().unwrap();
        let dir = std::env::temp_dir().join(format!("sigil-kh-ca-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let kh = dir.join("known_hosts");
        let line = host_key.public_key().to_openssh().unwrap();
        std::fs::write(
            &kh,
            format!("@cert-authority [gitfoo.example]:2222 {line}\n"),
        )
        .unwrap();
        assert_eq!(
            known_hosts_lookup(&host_blob, &kh).as_deref(),
            Some("gitfoo.example"),
            "marker stripped and [host]:port normalized"
        );
        std::fs::remove_dir_all(&dir).ok();
    }

    // --- fetch-and-sign against a fake `op` ---------------------------------

    /// Write a fake `op` that, on `read <ref>`, emits a fixed OpenSSH private key
    /// only when the expected token is in its env (proving token injection). The
    /// key is generated by the caller and passed in as PEM.
    fn write_fake_op(dir: &Path, expected_token: &str, pem: &str) -> PathBuf {
        use std::os::unix::fs::PermissionsExt;
        let path = dir.join("op");
        // The PEM is written to a sidecar file the script cats, to avoid quoting.
        let pem_file = dir.join("key.pem");
        std::fs::write(&pem_file, pem).unwrap();
        let script = format!(
            "#!/bin/sh\nif [ \"$OP_SERVICE_ACCOUNT_TOKEN\" = \"{expected_token}\" ]; then cat \"{}\"; else exit 1; fi\n",
            pem_file.display()
        );
        std::fs::write(&path, script).unwrap();
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o755)).unwrap();
        path
    }

    #[test]
    fn fetch_and_sign_reads_the_key_and_signs_a_verifiable_signature() {
        let key = ssh_key::PrivateKey::random(&mut rand_core::OsRng, ssh_key::Algorithm::Ed25519)
            .unwrap();
        let pem = key.to_openssh(ssh_key::LineEnding::LF).unwrap();

        let dir = std::env::temp_dir().join(format!("sigil-fetchsign-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let op = write_fake_op(&dir, "tok-xyz", &pem);

        let data = b"the-exact-bytes-to-sign";
        let sig_blob = fetch_and_sign(&op, b"tok-xyz", "op://Engineering/Test/private key", data)
            .expect("fetch-and-sign produced a signature");

        // The blob is string algo + string sig; verify it.
        let mut r = Reader::new(&sig_blob);
        assert_eq!(r.string(), Some(&b"ssh-ed25519"[..]));
        let raw = r.string().unwrap();
        verify_ed25519(key.public_key(), data, raw);
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn fetch_and_sign_fails_closed_when_the_token_is_wrong() {
        let key = ssh_key::PrivateKey::random(&mut rand_core::OsRng, ssh_key::Algorithm::Ed25519)
            .unwrap();
        let pem = key.to_openssh(ssh_key::LineEnding::LF).unwrap();
        let dir = std::env::temp_dir().join(format!("sigil-fetchsign-bad-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let op = write_fake_op(&dir, "the-right-token", &pem);
        // A wrong token makes the fake op exit 1; we must get None, not a panic.
        assert!(
            fetch_and_sign(&op, b"WRONG", "op://Engineering/Test/private key", b"d").is_none(),
            "a failed op read fails closed"
        );
        std::fs::remove_dir_all(&dir).ok();
    }

    // --- config round trip --------------------------------------------------

    #[test]
    fn config_entry_resolves_to_a_served_identity() {
        let key = ssh_key::PrivateKey::random(&mut rand_core::OsRng, ssh_key::Algorithm::Ed25519)
            .unwrap();
        let pub_line = key.public_key().to_openssh().unwrap();
        let entry = SshKeyEntry {
            public_key: pub_line,
            vault: "Engineering".to_string(),
            item: "GitHub".to_string(),
            field: "private key".to_string(),
            comment: "tom@github".to_string(),
        };
        let id = resolve_identity(&entry).expect("ed25519 entry resolves");
        assert_eq!(id.key_blob, key.public_key().to_bytes().unwrap());
        assert_eq!(id.key_ref, "op://Engineering/GitHub/private key");
        assert_eq!(id.label, "GitHub");
        assert_eq!(id.comment, "tom@github");
        assert!(id.fingerprint.starts_with("SHA256:"));
    }

    // --- an end-to-end socket round trip with a raw client ------------------

    #[test]
    fn listener_serves_identities_and_a_sign_over_a_real_socket() {
        use std::io::Write as _;

        let backend = std::sync::Arc::new(FakeBackend::new(true));
        let (mut client, server) = UnixStream::pair().unwrap();

        let b = backend.clone();
        let worker = std::thread::spawn(move || handle_connection(b.as_ref(), server));

        // 1) REQUEST_IDENTITIES over the wire.
        let mut w = Writer::default();
        w.u8(SSH2_AGENTC_REQUEST_IDENTITIES);
        client.write_all(&w.frame()).unwrap();
        let answer = read_message(&mut client).unwrap().unwrap();
        assert_eq!(answer[0], SSH2_AGENT_IDENTITIES_ANSWER);

        // 2) SIGN_REQUEST over the wire; the response verifies.
        let data = b"wire-data";
        let mut w = Writer::default();
        w.u8(SSH2_AGENTC_SIGN_REQUEST);
        w.string(&backend.identity.key_blob);
        w.string(data);
        w.u32(0);
        client.write_all(&w.frame()).unwrap();
        let resp = read_message(&mut client).unwrap().unwrap();
        assert_eq!(resp[0], SSH2_AGENT_SIGN_RESPONSE);
        let mut r = Reader::new(&resp[1..]);
        let sig_blob = r.string().unwrap();
        let mut sr = Reader::new(sig_blob);
        assert_eq!(sr.string(), Some(&b"ssh-ed25519"[..]));
        let raw = sr.string().unwrap();
        verify_ed25519(backend.key.public_key(), data, raw);

        // Closing the client ends the connection loop cleanly.
        drop(client);
        worker.join().unwrap().unwrap();
    }

    #[test]
    fn peer_pid_is_readable_on_the_agent_socket() {
        // The handler reads the peer pid; confirm the primitive works on a
        // socketpair so caller-scoped bookkeeping has a real value in production.
        let (a, _b) = UnixStream::pair().unwrap();
        // Not asserting a specific pid (a socketpair peer is this process), only
        // that the call is wired and returns without error on this platform.
        let _ = crate::lease::peer_pid(a.as_raw_fd());
    }

    // --- a REAL OpenSSH client (`ssh-add -l`) against our listener ----------

    #[test]
    fn real_ssh_add_l_lists_our_served_key() {
        use std::os::unix::net::UnixListener;
        use std::process::Command;

        // Soft-skip where `ssh-add` is unavailable (CI without OpenSSH).
        if Command::new("ssh-add").arg("-l").output().is_err() {
            eprintln!("SKIPPED real_ssh_add_l_lists_our_served_key: ssh-add not found");
            return;
        }

        let backend = std::sync::Arc::new(FakeBackend::new(true));
        let dir = std::env::temp_dir().join(format!("sigil-sshadd-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let sock_path = dir.join("agent.sock");
        let listener = UnixListener::bind(&sock_path).unwrap();

        // Serve exactly the one connection `ssh-add -l` makes, then return.
        let b = backend.clone();
        let handle = std::thread::spawn(move || {
            if let Some(Ok(stream)) = listener.incoming().next() {
                let _ = handle_connection(b.as_ref(), stream);
            }
        });

        let out = Command::new("ssh-add")
            .arg("-l")
            .env("SSH_AUTH_SOCK", &sock_path)
            .output()
            .expect("ssh-add runs");
        handle.join().unwrap();

        // `ssh-add -l` prints `256 SHA256:<b64> <comment> (ED25519)`. The base64
        // portion of our served key's fingerprint must appear.
        let stdout = String::from_utf8_lossy(&out.stdout);
        let want = backend
            .identity
            .fingerprint
            .strip_prefix("SHA256:")
            .unwrap();
        assert!(
            stdout.contains(want),
            "ssh-add -l should list our key fingerprint.\nwant contains: {want}\ngot: {stdout}\nstderr: {}",
            String::from_utf8_lossy(&out.stderr)
        );
        assert!(stdout.contains("tom@sigil-test"), "and its comment");
        std::fs::remove_dir_all(&dir).ok();
    }

    // --- the pluggable signer seam -----------------------------------------

    /// Generate an ed25519 key and its served identity with `key_ref`.
    fn gen_identity(key_ref: &str) -> (ssh_key::PrivateKey, ServedIdentity) {
        let key = ssh_key::PrivateKey::random(&mut rand_core::OsRng, ssh_key::Algorithm::Ed25519)
            .unwrap();
        let pk = key.public_key();
        let id = ServedIdentity {
            key_blob: pk.to_bytes().unwrap(),
            comment: "tom@seam".to_string(),
            key_ref: key_ref.to_string(),
            label: "Seam".to_string(),
            fingerprint: pk.fingerprint(ssh_key::HashAlg::Sha256).to_string(),
        };
        (key, id)
    }

    #[test]
    fn file_signer_signs_from_a_local_key_and_needs_no_account() {
        // The second reference signer: sign from a local OpenSSH key file, no
        // 1Password, no account credential.
        let (key, id) = gen_identity("/does/not/matter");
        let dir = std::env::temp_dir().join(format!("sigil-filesign-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("id_ed25519");
        std::fs::write(&path, key.to_openssh(ssh_key::LineEnding::LF).unwrap()).unwrap();

        let signer = FileSshSigner::new(vec![(id.clone(), path.clone())]);
        assert!(!signer.needs_account(), "a file signer needs no account");
        assert!(signer.owns(&id.key_blob));

        let data = b"file-signer-challenge";
        let sig_blob = signer
            .sign(&id, data, None)
            .expect("file signer produces a signature");
        let mut r = Reader::new(&sig_blob);
        assert_eq!(r.string(), Some(&b"ssh-ed25519"[..]));
        let raw = r.string().unwrap();
        verify_ed25519(key.public_key(), data, raw);
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn op_signer_fetches_and_signs_and_requires_a_credential() {
        // The default signer: fetch from 1Password per signature via the SA
        // token, then sign. Proves the same seam the file signer implements.
        let (key, id) = gen_identity("op://Engineering/Seam/private key");
        let pem = key.to_openssh(ssh_key::LineEnding::LF).unwrap();
        let dir = std::env::temp_dir().join(format!("sigil-opsign-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let op = write_fake_op(&dir, "tok-xyz", &pem);

        let signer = OpSshSigner::new(vec![id.clone()], Some(op));
        assert!(
            signer.needs_account(),
            "the op signer needs an account token"
        );

        let data = b"op-signer-challenge";
        let token: Token = Zeroizing::new(b"tok-xyz".to_vec());
        let sig_blob = signer
            .sign(&id, data, Some(&token))
            .expect("op signer produces a signature");
        let mut r = Reader::new(&sig_blob);
        assert_eq!(r.string(), Some(&b"ssh-ed25519"[..]));
        let raw = r.string().unwrap();
        verify_ed25519(key.public_key(), data, raw);

        // Without a credential the op signer fails closed (no key to fetch).
        assert!(
            signer.sign(&id, data, None).is_none(),
            "no credential, no signature"
        );
        std::fs::remove_dir_all(&dir).ok();
    }

    // --- the LIVE op read -> decode -> sign path (ignored; needs a token) ----

    /// Deletes a 1Password item on drop, so the live test leaves the vault clean
    /// even if an assertion panics mid-test.
    struct OpItemGuard {
        title: String,
        vault: String,
    }
    impl Drop for OpItemGuard {
        fn drop(&mut self) {
            let _ = std::process::Command::new("op")
                .args(["item", "delete", &self.title, "--vault", &self.vault])
                .output();
        }
    }

    /// End-to-end against the LIVE service account: create a throwaway ed25519
    /// SSH Key item, fetch+decode+sign through [`fetch_and_sign`] exactly as the
    /// daemon would, verify the signature against the item's real public key, and
    /// delete the item. Ignored by default (needs `OP_SERVICE_ACCOUNT_TOKEN` and
    /// network); run with:
    ///   OP_SERVICE_ACCOUNT_TOKEN=… cargo test -p sigil fetch_and_sign_live_op -- --ignored --nocapture
    #[test]
    #[ignore = "needs a live OP_SERVICE_ACCOUNT_TOKEN and network"]
    fn fetch_and_sign_live_op() {
        use std::process::Command;

        let Ok(token) = std::env::var("OP_SERVICE_ACCOUNT_TOKEN") else {
            eprintln!("SKIPPED fetch_and_sign_live_op: no OP_SERVICE_ACCOUNT_TOKEN");
            return;
        };
        let op = crate::paths::find_real_op().expect("a real op on PATH");
        let vault = "Engineering";
        let title = format!("sigil-agent-livetest-{}-DELETE-ME", std::process::id());

        // Create the throwaway key and arrange for its deletion no matter what.
        let created = Command::new(&op)
            .args([
                "item",
                "create",
                "--category",
                "SSH Key",
                "--title",
                &title,
                "--vault",
                vault,
                "--ssh-generate-key",
                "ed25519",
                "--format=json",
            ])
            .env("OP_SERVICE_ACCOUNT_TOKEN", &token)
            .output()
            .expect("op item create runs");
        assert!(
            created.status.success(),
            "op item create failed: {}",
            String::from_utf8_lossy(&created.stderr)
        );
        let _guard = OpItemGuard {
            title: title.clone(),
            vault: vault.to_string(),
        };

        // Read the item's real public key line to verify against.
        let pub_out = Command::new(&op)
            .args(["read", &format!("op://{vault}/{title}/public key")])
            .env("OP_SERVICE_ACCOUNT_TOKEN", &token)
            .output()
            .expect("op read public key runs");
        assert!(pub_out.status.success());
        let pub_line = String::from_utf8(pub_out.stdout).unwrap();
        let pk = ssh_key::PublicKey::from_openssh(pub_line.trim()).unwrap();

        // Fetch the private key and sign, exactly as the daemon's sign path does.
        let data = b"live-op-challenge-bytes";
        let reference = format!("op://{vault}/{title}/private key");
        let sig_blob = fetch_and_sign(&op, token.as_bytes(), &reference, data)
            .expect("live fetch_and_sign produced a signature");

        // The blob is string algo + string sig; verify the raw signature.
        let mut r = Reader::new(&sig_blob);
        assert_eq!(r.string(), Some(&b"ssh-ed25519"[..]));
        let raw = r.string().unwrap();
        verify_ed25519(&pk, data, raw);
        // _guard deletes the item on drop.
    }
}
