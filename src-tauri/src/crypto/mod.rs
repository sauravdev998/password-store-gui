//! Crypto: our [`Gpg`] trait and the backend behind it.
//!
//! There is one backend, [`gnupg`], and it spawns `gpg` for everything. That is
//! newer than it looks. ADR-6 split the trait's implementation in two —
//! encryption ours, decryption wrapped from `prs-lib` — and ADR-4b closed the
//! split when ADR-14 decided to bundle GnuPG: a bundled binary need not be on
//! `PATH`, and `prs-lib` cannot be told where one is, so leaving decryption
//! there would have left it driving a different `gpg` than everything else.
//!
//! `prs-lib` still backs the store walk in `store/prs.rs`, and ADR-4's rule
//! holds there unchanged: none of its types may appear in a signature here, in
//! `commands.rs`, or in a serialized payload. Everything outside that module
//! sees [`Secret`].

pub mod gnupg;

use std::collections::BTreeSet;
use std::path::Path;

use serde::Serialize;

#[cfg(doc)]
use crate::error::Error;
use crate::error::Result;
use crate::secret::Secret;
use crate::store::Recipients;

pub use gnupg::Gnupg;

/// A set of long (16 hex digit) key ids.
///
/// Always *encryption subkey* ids — never a primary key's, which is what a
/// `.gpg-id` usually spells but never what a ciphertext names. Translating
/// between the two is what [`Gpg::describe_key`] is for.
pub type KeyIds = BTreeSet<String>;

/// What is known about one recipient id, without decrypting anything.
///
/// None of this is secret: a public key's user id and fingerprint are metadata,
/// which is why they may cross IPC when a decrypted field may not. The store
/// already renders the raw ids — they are what the `.gpg-id` says.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct KeyInfo {
    /// The id exactly as the `.gpg-id` spells it, or as the user typed it.
    ///
    /// Kept verbatim rather than normalized to a fingerprint: it is the string
    /// the store holds, and rewriting it would be us editing the user's file to
    /// suit our display (§4.1 principle 3).
    pub id: String,

    /// The primary user id `gpg` reports, when the key is on the keyring.
    ///
    /// What lets the interface show "Ada <ada@example.com>" beside a
    /// fingerprint nobody can read. `None` means the key is not present, which
    /// is the ordinary state for a store shared with someone whose key was
    /// never imported.
    pub label: Option<String>,

    /// The primary key's fingerprint, for an id that spells something shorter.
    pub fingerprint: Option<String>,

    /// Whether this machine holds a secret key able to decrypt for this
    /// recipient.
    ///
    /// The one field here that is about the *user* rather than the key. It is
    /// what lets the interface refuse to let someone remove the last key they
    /// own from a store — an irreversible lockout `pass init` performs without
    /// comment (ADR-13).
    pub usable_here: bool,

    /// The encryption subkeys a ciphertext for this recipient names.
    ///
    /// Not serialized: the webview has no use for a subkey id, and this is the
    /// internal half of the translation above.
    #[serde(skip)]
    pub keys: KeyIds,
}

/// Decryption of store entries.
///
/// Object-safe on purpose: the app holds a `dyn Gpg` so the backend can be
/// swapped — ADR-3 lists GPGME and `rpgp` as later options — without touching
/// the command surface.
pub trait Gpg: Send + Sync {
    /// Decrypt ciphertext already in memory.
    ///
    /// Exists for the one thing that has no file behind it: a past version of
    /// an entry, read out of a git object rather than off disk (Phase 4). The
    /// error it returns therefore names nothing — see [`Error::DecryptBlob`] —
    /// and the caller, which does know what it asked for, replaces it with
    /// something that says so.
    ///
    /// Passphrase handling belongs entirely to `gpg-agent` and its pinentry
    /// (Invariant 3); this never sees one, and never prompts.
    fn decrypt(&self, ciphertext: &[u8]) -> Result<Secret>;

    /// Decrypt the encrypted file at `path`.
    ///
    /// The same operation as [`Gpg::decrypt`] with the read attached, kept
    /// separate so the error can carry the path — which is what makes a failure
    /// here actionable and a failure there not.
    fn decrypt_file(&self, path: &Path) -> Result<Secret>;

    /// Encrypt `plaintext` to `recipients` and write it to `path`.
    ///
    /// `recipients` must be the ones our own `.gpg-id` walk-up resolved
    /// (Invariant 8), and an implementation must encrypt to **all** of them or
    /// fail — quietly dropping one produces a file that looks correct and is
    /// unreadable to someone the store says may read it.
    ///
    /// Creating the entry's directory is the implementation's job, so a new
    /// entry in a new folder is one call.
    fn encrypt_file(&self, path: &Path, recipients: &Recipients, plaintext: &Secret) -> Result<()>;

    /// What a recipient id resolves to.
    ///
    /// **Must not decrypt.** This and [`Gpg::encrypted_to`] exist to answer
    /// "who can open this?" without opening it, which is what lets a recipient
    /// change report its cost before the user commits to paying it (ADR-13,
    /// §4.1 principle 1). An implementation that decrypted here would turn a
    /// question into a pinentry prompt per entry.
    ///
    /// An unresolvable id is an error, never a [`KeyInfo`] with an empty
    /// [`KeyInfo::keys`]: silently dropping one is ADR-6's F-8, which encrypts
    /// an entry to fewer people than the store demands and looks entirely
    /// normal afterwards.
    fn describe_key(&self, id: &str) -> Result<KeyInfo>;

    /// Every key on this machine that could back a store.
    ///
    /// **Must not decrypt**, like the two queries above: onboarding asks this
    /// before the user has committed to anything, and a pinentry raised by a
    /// question is §4.1 principle 1's central defect.
    ///
    /// An empty list is the ordinary state of a machine that has never used
    /// GnuPG — the state Phase 7 exists for — and not a failure to report.
    fn usable_keys(&self) -> Result<Vec<KeyInfo>>;

    /// Create a key pair for `name` and `email`, and describe what was made.
    ///
    /// **The passphrase is the agent's business and never ours** (Invariant 3).
    /// An implementation must let `gpg-agent` and the platform pinentry prompt
    /// for it — never `--passphrase`, never `--pinentry-mode loopback`, never
    /// an unprotected key — and ADR-7 records the probe that shows `--batch` is
    /// what *allows* that rather than what prevents it.
    ///
    /// This is on the trait for ADR-3's reason: it is a backend capability, and
    /// a later pure-Rust backend would have to answer for it with no agent
    /// behind it — at which point Invariant 3 is the whole question again.
    fn generate_key(&self, name: &str, email: &str) -> Result<KeyInfo>;

    /// The keys the ciphertext at `path` is actually encrypted to.
    ///
    /// The other half of the pair above: [`Gpg::describe_key`] says who the
    /// store *wants* to be able to read an entry, this says who *can*. **Must
    /// not decrypt** — and must work on an entry this machine holds no secret
    /// key for, so a store the user has partly lost access to can still be
    /// described to them rather than failing silently.
    fn encrypted_to(&self, path: &Path) -> Result<KeyIds>;
}
