//! Typed, secret-free errors.
//!
//! Invariant 5 in `PLAN.md` §4: no variant may carry decrypted content. Every
//! variant here holds a path, an entry name, or an `io::Error` — never a file's
//! contents and never anything derived from them. Keep it that way: a new
//! variant that interpolates a decrypted buffer is a security bug, not a
//! formatting choice.
//!
//! The single exception is [`Error::GpgUnavailable`], which carries a message
//! from the crypto backend. It is safe because of when it is raised, not
//! because the backend is trusted — see the variant's own note.

use std::io;
use std::path::PathBuf;

use thiserror::Error;

use crate::secret::NotUtf8;
use crate::store::{EntryName, InvalidName};

/// Crate result type.
pub type Result<T, E = Error> = std::result::Result<T, E>;

#[derive(Debug, Error)]
pub enum Error {
    #[error("could not determine the password store location; set PASSWORD_STORE_DIR")]
    StoreLocationUnknown,

    #[error("no password store directory at {path}")]
    StoreNotFound { path: PathBuf },

    #[error("invalid entry name: {0}")]
    InvalidName(#[from] InvalidName),

    #[error("no entry named {name}")]
    EntryNotFound { name: EntryName },

    /// A write would have overwritten an entry the user did not name as the
    /// target — an insert, a move, or a copy onto an occupied name.
    #[error("an entry named {name} already exists")]
    EntryExists { name: EntryName },

    /// A reveal named a field index the entry does not have.
    ///
    /// The index is the caller's own — the webview got it from
    /// `EntryMetadata::fields` — so echoing it back tells it nothing it did not
    /// already know, and nothing about the plaintext.
    #[error("entry {name} has no field at index {index}")]
    NoSuchField { name: EntryName, index: usize },

    #[error("entry {name} has no notes")]
    NoNotes { name: EntryName },

    #[error("entry {name} has no one-time-password source")]
    NoOtp { name: EntryName },

    /// The entry's `otpauth://` URI could not be read as a TOTP source.
    ///
    /// Carries nothing on purpose. `totp_rs::TotpUrlError` quotes the URI it
    /// rejected in several of its variants, and that URI contains the shared
    /// seed — so the parse error is dropped rather than wrapped.
    #[error("the entry's otpauth:// URI is not a usable TOTP source")]
    InvalidOtpUri,

    #[error("the system clock is set before the Unix epoch")]
    SystemClock,

    #[error("password length must be between {min} and {max}")]
    BadLength { min: usize, max: usize },

    /// A settings value measured in seconds was out of range.
    ///
    /// `setting` is a plain-language name for the thing, not the field or the
    /// environment variable behind it (Open Decision 6): the user is told which
    /// control they just moved too far, in the words the control uses. There is
    /// no floor because zero is meaningful at both call sites — no clipboard
    /// window, and no idle lock.
    #[error("{setting} cannot be more than {max} seconds")]
    BadDuration { setting: &'static str, max: u64 },

    /// The OS refused to provide randomness.
    ///
    /// Deliberately fatal to the generate path rather than a cue to fall back to
    /// a seeded generator: a password from a predictable source is worse than no
    /// password, and this is the one error here the user cannot act on.
    #[error("the operating system provided no randomness")]
    NoEntropy,

    #[error("no .gpg-id file found for {name}")]
    NoRecipients { name: EntryName },

    #[error("the .gpg-id file at {path} lists no recipients")]
    EmptyRecipients { path: PathBuf },

    /// A recipient id that could not survive being written to a `.gpg-id`.
    ///
    /// The file is line-delimited and read back trimmed, so an id holding a
    /// newline would come back as *two* recipients — a way to add a key to a
    /// store by typing it inside another one's name. Echoing the id back is safe
    /// and necessary: it is what the user just typed, not anything decrypted,
    /// and they cannot fix it without seeing which one was refused.
    #[error("{id} is not a usable recipient: it must be one line with no surrounding spaces")]
    InvalidRecipientId { id: String },

    /// No usable `gpg` binary.
    ///
    /// The one variant carrying a free-form message, and it is safe for a reason
    /// that does not generalize: `crypto::gnupg::bin` composes it out of binary
    /// names and version numbers while *looking for* GnuPG — before any
    /// ciphertext has been read, so there is no plaintext in the process for it
    /// to capture. Do not reuse the pattern elsewhere.
    ///
    /// It says which of two things went wrong, because the fixes are opposite:
    /// nothing was found anywhere (install GnuPG, or the bundle is damaged), or
    /// something was found and would not run (ADR-14's probe rejected it).
    #[error("no usable GnuPG installation: {reason}")]
    GpgUnavailable { reason: String },

    /// Decryption failed.
    ///
    /// Carries the ciphertext's path and nothing else — deliberately not the
    /// backend's error, since this is the one path where plaintext exists in
    /// the process (Invariant 5).
    #[error("failed to decrypt {path}")]
    Decrypt { path: PathBuf },

    /// Decryption failed for ciphertext that has no file behind it.
    ///
    /// The in-memory counterpart to [`Error::Decrypt`]: a blob read out of the
    /// store's git history was never a file, so there is nothing to name. It is
    /// deliberately thin, and callers that know what they were decrypting
    /// replace it with something that says so — see
    /// [`Error::DecryptRevision`]. It should not reach the webview as it
    /// stands; if it ever does, that is a missing `map_err`, not a message to
    /// improve here.
    #[error("failed to decrypt")]
    DecryptBlob,

    /// A past version of an entry could not be decrypted.
    ///
    /// The entry name is store metadata the webview already holds, and the
    /// commit is named nowhere: what the user needs to know is which entry, and
    /// that the failure is about an old version rather than the current one.
    /// Same reasoning as [`Error::Decrypt`] for what is *not* carried — the
    /// backend's own words never are.
    #[error("failed to decrypt the version of {name} held in your store's history")]
    DecryptRevision { name: EntryName },

    /// The webview asked for a version by an id that is not a git object id.
    ///
    /// Every id the webview has came from `entry_history`, so this is a
    /// malformed request rather than something a user can do — but the id is
    /// parsed rather than trusted, and this is what parsing it says when it
    /// fails.
    #[error("not a valid revision of the store's history")]
    NoSuchRevision,

    /// Encryption failed.
    ///
    /// Carries nothing at all — not even the destination path, which on a write
    /// is a name the user just typed rather than one they picked from the tree.
    /// `gpg`'s own output is dropped for the same reason [`Error::Decrypt`]
    /// drops it: this is a path with a live plaintext on it.
    #[error("failed to encrypt")]
    Encrypt,

    /// A `.gpg-id` lists a recipient `gpg` cannot resolve to a public key.
    ///
    /// Both fields are public store metadata — the id as the `.gpg-id` spells
    /// it, and the path of that file — and this is raised before any plaintext
    /// exists in the process. Naming them is what makes the error actionable:
    /// the fix is to import the key or correct the file.
    /// The field is `gpg_id` rather than `source`, which `thiserror` would take
    /// for the error's cause.
    #[error("no public key for recipient {id}, listed in {gpg_id}")]
    UnknownRecipient { id: String, gpg_id: PathBuf },

    /// A key the user just named cannot be resolved.
    ///
    /// The sibling of [`Error::UnknownRecipient`], separated by *where the id
    /// came from*. That one is raised for an id already written in a `.gpg-id`,
    /// and names the file so the user can go and correct it. This one is raised
    /// while validating ids typed into a form, before anything has been
    /// written — there is no file to name yet, and naming one would send the
    /// user looking for a problem in a file that does not have it.
    #[error("no public key for {id}")]
    UnknownKey { id: String },

    /// A key resolves, but nothing in it can encrypt.
    ///
    /// Every encryption subkey revoked, expired or disabled. `gpg` would refuse
    /// the encrypt eventually; catching it while validating means the refusal
    /// can name the key, which a failed encrypt could not (§4.1 principle 5).
    #[error("{id} has no usable encryption key: it may have expired or been revoked")]
    UnusableKey { id: String },

    /// The name typed for a new key could not go into a user id.
    ///
    /// Neither this nor [`Error::InvalidKeyEmail`] echoes what was typed, unlike
    /// [`Error::InvalidRecipientId`]: the text is still in the box in front of
    /// the user, and what they need is which of the two fields is wrong and
    /// why — which `gpg`'s own bare `Invalid user ID` does not say.
    #[error(
        "that name cannot go on a key: it must not be empty, start with a dash, or contain < > ( )"
    )]
    InvalidKeyName,

    #[error("that does not look like an email address")]
    InvalidKeyEmail,

    /// The pinentry asking for the new key's passphrase was dismissed.
    ///
    /// A choice rather than a fault, and `gpg` leaves nothing behind when it
    /// happens (ADR-7), so the wizard can simply offer the button again. Told
    /// apart from [`Error::KeyGeneration`] by a numeric status code rather than
    /// by matching a message that changes with the locale.
    #[error("no key was created: the passphrase prompt was dismissed")]
    KeyGenerationCancelled,

    /// Key generation failed for any other reason.
    ///
    /// Carries none of `gpg`'s output. There is no plaintext of the store in
    /// this process at the time, but the operation's whole subject is a
    /// passphrase being chosen, so the error leaving it is secret-free by
    /// construction rather than by audit — the same standard [`Error::Encrypt`]
    /// is held to.
    #[error("GnuPG could not create the key")]
    KeyGeneration,

    /// Onboarding was asked to create a store where one already exists.
    ///
    /// Not reachable from the wizard, which only appears when there is no store
    /// (ADR-7) — but the command is callable regardless, and refusing here is
    /// what stops a second `.gpg-id` write from re-pointing a populated store at
    /// one key without the re-encryption `set_recipients` would have done.
    #[error("there is already a password store at {path}")]
    StoreExists { path: PathBuf },

    /// A file under the store could not be read as OpenPGP ciphertext.
    ///
    /// Deliberately not [`Error::Decrypt`]: nothing was decrypted and no key was
    /// involved, so reporting it as a decryption failure would send the user
    /// looking for a key problem. Raised while inspecting which keys an entry is
    /// encrypted to, where the file being unreadable or not ciphertext at all is
    /// the likelier cause.
    #[error("{path} could not be read as an encrypted entry")]
    UnreadableCiphertext { path: PathBuf },

    /// Clipboard failures, with none of the platform's own error text.
    ///
    /// `arboard`'s messages are not known to quote clipboard *contents*, but
    /// the clipboard is the one subsystem whose whole job at this point is
    /// holding a password — so these are secret-free by construction rather
    /// than by audit, and the timer thread that fires most of them has no
    /// caller to report to anyway.
    #[error("no usable clipboard on this system")]
    ClipboardUnavailable,

    #[error("could not write to the clipboard")]
    ClipboardWrite,

    #[error("could not read the clipboard")]
    ClipboardRead,

    /// Git has no author, so it cannot write a commit.
    ///
    /// Separate from [`Error::Git`] because it is the ordinary first-run state
    /// on a machine that has never used git, and because libgit2's own wording
    /// for it does not say what to do (§4.1 principle 5).
    #[error("git does not know who you are: set user.name and user.email in your git config")]
    GitNoIdentity,

    /// A git operation failed.
    ///
    /// Carries libgit2's own message, which is safe in a way the crypto
    /// layer's errors are not: git only ever reads and writes what is on disk,
    /// and what is on disk is ciphertext (Invariant 1). Nothing this error can
    /// quote is plaintext, and by the time it is raised the write it describes
    /// has already dropped its secret.
    #[error("git could not record the change: {reason}")]
    Git { reason: String },

    /// No `git` binary, which only syncing needs.
    ///
    /// Worth its own variant because of what it does *not* mean: reading,
    /// writing and the store's local history all run on vendored libgit2 and
    /// work fine without it (ADR-9). Only talking to a remote needs the user's
    /// own `git`, so the message says which part is unavailable rather than
    /// implying the store is broken (§4.1 principle 5).
    #[error("syncing needs the git command line tool, which is not installed")]
    GitBinaryMissing,

    /// Fetching, merging or pushing failed.
    ///
    /// Separate from [`Error::Git`] only for its wording: that one is raised
    /// after a write and says so, and telling a user their change was not
    /// recorded when what actually failed was a push would be a lie in the
    /// direction that costs them confidence in the store.
    ///
    /// Carries `git`'s own output, which Invariant 1 makes safe — everything
    /// git touches is ciphertext. It is passed through
    /// [`crate::git::remote::redact`] first, which is not about store secrets
    /// but about the *other* credential in play: a remote URL may embed a
    /// token, and git quotes the URL back on failure.
    #[error("git could not sync your store: {reason}")]
    GitSync { reason: String },

    #[error(transparent)]
    NotUtf8(#[from] NotUtf8),

    #[error("failed to read {path}")]
    Io {
        path: PathBuf,
        #[source]
        source: io::Error,
    },
}

impl Error {
    /// Attach a path to an [`io::Error`].
    pub fn io(path: impl Into<PathBuf>, source: io::Error) -> Self {
        Self::Io {
            path: path.into(),
            source,
        }
    }
}

impl serde::Serialize for Error {
    /// Flatten to a single string for the IPC boundary.
    ///
    /// Safe by construction: every variant above, and every `source` they can
    /// carry (`io::Error`, i.e. an OS message), is secret-free.
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        let mut message = self.to_string();
        let mut source = std::error::Error::source(self);
        while let Some(err) = source {
            message.push_str(": ");
            message.push_str(&err.to_string());
            source = err.source();
        }
        serializer.serialize_str(&message)
    }
}
