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

    /// No usable `gpg` binary.
    ///
    /// `reason` comes from the backend, which is safe only because this is
    /// raised while *building* a crypto context — before any ciphertext has
    /// been read, so there is no plaintext in the process to capture. See the
    /// note on `crypto::prs::describe`; do not reuse the pattern elsewhere.
    #[error("no usable GnuPG installation: {reason}")]
    GpgUnavailable { reason: String },

    /// Decryption failed.
    ///
    /// Carries the ciphertext's path and nothing else — deliberately not the
    /// backend's error, since this is the one path where plaintext exists in
    /// the process (Invariant 5).
    #[error("failed to decrypt {path}")]
    Decrypt { path: PathBuf },

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
