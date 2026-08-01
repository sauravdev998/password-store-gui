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

    /// A reveal named a field index the entry does not have.
    ///
    /// The index is the caller's own — the webview got it from
    /// `EntryMetadata::fields` — so echoing it back tells it nothing it did not
    /// already know, and nothing about the plaintext.
    #[error("entry {name} has no field at index {index}")]
    NoSuchField { name: EntryName, index: usize },

    #[error("entry {name} has no notes")]
    NoNotes { name: EntryName },

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
