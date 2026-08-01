//! Typed, secret-free errors.
//!
//! Invariant 5 in `PLAN.md` §4: no variant may carry decrypted content. Every
//! variant here holds a path, an entry name, or an `io::Error` — never a file's
//! contents and never anything derived from them. Keep it that way: a new
//! variant that interpolates a decrypted buffer is a security bug, not a
//! formatting choice.

use std::io;
use std::path::PathBuf;

use thiserror::Error;

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

    #[error("no .gpg-id file found for {name}")]
    NoRecipients { name: EntryName },

    #[error("the .gpg-id file at {path} lists no recipients")]
    EmptyRecipients { path: PathBuf },

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
