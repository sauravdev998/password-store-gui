//! Decryption: our [`Gpg`] trait and the backend behind it.
//!
//! Per ADR-4 the `prs-lib` implementation lives in [`prs`] and nothing from
//! that crate may appear in a signature here, in `commands.rs`, or in a
//! serialized payload. In particular `prs_lib::Plaintext` stops at that
//! module's boundary; everything outside it sees [`Secret`].
//!
//! The trait is decrypt-only because Phase 1 is read-only. Encryption arrives
//! in Phase 3, where it also has to answer a question reading does not: turning
//! the recipient ids from our own `.gpg-id` walk-up (Invariant 8) into the keys
//! a backend wants.

pub mod prs;

use std::path::Path;

use crate::error::Result;
use crate::secret::Secret;

pub use prs::PrsGpg;

/// Decryption of store entries.
///
/// Object-safe on purpose: the app holds a `dyn Gpg` so the backend can be
/// swapped — ADR-3 lists GPGME and `rpgp` as later options — without touching
/// the command surface.
pub trait Gpg: Send + Sync {
    /// Decrypt the encrypted file at `path`.
    ///
    /// Passphrase handling belongs entirely to `gpg-agent` and its pinentry
    /// (Invariant 3); this never sees one, and never prompts.
    fn decrypt_file(&self, path: &Path) -> Result<Secret>;
}
