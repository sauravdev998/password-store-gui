//! Decryption: our [`Gpg`] trait and the backend behind it.
//!
//! Per ADR-4 the `prs-lib` implementation lives in [`prs`] and nothing from
//! that crate may appear in a signature here, in `commands.rs`, or in a
//! serialized payload. In particular `prs_lib::Plaintext` stops at that
//! module's boundary; everything outside it sees [`Secret`].
//!
//! The two halves are backed differently, which ADR-6 explains: decryption is
//! wrapped from `prs-lib` in [`prs`], encryption is our own `gpg` invocation in
//! [`gnupg`]. Reading a file has no flag-compatibility surface; writing one has
//! nothing but, since the argument list decides who can read the result.

pub mod gnupg;
pub mod prs;

use std::path::Path;

use crate::error::Result;
use crate::secret::Secret;
use crate::store::Recipients;

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
}
