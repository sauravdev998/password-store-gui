//! The password store: our domain types and the [`Store`] trait.
//!
//! Per ADR-4 the `prs-lib` implementation lives in [`prs`] and nothing from
//! that crate may appear in a signature here, in `commands.rs`, or in a
//! serialized payload. Two responsibilities are ours outright rather than
//! delegated, because `prs-lib` gets them wrong for our purposes: recipient
//! resolution ([`gpg_id`], F-1) and name validation ([`name`], F-6).

pub mod entry;
pub mod gpg_id;
pub mod name;
pub mod prs;
pub mod tree;

use std::ffi::OsString;
use std::path::{Path, PathBuf};

pub use entry::{Entry, EntryMetadata, Field};
pub use gpg_id::Recipients;
pub use name::{EntryName, InvalidName};
pub use prs::PrsStore;
pub use tree::{Node, Tree};

use crate::error::{Error, Result};

/// Environment variable `pass` uses to override the store location.
///
/// `prs-lib` never reads it — its `STORE_DEFAULT_ROOT` is a hardcoded
/// `~/.password-store` (ADR-4a) — so resolution is ours.
pub const STORE_DIR_ENV: &str = "PASSWORD_STORE_DIR";

/// Store directory relative to the user's home, when the variable is unset.
pub const DEFAULT_STORE_DIR: &str = ".password-store";

/// A password store we can read and write.
///
/// Object-safe on purpose: the app holds a `dyn Store` so the backing
/// implementation can be swapped without touching the command surface.
///
/// Note what is *not* here: nothing on this trait encrypts or decrypts. The
/// file-level moves below are only correct when source and destination resolve
/// to the same `.gpg-id`, and deciding that is `commands::Core`'s job — a move
/// across a recipient boundary has to be a decrypt and a re-encrypt
/// (Invariant 8), which is why these are named for the file operation they are
/// rather than for the user-facing verb.
pub trait Store: Send + Sync {
    /// Absolute, canonical store root.
    fn root(&self) -> &Path;

    /// The full tree of directories and entries.
    fn tree(&self) -> Result<Tree>;

    /// Every entry in the store, flat and unordered.
    ///
    /// What [`Tree`] is built from, before the hierarchy is put back. A
    /// recipient change wants it in this form: the question "which entries does
    /// this `.gpg-id` govern?" is asked of each name independently, by walking
    /// up from it, and a tree would have to be flattened again to ask it.
    fn entries(&self) -> Result<Vec<EntryName>>;

    /// Path of the encrypted file backing `name`.
    ///
    /// Errors if no such entry exists, so callers never hand a phantom path to
    /// the crypto layer.
    fn secret_path(&self, name: &EntryName) -> Result<PathBuf>;

    /// Recipients governing `name`, from the nearest `.gpg-id` (Invariant 8).
    ///
    /// Answerable for a name that does not exist yet, which is what lets a
    /// write resolve its recipients before it creates anything.
    fn recipients(&self, name: &EntryName) -> Result<Recipients>;

    /// Whether an entry by this name exists.
    fn contains(&self, name: &EntryName) -> bool;

    /// Delete the entry, and any directory the deletion leaves empty.
    fn remove(&self, name: &EntryName) -> Result<()>;

    /// Move the ciphertext as-is, without re-encrypting.
    ///
    /// Only valid when `from` and `to` share a `.gpg-id`; see the trait note.
    fn rename_file(&self, from: &EntryName, to: &EntryName) -> Result<()>;

    /// Copy the ciphertext as-is, without re-encrypting.
    ///
    /// Only valid when `from` and `to` share a `.gpg-id`; see the trait note.
    fn copy_file(&self, from: &EntryName, to: &EntryName) -> Result<()>;
}

/// Where the store lives with nothing configured: `PASSWORD_STORE_DIR`, else
/// `~/.password-store`.
///
/// The settings-aware version is [`crate::settings::SettingsFile::store_root`];
/// this is what a core with no settings behind it uses.
pub fn default_root() -> Result<PathBuf> {
    resolve_root(std::env::var_os(STORE_DIR_ENV), None, dirs::home_dir())
}

/// The user's home directory, as the store's default location is derived from.
///
/// Re-exported so `settings` does not have to reach for `dirs` itself to answer
/// a question this module owns.
pub fn home_dir() -> Option<PathBuf> {
    dirs::home_dir()
}

/// The path rule behind [`default_root`], separated so it is testable without
/// mutating process-global environment state.
///
/// Precedence is ADR-11's: the environment first, because `PASSWORD_STORE_DIR`
/// is what the `pass` CLI obeys and the two must not disagree about which store
/// is the user's; then whatever they configured in this app; then the default.
pub fn resolve_root(
    env_dir: Option<OsString>,
    configured: Option<PathBuf>,
    home: Option<PathBuf>,
) -> Result<PathBuf> {
    // An empty variable is treated as unset, as the shell would.
    if let Some(dir) = env_dir.filter(|dir| !dir.is_empty()) {
        return Ok(PathBuf::from(dir));
    }
    if let Some(dir) = configured.filter(|dir| !dir.as_os_str().is_empty()) {
        return Ok(dir);
    }
    home.map(|home| home.join(DEFAULT_STORE_DIR))
        .ok_or(Error::StoreLocationUnknown)
}

#[cfg(test)]
// Test code handles fixtures, never real secrets.
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;

    #[test]
    fn env_var_wins_over_home() {
        let root = resolve_root(
            Some(OsString::from("/srv/passwords")),
            None,
            Some(PathBuf::from("/home/u")),
        )
        .unwrap();
        assert_eq!(root, Path::new("/srv/passwords"));
    }

    /// ADR-11: the variable the `pass` CLI obeys also wins here.
    #[test]
    fn env_var_wins_over_a_configured_path() {
        let root = resolve_root(
            Some(OsString::from("/srv/passwords")),
            Some(PathBuf::from("/mnt/configured")),
            Some(PathBuf::from("/home/u")),
        )
        .unwrap();
        assert_eq!(root, Path::new("/srv/passwords"));
    }

    #[test]
    fn a_configured_path_wins_over_home() {
        let root = resolve_root(
            None,
            Some(PathBuf::from("/mnt/configured")),
            Some(PathBuf::from("/home/u")),
        )
        .unwrap();
        assert_eq!(root, Path::new("/mnt/configured"));
    }

    #[test]
    fn falls_back_to_home() {
        let root = resolve_root(None, None, Some(PathBuf::from("/home/u"))).unwrap();
        assert_eq!(root, Path::new("/home/u/.password-store"));
    }

    #[test]
    fn an_empty_env_var_counts_as_unset() {
        let root =
            resolve_root(Some(OsString::new()), None, Some(PathBuf::from("/home/u"))).unwrap();
        assert_eq!(root, Path::new("/home/u/.password-store"));
    }

    #[test]
    fn an_empty_configured_path_counts_as_unset() {
        let root =
            resolve_root(None, Some(PathBuf::new()), Some(PathBuf::from("/home/u"))).unwrap();
        assert_eq!(root, Path::new("/home/u/.password-store"));
    }

    #[test]
    fn errors_without_a_home_or_a_variable() {
        assert!(matches!(
            resolve_root(None, None, None),
            Err(Error::StoreLocationUnknown)
        ));
    }
}
