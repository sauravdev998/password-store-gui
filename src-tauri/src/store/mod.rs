//! The password store: our domain types and the [`Store`] trait.
//!
//! Per ADR-4 the `prs-lib` implementation lives in [`prs`] and nothing from
//! that crate may appear in a signature here, in `commands.rs`, or in a
//! serialized payload. Two responsibilities are ours outright rather than
//! delegated, because `prs-lib` gets them wrong for our purposes: recipient
//! resolution ([`gpg_id`], F-1) and name validation ([`name`], F-6).

pub mod gpg_id;
pub mod name;
pub mod prs;
pub mod tree;

use std::ffi::OsString;
use std::path::{Path, PathBuf};

pub use gpg_id::Recipients;
pub use name::{EntryName, InvalidName};
pub use tree::{Node, Tree};

use crate::error::{Error, Result};

/// Environment variable `pass` uses to override the store location.
///
/// `prs-lib` never reads it — its `STORE_DEFAULT_ROOT` is a hardcoded
/// `~/.password-store` (ADR-4a) — so resolution is ours.
pub const STORE_DIR_ENV: &str = "PASSWORD_STORE_DIR";

/// Store directory relative to the user's home, when the variable is unset.
pub const DEFAULT_STORE_DIR: &str = ".password-store";

/// A password store we can read.
///
/// Object-safe on purpose: the app holds a `dyn Store` so the backing
/// implementation can be swapped without touching the command surface.
pub trait Store: Send + Sync {
    /// Absolute, canonical store root.
    fn root(&self) -> &Path;

    /// The full tree of directories and entries.
    fn tree(&self) -> Result<Tree>;

    /// Path of the encrypted file backing `name`.
    ///
    /// Errors if no such entry exists, so callers never hand a phantom path to
    /// the crypto layer.
    fn secret_path(&self, name: &EntryName) -> Result<PathBuf>;

    /// Recipients governing `name`, from the nearest `.gpg-id` (Invariant 8).
    fn recipients(&self, name: &EntryName) -> Result<Recipients>;
}

/// Where the store lives: `PASSWORD_STORE_DIR`, else `~/.password-store`.
pub fn default_root() -> Result<PathBuf> {
    resolve_root(std::env::var_os(STORE_DIR_ENV), dirs::home_dir())
}

/// The path rule behind [`default_root`], separated so it is testable without
/// mutating process-global environment state.
fn resolve_root(env_dir: Option<OsString>, home: Option<PathBuf>) -> Result<PathBuf> {
    // An empty variable is treated as unset, as the shell would.
    if let Some(dir) = env_dir.filter(|dir| !dir.is_empty()) {
        return Ok(PathBuf::from(dir));
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
            Some(PathBuf::from("/home/u")),
        )
        .unwrap();
        assert_eq!(root, Path::new("/srv/passwords"));
    }

    #[test]
    fn falls_back_to_home() {
        let root = resolve_root(None, Some(PathBuf::from("/home/u"))).unwrap();
        assert_eq!(root, Path::new("/home/u/.password-store"));
    }

    #[test]
    fn an_empty_env_var_counts_as_unset() {
        let root = resolve_root(Some(OsString::new()), Some(PathBuf::from("/home/u"))).unwrap();
        assert_eq!(root, Path::new("/home/u/.password-store"));
    }

    #[test]
    fn errors_without_a_home_or_a_variable() {
        assert!(matches!(
            resolve_root(None, None),
            Err(Error::StoreLocationUnknown)
        ));
    }
}
