//! Recipient resolution — nearest `.gpg-id`, walking up.
//!
//! Invariant 8 in `PLAN.md` §4. This is ours to own: `prs-lib`'s
//! `Recipients::load` resolves `.gpg-id` at the store root only
//! (`crypto/store.rs:19` is `store.root.join(".gpg-id")`, with no walk-up
//! anywhere in the crate), so using it on a write path would silently
//! mis-encrypt every entry under a subdirectory that has its own `.gpg-id`
//! (ADR-4a, F-1). Nothing in this crate may call it.

use std::fs;
use std::path::{Path, PathBuf};

use serde::Serialize;

use crate::error::{Error, Result};
use crate::store::EntryName;

/// Per-directory recipients file, as used by `pass`.
pub const GPG_ID_FILE: &str = ".gpg-id";

/// The GPG recipients an entry must be encrypted to.
///
/// The ids are whatever the store's `.gpg-id` holds — fingerprints, key ids, or
/// user ids. They identify *public* keys, so they are metadata, not secrets.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Recipients {
    /// Recipient ids, in file order.
    pub ids: Vec<String>,
    /// The `.gpg-id` file they came from.
    pub source: PathBuf,
}

/// Resolve the recipients for `name` by walking up from its directory.
pub fn resolve(root: &Path, name: &EntryName) -> Result<Recipients> {
    let path =
        nearest_gpg_id(root, name).ok_or_else(|| Error::NoRecipients { name: name.clone() })?;
    read(&path)
}

/// Find the `.gpg-id` file governing `name`.
///
/// Searches the entry's own directory first, then each ancestor, stopping at
/// the store root — the same order `pass`'s `set_gpg_recipients` uses. Ancestors
/// are built up from the root rather than walked back with `Path::parent`, so
/// the search cannot climb out of the store even if `root` is unusual.
pub fn nearest_gpg_id(root: &Path, name: &EntryName) -> Option<PathBuf> {
    let mut dirs = vec![root.to_path_buf()];
    let mut current = root.to_path_buf();

    let components: Vec<_> = name.components().collect();
    // The last component is the entry itself, not a directory.
    if let Some((_, parents)) = components.split_last() {
        for component in parents {
            current.push(component);
            dirs.push(current.clone());
        }
    }

    dirs.iter()
        .rev()
        .map(|dir| dir.join(GPG_ID_FILE))
        .find(|candidate| candidate.is_file())
}

/// Read a `.gpg-id` file.
///
/// Lines are taken verbatim apart from trimming and dropping blanks, matching
/// what `pass` does. Note we deliberately do not reuse `prs-lib`'s reader: it
/// uppercases each id and truncates it at `#`, which is right for fingerprints
/// but rewrites a user id.
pub fn read(path: &Path) -> Result<Recipients> {
    let contents = fs::read_to_string(path).map_err(|source| Error::io(path, source))?;
    let ids: Vec<String> = contents
        .lines()
        .map(str::trim)
        .filter(|line| !line.is_empty())
        .map(str::to_owned)
        .collect();

    if ids.is_empty() {
        return Err(Error::EmptyRecipients {
            path: path.to_path_buf(),
        });
    }

    Ok(Recipients {
        ids,
        source: path.to_path_buf(),
    })
}

#[cfg(test)]
// Test code handles fixtures, never real secrets.
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;

    /// Build a store fixture: directories to create, then `.gpg-id` files as
    /// (relative directory, contents).
    fn fixture(gpg_ids: &[(&str, &str)]) -> tempfile::TempDir {
        let dir = tempfile::tempdir().unwrap();
        for (relative, contents) in gpg_ids {
            let target = dir.path().join(relative);
            fs::create_dir_all(&target).unwrap();
            fs::write(target.join(GPG_ID_FILE), contents).unwrap();
        }
        dir
    }

    fn name(s: &str) -> EntryName {
        EntryName::new(s).unwrap()
    }

    #[test]
    fn prefers_the_nearest_gpg_id() {
        let store = fixture(&[("", "root-key\n"), ("Email", "email-key\n")]);
        let root = store.path();

        assert_eq!(
            resolve(root, &name("Email/work/gmail.com")).unwrap().ids,
            vec!["email-key"]
        );
        assert_eq!(
            resolve(root, &name("Email/gmail.com")).unwrap().ids,
            vec!["email-key"]
        );
        assert_eq!(
            resolve(root, &name("Bank/ing")).unwrap().ids,
            vec!["root-key"]
        );
        assert_eq!(resolve(root, &name("loose")).unwrap().ids, vec!["root-key"]);
    }

    #[test]
    fn an_entrys_own_directory_wins() {
        let store = fixture(&[("", "root-key"), ("a", "a-key"), ("a/b", "b-key")]);
        assert_eq!(
            resolve(store.path(), &name("a/b/secret")).unwrap().ids,
            vec!["b-key"]
        );
    }

    #[test]
    fn a_sibling_gpg_id_does_not_apply() {
        let store = fixture(&[("", "root-key"), ("other", "other-key")]);
        assert_eq!(
            resolve(store.path(), &name("Email/gmail.com")).unwrap().ids,
            vec!["root-key"]
        );
    }

    #[test]
    fn errors_when_no_gpg_id_exists() {
        let store = tempfile::tempdir().unwrap();
        let err = resolve(store.path(), &name("a/b")).unwrap_err();
        assert!(matches!(err, Error::NoRecipients { .. }));
    }

    #[test]
    fn errors_on_an_empty_gpg_id() {
        let store = fixture(&[("", "\n  \n\n")]);
        let err = resolve(store.path(), &name("a")).unwrap_err();
        assert!(matches!(err, Error::EmptyRecipients { .. }));
    }

    #[test]
    fn reads_ids_verbatim_apart_from_trimming() {
        let store = fixture(&[("", "  0xDEADBEEF  \n\nMe <me@example.com>\nlower-case-id\n")]);
        assert_eq!(
            resolve(store.path(), &name("a")).unwrap().ids,
            vec!["0xDEADBEEF", "Me <me@example.com>", "lower-case-id"]
        );
    }
}
