//! `prs-lib`-backed [`Store`] implementation.
//!
//! The only module allowed to name a `prs-lib` type (ADR-4). Three of that
//! crate's behaviours are deliberately bypassed here:
//!
//! - `Store::open` shell-expands its argument, so we build `prs_lib::Store`
//!   from an already-resolved `PathBuf` instead (F-6).
//! - `Store::find_at` / `normalize_secret_path` join unvalidated strings onto
//!   the root; entry paths come from [`EntryName`] instead (F-6).
//! - `Store::recipients` reads the root `.gpg-id` only; recipients come from
//!   [`gpg_id`] instead (F-1).
//! - `store::can_decrypt` decrypts a real secret and inspects the plaintext as
//!   a `&str` without zeroizing it (F-5). Never call it.

use std::path::{Path, PathBuf};

use crate::error::{Error, Result};
use crate::store::{gpg_id, tree, EntryName, Recipients, Store, Tree};

/// A store on the local filesystem.
pub struct PrsStore {
    inner: prs_lib::Store,
}

impl PrsStore {
    /// Open the store rooted at `root`.
    ///
    /// The path is canonicalized here, which is also what makes
    /// `strip_prefix` in [`EntryName::from_secret_path`] reliable: every path
    /// the walker yields is then a literal descendant of this root.
    pub fn open(root: impl AsRef<Path>) -> Result<Self> {
        let root = root.as_ref();
        let canonical = root
            .canonicalize()
            .map_err(|_| Error::StoreNotFound { path: root.into() })?;

        if !canonical.is_dir() {
            return Err(Error::StoreNotFound { path: canonical });
        }

        // Constructed field-wise on purpose: `prs_lib::Store::open` would run
        // the path through `shellexpand::full`, expanding any `~` or `$VAR` a
        // legitimate directory name happens to contain (F-6).
        Ok(Self {
            inner: prs_lib::Store { root: canonical },
        })
    }

    /// Open the store at `PASSWORD_STORE_DIR`, else `~/.password-store`.
    pub fn open_default() -> Result<Self> {
        Self::open(super::default_root()?)
    }
}

impl Store for PrsStore {
    fn root(&self) -> &Path {
        &self.inner.root
    }

    fn tree(&self) -> Result<Tree> {
        let root = self.root();
        let mut names = Vec::new();
        let mut unsupported = Vec::new();

        // `secret_iter` walks the store for `*.gpg`, skipping hidden
        // directories — so `.git` and `.public-keys` never appear.
        for secret in self.inner.secret_iter() {
            match EntryName::from_secret_path(root, &secret.path) {
                Ok(name) => names.push(name),
                Err(_) => unsupported.push(
                    secret
                        .path
                        .strip_prefix(root)
                        .unwrap_or(&secret.path)
                        .to_string_lossy()
                        .into_owned(),
                ),
            }
        }

        unsupported.sort();
        Ok(Tree {
            nodes: tree::build(&names),
            unsupported,
        })
    }

    fn secret_path(&self, name: &EntryName) -> Result<PathBuf> {
        let path = name.to_secret_path(self.root());
        if path.is_file() {
            Ok(path)
        } else {
            Err(Error::EntryNotFound { name: name.clone() })
        }
    }

    fn recipients(&self, name: &EntryName) -> Result<Recipients> {
        gpg_id::resolve(self.root(), name)
    }
}

#[cfg(test)]
// Test code handles fixtures, never real secrets: every `.gpg` file below is a
// placeholder byte string, not ciphertext.
#[allow(clippy::unwrap_used)]
mod tests {
    use std::fs;

    use super::*;

    /// Create a store fixture from a list of relative file paths.
    fn fixture(files: &[&str]) -> tempfile::TempDir {
        let dir = tempfile::tempdir().unwrap();
        for relative in files {
            let path = dir.path().join(relative);
            fs::create_dir_all(path.parent().unwrap()).unwrap();
            fs::write(&path, b"not-really-ciphertext").unwrap();
        }
        dir
    }

    fn entry_names(tree: &Tree) -> Vec<String> {
        fn walk(nodes: &[crate::store::Node], out: &mut Vec<String>) {
            for node in nodes {
                match node {
                    crate::store::Node::Dir { children, .. } => walk(children, out),
                    crate::store::Node::Entry { path, .. } => out.push(path.to_string()),
                }
            }
        }
        let mut out = Vec::new();
        walk(&tree.nodes, &mut out);
        out.sort();
        out
    }

    #[test]
    fn lists_only_gpg_files_and_skips_hidden_directories() {
        let store = fixture(&[
            "wifi.gpg",
            "Email/gmail.com.gpg",
            "Email/work/corp.gpg",
            "README.md",
            ".git/objects/abc.gpg",
            ".gpg-id",
        ]);
        let tree = PrsStore::open(store.path()).unwrap().tree().unwrap();

        assert_eq!(
            entry_names(&tree),
            vec!["Email/gmail.com", "Email/work/corp", "wifi"]
        );
        assert!(tree.unsupported.is_empty());
    }

    #[test]
    fn surfaces_names_we_refuse_rather_than_hiding_them() {
        let store = fixture(&["ok.gpg", "we$ird.gpg"]);
        let tree = PrsStore::open(store.path()).unwrap().tree().unwrap();

        assert_eq!(entry_names(&tree), vec!["ok"]);
        assert_eq!(tree.unsupported, vec!["we$ird.gpg"]);
    }

    #[test]
    fn secret_path_resolves_an_existing_entry() {
        let store = fixture(&["Email/gmail.com.gpg"]);
        let opened = PrsStore::open(store.path()).unwrap();
        let name = EntryName::new("Email/gmail.com").unwrap();

        assert_eq!(
            opened.secret_path(&name).unwrap(),
            opened.root().join("Email").join("gmail.com.gpg")
        );
    }

    #[test]
    fn secret_path_rejects_a_missing_entry() {
        let store = fixture(&["a.gpg"]);
        let opened = PrsStore::open(store.path()).unwrap();
        let missing = EntryName::new("nope").unwrap();

        assert!(matches!(
            opened.secret_path(&missing),
            Err(Error::EntryNotFound { .. })
        ));
    }

    #[test]
    fn recipients_come_from_the_nearest_gpg_id() {
        let store = fixture(&["Email/work/corp.gpg"]);
        fs::write(store.path().join(".gpg-id"), "root-key\n").unwrap();
        fs::write(store.path().join("Email/.gpg-id"), "email-key\n").unwrap();

        let opened = PrsStore::open(store.path()).unwrap();
        let name = EntryName::new("Email/work/corp").unwrap();
        assert_eq!(opened.recipients(&name).unwrap().ids, vec!["email-key"]);
    }

    #[test]
    fn opening_a_missing_directory_fails() {
        let dir = tempfile::tempdir().unwrap();
        assert!(matches!(
            PrsStore::open(dir.path().join("absent")),
            Err(Error::StoreNotFound { .. })
        ));
    }

    /// The store root may legitimately contain characters `shellexpand` would
    /// rewrite; opening such a store must not touch them (F-6).
    #[test]
    fn opens_a_root_whose_name_looks_like_a_shell_expansion() {
        let parent = tempfile::tempdir().unwrap();
        let root = parent.path().join("$HOME ~store");
        fs::create_dir(&root).unwrap();
        fs::write(root.join("a.gpg"), b"x").unwrap();

        let opened = PrsStore::open(&root).unwrap();
        assert_eq!(opened.root(), root.canonicalize().unwrap());
        assert_eq!(entry_names(&opened.tree().unwrap()), vec!["a"]);
    }
}
