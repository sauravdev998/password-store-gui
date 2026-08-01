//! Validated entry names — the single choke point for untrusted paths.
//!
//! `prs-lib` neither rejects `..` nor declines to shell-expand the strings it is
//! given: `Store::find_at` is a bare `root.join(path)`, and both `Store::open`
//! and `normalize_secret_path` run their argument through `shellexpand::full`,
//! which expands `~` and `$VAR` (`PLAN.md` ADR-4a, F-6). Nothing in this crate
//! may build a store path from a raw string; it goes through [`EntryName`]
//! first.

use std::fmt;
use std::path::{Component, Path, PathBuf};

use serde::{Deserialize, Deserializer, Serialize};
use thiserror::Error;

/// Longest accepted entry name, in bytes.
///
/// Well past anything a real store uses; it only bounds pathological input.
const MAX_LEN: usize = 4096;

/// The `.gpg` suffix every secret file carries.
pub const SECRET_SUFFIX: &str = ".gpg";

/// A validated password-store entry or directory name.
///
/// The canonical form is the identity `pass` itself uses: a relative,
/// `/`-separated path with no `.gpg` suffix, e.g. `Email/gmail.com`. It is
/// always relative to the store root, always separator-normalized, and is
/// guaranteed not to escape the root when joined onto it.
///
/// Deserialization goes through [`EntryName::new`], so a name arriving over IPC
/// cannot be constructed without passing validation.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize)]
#[serde(transparent)]
pub struct EntryName(String);

impl EntryName {
    /// Validate a `/`-separated, store-relative name.
    pub fn new(name: impl Into<String>) -> Result<Self, InvalidName> {
        let name = name.into();

        if name.is_empty() {
            return Err(InvalidName::Empty);
        }
        if name.len() > MAX_LEN {
            return Err(InvalidName::TooLong);
        }

        for ch in name.chars() {
            match ch {
                // Covers NUL. Control characters have no place in a file name
                // and are a terminal-escape vector wherever a name is rendered.
                c if c.is_control() => return Err(InvalidName::ControlCharacter),
                // A separator on Windows: allowing it would let `..\` through
                // the component checks below.
                '\\' => return Err(InvalidName::Backslash),
                // `shellexpand` would read this as `$VAR` (F-6). This does
                // reject a name the `pass` CLI would accept; that is the
                // trade `PLAN.md` chose, and such entries surface as
                // `Tree::unsupported` rather than vanishing.
                '$' => return Err(InvalidName::VariableExpansion),
                _ => {}
            }
        }

        // `shellexpand` only expands `~` in leading position.
        if name.starts_with('~') {
            return Err(InvalidName::HomeExpansion);
        }

        for component in name.split('/') {
            match component {
                "" => return Err(InvalidName::EmptyComponent),
                "." => return Err(InvalidName::CurrentDirComponent),
                ".." => return Err(InvalidName::ParentDirComponent),
                _ => {}
            }
            // A Windows drive-relative prefix (`C:foo`) escapes the root just
            // as an absolute path would.
            let bytes = component.as_bytes();
            if bytes.len() >= 2 && bytes[1] == b':' && bytes[0].is_ascii_alphabetic() {
                return Err(InvalidName::DrivePrefix);
            }
        }

        Ok(Self(name))
    }

    /// Build a name from a secret file's path inside `root`.
    ///
    /// Strips the store root and the `.gpg` suffix and rebuilds the name from
    /// [`Path::components`], so a platform separator never has to be guessed at.
    pub fn from_secret_path(root: &Path, path: &Path) -> Result<Self, InvalidName> {
        let relative = path
            .strip_prefix(root)
            .map_err(|_| InvalidName::OutsideRoot)?;

        let mut parts = Vec::new();
        for component in relative.components() {
            let Component::Normal(part) = component else {
                // Anything else (`..`, a root, a prefix) means the path was not
                // the plain descendant of `root` the walker promised.
                return Err(InvalidName::ParentDirComponent);
            };
            let part = part.to_str().ok_or(InvalidName::NotUtf8)?;
            parts.push(part);
        }

        let Some(last) = parts.pop() else {
            return Err(InvalidName::Empty);
        };
        parts.push(last.strip_suffix(SECRET_SUFFIX).unwrap_or(last));

        Self::new(parts.join("/"))
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }

    /// The `/`-separated components, always at least one.
    pub fn components(&self) -> impl DoubleEndedIterator<Item = &str> {
        self.0.split('/')
    }

    /// The last component — what the UI shows as the node's label.
    pub fn leaf(&self) -> &str {
        // `split` always yields at least one item.
        self.components().next_back().unwrap_or(&self.0)
    }

    /// Join onto `root`, one component at a time.
    ///
    /// Deliberately not `root.join(self.as_str())`: pushing components
    /// individually means the platform's separator handling never gets a chance
    /// to reinterpret the string.
    pub fn to_path(&self, root: &Path) -> PathBuf {
        let mut path = root.to_path_buf();
        for component in self.components() {
            path.push(component);
        }
        path
    }

    /// Path of the encrypted file backing this entry.
    pub fn to_secret_path(&self, root: &Path) -> PathBuf {
        // Append rather than `set_extension`, which would eat an existing one:
        // the entry `foo.bar` lives in `foo.bar.gpg`.
        let mut path = self.to_path(root).into_os_string();
        path.push(SECRET_SUFFIX);
        PathBuf::from(path)
    }
}

impl fmt::Display for EntryName {
    /// Entry names are metadata, not secrets — the tree renders them. Nothing
    /// derived from decrypted content may ever be stored in one.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

impl<'de> Deserialize<'de> for EntryName {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let raw = String::deserialize(deserializer)?;
        Self::new(raw).map_err(serde::de::Error::custom)
    }
}

/// Why a name was rejected.
///
/// Carries no copy of the offending name: the caller knows what it passed, and
/// a reason-only message cannot echo attacker-controlled text back into a log
/// or a dialog.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Error)]
pub enum InvalidName {
    #[error("name is empty")]
    Empty,
    #[error("name is too long")]
    TooLong,
    #[error("name contains a control character")]
    ControlCharacter,
    #[error("name contains a backslash")]
    Backslash,
    #[error("name contains '$'")]
    VariableExpansion,
    #[error("name starts with '~'")]
    HomeExpansion,
    #[error("name contains an empty path component")]
    EmptyComponent,
    #[error("name contains a '.' component")]
    CurrentDirComponent,
    #[error("name contains a '..' component")]
    ParentDirComponent,
    #[error("name contains a drive prefix")]
    DrivePrefix,
    #[error("name is not valid UTF-8")]
    NotUtf8,
    #[error("path is outside the store root")]
    OutsideRoot,
}

#[cfg(test)]
// Test code handles fixtures, never real secrets.
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;

    #[test]
    fn accepts_ordinary_names() {
        for name in [
            "gmail.com",
            "Email/gmail.com",
            "a/b/c",
            "with space",
            "ünïcode",
        ] {
            assert!(EntryName::new(name).is_ok(), "rejected {name}");
        }
    }

    #[test]
    fn rejects_traversal_and_expansion() {
        let cases = [
            ("", InvalidName::Empty),
            ("..", InvalidName::ParentDirComponent),
            ("a/../../etc/passwd", InvalidName::ParentDirComponent),
            ("./a", InvalidName::CurrentDirComponent),
            ("/etc/passwd", InvalidName::EmptyComponent),
            ("a//b", InvalidName::EmptyComponent),
            ("a/", InvalidName::EmptyComponent),
            ("a\\..\\b", InvalidName::Backslash),
            ("$HOME/keys", InvalidName::VariableExpansion),
            ("~/keys", InvalidName::HomeExpansion),
            ("a\0b", InvalidName::ControlCharacter),
            ("a\nb", InvalidName::ControlCharacter),
            ("C:/keys", InvalidName::DrivePrefix),
        ];
        for (input, expected) in cases {
            assert_eq!(
                EntryName::new(input).unwrap_err(),
                expected,
                "for input {input:?}"
            );
        }
    }

    #[test]
    fn to_path_cannot_escape_the_root() {
        let root = Path::new("/store");
        let name = EntryName::new("Email/gmail.com").unwrap();
        assert_eq!(name.to_path(root), Path::new("/store/Email/gmail.com"));
        assert_eq!(
            name.to_secret_path(root),
            Path::new("/store/Email/gmail.com.gpg")
        );
    }

    #[test]
    fn secret_path_appends_rather_than_replaces_an_extension() {
        let name = EntryName::new("archive.tar").unwrap();
        assert_eq!(
            name.to_secret_path(Path::new("/store")),
            Path::new("/store/archive.tar.gpg")
        );
    }

    #[test]
    fn round_trips_a_secret_path() {
        let root = Path::new("/store");
        let name =
            EntryName::from_secret_path(root, Path::new("/store/Email/gmail.com.gpg")).unwrap();
        assert_eq!(name.as_str(), "Email/gmail.com");
        assert_eq!(name.leaf(), "gmail.com");
        assert_eq!(
            name.to_secret_path(root),
            Path::new("/store/Email/gmail.com.gpg")
        );
    }

    #[test]
    fn rejects_a_secret_path_outside_the_root() {
        assert_eq!(
            EntryName::from_secret_path(Path::new("/store"), Path::new("/etc/shadow.gpg"))
                .unwrap_err(),
            InvalidName::OutsideRoot
        );
    }

    #[test]
    fn deserialization_validates() {
        assert!(serde_json::from_str::<EntryName>("\"a/b\"").is_ok());
        assert!(serde_json::from_str::<EntryName>("\"../etc/passwd\"").is_err());
    }
}
