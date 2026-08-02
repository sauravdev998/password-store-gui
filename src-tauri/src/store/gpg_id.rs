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
/// the store root — the same order `pass`'s `set_gpg_recipients` uses.
pub fn nearest_gpg_id(root: &Path, name: &EntryName) -> Option<PathBuf> {
    let components: Vec<_> = name.components().collect();
    // The last component is the entry itself, not a directory.
    let parents = components.split_last().map_or(&[][..], |(_, rest)| rest);
    search_up(root, parents)
}

/// Find the `.gpg-id` file governing a *directory*, `None` meaning the root.
///
/// The sibling of [`nearest_gpg_id`], and the difference is only which
/// components count as directories: for an entry the last one is the entry
/// itself, for a folder every one is a folder. Changing a folder's keys asks
/// this question, since the folder is what the user selected.
pub fn nearest_gpg_id_in(root: &Path, dir: Option<&EntryName>) -> Option<PathBuf> {
    let components: Vec<_> = dir
        .map(|dir| dir.components().collect())
        .unwrap_or_default();
    search_up(root, &components)
}

/// Where a `.gpg-id` for `dir` would live, whether or not one is there.
///
/// What a recipient change writes to: setting a folder's keys means putting a
/// `.gpg-id` *in that folder*, which is what makes it a boundary — as opposed to
/// editing whichever ancestor's file currently governs it.
pub fn path_in(root: &Path, dir: Option<&EntryName>) -> PathBuf {
    match dir {
        Some(dir) => dir.to_path(root).join(GPG_ID_FILE),
        None => root.join(GPG_ID_FILE),
    }
}

/// Walk up from `dirs` to the store root, returning the first `.gpg-id` found.
///
/// Ancestors are built up from the root rather than walked back with
/// `Path::parent`, so the search cannot climb out of the store even if `root` is
/// unusual.
fn search_up(root: &Path, dirs: &[&str]) -> Option<PathBuf> {
    let mut candidates = vec![root.to_path_buf()];
    let mut current = root.to_path_buf();
    for component in dirs {
        current.push(component);
        candidates.push(current.clone());
    }

    candidates
        .iter()
        .rev()
        .map(|dir| dir.join(GPG_ID_FILE))
        .find(|candidate| candidate.is_file())
}

/// The entries a `.gpg-id` in `folder` governs, whether or not one is there yet.
///
/// Not "everything under the folder": a subdirectory with its own `.gpg-id` is a
/// separate decision about a separate audience, and re-encrypting through it
/// would overwrite that decision with this one. So an entry belongs here when it
/// is inside `folder` and **nothing between the two** claims it first — the same
/// nearest-wins rule [`resolve`] applies, asked in the other direction.
///
/// It answers for a file that does not exist yet on purpose. Setting keys on a
/// folder that had none is `pass init --path`, and what that does is move the
/// folder's subtree out from under whatever governed it — so the entries it
/// affects have to be worked out from where the file *will* be.
pub fn governed_by<'a>(
    root: &Path,
    folder: Option<&EntryName>,
    entries: impl IntoIterator<Item = &'a EntryName>,
) -> Vec<EntryName> {
    let prefix: Vec<&str> = folder
        .map(|folder| folder.components().collect())
        .unwrap_or_default();

    entries
        .into_iter()
        .filter(|name| {
            let components: Vec<&str> = name.components().collect();
            // The last component is the entry itself, not a directory.
            let Some((_, dirs)) = components.split_last() else {
                return false;
            };
            if !dirs.starts_with(&prefix[..]) {
                return false;
            }

            // Walk down from the folder to the entry. Any `.gpg-id` on the way
            // is nearer than the one being asked about, and takes the entry.
            let mut current = root.to_path_buf();
            for component in &prefix {
                current.push(component);
            }
            for component in &dirs[prefix.len()..] {
                current.push(component);
                if current.join(GPG_ID_FILE).is_file() {
                    return false;
                }
            }
            true
        })
        .cloned()
        .collect()
}

/// The folder a `.gpg-id` path sits in, `None` meaning the store root.
///
/// The inverse of [`path_in`], for reporting *where* a decision was made back to
/// an interface that speaks in folders rather than in paths.
pub fn folder_of(root: &Path, gpg_id: &Path) -> Option<EntryName> {
    let relative = gpg_id.parent()?.strip_prefix(root).ok()?;
    let components: Vec<&str> = relative
        .components()
        .filter_map(|component| match component {
            std::path::Component::Normal(part) => part.to_str(),
            _ => None,
        })
        .collect();

    if components.is_empty() {
        return None;
    }
    EntryName::new(components.join("/")).ok()
}

/// Write a `.gpg-id` file, one id per line.
///
/// Byte-compatible with `pass init`, which does `printf "%s\n" "$@"` — so every
/// line including the last is newline-terminated, and no comment, header or
/// ordering of our own is added. §4.1 principle 3: nothing goes into the format
/// for our convenience.
///
/// Written atomically for a reason sharper than an entry's: this file *is* the
/// store's access-control decision, so a truncated one would silently encrypt
/// the next write to fewer people than the store demands.
pub fn write(path: &Path, ids: &[String]) -> Result<()> {
    if ids.is_empty() {
        return Err(Error::EmptyRecipients {
            path: path.to_path_buf(),
        });
    }
    for id in ids {
        validate_id(id)?;
    }

    let mut contents = String::new();
    for id in ids {
        contents.push_str(id);
        contents.push('\n');
    }
    crate::atomic::write(path, contents.as_bytes())
}

/// Reject an id that could not survive the round trip through this file.
///
/// The ids reach us from a form, and this file is line-delimited: an id
/// containing a newline would be *read back as two recipients*, which is a way
/// to add a key to a store by typing it into the middle of another one's name.
/// [`read`] trims, so leading and trailing whitespace would not round-trip
/// either, and an id that is only whitespace would vanish entirely.
fn validate_id(id: &str) -> Result<()> {
    let trimmed = id.trim();
    if trimmed.is_empty() || trimmed != id || id.chars().any(char::is_control) {
        return Err(Error::InvalidRecipientId { id: id.to_owned() });
    }
    Ok(())
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

    /// A folder's own `.gpg-id` governs it; without one it inherits.
    #[test]
    fn a_directorys_walk_up_counts_every_component_as_a_directory() {
        let store = fixture(&[("", "root-key"), ("Email", "email-key")]);
        let root = store.path();

        assert_eq!(
            nearest_gpg_id_in(root, Some(&name("Email"))),
            Some(root.join("Email").join(GPG_ID_FILE))
        );
        // `Email/work` has none of its own, so the walk-up lands on `Email`'s —
        // where the *entry* walk-up for the name "Email/work" would have taken
        // "work" for an entry and landed in the same place for a different
        // reason. The two questions are only accidentally the same here.
        assert_eq!(
            nearest_gpg_id_in(root, Some(&name("Email/work"))),
            Some(root.join("Email").join(GPG_ID_FILE))
        );
        assert_eq!(nearest_gpg_id_in(root, None), Some(root.join(GPG_ID_FILE)));
    }

    #[test]
    fn a_gpg_id_path_is_inside_the_folder_it_governs() {
        let root = Path::new("/store");
        assert_eq!(path_in(root, None), Path::new("/store/.gpg-id"));
        assert_eq!(
            path_in(root, Some(&name("Email/work"))),
            Path::new("/store/Email/work/.gpg-id")
        );
    }

    /// The subtree rule: a deeper `.gpg-id` is its own decision about its own
    /// audience, so the entries under it belong to that file and not this one.
    #[test]
    fn a_nested_gpg_id_shields_its_own_subtree() {
        let store = fixture(&[("", "root-key"), ("Work", "work-key")]);
        let root = store.path();
        let entries = [
            name("wifi"),
            name("Email/gmail.com"),
            name("Work/vpn"),
            name("Work/deep/nested"),
        ];

        assert_eq!(
            governed_by(root, None, &entries),
            vec![name("wifi"), name("Email/gmail.com")],
            "entries under Work/ answer to Work/.gpg-id, not the root's"
        );

        assert_eq!(
            governed_by(root, Some(&name("Work")), &entries),
            vec![name("Work/vpn"), name("Work/deep/nested")]
        );
    }

    /// Setting keys on a folder that has none is `pass init --path`: it moves
    /// that subtree out from under whatever governs it. The entries affected
    /// have to be worked out from where the file *will* be, not from where the
    /// existing ones are.
    #[test]
    fn a_folder_with_no_gpg_id_yet_still_has_a_subtree() {
        let store = fixture(&[("", "root-key")]);
        let root = store.path();
        fs::create_dir_all(root.join("Email/work")).unwrap();
        let entries = [
            name("wifi"),
            name("Email/gmail.com"),
            name("Email/work/corp"),
        ];

        assert_eq!(
            governed_by(root, Some(&name("Email")), &entries),
            vec![name("Email/gmail.com"), name("Email/work/corp")],
            "a prospective .gpg-id in Email/ would take everything below it"
        );
    }

    #[test]
    fn a_gpg_id_path_round_trips_to_the_folder_it_governs() {
        let root = Path::new("/store");
        assert_eq!(folder_of(root, &path_in(root, None)), None);
        for folder in ["Email", "Email/work"] {
            let named = name(folder);
            assert_eq!(
                folder_of(root, &path_in(root, Some(&named))),
                Some(named),
                "did not round trip {folder}"
            );
        }
    }

    #[test]
    fn a_written_gpg_id_reads_back_as_what_was_written() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join(GPG_ID_FILE);
        let ids = vec![
            "0xDEADBEEF".to_owned(),
            "Me <me@example.com>".to_owned(),
            "another-key".to_owned(),
        ];

        write(&path, &ids).unwrap();

        // Byte-compatible with `pass init`'s `printf "%s\n"`: one id per line,
        // every line terminated, nothing else added.
        assert_eq!(
            fs::read_to_string(&path).unwrap(),
            "0xDEADBEEF\nMe <me@example.com>\nanother-key\n"
        );
        assert_eq!(read(&path).unwrap().ids, ids);
    }

    /// An id holding a newline would be read back as two recipients — a way to
    /// add a key to a store by typing it inside another one's name.
    #[test]
    fn refuses_an_id_that_would_not_round_trip() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join(GPG_ID_FILE);

        for bad in [
            "a\nsmuggled-key",
            " leading",
            "trailing ",
            "",
            "   ",
            "a\0b",
        ] {
            let err = write(&path, &[bad.to_owned()]).unwrap_err();
            assert!(
                matches!(err, Error::InvalidRecipientId { .. }),
                "accepted {bad:?}"
            );
        }
        // Nothing was written by any of the refusals.
        assert!(!path.exists());
    }

    #[test]
    fn refuses_to_write_an_empty_recipient_list() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join(GPG_ID_FILE);
        assert!(matches!(
            write(&path, &[]).unwrap_err(),
            Error::EmptyRecipients { .. }
        ));
        assert!(!path.exists());
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
