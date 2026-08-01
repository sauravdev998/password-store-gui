//! Git: the store's history.
//!
//! Phase 3 needs exactly one operation — record what a mutation just changed,
//! with the message `pass` would have written — so that is all this module
//! does. Status, pull, push and per-entry history are Phase 4, and the network
//! question they raise (Open Decision 2) is untouched here: a commit is a local
//! operation, which is why `git2` is taken with its network features off.
//!
//! Three decisions shape the module:
//!
//! - **A store that is not a repository is not an error.** `pass git init` is
//!   optional and most stores never run it, so [`GitRepo::discover`] returning
//!   `None` is the ordinary case rather than a failure to report.
//! - **A failed commit does not fail the mutation.** By the time anything here
//!   runs, the entry is already encrypted and on disk. Reporting a commit
//!   failure as a failed *write* would tell the user their password was not
//!   saved when it was — the same reasoning that makes `generate`'s clipboard
//!   receipt optional. The outcome travels back in the receipt instead, and the
//!   interface says what actually happened (§4.1 principle 5).
//! - **Git only ever sees ciphertext.** Invariant 1 keeps plaintext off disk,
//!   so nothing this module stages, diffs, or reports on can contain a secret.
//!   That is what makes [`Error::Git`] safe to carry libgit2's own message
//!   when the crypto layer's errors deliberately carry nothing.

use std::path::{Path, PathBuf};

use crate::error::{Error, Result};
use crate::store::EntryName;

/// Recording a change in the store's history.
///
/// A trait for the same reason [`crate::store::Store`] is one: the command
/// tests need to see which message a mutation would have written without
/// standing up a repository on disk.
///
/// Unlike the other traits in the crate this is not `Send + Sync`, and does not
/// need to be. `git2::Repository` is neither, and a repository is discovered
/// inside the command that commits and dropped before it returns — the same
/// per-command lifetime the store and the crypto backend already have.
pub trait Vcs {
    /// Stage `paths` and commit them.
    ///
    /// Paths are relative to the **store root**, not to the repository: the
    /// store may sit in a subdirectory of a larger repository, and knowing
    /// where is this module's job rather than the caller's.
    ///
    /// A path that no longer exists is staged as a deletion, which is what
    /// makes one method serve a write and a removal alike.
    fn commit(&self, message: &str, paths: &[PathBuf]) -> Result<()>;
}

/// What a mutation did, in the words `pass` uses for it.
///
/// Keeping the wording in one enum rather than at six call sites is what makes
/// it testable — and a store's history is shared with the CLI, so the messages
/// are a compatibility surface in their own small way: someone reading
/// `git log` should not be able to tell which client wrote which commit.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Change<'a> {
    Insert(&'a EntryName),
    Generate(&'a EntryName),
    Edit(&'a EntryName),
    Remove(&'a EntryName),
    Rename {
        from: &'a EntryName,
        to: &'a EntryName,
    },
    Copy {
        from: &'a EntryName,
        to: &'a EntryName,
    },
}

impl Change<'_> {
    /// The commit message, matching `pass`'s own.
    ///
    /// One deviation: `pass edit` ends its message with the editor it invoked
    /// (`using vi.`), because that is literally what happened. Here the app is
    /// the editor, so it names itself in the same slot rather than dropping the
    /// clause and producing a message no `pass` user would recognise.
    pub fn message(&self) -> String {
        match self {
            Self::Insert(name) => format!("Add given password for {name} to store."),
            Self::Generate(name) => format!("Add generated password for {name}."),
            Self::Edit(name) => format!("Edit password for {name} using Password Store."),
            Self::Remove(name) => format!("Remove {name} from store."),
            Self::Rename { from, to } => format!("Rename {from} to {to}."),
            Self::Copy { from, to } => format!("Copy {from} to {to}."),
        }
    }

    /// The files the change touched, relative to the store root.
    ///
    /// A rename yields both ends: git has no rename operation, only a removal
    /// and an addition that a later `git log --follow` can recognise as one.
    pub fn paths(&self) -> Vec<PathBuf> {
        match self {
            Self::Insert(name) | Self::Generate(name) | Self::Edit(name) | Self::Remove(name) => {
                vec![relative(name)]
            }
            Self::Rename { from, to } => vec![relative(from), relative(to)],
            Self::Copy { to, .. } => vec![relative(to)],
        }
    }
}

/// An entry's ciphertext path, relative to the store root.
fn relative(name: &EntryName) -> PathBuf {
    name.to_secret_path(Path::new(""))
}

/// The git repository a store lives in.
pub struct GitRepo {
    repo: git2::Repository,
    /// The store root, relative to the repository's working directory.
    ///
    /// Usually empty — `pass git init` makes the store root the repository
    /// root — but a store nested inside a larger repository is exactly what
    /// `pass` supports, so the offset is carried rather than assumed away.
    prefix: PathBuf,
}

impl GitRepo {
    /// The repository governing the store at `root`, or `None` if there is
    /// none.
    ///
    /// Searches upward, which is what `pass`'s own `set_git` does: it asks
    /// `git rev-parse --is-inside-work-tree` from inside the store, and that
    /// finds a repository whose root is an ancestor. So a store kept inside a
    /// dotfiles repository is versioned by it here exactly as it is there.
    ///
    /// A bare repository has no working tree to write into, so it is `None`
    /// rather than an error: there is nothing to commit against.
    pub fn discover(root: &Path) -> Option<Self> {
        let repo = git2::Repository::discover(root).ok()?;
        let workdir = dunce::canonicalize(repo.workdir()?).ok()?;
        let prefix = dunce::canonicalize(root)
            .ok()?
            .strip_prefix(&workdir)
            .ok()?
            .to_path_buf();
        Some(Self { repo, prefix })
    }

    /// Where `path` — store-relative — sits inside the repository.
    fn in_repo(&self, path: &Path) -> PathBuf {
        self.prefix.join(path)
    }
}

impl Vcs for GitRepo {
    fn commit(&self, message: &str, paths: &[PathBuf]) -> Result<()> {
        let workdir = self.repo.workdir().ok_or(Error::Git {
            reason: "the repository has no working tree".to_owned(),
        })?;
        let mut index = self.repo.index().map_err(as_error)?;

        for path in paths {
            let relative = self.in_repo(path);
            let staged = if workdir.join(&relative).exists() {
                index.add_path(&relative)
            } else {
                // The file is gone, so staging it *is* the deletion. A path git
                // never tracked has nothing to remove — that is not a failure,
                // it just leaves the index as it was.
                match index.remove_path(&relative) {
                    Err(err) if err.code() == git2::ErrorCode::NotFound => Ok(()),
                    other => other,
                }
            };
            staged.map_err(as_error)?;
        }

        index.write().map_err(as_error)?;
        let tree_id = index.write_tree().map_err(as_error)?;
        let head = self.repo.head().ok().and_then(|h| h.peel_to_commit().ok());

        // Nothing changed that was not already committed. `pass` gets this for
        // free — `git commit` refuses an empty commit — and without it a
        // no-op mutation would leave an empty commit in a history shared with
        // the CLI.
        if head.as_ref().map(git2::Commit::tree_id) == Some(tree_id) {
            return Ok(());
        }

        let tree = self.repo.find_tree(tree_id).map_err(as_error)?;
        // The one failure worth naming separately: it is the common first-run
        // state on a fresh machine, and the fix is not guessable from
        // libgit2's own wording.
        let who = self.repo.signature().map_err(|_| Error::GitNoIdentity)?;
        let parents: Vec<&git2::Commit> = head.iter().collect();

        self.repo
            .commit(Some("HEAD"), &who, &who, message, &tree, &parents)
            .map_err(as_error)?;
        Ok(())
    }
}

/// Carry libgit2's message through.
///
/// Safe here and nowhere else in the crate: git sees only what is on disk, and
/// what is on disk is ciphertext (Invariant 1). By the time any of this runs
/// the plaintext has already been dropped, so there is nothing in the process
/// for a message to capture.
fn as_error(err: git2::Error) -> Error {
    Error::Git {
        reason: err.message().to_owned(),
    }
}

#[cfg(test)]
// Test code handles fixtures, never real secrets: every file below is a
// placeholder byte string, not ciphertext.
#[allow(clippy::unwrap_used)]
mod tests {
    use std::fs;

    use super::*;

    fn name(name: &str) -> EntryName {
        EntryName::new(name).unwrap()
    }

    /// An initialised repository with an author configured, so `signature()`
    /// does not depend on whatever global git config the machine has.
    fn repo() -> tempfile::TempDir {
        let dir = tempfile::tempdir().unwrap();
        let repo = git2::Repository::init(dir.path()).unwrap();
        let mut config = repo.config().unwrap();
        config.set_str("user.name", "Test").unwrap();
        config
            .set_str("user.email", "test@example.invalid")
            .unwrap();
        dir
    }

    /// Write an entry's ciphertext, creating its folder.
    fn write(root: &Path, entry: &str, contents: &str) {
        let path = name(entry).to_secret_path(root);
        fs::create_dir_all(path.parent().unwrap()).unwrap();
        fs::write(path, contents).unwrap();
    }

    /// Every commit message in the repository, newest first.
    fn log(root: &Path) -> Vec<String> {
        let repo = git2::Repository::discover(root).unwrap();
        let mut walk = repo.revwalk().unwrap();
        walk.push_head().unwrap();
        walk.map(|id| {
            repo.find_commit(id.unwrap())
                .unwrap()
                .message()
                .unwrap_or_default()
                .to_owned()
        })
        .collect()
    }

    /// Paths tracked by HEAD's tree, relative to the repository root.
    fn tracked(root: &Path) -> Vec<String> {
        let repo = git2::Repository::discover(root).unwrap();
        let tree = repo.head().unwrap().peel_to_tree().unwrap();
        let mut out = Vec::new();
        tree.walk(git2::TreeWalkMode::PreOrder, |dir, entry| {
            if entry.kind() == Some(git2::ObjectType::Blob) {
                out.push(format!("{dir}{}", entry.name().unwrap_or_default()));
            }
            git2::TreeWalkResult::Ok
        })
        .unwrap();
        out.sort();
        out
    }

    #[test]
    fn a_store_that_is_not_a_repository_has_no_history() {
        let dir = tempfile::tempdir().unwrap();
        assert!(GitRepo::discover(dir.path()).is_none());
    }

    #[test]
    fn the_first_commit_needs_no_parent() {
        let dir = repo();
        write(dir.path(), "wifi", "ciphertext");

        let git = GitRepo::discover(dir.path()).unwrap();
        let change = Change::Insert(&name("wifi"));
        git.commit(&change.message(), &change.paths()).unwrap();

        assert_eq!(
            log(dir.path()),
            vec!["Add given password for wifi to store."]
        );
        assert_eq!(tracked(dir.path()), vec!["wifi.gpg"]);
    }

    #[test]
    fn a_removed_entry_is_staged_as_a_deletion() {
        let dir = repo();
        write(dir.path(), "wifi", "ciphertext");
        write(dir.path(), "keep", "ciphertext");
        let git = GitRepo::discover(dir.path()).unwrap();
        let added = Change::Insert(&name("wifi"));
        git.commit(&added.message(), &added.paths()).unwrap();
        let kept = Change::Insert(&name("keep"));
        git.commit(&kept.message(), &kept.paths()).unwrap();

        fs::remove_file(name("wifi").to_secret_path(dir.path())).unwrap();
        let removed = Change::Remove(&name("wifi"));
        git.commit(&removed.message(), &removed.paths()).unwrap();

        assert_eq!(tracked(dir.path()), vec!["keep.gpg"]);
        assert_eq!(log(dir.path())[0], "Remove wifi from store.");
    }

    /// A rename is a removal and an addition in one commit, which is what lets
    /// `git log --follow` join them back up.
    #[test]
    fn a_rename_commits_both_ends_together() {
        let dir = repo();
        write(dir.path(), "wifi", "ciphertext");
        let git = GitRepo::discover(dir.path()).unwrap();
        let added = Change::Insert(&name("wifi"));
        git.commit(&added.message(), &added.paths()).unwrap();

        fs::remove_file(name("wifi").to_secret_path(dir.path())).unwrap();
        write(dir.path(), "Home/wifi", "ciphertext");
        let moved = Change::Rename {
            from: &name("wifi"),
            to: &name("Home/wifi"),
        };
        git.commit(&moved.message(), &moved.paths()).unwrap();

        assert_eq!(tracked(dir.path()), vec!["Home/wifi.gpg"]);
        assert_eq!(log(dir.path())[0], "Rename wifi to Home/wifi.");
    }

    /// The store may be a subdirectory of a larger repository — a dotfiles
    /// checkout, say — and `pass` versions it with that repository, so paths
    /// have to be staged relative to the repository root rather than the store.
    #[test]
    fn a_store_nested_in_a_repository_stages_paths_from_the_repository_root() {
        let dir = repo();
        let root = dir.path().join("secrets");
        fs::create_dir(&root).unwrap();
        write(&root, "Email/gmail.com", "ciphertext");

        let git = GitRepo::discover(&root).unwrap();
        let change = Change::Insert(&name("Email/gmail.com"));
        git.commit(&change.message(), &change.paths()).unwrap();

        assert_eq!(tracked(&root), vec!["secrets/Email/gmail.com.gpg"]);
    }

    /// Committing the same state twice must not leave an empty commit behind:
    /// the history is shared with the CLI, where `git commit` refuses one.
    #[test]
    fn nothing_to_record_writes_no_commit() {
        let dir = repo();
        write(dir.path(), "wifi", "ciphertext");
        let git = GitRepo::discover(dir.path()).unwrap();
        let change = Change::Insert(&name("wifi"));

        git.commit(&change.message(), &change.paths()).unwrap();
        git.commit(&change.message(), &change.paths()).unwrap();

        assert_eq!(log(dir.path()).len(), 1);
    }

    /// Removing an entry git never tracked leaves the history alone rather than
    /// reporting a failure the user cannot act on.
    #[test]
    fn removing_an_untracked_entry_is_not_a_failure() {
        let dir = repo();
        let change = Change::Remove(&name("never-tracked"));

        assert!(git_of(&dir)
            .commit(&change.message(), &change.paths())
            .is_ok());
    }

    fn git_of(dir: &tempfile::TempDir) -> GitRepo {
        GitRepo::discover(dir.path()).unwrap()
    }

    #[test]
    fn messages_match_the_cli_wording() {
        let wifi = name("wifi");
        let home = name("Home/wifi");

        assert_eq!(
            Change::Insert(&wifi).message(),
            "Add given password for wifi to store."
        );
        assert_eq!(
            Change::Generate(&wifi).message(),
            "Add generated password for wifi."
        );
        assert_eq!(
            Change::Edit(&wifi).message(),
            "Edit password for wifi using Password Store."
        );
        assert_eq!(Change::Remove(&wifi).message(), "Remove wifi from store.");
        assert_eq!(
            Change::Rename {
                from: &wifi,
                to: &home
            }
            .message(),
            "Rename wifi to Home/wifi."
        );
        assert_eq!(
            Change::Copy {
                from: &wifi,
                to: &home
            }
            .message(),
            "Copy wifi to Home/wifi."
        );
    }

    /// A copy leaves the source untouched, so only the destination is staged.
    #[test]
    fn paths_are_store_relative_and_carry_the_gpg_suffix() {
        let wifi = name("wifi");
        let home = name("Home/wifi");

        assert_eq!(
            Change::Insert(&wifi).paths(),
            vec![PathBuf::from("wifi.gpg")]
        );
        assert_eq!(
            Change::Rename {
                from: &wifi,
                to: &home
            }
            .paths(),
            vec![
                PathBuf::from("wifi.gpg"),
                Path::new("Home").join("wifi.gpg")
            ]
        );
        assert_eq!(
            Change::Copy {
                from: &wifi,
                to: &home
            }
            .paths(),
            vec![Path::new("Home").join("wifi.gpg")]
        );
    }
}
