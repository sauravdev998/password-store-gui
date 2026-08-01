//! Git: the store's history, and its remote.
//!
//! The module is split along the line ADR-9 draws. Everything here runs on
//! vendored libgit2 and touches no network: recording a mutation, saying where
//! the store stands relative to its remote, reading an entry's past. Anything
//! that reaches the network is in [`remote`], which spawns the user's own
//! `git` so that their credential helper, `ssh-agent` and keychain keep working
//! without us ever holding a credential.
//!
//! That is why `git2` is still taken with `default-features = false`: with the
//! network half delegated, libssh2 and OpenSSL are never needed.
//!
//! Five decisions shape the module:
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
//! - **A store with no remote is not a broken store.** Most are not shared at
//!   all, so [`SyncOutcome::NoRemote`] is an answer rather than a failure — the
//!   same shape as a store with no repository at all.
//! - **A conflicted merge is rolled back, never left in place.** An unresolved
//!   merge writes conflict markers *into* the files, and here the files are
//!   ciphertext: the result decrypts nowhere, in this app or any other client.
//!   See [`GitRepo::merge`].

pub mod remote;

use std::path::{Path, PathBuf};

use serde::Serialize;

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

    /// Where the store stands relative to its remote.
    ///
    /// Local only: it reports the distance to the remote-tracking ref as it was
    /// at the last fetch, and never goes and looks. That is deliberate — an
    /// indicator the interface can draw on arrival must not be an operation
    /// that can hang, prompt for a credential, or fail because a laptop is on a
    /// train.
    fn status(&self) -> Result<SyncStatus>;

    /// The commits that touched `name`, newest first.
    ///
    /// Names and dates only. Nothing here is decrypted, so opening a history is
    /// free of §4.1 principle 1's concern: no pinentry, no key tap.
    fn history(&self, name: &EntryName) -> Result<Vec<Revision>>;

    /// The **ciphertext** of `name` as it was at `revision`.
    ///
    /// Returns bytes rather than a [`crate::secret::Secret`] because that is
    /// what it is: a blob out of a git object, still encrypted. Decrypting it
    /// is the crypto layer's job and a separate, explicit request (ADR-10).
    fn blob_at(&self, name: &EntryName, revision: &str) -> Result<Vec<u8>>;

    /// Fetch, merge what came back, and push what is ours.
    ///
    /// The one method here that reaches the network, and so the one that needs
    /// the user's `git` (ADR-9).
    fn sync(&self) -> Result<SyncOutcome>;
}

/// Where the store stands relative to its remote, as of the last fetch.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct SyncStatus {
    /// The branch the store is on, or `None` on a repository with no commits
    /// yet or a detached HEAD.
    pub branch: Option<String>,
    /// The remote-tracking branch and the distance to it, or `None` when the
    /// branch tracks nothing — which is the ordinary state of a store that was
    /// `git init`ed locally and never pushed anywhere.
    pub tracking: Option<Tracking>,
    /// How many files under the store have changes the history does not have.
    ///
    /// Normally zero, because every mutation commits itself (Phase 3). It is
    /// non-zero after a commit that failed, or when the store was edited by
    /// something else — and a sync that pushed without saying so would leave
    /// the user believing those changes had gone out.
    pub uncommitted: usize,
}

/// A branch's relationship to the one it tracks.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Tracking {
    /// The remote-tracking branch, as git names it: `origin/main`.
    pub upstream: String,
    /// Commits we have that it does not.
    pub ahead: usize,
    /// Commits it has that we do not.
    pub behind: usize,
}

/// One commit that touched an entry.
///
/// Everything on it is store metadata or the user's own git identity. No field
/// can hold decrypted content, and none is derived from any (Invariant 5).
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Revision {
    /// The commit id in full, which is how a version is asked for.
    pub id: String,
    /// The first line of the commit message — for a store written by `pass` or
    /// by us, a sentence naming the entry and what happened to it.
    pub summary: String,
    /// Who made the commit.
    pub author: String,
    /// Unix seconds. Formatting is the interface's job: it knows the user's
    /// locale and time zone, and this does not.
    pub committed_at: i64,
    /// What the commit did to this entry.
    pub change: RevisionKind,
}

/// What a commit did to the entry being asked about.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub enum RevisionKind {
    Added,
    Modified,
    /// Deleted here — so this commit holds no version of the entry to read.
    /// The one before it does, which is why a removal is listed rather than
    /// skipped.
    Removed,
}

/// What a sync did.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase", tag = "status")]
pub enum SyncOutcome {
    /// The store's branch tracks nothing, so there was nothing to sync with.
    /// Not a failure: a store that is not shared is the ordinary case.
    NoRemote,
    /// Already in step with the remote.
    UpToDate,
    Synced {
        /// Commits brought in.
        pulled: usize,
        /// Commits sent.
        pushed: usize,
    },
    /// The same entries changed on both sides, so the merge could not be
    /// completed. **Nothing on disk was changed** — see [`GitRepo::merge`].
    Conflicted {
        /// The entries involved, named as the user knows them. A path that is
        /// not an entry — a `.gpg-id`, or a file outside the store in a larger
        /// repository — is listed as its path rather than dropped, for the same
        /// reason `Tree::unsupported` exists.
        entries: Vec<String>,
    },
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

    /// The repository's working tree.
    fn workdir(&self) -> Result<&Path> {
        self.repo.workdir().ok_or_else(|| Error::Git {
            reason: "the repository has no working tree".to_owned(),
        })
    }

    /// The branch HEAD is on, or `None` if there is no such thing yet.
    ///
    /// Two states answer `None` and neither is a fault: a repository that has
    /// been `git init`ed and never committed to has an unborn HEAD, and a
    /// detached HEAD is on no branch at all.
    fn branch(&self) -> Result<Option<git2::Branch<'_>>> {
        let head = match self.repo.head() {
            Ok(head) => head,
            Err(err)
                if matches!(
                    err.code(),
                    git2::ErrorCode::UnbornBranch | git2::ErrorCode::NotFound
                ) =>
            {
                return Ok(None)
            }
            Err(err) => return Err(as_error(err)),
        };
        if !head.is_branch() {
            return Ok(None);
        }
        // A ref whose name is not UTF-8 is one we cannot name back to git, so
        // it is treated as no branch rather than guessed at.
        let Ok(name) = head.shorthand() else {
            return Ok(None);
        };
        match self.repo.find_branch(name, git2::BranchType::Local) {
            Ok(branch) => Ok(Some(branch)),
            Err(err) if err.code() == git2::ErrorCode::NotFound => Ok(None),
            Err(err) => Err(as_error(err)),
        }
    }

    /// How far the current branch is from the one it tracks.
    ///
    /// `None` when there is nothing to compare against: no branch, no upstream
    /// configured, or an upstream ref that does not resolve.
    fn tracking(&self) -> Result<Option<Tracking>> {
        let Some(branch) = self.branch()? else {
            return Ok(None);
        };
        // No upstream is the ordinary state of a local-only store, so it is a
        // `None` rather than an error to relay.
        let Ok(upstream) = branch.upstream() else {
            return Ok(None);
        };

        let (Some(local), Some(remote)) = (branch.get().target(), upstream.get().target()) else {
            return Ok(None);
        };
        let (ahead, behind) = self
            .repo
            .graph_ahead_behind(local, remote)
            .map_err(as_error)?;

        Ok(Some(Tracking {
            upstream: upstream
                .name()
                .ok()
                .flatten()
                .unwrap_or("the remote branch")
                .to_owned(),
            ahead,
            behind,
        }))
    }

    /// Files under the store that differ from the history.
    ///
    /// Scoped to the store's own prefix: the repository may be a dotfiles
    /// checkout, and whatever else the user has uncommitted in it is not this
    /// app's business to count or to report.
    fn uncommitted(&self) -> Result<usize> {
        let mut options = git2::StatusOptions::new();
        options.include_untracked(true).include_ignored(false);

        // git's pathspecs are `/`-separated on every platform, which a
        // `PathBuf` rendered on Windows would not be.
        let prefix = self.prefix.to_string_lossy().replace('\\', "/");
        if !prefix.is_empty() {
            options.pathspec(prefix);
        }

        Ok(self
            .repo
            .statuses(Some(&mut options))
            .map_err(as_error)?
            .len())
    }

    /// The blob id `path` had in `tree`, or `None` if it was not there.
    fn blob_in(tree: &git2::Tree<'_>, path: &Path) -> Option<git2::Oid> {
        tree.get_path(path).ok().map(|entry| entry.id())
    }

    /// What `commit` did to `path`, or `None` if it left it alone.
    ///
    /// Compared against the first parent only, which is what `git log <path>`
    /// shows by default: a merge that took one side's version of a file did not
    /// itself change it, and listing every merge in a store's history as a
    /// change to the entry would bury the commits that actually were.
    fn touched(&self, commit: &git2::Commit<'_>, path: &Path) -> Result<Option<RevisionKind>> {
        let tree = commit.tree().map_err(as_error)?;
        let here = Self::blob_in(&tree, path);

        let Some(parent) = commit.parents().next() else {
            // A parentless commit created everything it contains.
            return Ok(here.map(|_| RevisionKind::Added));
        };
        let before = Self::blob_in(&parent.tree().map_err(as_error)?, path);

        Ok(match (before, here) {
            (None, Some(_)) => Some(RevisionKind::Added),
            (Some(_), None) => Some(RevisionKind::Removed),
            (Some(before), Some(here)) if before != here => Some(RevisionKind::Modified),
            _ => None,
        })
    }

    /// Bring the remote's commits in, rolling back rather than leaving a mess.
    ///
    /// `Some(entries)` means the merge could not be completed and **nothing on
    /// disk changed**. That rollback is the point of the method. An unresolved
    /// merge leaves conflict markers inside the conflicting files, and here
    /// every file is ciphertext: the result is an entry that decrypts nowhere —
    /// not in this app, not in the `pass` CLI, not on a phone — and a user who
    /// did not choose `pass` in order to learn `git mergetool` has no way back.
    /// So the working tree is returned to what it was and the interface says
    /// which entries need a decision.
    ///
    /// The common case does not reach that: a store keeps one file per entry,
    /// so two people changing two different entries merges cleanly and this
    /// returns `None` having done the whole job.
    fn merge(&self, git: &remote::Git, workdir: &Path) -> Result<Option<Vec<String>>> {
        // `--no-edit` because there is no editor to open. Deliberately not
        // `--ff-only`: a real merge is correct here and usually clean, and
        // refusing one would report every ordinary two-sided change as a
        // conflict.
        let attempt = git.try_run(workdir, &["merge", "--no-edit", "@{u}"])?;
        if attempt.ok {
            return Ok(None);
        }

        let conflicted = self.conflicted()?;
        if self.repo.state() != git2::RepositoryState::Clean {
            // Best effort by necessity: if the abort itself fails there is
            // nothing further this app can do, and the conflict report below is
            // still the more useful thing to return.
            let _ = git.try_run(workdir, &["merge", "--abort"]);
        }

        if conflicted.is_empty() {
            // It failed for some other reason — uncommitted local changes in
            // the way, a missing upstream ref — and git's own words are the
            // only ones that name it.
            return Err(Error::GitSync {
                reason: attempt.message,
            });
        }
        Ok(Some(conflicted))
    }

    /// The paths the index reports as conflicted, named as the user knows them.
    fn conflicted(&self) -> Result<Vec<String>> {
        let mut index = self.repo.index().map_err(as_error)?;
        // The merge ran in another process, so what libgit2 has in memory is
        // the index from before it. Re-read before asking.
        index.read(false).map_err(as_error)?;
        if !index.has_conflicts() {
            return Ok(Vec::new());
        }

        let mut names = Vec::new();
        for conflict in index.conflicts().map_err(as_error)? {
            let conflict = conflict.map_err(as_error)?;
            let entry = conflict
                .our
                .or(conflict.their)
                .or(conflict.ancestor)
                .map(|entry| entry.path);
            if let Some(path) = entry {
                let name = self.describe(Path::new(&String::from_utf8_lossy(&path).into_owned()));
                if !names.contains(&name) {
                    names.push(name);
                }
            }
        }
        Ok(names)
    }

    /// A repository-relative path, said the way the user knows it.
    fn describe(&self, path: &Path) -> String {
        let relative = path.strip_prefix(&self.prefix).unwrap_or(path);
        match EntryName::from_secret_path(Path::new(""), relative) {
            Ok(name) => name.as_str().to_owned(),
            // Not an entry: a `.gpg-id`, or something else in a larger
            // repository the store happens to live in. Shown as its path
            // rather than dropped — the user still has to deal with it.
            Err(_) => relative.to_string_lossy().replace('\\', "/"),
        }
    }
}

/// Most revisions we will list for one entry.
///
/// A store's history is per-entry short — a password changes a handful of
/// times — but the repository it lives in may not be, and a list nobody will
/// scroll to the end of is not worth building. The cap is on what is returned;
/// the walk stops as soon as it is reached.
const MAX_REVISIONS: usize = 100;

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

    fn status(&self) -> Result<SyncStatus> {
        Ok(SyncStatus {
            branch: self
                .branch()?
                .and_then(|branch| branch.name().ok().flatten().map(str::to_owned)),
            tracking: self.tracking()?,
            uncommitted: self.uncommitted()?,
        })
    }

    fn history(&self, name: &EntryName) -> Result<Vec<Revision>> {
        let path = self.in_repo(&relative(name));

        // A repository with no commits has no history, which is an empty list
        // rather than a failure to report. Asked of `head`, which names the
        // unborn state; `Revwalk::push_head` reports it as an ordinary missing
        // reference, indistinguishable from a real one.
        match self.repo.head() {
            Ok(_) => {}
            Err(err)
                if matches!(
                    err.code(),
                    git2::ErrorCode::UnbornBranch | git2::ErrorCode::NotFound
                ) =>
            {
                return Ok(Vec::new())
            }
            Err(err) => return Err(as_error(err)),
        }

        let mut walk = self.repo.revwalk().map_err(as_error)?;
        walk.push_head().map_err(as_error)?;
        // Topological as well as by time, which is what `git log` guarantees:
        // a commit always precedes its parents. Time alone is not enough, and
        // the case where it fails is not exotic — two commits made in the same
        // second on two sides of a merge sort arbitrarily against each other,
        // so a store synced between two machines could show the version that
        // created an entry as newer than a change to it.
        walk.set_sorting(git2::Sort::TIME | git2::Sort::TOPOLOGICAL)
            .map_err(as_error)?;

        let mut revisions = Vec::new();
        for id in walk {
            let commit = self
                .repo
                .find_commit(id.map_err(as_error)?)
                .map_err(as_error)?;
            let Some(change) = self.touched(&commit, &path)? else {
                continue;
            };

            revisions.push(Revision {
                id: commit.id().to_string(),
                // Lossy rather than rejected: a commit written by another
                // client with a non-UTF-8 message is still a version of the
                // entry the user may want back.
                summary: String::from_utf8_lossy(commit.summary_bytes().unwrap_or_default())
                    .into_owned(),
                author: String::from_utf8_lossy(commit.author().name_bytes()).into_owned(),
                committed_at: commit.time().seconds(),
                change,
            });

            if revisions.len() >= MAX_REVISIONS {
                break;
            }
        }
        Ok(revisions)
    }

    fn blob_at(&self, name: &EntryName, revision: &str) -> Result<Vec<u8>> {
        // The id came from `history`, but it arrived back over IPC, so it is
        // parsed rather than trusted. Everything below is a lookup in the
        // object database — nothing is interpolated into a command line.
        let id = git2::Oid::from_str(revision).map_err(|_| Error::NoSuchRevision)?;
        let commit = self
            .repo
            .find_commit(id)
            .map_err(|_| Error::NoSuchRevision)?;

        let entry = commit
            .tree()
            .map_err(as_error)?
            .get_path(&self.in_repo(&relative(name)))
            .map_err(|_| Error::NoSuchRevision)?;

        Ok(self
            .repo
            .find_blob(entry.id())
            .map_err(|_| Error::NoSuchRevision)?
            .content()
            .to_vec())
    }

    fn sync(&self) -> Result<SyncOutcome> {
        // Asked before `git` is even looked for: a store with no remote should
        // say so, not report a missing tool it has no use for.
        if self.tracking()?.is_none() {
            return Ok(SyncOutcome::NoRemote);
        }

        let git = remote::Git::locate()?;
        let workdir = self.workdir()?.to_path_buf();

        git.run(&workdir, &["fetch", "--quiet"])?;

        // Read after the fetch: this is the first point at which the distance
        // to the remote reflects what is actually there.
        let Some(fetched) = self.tracking()? else {
            return Ok(SyncOutcome::NoRemote);
        };
        let pulled = fetched.behind;

        if pulled > 0 {
            if let Some(entries) = self.merge(&git, &workdir)? {
                return Ok(SyncOutcome::Conflicted { entries });
            }
        }

        // Recomputed rather than carried from `fetched`: a merge that just ran
        // added a commit of its own, and what has to go out is what is ahead
        // now.
        let pushed = self.tracking()?.map_or(0, |tracking| tracking.ahead);
        if pushed > 0 {
            git.run(&workdir, &["push", "--quiet"])?;
        }

        if pulled == 0 && pushed == 0 {
            Ok(SyncOutcome::UpToDate)
        } else {
            Ok(SyncOutcome::Synced { pulled, pushed })
        }
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

    // --- status ----------------------------------------------------------

    /// The ordinary state of a store someone `git init`ed and never pushed:
    /// versioned, on a branch, tracking nothing. The interface has to be able
    /// to say that without it reading as a fault.
    #[test]
    fn a_local_only_store_is_on_a_branch_and_tracks_nothing() {
        let dir = repo();
        write(dir.path(), "wifi", "ciphertext");
        let git = git_of(&dir);
        let change = Change::Insert(&name("wifi"));
        git.commit(&change.message(), &change.paths()).unwrap();

        let status = git.status().unwrap();

        assert!(status.branch.is_some());
        assert_eq!(status.tracking, None);
        assert_eq!(status.uncommitted, 0);
    }

    /// A repository with no commits at all. Nothing here is an error — the
    /// store simply has no history yet.
    #[test]
    fn a_repository_with_no_commits_has_no_branch_and_no_history() {
        let dir = repo();
        let git = git_of(&dir);

        let status = git.status().unwrap();

        assert_eq!(status.branch, None);
        assert_eq!(status.tracking, None);
        assert!(git.history(&name("wifi")).unwrap().is_empty());
    }

    /// Phase 3 commits every mutation, so anything uncommitted came from
    /// elsewhere — a commit that failed, or another client. A sync that pushed
    /// without mentioning it would leave the user believing it had gone out.
    #[test]
    fn uncommitted_changes_are_counted() {
        let dir = repo();
        write(dir.path(), "wifi", "ciphertext");

        assert_eq!(git_of(&dir).status().unwrap().uncommitted, 1);
    }

    /// The repository may be a dotfiles checkout. Whatever else is uncommitted
    /// in it belongs to the user's other work, not to their store.
    #[test]
    fn only_the_stores_own_files_are_counted() {
        let dir = repo();
        let root = dir.path().join("secrets");
        fs::create_dir(&root).unwrap();
        write(&root, "wifi", "ciphertext");
        fs::write(dir.path().join("elsewhere.txt"), "not ours").unwrap();

        let git = GitRepo::discover(&root).unwrap();

        assert_eq!(git.status().unwrap().uncommitted, 1);
    }

    // --- history ---------------------------------------------------------

    /// A history is per entry: commits that touched something else are not
    /// this entry's past, however recent they are.
    #[test]
    fn a_history_lists_only_the_commits_that_touched_the_entry() {
        let dir = repo();
        let git = git_of(&dir);

        write(dir.path(), "wifi", "first");
        commit(&git, Change::Insert(&name("wifi")));
        write(dir.path(), "other", "unrelated");
        commit(&git, Change::Insert(&name("other")));
        write(dir.path(), "wifi", "second");
        commit(&git, Change::Edit(&name("wifi")));

        let history = git.history(&name("wifi")).unwrap();

        assert_eq!(
            history
                .iter()
                .map(|revision| (revision.summary.clone(), revision.change))
                .collect::<Vec<_>>(),
            vec![
                (
                    "Edit password for wifi using Password Store.".to_owned(),
                    RevisionKind::Modified
                ),
                (
                    "Add given password for wifi to store.".to_owned(),
                    RevisionKind::Added
                ),
            ]
        );
    }

    /// A deletion is listed rather than skipped: it is the commit *before* it
    /// that holds the version worth recovering, and the user has to be able to
    /// see where the entry went.
    #[test]
    fn a_removal_is_listed_as_one() {
        let dir = repo();
        let git = git_of(&dir);

        write(dir.path(), "wifi", "ciphertext");
        commit(&git, Change::Insert(&name("wifi")));
        fs::remove_file(name("wifi").to_secret_path(dir.path())).unwrap();
        commit(&git, Change::Remove(&name("wifi")));

        let history = git.history(&name("wifi")).unwrap();

        assert_eq!(history[0].change, RevisionKind::Removed);
        assert_eq!(history[1].change, RevisionKind::Added);
    }

    /// What a version holds is ciphertext, byte for byte: the history is what
    /// makes a store cloned from that repository a store `pass` can read, so a
    /// blob that came back altered would be a compatibility bug, not a display
    /// one.
    #[test]
    fn a_past_version_comes_back_byte_for_byte() {
        let dir = repo();
        let git = git_of(&dir);

        write(dir.path(), "wifi", "first");
        commit(&git, Change::Insert(&name("wifi")));
        write(dir.path(), "wifi", "second");
        commit(&git, Change::Edit(&name("wifi")));

        let history = git.history(&name("wifi")).unwrap();

        assert_eq!(
            git.blob_at(&name("wifi"), &history[1].id).unwrap(),
            b"first"
        );
        assert_eq!(
            git.blob_at(&name("wifi"), &history[0].id).unwrap(),
            b"second"
        );
    }

    /// The id arrives back from the webview, so it is parsed rather than
    /// trusted — and a commit from before the entry existed holds no version
    /// of it.
    #[test]
    fn a_revision_that_holds_no_version_of_the_entry_is_refused() {
        let dir = repo();
        let git = git_of(&dir);
        write(dir.path(), "other", "ciphertext");
        commit(&git, Change::Insert(&name("other")));

        let only = git.history(&name("other")).unwrap()[0].id.clone();

        assert!(matches!(
            git.blob_at(&name("wifi"), &only),
            Err(Error::NoSuchRevision)
        ));
        assert!(matches!(
            git.blob_at(&name("other"), "not-an-object-id"),
            Err(Error::NoSuchRevision)
        ));
    }

    /// Nested in a larger repository, a version is still found: the entry's
    /// path inside the tree carries the store's own prefix.
    #[test]
    fn a_nested_stores_history_resolves_through_the_prefix() {
        let dir = repo();
        let root = dir.path().join("secrets");
        fs::create_dir(&root).unwrap();
        write(&root, "Email/gmail.com", "ciphertext");

        let git = GitRepo::discover(&root).unwrap();
        commit(&git, Change::Insert(&name("Email/gmail.com")));

        let history = git.history(&name("Email/gmail.com")).unwrap();

        assert_eq!(history.len(), 1);
        assert_eq!(
            git.blob_at(&name("Email/gmail.com"), &history[0].id)
                .unwrap(),
            b"ciphertext"
        );
    }

    // --- sync ------------------------------------------------------------

    /// A store that tracks nothing says so, and says it *before* looking for
    /// the `git` binary: reporting a missing tool to someone who has no remote
    /// to use it on would name the wrong problem entirely.
    #[test]
    fn syncing_a_store_that_tracks_nothing_reaches_no_network() {
        let dir = repo();
        let git = git_of(&dir);
        write(dir.path(), "wifi", "ciphertext");
        commit(&git, Change::Insert(&name("wifi")));

        assert_eq!(git.sync().unwrap(), SyncOutcome::NoRemote);
    }

    /// A conflicted path is reported as the entry the user knows, and anything
    /// that is not an entry is still reported rather than dropped.
    #[test]
    fn a_conflicted_path_is_named_the_way_the_user_knows_it() {
        let dir = repo();
        let git = git_of(&dir);

        assert_eq!(
            git.describe(Path::new("Email/gmail.com.gpg")),
            "Email/gmail.com"
        );
        assert_eq!(git.describe(Path::new(".gpg-id")), ".gpg-id");
    }

    /// Commit `change`, which every history test needs and none is about.
    fn commit(git: &GitRepo, change: Change<'_>) {
        git.commit(&change.message(), &change.paths()).unwrap();
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
