//! Phase 4 end to end: two real stores, a real remote, and a real `git`.
//!
//! Drives the command surface against two clones of one repository, with a real
//! `gpg` behind both, and checks the three outcomes that matter:
//!
//! - a change made in one store reaches the other, and **decrypts** there — the
//!   cross-tool claim, since a sync that moved bytes but produced an unreadable
//!   entry would pass any assertion about git alone;
//! - two people changing *different* entries merges without anyone being asked
//!   anything, which is the ordinary case for a store of one file per entry;
//! - two people changing the *same* entry is reported and **rolled back**. That
//!   last one is the point of the whole design: an unresolved merge writes
//!   conflict markers into the ciphertext, and a `.gpg` file with conflict
//!   markers in it decrypts nowhere.
//!
//! It also drives the per-entry history over real ciphertext: a past version is
//! listed without decrypting, then decrypted on request and compared to what was
//! actually written.
//!
//! One `#[test]`, because `GNUPGHOME` is process-global (see `common`).

// Test-only: the harness captures these, and a silent skip is worse than a
// noisy one when the reason is "this machine has no gpg".
#![allow(clippy::print_stdout, clippy::print_stderr)]
// Test code handles fixtures, never real secrets: the key is generated into a
// temporary directory and discarded with it.
#![allow(clippy::unwrap_used, clippy::expect_used)]

mod common;

use std::path::Path;
use std::process::Command;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use password_store_gui_lib::clipboard::{Backend, Clipboard, Scheduler};
use password_store_gui_lib::commands::Core;
use password_store_gui_lib::error::Result;
use password_store_gui_lib::git::{RevisionKind, SyncOutcome};
use password_store_gui_lib::secret::Secret;
use password_store_gui_lib::store::EntryName;

fn name(s: &str) -> EntryName {
    EntryName::new(s).unwrap()
}

fn secret(text: &str) -> Secret {
    Secret::from_slice(text.as_bytes())
}

/// A clipboard confined to this process. See `write_store.rs` for why no test
/// may touch the real one.
#[derive(Clone, Default)]
struct TestClipboard(Arc<Mutex<Option<String>>>);

impl Backend for TestClipboard {
    fn set_text(&mut self, text: &str) -> Result<()> {
        *self.0.lock().unwrap() = Some(text.to_owned());
        Ok(())
    }

    fn text(&mut self) -> Result<Option<Secret>> {
        Ok(self.0.lock().unwrap().as_deref().map(secret))
    }

    fn clear(&mut self) -> Result<()> {
        *self.0.lock().unwrap() = None;
        Ok(())
    }
}

/// A scheduler whose timers never fire; nothing here is about the clip window.
struct NeverFires;

impl Scheduler for NeverFires {
    fn schedule(&self, _delay: Duration, _task: Box<dyn FnOnce() + Send + 'static>) {}
}

fn core_at(root: &Path) -> Core {
    Core::with_store_root(
        root,
        Clipboard::new(Box::new(TestClipboard::default()), Box::new(NeverFires)),
    )
}

/// Run `git` in `dir`, insisting it worked.
fn git(dir: &Path, args: &[&str]) -> String {
    let output = Command::new("git")
        .args(args)
        .current_dir(dir)
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "git {args:?} failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    String::from_utf8_lossy(&output.stdout).trim().to_owned()
}

/// Pin a repository's configuration to git's defaults.
///
/// Not tidiness: this test would otherwise depend on the developer's global
/// config. `merge.ff = only` would turn the clean-merge case into a failure,
/// `commit.gpgsign = true` would make the merge commit prompt, and CI machines
/// have no identity at all.
fn configure(dir: &Path) {
    git(dir, &["config", "user.name", "Test"]);
    git(dir, &["config", "user.email", "test@example.invalid"]);
    git(dir, &["config", "commit.gpgsign", "false"]);
    git(dir, &["config", "merge.ff", "true"]);
}

/// The ciphertext of `entry` in the store at `root`.
fn ciphertext(root: &Path, entry: &str) -> Vec<u8> {
    std::fs::read(name(entry).to_secret_path(root)).unwrap()
}

#[test]
fn two_stores_sharing_a_remote_stay_in_step() {
    let Some(fixture) = common::GpgFixture::new() else {
        println!("skipping: no gpg on PATH");
        return;
    };
    if which::which("git").is_err() {
        // ADR-9's one cost: syncing needs the `git` binary, unlike everything
        // else in the app. On a machine without it there is nothing to test.
        println!("skipping: no git on PATH");
        return;
    }

    let scratch = tempfile::tempdir().unwrap();
    let remote = scratch.path().join("remote.git");
    let alice = scratch.path().join("alice");
    let bob = scratch.path().join("bob");

    // --- a shared store, published -----------------------------------------
    std::fs::create_dir(&remote).unwrap();
    git(scratch.path(), &["init", "--bare", "--quiet", "remote.git"]);

    std::fs::create_dir(&alice).unwrap();
    std::fs::write(alice.join(".gpg-id"), format!("{}\n", common::RECIPIENT)).unwrap();
    git(&alice, &["init", "--quiet"]);
    configure(&alice);
    // `.gpg-id` is part of the store, and `pass init` commits it. Without it a
    // clone would have entries and no recipients to write new ones to.
    git(&alice, &["add", ".gpg-id"]);
    git(&alice, &["commit", "--quiet", "-m", "Set GPG id."]);

    let core_a = core_at(&alice);
    core_a
        .insert(&name("Email/gmail.com"), &secret("hunter2\nuser: alice\n"))
        .unwrap();

    git(&alice, &["remote", "add", "origin", "../remote.git"]);
    git(&alice, &["push", "--quiet", "-u", "origin", "HEAD"]);

    // Published, so there is nothing to send and nothing to fetch.
    let status = core_a.sync_status().unwrap().unwrap();
    let tracking = status.tracking.expect("the branch tracks the remote");
    assert_eq!((tracking.ahead, tracking.behind), (0, 0));
    assert_eq!(
        status.uncommitted, 0,
        "every mutation commits itself, so nothing should be outstanding"
    );
    assert_eq!(core_a.sync().unwrap(), SyncOutcome::UpToDate);

    // --- a second copy ------------------------------------------------------
    git(scratch.path(), &["clone", "--quiet", "remote.git", "bob"]);
    configure(&bob);
    let core_b = core_at(&bob);

    // The clone is a working store, not just a directory of files: what came
    // down the wire decrypts.
    assert_eq!(
        core_b.reveal_password(&name("Email/gmail.com")).unwrap(),
        "hunter2"
    );

    // --- a change made in one store reaches the other -----------------------
    core_a
        .insert(&name("wifi"), &secret("correct horse\n"))
        .unwrap();
    assert_eq!(
        core_a.sync().unwrap(),
        SyncOutcome::Synced {
            pulled: 0,
            pushed: 1
        }
    );

    assert_eq!(
        core_b.sync().unwrap(),
        SyncOutcome::Synced {
            pulled: 1,
            pushed: 0
        }
    );
    assert_eq!(
        core_b.reveal_password(&name("wifi")).unwrap(),
        "correct horse",
        "an entry that arrived over the network must decrypt on this side too"
    );

    // --- two people, two different entries ----------------------------------
    // The ordinary case for a store that keeps one file per entry, and it has
    // to merge without asking anyone anything.
    core_a
        .edit(&name("Email/gmail.com"), &secret("alice-changed-this\n"))
        .unwrap();
    core_a.sync().unwrap();

    core_b
        .edit(&name("wifi"), &secret("bob-changed-this\n"))
        .unwrap();
    let outcome = core_b.sync().unwrap();

    assert!(
        matches!(outcome, SyncOutcome::Synced { pulled: 1, .. }),
        "two different entries must merge cleanly, got {outcome:?}"
    );
    assert_eq!(
        core_b.reveal_password(&name("Email/gmail.com")).unwrap(),
        "alice-changed-this"
    );
    assert_eq!(
        core_b.reveal_password(&name("wifi")).unwrap(),
        "bob-changed-this"
    );

    // Alice gets Bob's half back, so both stores hold both changes.
    core_a.sync().unwrap();
    assert_eq!(
        core_a.reveal_password(&name("wifi")).unwrap(),
        "bob-changed-this"
    );

    // --- two people, the same entry -----------------------------------------
    core_a
        .edit(&name("wifi"), &secret("alice-again\n"))
        .unwrap();
    core_a.sync().unwrap();

    core_b.edit(&name("wifi"), &secret("bob-again\n")).unwrap();
    let before = ciphertext(&bob, "wifi");

    let outcome = core_b.sync().unwrap();

    match outcome {
        SyncOutcome::Conflicted { entries } => {
            assert_eq!(
                entries,
                vec!["wifi".to_owned()],
                "the entry is named as the user knows it"
            );
        }
        other => panic!("expected a conflict, got {other:?}"),
    }

    // The whole reason the merge is rolled back: an unresolved one would leave
    // conflict markers inside the ciphertext. Byte-identical is the strongest
    // form of "nothing on this computer was changed", which is what the
    // interface tells the user.
    assert_eq!(
        ciphertext(&bob, "wifi"),
        before,
        "a conflicted sync must leave the store exactly as it was"
    );
    assert_eq!(
        core_b.reveal_password(&name("wifi")).unwrap(),
        "bob-again",
        "the entry must still decrypt after a conflict was rolled back"
    );
    // And it is `gpg` itself saying so, not only our own backend.
    assert_eq!(
        fixture.decrypt(&name("wifi").to_secret_path(&bob)),
        b"bob-again\n"
    );

    // Alice is untouched by Bob's failed sync; the conflict is Bob's to settle.
    assert_eq!(
        core_a.reveal_password(&name("wifi")).unwrap(),
        "alice-again"
    );

    // --- the entry's past ---------------------------------------------------
    let wifi = name("wifi");
    let history = core_a.history(&wifi).unwrap();

    assert!(
        history.len() >= 3,
        "insert, then two edits, at least: {history:?}"
    );
    assert_eq!(history[0].change, RevisionKind::Modified);
    assert_eq!(
        history.last().unwrap().change,
        RevisionKind::Added,
        "the oldest version of an entry is the one that created it"
    );
    assert_eq!(
        history.last().unwrap().summary,
        "Add given password for wifi to store.",
        "the history reads in the words `pass` uses"
    );

    // A listing carries no content — the whole reason it costs no pinentry.
    let listed = serde_json::to_string(&history).unwrap();
    for value in ["correct horse", "bob-again", "alice-again", "hunter2"] {
        assert!(
            !listed.contains(value),
            "the history listing leaked {value:?}"
        );
    }

    // The version that created the entry, decrypted out of a git object rather
    // than off disk (ADR-10).
    let oldest = &history.last().unwrap().id;
    assert_eq!(
        core_a.reveal_revision(&wifi, oldest).unwrap(),
        "correct horse\n"
    );

    // The recovery path: the old password reaches the clipboard without the
    // caller ever seeing it.
    let receipt = core_a.copy_revision_password(&wifi, oldest).unwrap();
    assert!(!serde_json::to_string(&receipt)
        .unwrap()
        .contains("correct horse"));

    // Invariant 1, over the whole exercise: nothing under either store holds a
    // plaintext, including everything git wrote into `.git`.
    for root in [&alice, &bob] {
        for path in common::snapshot(root) {
            let full = root.join(&path);
            if !full.is_file() {
                continue;
            }
            let bytes = std::fs::read(&full).unwrap();
            for value in ["correct horse", "bob-again", "alice-again", "hunter2"] {
                assert!(
                    !contains(&bytes, value.as_bytes()),
                    "{} holds the plaintext {value:?}",
                    path.display()
                );
            }
        }
    }
}

/// Whether `haystack` contains `needle`, on raw bytes since most of what is
/// scanned above is compressed git objects rather than text.
fn contains(haystack: &[u8], needle: &[u8]) -> bool {
    haystack
        .windows(needle.len())
        .any(|window| window == needle)
}
