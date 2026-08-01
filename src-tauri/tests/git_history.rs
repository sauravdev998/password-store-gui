//! Phase 3's other half: a mutation lands in the store's git history, and what
//! it committed is ciphertext the user's own `gpg` can read back.
//!
//! Drives the real command surface against a real `gpg`, a real store, and a
//! real repository — no fakes on either side — then inspects the repository
//! rather than our own receipts, so the assertions are about what a `pass` user
//! would find in `git log` rather than about what we believe we did.
//!
//! One `#[test]`, because `GNUPGHOME` is process-global (see `common`).

// Test-only: the harness captures these, and a silent skip is worse than a noisy
// one when the reason is "this machine has no gpg".
#![allow(clippy::print_stdout, clippy::print_stderr)]
// Test code handles fixtures, never real secrets: the key is generated into a
// temporary directory and discarded with it.
#![allow(clippy::unwrap_used, clippy::expect_used)]

mod common;

use std::path::Path;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use password_store_gui_lib::clipboard::{Backend, Clipboard, Scheduler};
use password_store_gui_lib::commands::{Commit, Core};
use password_store_gui_lib::error::Result;
use password_store_gui_lib::generate::Recipe;
use password_store_gui_lib::secret::Secret;
use password_store_gui_lib::store::EntryName;

fn name(s: &str) -> EntryName {
    EntryName::new(s).unwrap()
}

fn secret(text: &str) -> Secret {
    Secret::from_slice(text.as_bytes())
}

/// A clipboard confined to this process — `generate` copies, and the real one
/// belongs to the developer's desktop session. See `write_store.rs`.
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

/// Commit subjects, newest first.
fn log(repo: &git2::Repository) -> Vec<String> {
    let mut walk = repo.revwalk().unwrap();
    walk.push_head().unwrap();
    let mut out = Vec::new();
    for id in walk {
        let commit = repo.find_commit(id.unwrap()).unwrap();
        out.push(commit.summary().unwrap().unwrap_or_default().to_owned());
    }
    out
}

/// The bytes HEAD holds at `path`, or `None` if it tracks no such file.
fn committed(repo: &git2::Repository, path: &str) -> Option<Vec<u8>> {
    let tree = repo.head().ok()?.peel_to_tree().ok()?;
    let entry = tree.get_path(Path::new(path)).ok()?;
    let blob = entry.to_object(repo).ok()?.peel_to_blob().ok()?;
    Some(blob.content().to_vec())
}

/// Paths git reports as differing from HEAD, ignoring nothing.
fn dirty(repo: &git2::Repository) -> Vec<String> {
    let mut options = git2::StatusOptions::new();
    options.include_untracked(true).include_ignored(false);
    let statuses = repo.statuses(Some(&mut options)).unwrap();
    let mut out = Vec::new();
    for entry in statuses.iter() {
        out.push(entry.path().unwrap_or_default().to_owned());
    }
    out
}

#[test]
fn mutations_are_committed_to_the_stores_git_history() {
    let Some(fixture) = common::GpgFixture::new() else {
        println!("skipping: no gpg on PATH");
        return;
    };

    let store = tempfile::tempdir().unwrap();
    std::fs::write(
        store.path().join(".gpg-id"),
        format!("{}\n", common::RECIPIENT),
    )
    .unwrap();

    let repo = git2::Repository::init(store.path()).unwrap();
    // Set on the repository rather than globally: CI machines have no git
    // identity, and a test must not depend on the developer's.
    let mut config = repo.config().unwrap();
    config.set_str("user.name", "Test").unwrap();
    config
        .set_str("user.email", "test@example.invalid")
        .unwrap();
    drop(config);

    let core = Core::with_store_root(
        store.path(),
        Clipboard::new(Box::new(TestClipboard::default()), Box::new(NeverFires)),
    );

    // --- insert ---------------------------------------------------------
    let gmail = name("Email/gmail.com");
    let body = "hunter2\nuser: alice\n";
    let receipt = core.insert(&gmail, &secret(body)).unwrap();

    assert_eq!(receipt.commit, Some(Commit::Committed));
    assert_eq!(
        log(&repo)[0],
        "Add given password for Email/gmail.com to store."
    );
    assert_eq!(
        dirty(&repo),
        vec![".gpg-id"],
        "only the pre-existing .gpg-id should be uncommitted"
    );

    // What landed in the history is the ciphertext, and the user's own `gpg`
    // reads it back. This is the cross-tool half: a store cloned from this
    // repository is a store `pass` can use.
    let blob = committed(&repo, "Email/gmail.com.gpg").expect("the entry must be committed");
    let checkout = store.path().join("from-git.gpg");
    std::fs::write(&checkout, &blob).unwrap();
    assert_eq!(fixture.decrypt(&checkout), body.as_bytes());
    std::fs::remove_file(&checkout).unwrap();
    assert_ne!(blob, body.as_bytes(), "the history must hold ciphertext");

    // --- edit -----------------------------------------------------------
    core.edit(&gmail, &secret("new-password\n")).unwrap();
    assert_eq!(
        log(&repo)[0],
        "Edit password for Email/gmail.com using Password Store."
    );

    // --- generate -------------------------------------------------------
    let wifi = name("wifi");
    core.generate(
        &wifi,
        Recipe {
            length: 24,
            symbols: false,
        },
        None,
    )
    .unwrap();
    assert_eq!(log(&repo)[0], "Add generated password for wifi.");

    // --- copy and rename ------------------------------------------------
    core.copy_entry(&wifi, &name("Home/wifi")).unwrap();
    assert_eq!(log(&repo)[0], "Copy wifi to Home/wifi.");

    core.rename(&name("Home/wifi"), &name("Home/router"))
        .unwrap();
    assert_eq!(log(&repo)[0], "Rename Home/wifi to Home/router.");
    // A rename is a removal and an addition in one commit, so the old path must
    // be gone from the tree and not merely absent from the working directory.
    assert!(committed(&repo, "Home/wifi.gpg").is_none());
    assert!(committed(&repo, "Home/router.gpg").is_some());

    // --- remove ---------------------------------------------------------
    core.remove(&name("Home/router")).unwrap();
    assert_eq!(log(&repo)[0], "Remove Home/router from store.");
    assert!(committed(&repo, "Home/router.gpg").is_none());

    // Every mutation left the working tree matching HEAD: nothing was written
    // that was not also committed.
    assert_eq!(dirty(&repo), vec![".gpg-id"]);

    // The whole history, oldest first, in the words `pass` uses.
    let mut history = log(&repo);
    history.reverse();
    assert_eq!(
        history,
        vec![
            "Add given password for Email/gmail.com to store.",
            "Edit password for Email/gmail.com using Password Store.",
            "Add generated password for wifi.",
            "Copy wifi to Home/wifi.",
            "Rename Home/wifi to Home/router.",
            "Remove Home/router from store.",
        ]
    );
}
