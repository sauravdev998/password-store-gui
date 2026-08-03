//! Phase 7's definition of done: a store this app creates is a `pass` store.
//!
//! Drives the real command surface — `Core`, not `gpg_id` directly — against a
//! real `gpg` and a temp root that **does not exist yet**, which is the state
//! the whole phase is about. One `#[test]`, because `GNUPGHOME` is
//! process-global (see `common`).
//!
//! **What is deliberately not here: key generation.** A real
//! `Gpg::generate_key` raises a pinentry no unattended runner can answer, and
//! the two ways around that — `--passphrase` and `--pinentry-mode loopback` —
//! are exactly what Invariant 3 forbids. So ADR-7 puts that half in an argv
//! unit test in `crypto/gnupg.rs`, where the forbidden flags can be asserted
//! absent without a prompt, plus an `#[ignore]`d test run by hand. This file
//! covers the half that has no such problem, and the fixture's key stands in
//! for one the user already had — which is itself the path ADR-7 says to offer
//! first.

// Test-only: the harness captures these, and a silent skip is worse than a
// noisy one when the reason is "this machine has no gpg".
#![allow(clippy::print_stdout, clippy::print_stderr)]
// Test code handles fixtures, never real secrets: the key is generated into a
// temporary directory and discarded with it.
#![allow(clippy::unwrap_used)]

mod common;

use std::path::Path;
use std::process::Command;
use std::time::Duration;

use password_store_gui_lib::clipboard::{Backend, Clipboard, Scheduler};
use password_store_gui_lib::commands::{Commit, Core, StoreState};
use password_store_gui_lib::error::{Error, Result};
use password_store_gui_lib::secret::Secret;
use password_store_gui_lib::store::EntryName;

fn name(s: &str) -> EntryName {
    EntryName::new(s).unwrap()
}

fn secret(text: &str) -> Secret {
    Secret::from_slice(text.as_bytes())
}

/// A clipboard that goes nowhere.
///
/// Nothing here copies, but `Core::new` would wire up the real system
/// clipboard — and on Wayland and X11 the value is served by the process that
/// set it, so a test that touched it would leave the developer with an empty
/// clipboard when the process exited (`PLAN.md` §8).
struct NoClipboard;

impl Backend for NoClipboard {
    fn set_text(&mut self, _text: &str) -> Result<()> {
        Ok(())
    }
    fn text(&mut self) -> Result<Option<Secret>> {
        Ok(None)
    }
    fn clear(&mut self) -> Result<()> {
        Ok(())
    }
}

struct NeverFires;

impl Scheduler for NeverFires {
    fn schedule(&self, _delay: Duration, _task: Box<dyn FnOnce() + Send + 'static>) {}
}

fn core_at(root: &Path) -> Core {
    Core::with_store_root(
        root,
        Clipboard::new(Box::new(NoClipboard), Box::new(NeverFires)),
    )
}

/// Read an entry back through `pass show`, or `None` if `pass` is not
/// installed. It is the authority on whether the store we made is one.
fn pass_show(store: &Path, entry: &str) -> Option<String> {
    let output = Command::new("pass")
        .arg("show")
        .arg(entry)
        .env("PASSWORD_STORE_DIR", store)
        .output()
        .ok()?;
    assert!(
        output.status.success(),
        "pass show {entry} failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    Some(String::from_utf8_lossy(&output.stdout).into_owned())
}

#[test]
fn a_store_created_here_is_a_store_pass_can_use() {
    let Some(fixture) = common::GpgFixture::new() else {
        println!("skipping: no gpg on PATH");
        return;
    };

    let parent = tempfile::tempdir().unwrap();
    // Does not exist. Creating it is the operation under test — and it is also
    // what stops this test from ever pointing at a real store.
    let root = parent.path().join("password-store");
    let core = core_at(&root);

    // --- what onboarding finds -------------------------------------------
    let status = core.setup_status().unwrap();
    assert_eq!(status.store, StoreState::Missing);
    assert_eq!(status.store_path, root);
    assert_eq!(status.gpg_problem, None, "the fixture has a working gpg");

    // The fixture's key is on the secret keyring, so it is offered — which is
    // the path ADR-7 says to take before generating anything. Identified by
    // fingerprint, because that string is about to become a `.gpg-id` line and
    // must still resolve to one key years from now.
    let fingerprint = fixture.fingerprint_of(common::RECIPIENT);
    let offered = status
        .keys
        .iter()
        .find(|key| key.id == fingerprint)
        .unwrap_or_else(|| panic!("the fixture's key was not offered: {:?}", status.keys));
    assert!(
        offered.usable_here,
        "it is on this machine's secret keyring"
    );
    assert_eq!(
        offered.label.as_deref(),
        Some("Password Store GUI Test <test@example.invalid>")
    );

    // --- creating the store -----------------------------------------------
    let receipt = core
        .init_store(std::slice::from_ref(&fingerprint), false)
        .unwrap();
    assert_eq!(receipt.commit, None, "nothing asked for a history");

    // Byte-compatible with `pass init`, which writes `printf '%s\n'`: one id
    // per line, newline-terminated, and no header, comment or ordering of ours.
    assert_eq!(
        std::fs::read_to_string(root.join(".gpg-id")).unwrap(),
        format!("{fingerprint}\n")
    );
    // And nothing else — in particular no `.gpg-id.sig`, which `pass` writes
    // only under `PASSWORD_STORE_SIGNING_KEY` and which every other client
    // would ignore (ADR-7).
    assert_eq!(common::snapshot(&root), vec![Path::new(".gpg-id")]);

    // --- it is a store, not a directory with a file in it ------------------
    let gmail = name("Email/gmail.com");
    let body = "hunter2\nuser: alice\nurl: example.com\n";
    core.insert(&gmail, &secret(body)).unwrap();

    assert_eq!(core.reveal_password(&gmail).unwrap(), "hunter2");
    assert!(core.tree().unwrap().unsupported.is_empty());

    // Invariant 8, asked of the file rather than of our own receipt: the entry
    // is encrypted to the key the `.gpg-id` we just wrote names, and to nothing
    // else.
    let entry_path = root.join("Email").join("gmail.com.gpg");
    assert_eq!(
        fixture.recipients_of(&entry_path).len(),
        1,
        "the new store's entries must go to exactly the key it lists"
    );
    assert!(fixture.can_decrypt(&entry_path));

    // The definition of done: the CLI reads what this app set up, verbatim.
    match pass_show(&root, "Email/gmail.com") {
        Some(shown) => assert_eq!(shown, body, "pass must read back exactly what we wrote"),
        None => println!("note: pass is not installed; the CLI assertions are skipped"),
    }

    // Invariant 1: nothing under the store holds the plaintext.
    for relative in common::snapshot(&root) {
        let path = root.join(&relative);
        if path.is_file() {
            let bytes = std::fs::read(&path).unwrap();
            assert!(
                !bytes.windows(7).any(|window| window == b"hunter2"),
                "{} holds plaintext",
                relative.display()
            );
        }
    }

    // --- a store that exists is not offered for setup again ----------------
    assert_eq!(core.setup_status().unwrap().store, StoreState::Ready);
    match core.init_store(std::slice::from_ref(&fingerprint), false) {
        Err(Error::StoreExists { .. }) => {}
        other => panic!("expected StoreExists, got {other:?}"),
    }

    // --- a key that does not resolve creates nothing -----------------------
    let unresolvable_root = parent.path().join("never-made");
    match core_at(&unresolvable_root).init_store(&["nobody@example.invalid".to_owned()], false) {
        Err(Error::UnknownKey { id }) => assert_eq!(id, "nobody@example.invalid"),
        other => panic!("expected UnknownKey, got {other:?}"),
    }
    assert!(
        !unresolvable_root.exists(),
        "a refused setup must leave no directory behind"
    );

    // --- with a history ----------------------------------------------------
    let versioned_root = parent.path().join("versioned-store");
    let receipt = core_at(&versioned_root)
        .init_store(std::slice::from_ref(&fingerprint), true)
        .unwrap();

    // The repository is made either way; whether the *commit* lands depends on
    // something this test does not control.
    assert!(
        versioned_root.join(".git").is_dir(),
        "asking for a history must create the repository"
    );

    let repo = git2::Repository::open(&versioned_root).unwrap();
    if password_store_gui_lib::git::has_identity() {
        assert_eq!(receipt.commit, Some(Commit::Committed));

        let head = repo.head().unwrap().peel_to_commit().unwrap();
        // `pass git init`'s own words: a store's history is shared with the
        // CLI, so `git log` should not betray which client wrote it.
        assert_eq!(
            head.message().unwrap(),
            "Add current contents of password store."
        );
        assert!(
            head.tree().unwrap().get_name(".gpg-id").is_some(),
            "the commit must actually hold the store's keys"
        );
    } else {
        // The ordinary first-run state on a machine that has never used git,
        // and exactly why the interface defaults the offer off there (ADR-7).
        // The point being checked is that the *store* survived it.
        assert!(
            matches!(receipt.commit, Some(Commit::Failed(_))),
            "a machine with no git identity should report the commit, not the store, as failed"
        );
        println!("note: git has no identity here; the commit assertions are skipped");
    }
    assert_eq!(
        std::fs::read_to_string(versioned_root.join(".gpg-id")).unwrap(),
        format!("{fingerprint}\n"),
        "the store must exist even when its history does not"
    );
}
