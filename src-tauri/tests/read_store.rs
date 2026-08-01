//! The Phase 1 read path end to end: a real store, a real `gpg`, and the
//! command surface the webview actually calls.
//!
//! This is the **definition of done** for Phase 1 in `PLAN.md` §7 — browse a
//! store and reveal a password, with nothing written to disk — expressed as a
//! test rather than as a click-through. The unit tests in `commands.rs` cover
//! the same surface against fakes; what this adds is real ciphertext, the real
//! backend, and `PASSWORD_STORE_DIR` resolution.
//!
//! One `#[test]` only: [`common::GpgFixture`] sets `GNUPGHOME`, and this test
//! also sets `PASSWORD_STORE_DIR` — both are process-global.

// Test-only: the harness captures these, and a silent skip is worse than a
// noisy one when the reason is "this machine has no gpg".
#![allow(clippy::print_stdout, clippy::print_stderr)]
// Test code handles fixtures, never real secrets: the plaintexts below are
// literals encrypted to a throwaway key in a temporary directory.
#![allow(clippy::unwrap_used)]

mod common;

use std::fs;

use password_store_gui_lib::commands::Core;
use password_store_gui_lib::error::Error;
use password_store_gui_lib::store::{EntryName, Node};

/// An entry of every shape Phase 1 can render.
const GMAIL: &[u8] = b"hunter2\n\
user: alice\n\
url: example.com\n\
url: other.example\n\
otpauth://totp/ACME?secret=JBSWY3DP\n\
remember the milk\n";

/// Password only: no fields, no OTP, no notes.
const WIFI: &[u8] = b"correct-horse-battery-staple\n";

#[test]
fn browses_a_real_store_and_reveals_a_password() {
    let Some(fixture) = common::GpgFixture::new() else {
        println!("skipping: no gpg on PATH");
        return;
    };

    let store = tempfile::tempdir().unwrap();
    let root = store.path();
    fs::create_dir_all(root.join("Email")).unwrap();
    fs::write(root.join(".gpg-id"), format!("{}\n", common::RECIPIENT)).unwrap();
    fixture.encrypt(GMAIL, &root.join("Email/gmail.com.gpg"));
    fixture.encrypt(WIFI, &root.join("wifi.gpg"));

    // Resolution is ours, not `prs-lib`'s — it ignores this variable entirely
    // (ADR-4a). Set before `Core::new`, which reads it per command.
    std::env::set_var("PASSWORD_STORE_DIR", root);
    let before = common::snapshot(root);

    let core = Core::new();

    // Browse: names only, and nothing decrypted to produce them.
    let tree = core.tree().unwrap();
    assert!(tree.unsupported.is_empty());
    let names: Vec<&str> = tree.nodes.iter().map(Node::name).collect();
    assert_eq!(names, vec!["Email", "wifi"], "directories sort first");

    let gmail = EntryName::new("Email/gmail.com").unwrap();

    // Shape without content.
    let metadata = core.metadata(&gmail).unwrap();
    assert!(metadata.has_password);
    assert_eq!(metadata.fields, vec!["user", "url", "url"]);
    assert!(metadata.has_otp);
    assert!(metadata.has_notes);

    // Invariant 2: what `show_entry` actually puts on the wire holds no value.
    let json = serde_json::to_string(&metadata).unwrap();
    for secret in [
        "hunter2",
        "alice",
        "example.com",
        "JBSWY3DP",
        "remember the milk",
    ] {
        assert!(
            !json.contains(secret),
            "show_entry leaked {secret:?} across the IPC boundary"
        );
    }

    // Reveal: one value at a time, only when asked for.
    assert_eq!(core.reveal_password(&gmail).unwrap(), "hunter2");
    assert_eq!(core.reveal_field(&gmail, 0).unwrap(), "alice");
    // Repeated keys are addressed by index, so the second `url` is reachable.
    assert_eq!(core.reveal_field(&gmail, 2).unwrap(), "other.example");
    assert_eq!(core.reveal_notes(&gmail).unwrap(), "remember the milk");

    let wifi = EntryName::new("wifi").unwrap();
    assert_eq!(
        core.reveal_password(&wifi).unwrap(),
        "correct-horse-battery-staple"
    );
    match core.reveal_notes(&wifi) {
        Err(Error::NoNotes { name }) => assert_eq!(name.as_str(), "wifi"),
        Err(other) => panic!("expected NoNotes, got {other}"),
        Ok(_) => panic!("wifi has no free text"),
    }

    // A name the frontend could send but the store does not have.
    match core.metadata(&EntryName::new("Email/absent").unwrap()) {
        Err(Error::EntryNotFound { name }) => assert_eq!(name.as_str(), "Email/absent"),
        Err(other) => panic!("expected EntryNotFound, got {other}"),
        Ok(_) => panic!("expected EntryNotFound for a name not in the store"),
    }

    // Invariant 1: after all of that, the store is byte-for-byte the directory
    // we built. No temp file, no backup, no editor swap file.
    assert_eq!(
        common::snapshot(root),
        before,
        "reading the store must not write to it"
    );
    assert!(
        !fs::read(root.join("Email/gmail.com.gpg"))
            .unwrap()
            .is_empty(),
        "the ciphertext must still be there"
    );

    // The snapshot compares names, so this compares contents: no file under the
    // root was rewritten in place to hold the plaintext either.
    for relative in &before {
        let path = root.join(relative);
        if path.is_file() {
            let bytes = fs::read(&path).unwrap();
            assert!(
                !contains(&bytes, b"hunter2"),
                "{} holds plaintext",
                relative.display()
            );
        }
    }
}

fn contains(haystack: &[u8], needle: &[u8]) -> bool {
    haystack.windows(needle.len()).any(|w| w == needle)
}
