//! Encryption against a real `gpg` and a throwaway key.
//!
//! The counterpart to `gpg_roundtrip.rs`, and separate from it for the same
//! reason that one holds a single `#[test]`: `GNUPGHOME` is process-global, so a
//! binary using the fixture may contain exactly one test.
//!
//! What this pins is the half of ADR-6 that unit tests cannot reach — that the
//! file we write is a real OpenPGP message, readable by the tool the store
//! belongs to rather than only by us, and encrypted to every recipient the
//! `.gpg-id` named and to no one else (Invariant 8).

// Test-only: the harness captures these, and a silent skip is worse than a
// noisy one when the reason is "this machine has no gpg".
#![allow(clippy::print_stdout, clippy::print_stderr)]
// Test code handles fixtures, never real secrets: the key is generated into a
// temporary directory and discarded with it.
#![allow(clippy::unwrap_used)]

mod common;

use std::fs;
use std::path::PathBuf;

use password_store_gui_lib::crypto::{Gpg, PrsGpg};
use password_store_gui_lib::error::Error;
use password_store_gui_lib::secret::Secret;
use password_store_gui_lib::store::{gpg_id, EntryName, PrsStore, Recipients, Store};

/// Plaintext with the shape a real entry has: password first, then fields.
const PLAINTEXT: &[u8] = b"correct-horse-battery-staple\nurl: example.com\nuser: alice\n";

#[test]
fn writes_a_secret_the_real_gpg_can_read() {
    let Some(fixture) = common::GpgFixture::new() else {
        println!("skipping: no gpg on PATH");
        return;
    };

    let store_dir = tempfile::tempdir().unwrap();
    fs::write(
        store_dir.path().join(gpg_id::GPG_ID_FILE),
        format!("{}\n", common::RECIPIENT),
    )
    .unwrap();

    let store = PrsStore::open(store_dir.path()).unwrap();
    let gpg = match PrsGpg::new() {
        Ok(gpg) => gpg,
        Err(err) => panic!("building a crypto context failed: {err}"),
    };

    // An entry in a subdirectory that does not exist yet: creating it is the
    // backend's job, so a new entry in a new folder is one call.
    let name = EntryName::new("Email/gmail.com").unwrap();
    let path = name.to_secret_path(store.root());
    let recipients = store.recipients(&name).unwrap();
    assert_eq!(recipients.ids, vec![common::RECIPIENT]);

    if let Err(err) = gpg.encrypt_file(&path, &recipients, &Secret::from_slice(PLAINTEXT)) {
        panic!("encrypt failed: {err}");
    }

    // The round trip that matters: the *real* gpg reads what we wrote.
    assert_eq!(fixture.decrypt(&path), PLAINTEXT);

    // And so do we.
    let read_back = match gpg.decrypt_file(&path) {
        Ok(secret) => secret,
        Err(err) => panic!("decrypt failed: {err}"),
    };
    assert_eq!(read_back.expose(), PLAINTEXT);

    // Invariant 8, checked against the file rather than against our intent:
    // exactly one recipient, because the `.gpg-id` named exactly one. A
    // `gpg.conf` carrying `encrypt-to` would show up here as a second key id
    // (ADR-6, F-9) — which is what `--no-encrypt-to` prevents.
    assert_eq!(
        fixture.recipients_of(&path).len(),
        1,
        "the entry must be encrypted to the .gpg-id's recipients and no others"
    );

    // Invariant 1: nothing but the entry and the `.gpg-id` exists in the store.
    // In particular the temporary the atomic write goes through is gone, and no
    // plaintext file was ever left behind.
    assert_eq!(
        common::snapshot(store_dir.path()),
        vec![
            PathBuf::from(".gpg-id"),
            PathBuf::from("Email"),
            PathBuf::from("Email/gmail.com.gpg"),
        ],
        "a write must leave only the ciphertext behind"
    );

    // The ciphertext really is one: the plaintext is not sitting in the file.
    let on_disk = fs::read(&path).unwrap();
    assert!(
        !on_disk
            .windows(PLAINTEXT.len())
            .any(|window| window == PLAINTEXT),
        "the plaintext must not be readable in the stored file"
    );

    // A rewrite replaces the entry rather than appending to it or leaving the
    // old ciphertext behind — the property the atomic write buys.
    let updated = b"a-different-password\nuser: alice\n";
    gpg.encrypt_file(&path, &recipients, &Secret::from_slice(updated))
        .unwrap();
    assert_eq!(fixture.decrypt(&path), updated);

    // A recipient no key exists for is refused by name, before anything is
    // written — the failure `prs-lib` would have swallowed (ADR-6, F-8).
    let unknown = Recipients {
        ids: vec!["nobody@example.invalid".to_owned()],
        source: store_dir.path().join(gpg_id::GPG_ID_FILE),
    };
    let fresh = store_dir.path().join("never-written.gpg");
    match gpg.encrypt_file(&fresh, &unknown, &Secret::from_slice(PLAINTEXT)) {
        Err(Error::UnknownRecipient { id, .. }) => {
            assert_eq!(id, "nobody@example.invalid");
        }
        Err(other) => panic!("expected UnknownRecipient, got {other}"),
        Ok(()) => panic!("encrypting to an unknown recipient must fail"),
    }
    assert!(
        !fresh.exists(),
        "a refused write must not create the entry file"
    );
}
