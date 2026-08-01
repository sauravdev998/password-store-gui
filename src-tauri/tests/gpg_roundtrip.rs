//! Decryption against a real `gpg` and a throwaway key.
//!
//! The fixture lives in [`common`], which explains why this file holds exactly
//! one `#[test]`: `GNUPGHOME` is process-global.

// Test-only: the harness captures these, and a silent skip is worse than a
// noisy one when the reason is "this machine has no gpg".
#![allow(clippy::print_stdout, clippy::print_stderr)]
// Test code handles fixtures, never real secrets: the key is generated into a
// temporary directory and discarded with it.
#![allow(clippy::unwrap_used)]

mod common;

use std::fs;

use password_store_gui_lib::crypto::{Gpg, PrsGpg};
use password_store_gui_lib::error::Error;

/// Plaintext with the shape a real entry has: password first, then fields.
const PLAINTEXT: &[u8] = b"correct-horse-battery-staple\nurl: example.com\nuser: alice\n";

#[test]
fn decrypts_a_secret_written_by_the_real_gpg() {
    let Some(fixture) = common::GpgFixture::new() else {
        println!("skipping: no gpg on PATH");
        return;
    };

    let store = tempfile::tempdir().unwrap();
    let secret_path = store.path().join("gmail.com.gpg");
    fixture.encrypt(PLAINTEXT, &secret_path);

    let gpg = match PrsGpg::new() {
        Ok(gpg) => gpg,
        Err(err) => panic!("building a crypto context failed: {err}"),
    };

    // The round trip itself.
    let secret = match gpg.decrypt_file(&secret_path) {
        Ok(secret) => secret,
        Err(err) => panic!("decrypt failed: {err}"),
    };
    assert_eq!(secret.expose(), PLAINTEXT);
    assert_eq!(
        secret.expose_str().unwrap().lines().next().unwrap(),
        "correct-horse-battery-staple",
    );

    // Invariant 1: decrypting leaves nothing behind. Only the ciphertext we put
    // there may exist in the store directory.
    assert_eq!(
        common::snapshot(store.path()),
        vec![std::path::PathBuf::from("gmail.com.gpg")],
        "decryption must not write a temporary file"
    );

    // A file that is not ciphertext fails as our typed error, carrying only the
    // path — gpg's own output never reaches it (Invariant 5).
    let garbage = store.path().join("garbage.gpg");
    fs::write(&garbage, b"this is not an OpenPGP message").unwrap();
    match gpg.decrypt_file(&garbage) {
        Err(Error::Decrypt { path }) => {
            assert_eq!(path, garbage);
            let message = Error::Decrypt { path: garbage }.to_string();
            assert!(
                !message.contains("gpg:") && !message.contains("decryption failed"),
                "the error must not carry gpg's output: {message}"
            );
        }
        Err(other) => panic!("expected a Decrypt error, got {other}"),
        Ok(_) => panic!("garbage must not decrypt"),
    }
}
