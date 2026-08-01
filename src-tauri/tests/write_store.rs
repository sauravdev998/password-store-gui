//! Phase 3's definition of done: an entry created here is readable by `pass`.
//!
//! Drives the real command surface — `Core`, not the store or the backend
//! directly — against a real `gpg` and a temp store, then hands the store to the
//! `pass` CLI and asks it to read what we wrote. One `#[test]`, because
//! `GNUPGHOME` is process-global (see `common`).
//!
//! `pass` is checked for and skipped around rather than required: it is a bash
//! script and does not exist on Windows, which is exactly why ADR-2 says we
//! reimplement the format rather than shell out to it. Where it *is* present —
//! Linux and macOS CI — it is the authority on whether we got the format right.

// Test-only: the harness captures these, and a silent skip is worse than a noisy
// one when the reason is "this machine has no gpg".
#![allow(clippy::print_stdout, clippy::print_stderr)]
// Test code handles fixtures, never real secrets: the key is generated into a
// temporary directory and discarded with it.
#![allow(clippy::unwrap_used)]

mod common;

use std::path::Path;
use std::process::Command;

use password_store_gui_lib::commands::Core;
use password_store_gui_lib::error::Error;
use password_store_gui_lib::generate::Recipe;
use password_store_gui_lib::store::EntryName;

fn name(s: &str) -> EntryName {
    EntryName::new(s).unwrap()
}

/// Read an entry back through `pass show`, or `None` if `pass` is not installed.
///
/// `PASSWORD_STORE_DIR` points it at our temp store; `GNUPGHOME` is already set
/// process-wide by the fixture and is inherited.
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
fn an_entry_written_here_is_readable_by_the_pass_cli() {
    let Some(_fixture) = common::GpgFixture::new() else {
        println!("skipping: no gpg on PATH");
        return;
    };

    let store = tempfile::tempdir().unwrap();
    std::fs::write(
        store.path().join(".gpg-id"),
        format!("{}\n", common::RECIPIENT),
    )
    .unwrap();
    // `Core` resolves the store the way the app does, so pointing the variable
    // at the fixture is what makes this the real command surface and not a
    // special-cased one.
    std::env::set_var("PASSWORD_STORE_DIR", store.path());

    let core = Core::new();

    // --- insert ---------------------------------------------------------
    let gmail = name("Email/gmail.com");
    let body = "hunter2\nuser: alice\nurl: example.com\n";
    core.insert(&gmail, &secret(body)).unwrap();

    // Read back through our own surface first.
    assert_eq!(core.reveal_password(&gmail).unwrap(), "hunter2");
    assert_eq!(core.reveal_field(&gmail, 0).unwrap(), "alice");
    assert!(core.tree().unwrap().unsupported.is_empty());

    // The definition of done. `pass show` prints the entry verbatim.
    match pass_show(store.path(), "Email/gmail.com") {
        Some(shown) => assert_eq!(shown, body, "pass must read back exactly what we wrote"),
        None => println!("note: pass is not installed; the CLI assertions are skipped"),
    }

    // --- edit -----------------------------------------------------------
    let edited = "new-password\nuser: alice\n";
    core.edit(&gmail, &secret(edited)).unwrap();
    assert_eq!(core.reveal_password(&gmail).unwrap(), "new-password");
    if let Some(shown) = pass_show(store.path(), "Email/gmail.com") {
        assert_eq!(shown, edited);
    }

    // --- generate -------------------------------------------------------
    // The generated password is never returned, so what it *is* can only be
    // learned by reading the entry back — which is the property under test.
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
    let generated = core.reveal_password(&wifi).unwrap();
    assert_eq!(generated.len(), 24);
    if let Some(shown) = pass_show(store.path(), "wifi") {
        assert_eq!(shown.trim_end_matches('\n'), generated);
    }

    // --- copy and rename ------------------------------------------------
    core.copy_entry(&wifi, &name("Home/wifi")).unwrap();
    assert_eq!(core.reveal_password(&name("Home/wifi")).unwrap(), generated);
    assert!(store.path().join("wifi.gpg").is_file());

    core.rename(&name("Home/wifi"), &name("Home/router"))
        .unwrap();
    assert!(!store.path().join("Home/wifi.gpg").exists());
    if let Some(shown) = pass_show(store.path(), "Home/router") {
        assert_eq!(shown.trim_end_matches('\n'), generated);
    }

    // --- remove ---------------------------------------------------------
    core.remove(&name("Home/router")).unwrap();
    assert!(!store.path().join("Home/router.gpg").exists());
    // The directory went with its last entry, so the tree does not keep an
    // empty folder the user cannot delete.
    assert!(
        !store.path().join("Home").exists(),
        "an emptied directory must be pruned"
    );

    // --- what must never be on disk -------------------------------------
    // Invariant 1, over the whole store: no file holds any plaintext we wrote,
    // and nothing is left behind by the atomic write.
    for secret_text in ["new-password", "hunter2", generated.as_str(), "alice"] {
        assert!(
            !store_contains(store.path(), secret_text.as_bytes()),
            "plaintext {secret_text:?} was found on disk"
        );
    }
    for path in common::snapshot(store.path()) {
        let name = path.to_string_lossy();
        assert!(
            name == ".gpg-id" || name.ends_with(".gpg") || store.path().join(&path).is_dir(),
            "unexpected file left in the store: {name}"
        );
    }

    // --- refusals -------------------------------------------------------
    match core.insert(&gmail, &secret("clobbered")) {
        Err(Error::EntryExists { .. }) => {}
        Err(other) => panic!("expected EntryExists, got {other}"),
        Ok(()) => panic!("insert must not overwrite"),
    }
    assert_eq!(core.reveal_password(&gmail).unwrap(), "new-password");
}

fn secret(text: &str) -> password_store_gui_lib::secret::Secret {
    password_store_gui_lib::secret::Secret::from_slice(text.as_bytes())
}

/// Whether any file under `root` contains `needle`.
fn store_contains(root: &Path, needle: &[u8]) -> bool {
    common::snapshot(root).iter().any(|relative| {
        let path = root.join(relative);
        path.is_file()
            && std::fs::read(&path)
                .map(|bytes| bytes.windows(needle.len()).any(|w| w == needle))
                .unwrap_or(false)
    })
}
