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
use std::sync::{Arc, Mutex};
use std::time::Duration;

use password_store_gui_lib::clipboard::{Backend, Clipboard, Scheduler};
use password_store_gui_lib::commands::Core;
use password_store_gui_lib::error::{Error, Result};
use password_store_gui_lib::generate::Recipe;
use password_store_gui_lib::secret::Secret;
use password_store_gui_lib::store::EntryName;

fn name(s: &str) -> EntryName {
    EntryName::new(s).unwrap()
}

/// A clipboard that lives in this process and nowhere else.
///
/// The point is what it is *not*. `Core::generate` copies, and `Core::new`
/// wires up the real system clipboard — so going through that here would
/// overwrite whatever the developer running `cargo test` had copied. Worse,
/// on Wayland and X11 the clipboard is served by the process that set it, so
/// the value would vanish with the test process and leave them with an empty
/// clipboard rather than a wrong one. CI cannot catch this: with no display
/// server the copy fails and the test passes anyway.
#[derive(Clone, Default)]
struct TestClipboard(Arc<Mutex<Option<String>>>);

impl TestClipboard {
    fn contents(&self) -> Option<String> {
        self.0.lock().unwrap().clone()
    }
}

impl Backend for TestClipboard {
    fn set_text(&mut self, text: &str) -> Result<()> {
        *self.0.lock().unwrap() = Some(text.to_owned());
        Ok(())
    }

    fn text(&mut self) -> Result<Option<Secret>> {
        Ok(self
            .0
            .lock()
            .unwrap()
            .as_ref()
            .map(|text| Secret::from_slice(text.as_bytes())))
    }

    fn clear(&mut self) -> Result<()> {
        *self.0.lock().unwrap() = None;
        Ok(())
    }
}

/// A scheduler whose timers never fire.
///
/// The clip window is not what this test is about, and `clipboard.rs` already
/// pins the auto-clear rule deterministically against its own stubs. Here it
/// only matters that nothing outlives the test.
struct NeverFires;

impl Scheduler for NeverFires {
    fn schedule(&self, _delay: Duration, _task: Box<dyn FnOnce() + Send + 'static>) {}
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
    // The store root is passed rather than exported through
    // `PASSWORD_STORE_DIR`: that would be `std::env::set_var`, which races
    // anything else in the binary and which edition 2024 makes `unsafe` — a
    // thing this crate forbids across every target. `read_store.rs` still
    // covers the variable end to end, and `store::resolve_root` covers the
    // rule itself, so nothing is lost by not repeating it here.
    //
    // Never `Core::new()` either: see [`TestClipboard`].
    let clipboard = TestClipboard::default();
    let core = Core::with_store_root(
        store.path(),
        Clipboard::new(Box::new(clipboard.clone()), Box::new(NeverFires)),
    );

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
    let receipt = core
        .generate(
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

    // The password reached the clipboard from inside the core, and the receipt
    // said only when it would be wiped (Invariant 2).
    assert_eq!(clipboard.contents().as_deref(), Some(generated.as_str()));
    // `Some` because `TestClipboard` always opens; the `None` arm is the
    // no-display-server case, where the entry is still created.
    let clip = receipt.clipboard.unwrap();
    assert_eq!(clip.clears_in_secs, 45);
    assert!(!serde_json::to_string(&receipt)
        .unwrap()
        .contains(&generated));
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
        Ok(_) => panic!("insert must not overwrite"),
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
