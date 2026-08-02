//! Phase 6's definition of done: changing a store's keys re-encrypts what they
//! govern, and the result is a store the other key can actually open.
//!
//! Invariant 8's second sentence — "on recipient change, re-encrypt the whole
//! affected subtree, matching `pass init`" — which nothing implemented before
//! ADR-13. Drives the real command surface against a real `gpg` with **two**
//! real keys, and checks the outcome with `gpg` itself rather than through our
//! own receipts: whether a key can open an entry is a fact about the ciphertext,
//! not about what we believe we wrote.
//!
//! One `#[test]`, because `GNUPGHOME` is process-global (see `common`).

// Test-only: the harness captures these, and a silent skip is worse than a noisy
// one when the reason is "this machine has no gpg".
#![allow(clippy::print_stdout, clippy::print_stderr)]
// Test code handles fixtures, never real secrets: the keys are generated into a
// temporary directory and discarded with it.
#![allow(clippy::unwrap_used)]

mod common;

use std::path::Path;
use std::process::Command;
use std::time::Duration;

use password_store_gui_lib::clipboard::{Clipboard, Scheduler};
use password_store_gui_lib::commands::Core;
use password_store_gui_lib::error::Error;
use password_store_gui_lib::secret::Secret;
use password_store_gui_lib::store::EntryName;

/// The second key: someone the store is shared with.
const OTHER: &str = "other@example.invalid";

fn name(s: &str) -> EntryName {
    EntryName::new(s).unwrap()
}

fn secret(text: &str) -> Secret {
    Secret::from_slice(text.as_bytes())
}

/// A scheduler whose timers never fire; nothing here copies anything.
struct NeverFires;

impl Scheduler for NeverFires {
    fn schedule(&self, _delay: Duration, _task: Box<dyn FnOnce() + Send + 'static>) {}
}

/// A clipboard that cannot reach the developer's desktop session (`PLAN.md` §8).
#[derive(Default)]
struct NoClipboard;

impl password_store_gui_lib::clipboard::Backend for NoClipboard {
    fn set_text(&mut self, _text: &str) -> password_store_gui_lib::error::Result<()> {
        Ok(())
    }
    fn text(&mut self) -> password_store_gui_lib::error::Result<Option<Secret>> {
        Ok(None)
    }
    fn clear(&mut self) -> password_store_gui_lib::error::Result<()> {
        Ok(())
    }
}

fn core_at(root: &Path) -> Core {
    Core::with_store_root(
        root,
        Clipboard::new(Box::new(NoClipboard), Box::new(NeverFires)),
    )
}

/// What `pass` thinks the keys are, or `None` when `pass` is not installed.
///
/// `pass init` writes the same file we do, so reading it back through the CLI is
/// a weaker check than `pass show` — but a store whose `.gpg-id` the CLI cannot
/// parse is one it will mis-encrypt the next write to, so it is worth asking.
fn pass_can_read(store: &Path, entry: &str) -> Option<String> {
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

/// Every file under `root` that holds `needle`, so Invariant 1 can be asserted
/// over the whole store rather than over the files we happen to remember.
fn files_containing(root: &Path, needle: &str) -> Vec<std::path::PathBuf> {
    let mut found = Vec::new();
    for relative in common::snapshot(root) {
        let path = root.join(&relative);
        if path.is_file() {
            let bytes = std::fs::read(&path).unwrap();
            if bytes
                .windows(needle.len())
                .any(|window| window == needle.as_bytes())
            {
                found.push(relative);
            }
        }
    }
    found
}

#[test]
fn changing_a_folders_keys_re_encrypts_what_they_govern() {
    let Some(fixture) = common::GpgFixture::new() else {
        println!("skipping: no gpg on PATH");
        return;
    };
    fixture.add_key(OTHER);

    let store = tempfile::tempdir().unwrap();
    let root = store.path();
    std::fs::write(root.join(".gpg-id"), format!("{}\n", common::RECIPIENT)).unwrap();
    let core = core_at(root);

    // A store with a nested `.gpg-id`, so the subtree rule has something to be
    // wrong about. `Work/` is its own decision about its own audience.
    let wifi = name("wifi");
    let gmail = name("Email/gmail.com");
    let vpn = name("Work/vpn");
    core.insert(&wifi, &secret("correct horse\n")).unwrap();
    core.insert(&gmail, &secret("hunter2\nuser: alice\n"))
        .unwrap();
    std::fs::create_dir_all(root.join("Work")).unwrap();
    std::fs::write(
        root.join("Work").join(".gpg-id"),
        format!("{}\n", common::RECIPIENT),
    )
    .unwrap();
    core.insert(&vpn, &secret("vpn-secret\n")).unwrap();

    // --- reading the current state decrypts nothing ----------------------
    let keys = core.folder_keys(None).unwrap();
    assert_eq!(keys.keys.len(), 1);
    assert_eq!(keys.keys[0].id, common::RECIPIENT);
    assert!(
        keys.keys[0].usable_here,
        "the fixture holds this key's secret half"
    );
    assert!(!keys.inherited, "the root's .gpg-id is the root's own");
    assert_eq!(
        keys.entries, 2,
        "Work/ has its own .gpg-id, so its entries are not the root's"
    );

    let nested = core.folder_keys(Some(&name("Work"))).unwrap();
    assert!(!nested.inherited);
    assert_eq!(nested.entries, 1);

    // A folder with no `.gpg-id` of its own inherits, and says so.
    let inheriting = core.folder_keys(Some(&name("Email"))).unwrap();
    assert!(inheriting.inherited);
    assert_eq!(inheriting.source, None, "decided at the store root");

    // --- planning states the real cost, without decrypting ---------------
    let both = vec![common::RECIPIENT.to_owned(), OTHER.to_owned()];
    let plan = core.plan_recipients(None, &both).unwrap();
    assert_eq!(
        plan.reencrypts,
        vec![gmail.clone(), wifi.clone()],
        "both root entries need rewriting; Work/ is not the root's to touch"
    );
    assert_eq!(plan.unchanged, 0);
    assert!(!plan.locks_you_out);
    assert!(!plan.creates_boundary);

    // --- an unresolvable key is refused before anything is written -------
    let before = std::fs::read(gmail.to_secret_path(root)).unwrap();
    let bogus = vec![
        common::RECIPIENT.to_owned(),
        "nobody@nowhere.invalid".into(),
    ];
    match core.set_recipients(None, &bogus) {
        Err(Error::UnknownKey { id }) => assert_eq!(id, "nobody@nowhere.invalid"),
        Err(other) => panic!("expected UnknownKey, got {other:?}"),
        Ok(_) => panic!("a key gpg cannot resolve must not be accepted"),
    }
    assert_eq!(
        std::fs::read(root.join(".gpg-id")).unwrap(),
        format!("{}\n", common::RECIPIENT).as_bytes(),
        "a refused change must not have touched the .gpg-id"
    );
    assert_eq!(
        std::fs::read(gmail.to_secret_path(root)).unwrap(),
        before,
        "a refused change must not have rewritten an entry"
    );

    // --- the change itself ------------------------------------------------
    core.set_recipients(None, &both).unwrap();

    assert_eq!(
        std::fs::read_to_string(root.join(".gpg-id")).unwrap(),
        format!("{}\n{OTHER}\n", common::RECIPIENT),
        "written in pass's format: one id per line"
    );

    // The definition of done, asked of `gpg` rather than of us: the second key
    // can now open the root's entries, and still cannot open Work/'s.
    fixture.forget_secret_key(common::RECIPIENT);
    assert!(
        fixture.can_decrypt(&gmail.to_secret_path(root)),
        "the added key must be able to open a re-encrypted entry"
    );
    assert!(
        fixture.can_decrypt(&wifi.to_secret_path(root)),
        "every entry the .gpg-id governs, not just the first"
    );
    assert!(
        !fixture.can_decrypt(&vpn.to_secret_path(root)),
        "Work/ has its own .gpg-id: a change at the root must not reach through it"
    );

    // The contents survived the round trip.
    assert_eq!(core.reveal_password(&gmail).unwrap(), "hunter2");
    assert_eq!(core.reveal_field(&gmail, 0).unwrap(), "alice");
    assert_eq!(core.reveal_password(&wifi).unwrap(), "correct horse");

    // --- re-running is free ------------------------------------------------
    let again = core.plan_recipients(None, &both).unwrap();
    assert!(
        again.reencrypts.is_empty(),
        "already encrypted to exactly these keys; re-encrypting would be a \
         decrypt nobody asked for (§4.1 principle 1)"
    );
    assert_eq!(again.unchanged, 2);

    // --- creating a boundary where there was none --------------------------
    let only_other = vec![OTHER.to_owned()];
    let split = core
        .plan_recipients(Some(&name("Email")), &only_other)
        .unwrap();
    assert!(split.creates_boundary);
    assert_eq!(
        split.reencrypts,
        vec![gmail.clone()],
        "a new .gpg-id in Email/ takes Email/'s entries out from under the root's"
    );

    // --- the lockout warning ----------------------------------------------
    // The fixture no longer holds RECIPIENT's secret key, so a change to OTHER
    // alone is fine, and a change to RECIPIENT alone would lock the user out.
    assert!(!split.locks_you_out, "OTHER's secret key is still held");
    let orphaning = core
        .plan_recipients(None, &[common::RECIPIENT.to_owned()])
        .unwrap();
    assert!(
        orphaning.locks_you_out,
        "no key in the new set is one this machine can decrypt with — the \
         irreversible mistake pass init makes without comment"
    );

    // --- a failed re-encrypt leaves the store byte-identical ---------------
    // `Work/vpn` is encrypted to a key whose secret half is gone, so decrypting
    // it — the first thing a re-encryption does — fails. Nothing may move.
    //
    // A second entry alongside it, encrypted to a key we *do* hold, is what
    // makes this cover the rollback rather than only the refusal: entries are
    // rewritten in sorted order, so `Work/intranet` is staged successfully
    // before `Work/vpn` fails, and the staged file has to be cleaned up.
    std::fs::write(root.join("Work").join(".gpg-id"), format!("{OTHER}\n")).unwrap();
    let intranet = name("Work/intranet");
    core.insert(&intranet, &secret("intranet-secret\n"))
        .unwrap();
    std::fs::write(
        root.join("Work").join(".gpg-id"),
        format!("{}\n", common::RECIPIENT),
    )
    .unwrap();

    let vpn_before = std::fs::read(vpn.to_secret_path(root)).unwrap();
    let intranet_before = std::fs::read(intranet.to_secret_path(root)).unwrap();
    let work_gpg_id_before = std::fs::read(root.join("Work").join(".gpg-id")).unwrap();
    let tree_before = common::snapshot(root);

    let work = name("Work");
    // Pinned to the decrypt so this cannot pass vacuously: the plan must have
    // succeeded and `Work/intranet` must have been staged before `Work/vpn`
    // failed, which is what puts the rollback on the path being tested.
    match core.set_recipients(Some(&work), &only_other) {
        Err(Error::Decrypt { path }) => {
            assert_eq!(path, vpn.to_secret_path(root));
        }
        Err(other) => panic!("expected the re-encrypt to fail on the decrypt, got {other:?}"),
        Ok(_) => panic!("an entry that cannot be decrypted cannot be re-encrypted"),
    }

    assert_eq!(
        std::fs::read(vpn.to_secret_path(root)).unwrap(),
        vpn_before,
        "the entry that failed must be exactly as it was"
    );
    assert_eq!(
        std::fs::read(intranet.to_secret_path(root)).unwrap(),
        intranet_before,
        "the entry that succeeded must be rolled back too — all or nothing"
    );
    assert_eq!(
        std::fs::read(root.join("Work").join(".gpg-id")).unwrap(),
        work_gpg_id_before,
        "the .gpg-id must not have been changed by a change that failed"
    );
    assert_eq!(
        common::snapshot(root),
        tree_before,
        "no staging file may be left behind"
    );

    // --- Invariant 1: no plaintext anywhere under the store ----------------
    for needle in ["hunter2", "correct horse", "vpn-secret", "alice"] {
        assert!(
            files_containing(root, needle).is_empty(),
            "{needle} appears in plaintext under the store"
        );
    }

    // --- and the CLI still reads the store ---------------------------------
    match pass_can_read(root, "Email/gmail.com") {
        Some(shown) => assert_eq!(shown, "hunter2\nuser: alice\n"),
        None => println!("note: pass is not installed; the CLI assertions are skipped"),
    }
}
