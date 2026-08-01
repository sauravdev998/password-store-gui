//! The `#[tauri::command]` surface — the only door between the webview and the
//! core.
//!
//! Three rules govern everything here:
//!
//! - **Metadata by default.** [`show_entry`] returns shape, never content. The
//!   only values that cross into the webview are the ones a user asked to see,
//!   one at a time, through a `reveal_*` command (Invariant 2). [`reveal`] is
//!   the single place a [`Secret`] becomes a `String`. A `copy_*` command does
//!   not go through it at all: the value goes to the clipboard from inside the
//!   core, and what comes back is a [`CopyReceipt`] that says only when the
//!   clipboard will be wiped.
//! - **Nothing decrypted is kept.** A command decrypts, answers, and drops the
//!   plaintext before it returns. There is no cache in Phase 1 — which is also
//!   why there is nothing for Invariant 7's auto-lock to clear yet.
//! - **No `prs-lib` type appears in a signature** (ADR-4). The commands speak
//!   only in our own domain types.
//!
//! The command functions themselves are thin: the logic lives on [`Core`], so
//! it can be tested against a fake store and a fake backend without standing up
//! a Tauri app.

use serde::Serialize;
use tauri::State;

use crate::clipboard::Clipboard;
use crate::crypto::{Gpg, PrsGpg};
use crate::error::{Error, Result};
use crate::otp::{Otp, OtpCode};
use crate::secret::Secret;
use crate::store::{Entry, EntryMetadata, EntryName, PrsStore, Store, Tree};

/// What every command needs: a store to read, a backend to decrypt with, and a
/// clipboard to copy into.
///
/// The store and the backend are opened per command rather than once at
/// startup. That is deliberate — each can fail for a reason the user can fix
/// while the app is running (no store directory yet, no `gpg` on `PATH`), and
/// reopening means the fix takes effect on the next click instead of the next
/// launch. Neither is expensive: opening the store is a `canonicalize`, and the
/// `gpg` probe hits the thread-local context cache in `crypto::prs` after the
/// first call.
///
/// The clipboard is the exception: on X11 and Wayland the process that set the
/// clipboard is the one that serves it, so the handle has to outlive the
/// command. It opens lazily, so a machine with no display server still starts
/// and still reads.
///
/// Holds no decrypted state, so it is `Send + Sync` without a lock.
pub struct Core {
    store: StoreFactory,
    gpg: GpgFactory,
    clipboard: Clipboard,
}

type StoreFactory = Box<dyn Fn() -> Result<Box<dyn Store>> + Send + Sync>;
type GpgFactory = Box<dyn Fn() -> Result<Box<dyn Gpg>> + Send + Sync>;

impl Core {
    /// The real store — `PASSWORD_STORE_DIR`, else `~/.password-store` — read
    /// through the user's `gpg`, copying to the system clipboard.
    pub fn new() -> Self {
        Self::from_parts(
            Box::new(|| Ok(Box::new(PrsStore::open_default()?))),
            Box::new(|| Ok(Box::new(PrsGpg::new()?))),
            Clipboard::system(),
        )
    }

    /// Seam for the tests below: any [`Store`], any [`Gpg`], any clipboard.
    fn from_parts(store: StoreFactory, gpg: GpgFactory, clipboard: Clipboard) -> Self {
        Self {
            store,
            gpg,
            clipboard,
        }
    }

    /// The store's directories and entries. Names only — nothing is decrypted.
    pub fn tree(&self) -> Result<Tree> {
        (self.store)()?.tree()
    }

    /// What an entry contains, without what it contains.
    ///
    /// This has to decrypt — an entry's shape is only knowable from its
    /// plaintext — but the plaintext is dropped as this returns and only
    /// [`EntryMetadata`] survives.
    pub fn metadata(&self, name: &EntryName) -> Result<EntryMetadata> {
        Ok(self.entry(name)?.metadata())
    }

    /// The first line of `name`.
    pub fn reveal_password(&self, name: &EntryName) -> Result<String> {
        reveal(self.entry(name)?.password())
    }

    /// The value of the field at `index` in [`EntryMetadata::fields`].
    ///
    /// Addressed by index rather than by key because keys may repeat: the file
    /// order is a field's identity.
    pub fn reveal_field(&self, name: &EntryName, index: usize) -> Result<String> {
        let entry = self.entry(name)?;
        let field = entry.field(index).ok_or_else(|| Error::NoSuchField {
            name: name.clone(),
            index,
        })?;
        reveal(field.value())
    }

    /// The entry's free text.
    pub fn reveal_notes(&self, name: &EntryName) -> Result<String> {
        let entry = self.entry(name)?;
        let notes = entry
            .notes()
            .ok_or_else(|| Error::NoNotes { name: name.clone() })?;
        reveal(notes)
    }

    /// Copy the password to the clipboard.
    pub fn copy_password(&self, name: &EntryName) -> Result<CopyReceipt> {
        self.copy(self.entry(name)?.password())
    }

    /// Copy the value of the field at `index`.
    pub fn copy_field(&self, name: &EntryName, index: usize) -> Result<CopyReceipt> {
        let entry = self.entry(name)?;
        let field = entry.field(index).ok_or_else(|| Error::NoSuchField {
            name: name.clone(),
            index,
        })?;
        self.copy(field.value())
    }

    /// Copy the entry's free text.
    pub fn copy_notes(&self, name: &EntryName) -> Result<CopyReceipt> {
        let entry = self.entry(name)?;
        let notes = entry
            .notes()
            .ok_or_else(|| Error::NoNotes { name: name.clone() })?;
        self.copy(notes)
    }

    /// Copy the current one-time password — the code, never the URI.
    pub fn copy_otp(&self, name: &EntryName) -> Result<CopyReceipt> {
        let code = self.otp_code(name)?;
        // Re-wrapped so every copy takes the same path: the code is already a
        // `String` — it is what `otp_code` puts on the wire — but the clipboard
        // has exactly one entry point, and that entry point takes a `Secret`.
        self.copy(&Secret::from_slice(code.code.as_bytes()))
    }

    /// The current one-time password for `name`, with its countdown.
    ///
    /// The `otpauth://` URI is decrypted, used, and dropped inside this call.
    /// Only the digits leave the core (Invariant 2) — which is why there is no
    /// `reveal_otp` to go with the other reveals.
    pub fn otp_code(&self, name: &EntryName) -> Result<OtpCode> {
        let entry = self.entry(name)?;
        let uri = entry
            .otp()
            .ok_or_else(|| Error::NoOtp { name: name.clone() })?;
        Otp::parse(uri)?.code()
    }

    /// Wipe the clipboard now, without waiting for the timer.
    pub fn clear_clipboard(&self) -> Result<()> {
        self.clipboard.clear()
    }

    /// Decrypt `name` and parse it.
    ///
    /// The returned [`Entry`] holds the whole plaintext, so it is built to
    /// serve one request and dropped with it — never stored, never returned
    /// past this module.
    fn entry(&self, name: &EntryName) -> Result<Entry> {
        let path = (self.store)()?.secret_path(name)?;
        let plaintext = (self.gpg)()?.decrypt_file(&path)?;
        Entry::parse(plaintext)
    }

    /// The single place a [`Secret`] reaches the clipboard.
    ///
    /// The counterpart to [`reveal`]: that one is where a secret becomes a
    /// string for the webview, this one is where a secret leaves the core
    /// without becoming one.
    fn copy(&self, secret: &Secret) -> Result<CopyReceipt> {
        Ok(CopyReceipt {
            clears_in_secs: self.clipboard.copy(secret)?.as_secs(),
        })
    }
}

/// What the webview learns from a copy: when the clipboard will be wiped.
///
/// Nothing about the value — the point of copying in the core is that the value
/// never comes back here (Invariant 2). Adding a field that describes what was
/// copied would undo that.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct CopyReceipt {
    /// Seconds until the auto-clear fires, so the UI can count down with it.
    pub clears_in_secs: u64,
}

impl Default for Core {
    fn default() -> Self {
        Self::new()
    }
}

/// The one place a secret becomes a `String` bound for the webview.
///
/// Invariant 2 permits exactly this and nothing more: a single value the user
/// explicitly asked to see. Past this line our zeroizing discipline ends —
/// serde copies the `String` into the IPC response and neither buffer is
/// wiped — so the webview's obligation takes over: hold it in component state
/// for as long as it is on screen and no longer, never in a store, never in
/// `localStorage`, never in a URL (CLAUDE.md, Frontend).
///
/// Keep the call sites to the `reveal_*` methods above.
fn reveal(secret: &Secret) -> Result<String> {
    Ok(secret.expose_str()?.to_owned())
}

/// Liveness/version probe for the Rust core. Carries no store data.
#[tauri::command]
pub fn core_version() -> String {
    env!("CARGO_PKG_VERSION").to_string()
}

/// The whole store tree. Entry names are metadata; nothing here is decrypted.
#[tauri::command]
pub fn list_tree(core: State<'_, Core>) -> Result<Tree> {
    core.tree()
}

/// An entry's shape: which fields it has, whether it has an OTP or notes.
#[tauri::command]
pub fn show_entry(name: EntryName, core: State<'_, Core>) -> Result<EntryMetadata> {
    core.metadata(&name)
}

/// Reveal the password. Reached only from an explicit user action.
#[tauri::command]
pub fn reveal_password(name: EntryName, core: State<'_, Core>) -> Result<String> {
    core.reveal_password(&name)
}

/// Reveal one field's value. Reached only from an explicit user action.
#[tauri::command]
pub fn reveal_field(name: EntryName, index: usize, core: State<'_, Core>) -> Result<String> {
    core.reveal_field(&name, index)
}

/// Reveal the entry's free text. Reached only from an explicit user action.
#[tauri::command]
pub fn reveal_notes(name: EntryName, core: State<'_, Core>) -> Result<String> {
    core.reveal_notes(&name)
}

// The OTP URI deliberately has no reveal command: it embeds the shared TOTP
// seed, and what a user actually wants to see is the six-digit code. That is
// what `otp_code` returns, computed in the core.

/// Copy the password to the clipboard, without it passing through the webview.
#[tauri::command]
pub fn copy_password(name: EntryName, core: State<'_, Core>) -> Result<CopyReceipt> {
    core.copy_password(&name)
}

/// Copy one field's value, addressed by its index in `EntryMetadata::fields`.
#[tauri::command]
pub fn copy_field(name: EntryName, index: usize, core: State<'_, Core>) -> Result<CopyReceipt> {
    core.copy_field(&name, index)
}

/// Copy the entry's free text.
#[tauri::command]
pub fn copy_notes(name: EntryName, core: State<'_, Core>) -> Result<CopyReceipt> {
    core.copy_notes(&name)
}

/// Copy the current one-time password.
#[tauri::command]
pub fn copy_otp(name: EntryName, core: State<'_, Core>) -> Result<CopyReceipt> {
    core.copy_otp(&name)
}

/// The current one-time password and how long it lasts. Never the URI.
#[tauri::command]
pub fn otp_code(name: EntryName, core: State<'_, Core>) -> Result<OtpCode> {
    core.otp_code(&name)
}

/// Wipe the clipboard now.
#[tauri::command]
pub fn clear_clipboard(core: State<'_, Core>) -> Result<()> {
    core.clear_clipboard()
}

#[cfg(test)]
// Test code handles fixtures, never real secrets: the plaintexts below are
// literals, not decrypted content.
#[allow(clippy::unwrap_used)]
mod tests {
    use std::collections::BTreeMap;
    use std::path::{Path, PathBuf};
    use std::sync::{Arc, Mutex};
    use std::time::Duration;

    use super::*;
    use crate::clipboard::stub::{StubBackend, StubScheduler};
    use crate::store::{tree, Recipients};

    /// Root the fakes agree on. No file is ever opened under it.
    const ROOT: &str = "/store";

    /// A store whose entries are held in memory.
    ///
    /// `secret_path` returns a path that need not exist, since [`FakeGpg`]
    /// never opens it — together they model the store and the backend agreeing
    /// on a name, which is the only contract [`Core::entry`] depends on. The
    /// two share one table, so an entry written through the backend is an entry
    /// this store lists.
    struct FakeStore {
        root: PathBuf,
        gpg: FakeGpg,
    }

    impl FakeStore {
        fn names(&self) -> Vec<EntryName> {
            self.gpg
                .paths()
                .iter()
                .filter_map(|path| EntryName::from_secret_path(&self.root, path).ok())
                .collect()
        }
    }

    impl Store for FakeStore {
        fn root(&self) -> &Path {
            &self.root
        }

        fn tree(&self) -> Result<Tree> {
            Ok(Tree {
                nodes: tree::build(&self.names()),
                unsupported: Vec::new(),
            })
        }

        fn secret_path(&self, name: &EntryName) -> Result<PathBuf> {
            if self.names().contains(name) {
                Ok(name.to_secret_path(&self.root))
            } else {
                Err(Error::EntryNotFound { name: name.clone() })
            }
        }

        fn recipients(&self, name: &EntryName) -> Result<Recipients> {
            let _ = name;
            Ok(Recipients {
                ids: vec![RECIPIENT.to_owned()],
                source: self.root.join(crate::store::gpg_id::GPG_ID_FILE),
            })
        }
    }

    /// The id [`FakeStore`] reports for every entry, so a test can tell what a
    /// write was encrypted to apart from what it contained.
    const RECIPIENT: &str = "fake-key";

    /// A backend that "decrypts" by looking the path up in a table, and
    /// "encrypts" by writing back into it.
    ///
    /// The table is shared rather than copied per call, so a write through one
    /// handle is visible to the next command's read — which is the property a
    /// mutation test needs. `written_to` records the recipients each write was
    /// encrypted to, so Invariant 8 is checkable without a real key.
    #[derive(Clone, Default)]
    struct FakeGpg {
        plaintexts: Arc<Mutex<BTreeMap<PathBuf, String>>>,
        written_to: Arc<Mutex<Vec<Write>>>,
    }

    /// One encryption: where it went, and to whom.
    type Write = (PathBuf, Vec<String>);

    impl FakeGpg {
        fn with(entries: &[(&str, &str)], root: &Path) -> Self {
            let plaintexts = entries
                .iter()
                .map(|(name, text)| (name_of(name).to_secret_path(root), (*text).to_owned()))
                .collect();
            Self {
                plaintexts: Arc::new(Mutex::new(plaintexts)),
                written_to: Arc::new(Mutex::new(Vec::new())),
            }
        }

        /// Paths currently holding ciphertext, as [`FakeStore`] sees them.
        fn paths(&self) -> Vec<PathBuf> {
            lock(&self.plaintexts).keys().cloned().collect()
        }
    }

    impl Gpg for FakeGpg {
        fn decrypt_file(&self, path: &Path) -> Result<Secret> {
            match lock(&self.plaintexts).get(path) {
                Some(text) => Ok(Secret::from_slice(text.as_bytes())),
                None => Err(Error::Decrypt { path: path.into() }),
            }
        }

        fn encrypt_file(
            &self,
            path: &Path,
            recipients: &Recipients,
            plaintext: &Secret,
        ) -> Result<()> {
            let text = plaintext.expose_str()?.to_owned();
            lock(&self.plaintexts).insert(path.to_path_buf(), text);
            lock(&self.written_to).push((path.to_path_buf(), recipients.ids.clone()));
            Ok(())
        }
    }

    /// Take a lock, treating poisoning as the panic it already was.
    ///
    /// Test-only: the alternative is `unwrap()` at every call site, and a
    /// poisoned mutex here means another test thread panicked mid-assertion.
    fn lock<T>(mutex: &Mutex<T>) -> std::sync::MutexGuard<'_, T> {
        mutex
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
    }

    /// The clip window the fake clipboard reports, distinct from the default so
    /// a receipt carrying it is evidence it came from the configured value.
    const CLIP_TIME: Duration = Duration::from_secs(20);

    /// A core over the given `name -> plaintext` pairs, plus the handles a test
    /// needs to see what reached the clipboard and to fire its timer.
    fn core_with_clipboard(
        entries: &[(&'static str, &'static str)],
    ) -> (Core, StubBackend, StubScheduler) {
        let (core, backend, scheduler, _) = core_with_parts(entries);
        (core, backend, scheduler)
    }

    /// As [`core_with_clipboard`], plus the backend handle a write test needs to
    /// see what was encrypted and to whom.
    fn core_with_parts(
        entries: &[(&'static str, &'static str)],
    ) -> (Core, StubBackend, StubScheduler, FakeGpg) {
        let gpg = FakeGpg::with(entries, Path::new(ROOT));
        let backend = StubBackend::default();
        let scheduler = StubScheduler::default();

        let store_gpg = gpg.clone();
        let command_gpg = gpg.clone();
        let core = Core::from_parts(
            Box::new(move || {
                Ok(Box::new(FakeStore {
                    root: PathBuf::from(ROOT),
                    gpg: store_gpg.clone(),
                }))
            }),
            Box::new(move || Ok(Box::new(command_gpg.clone()))),
            Clipboard::new(
                Box::new(backend.clone()),
                Box::new(scheduler.clone()),
                CLIP_TIME,
            ),
        );
        (core, backend, scheduler, gpg)
    }

    /// A core over the given `name -> plaintext` pairs.
    fn core(entries: &[(&'static str, &'static str)]) -> Core {
        core_with_clipboard(entries).0
    }

    /// A clipboard nothing is expected to reach.
    fn unused_clipboard() -> Clipboard {
        Clipboard::new(
            Box::new(StubBackend::default()),
            Box::new(StubScheduler::default()),
            CLIP_TIME,
        )
    }

    fn name_of(name: &str) -> EntryName {
        EntryName::new(name).unwrap()
    }

    const GMAIL: &str = "hunter2\nuser: alice\nurl: example.com\nurl: other.example\n\
                         otpauth://totp/ACME?secret=JBSWY3DP\nremember the milk";

    /// Two entries: one of every shape, and one with a password only.
    fn store() -> Core {
        core(&[("Email/gmail.com", GMAIL), ("wifi", "correct horse")])
    }

    #[test]
    fn list_tree_returns_names_without_decrypting() {
        // The backend fails if it is used at all, so a decrypt on the listing
        // path would fail this test rather than pass unnoticed.
        let listed = FakeGpg::with(
            &[("Email/gmail.com", GMAIL), ("wifi", "correct horse")],
            Path::new(ROOT),
        );
        let core = Core::from_parts(
            Box::new(move || {
                Ok(Box::new(FakeStore {
                    root: PathBuf::from(ROOT),
                    gpg: listed.clone(),
                }))
            }),
            Box::new(|| {
                Err(Error::GpgUnavailable {
                    reason: "listing must not decrypt".into(),
                })
            }),
            unused_clipboard(),
        );

        let tree = core.tree().unwrap();
        assert_eq!(
            tree.nodes
                .iter()
                .map(crate::store::Node::name)
                .collect::<Vec<_>>(),
            vec!["Email", "wifi"]
        );
    }

    #[test]
    fn show_entry_returns_shape_and_no_values() {
        let metadata = store().metadata(&name_of("Email/gmail.com")).unwrap();

        assert_eq!(
            metadata,
            EntryMetadata {
                has_password: true,
                fields: vec!["user".to_owned(), "url".to_owned(), "url".to_owned()],
                has_otp: true,
                has_notes: true,
            }
        );
    }

    /// The IPC-facing half of Invariant 2: whatever `show_entry` serializes,
    /// none of the entry's content is in it.
    #[test]
    fn the_serialized_metadata_carries_no_plaintext() {
        let metadata = store().metadata(&name_of("Email/gmail.com")).unwrap();
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
    }

    #[test]
    fn reveal_password_returns_the_first_line() {
        assert_eq!(
            store()
                .reveal_password(&name_of("Email/gmail.com"))
                .unwrap(),
            "hunter2"
        );
    }

    #[test]
    fn reveal_field_is_addressed_by_index_so_repeated_keys_are_reachable() {
        let core = store();
        let gmail = name_of("Email/gmail.com");

        assert_eq!(core.reveal_field(&gmail, 0).unwrap(), "alice");
        assert_eq!(core.reveal_field(&gmail, 1).unwrap(), "example.com");
        assert_eq!(core.reveal_field(&gmail, 2).unwrap(), "other.example");
    }

    #[test]
    fn reveal_field_rejects_an_index_the_entry_does_not_have() {
        match store().reveal_field(&name_of("Email/gmail.com"), 9) {
            Err(Error::NoSuchField { name, index }) => {
                assert_eq!(name.as_str(), "Email/gmail.com");
                assert_eq!(index, 9);
            }
            Err(other) => panic!("expected NoSuchField, got {other:?}"),
            Ok(_) => panic!("expected NoSuchField for an out-of-range index"),
        }
    }

    #[test]
    fn reveal_notes_returns_the_free_text() {
        assert_eq!(
            store().reveal_notes(&name_of("Email/gmail.com")).unwrap(),
            "remember the milk"
        );
    }

    #[test]
    fn reveal_notes_reports_an_entry_that_has_none() {
        match store().reveal_notes(&name_of("wifi")) {
            Err(Error::NoNotes { name }) => assert_eq!(name.as_str(), "wifi"),
            Err(other) => panic!("expected NoNotes, got {other:?}"),
            Ok(_) => panic!("expected NoNotes for an entry without free text"),
        }
    }

    #[test]
    fn a_missing_entry_is_reported_before_anything_is_decrypted() {
        match store().metadata(&name_of("nope")) {
            Err(Error::EntryNotFound { name }) => assert_eq!(name.as_str(), "nope"),
            Err(other) => panic!("expected EntryNotFound, got {other:?}"),
            Ok(_) => panic!("expected EntryNotFound for a name not in the store"),
        }
    }

    /// Invariant 2 for the copy path: the value goes to the clipboard from
    /// inside the core, and the caller is told only when it will be wiped.
    #[test]
    fn copy_password_reaches_the_clipboard_and_not_the_caller() {
        let (core, clipboard, scheduler) = core_with_clipboard(&[("wifi", "correct horse")]);

        let receipt = core.copy_password(&name_of("wifi")).unwrap();

        assert_eq!(receipt.clears_in_secs, CLIP_TIME.as_secs());
        assert_eq!(clipboard.contents().as_deref(), Some("correct horse"));
        assert_eq!(scheduler.pending(), 1, "the copy must schedule its clear");
    }

    #[test]
    fn a_copied_value_is_wiped_when_its_timer_runs() {
        let (core, clipboard, scheduler) = core_with_clipboard(&[("wifi", "correct horse")]);
        core.copy_password(&name_of("wifi")).unwrap();

        scheduler.fire();

        assert_eq!(clipboard.contents(), None);
    }

    #[test]
    fn copy_field_is_addressed_by_index_like_reveal() {
        let (core, clipboard, _) = core_with_clipboard(&[("Email/gmail.com", GMAIL)]);
        let gmail = name_of("Email/gmail.com");

        core.copy_field(&gmail, 2).unwrap();
        assert_eq!(clipboard.contents().as_deref(), Some("other.example"));

        match core.copy_field(&gmail, 9) {
            Err(Error::NoSuchField { index, .. }) => assert_eq!(index, 9),
            Err(other) => panic!("expected NoSuchField, got {other:?}"),
            Ok(_) => panic!("expected NoSuchField for an out-of-range index"),
        }
    }

    #[test]
    fn copy_notes_copies_the_free_text() {
        let (core, clipboard, _) = core_with_clipboard(&[("Email/gmail.com", GMAIL)]);

        core.copy_notes(&name_of("Email/gmail.com")).unwrap();

        assert_eq!(clipboard.contents().as_deref(), Some("remember the milk"));
    }

    /// The whole reason the OTP has no reveal: what leaves the core is the
    /// code, and the URI that would give away the seed stays behind.
    #[test]
    fn copy_otp_copies_the_code_and_never_the_uri() {
        let (core, clipboard, _) = core_with_clipboard(&[("Email/gmail.com", GMAIL)]);

        core.copy_otp(&name_of("Email/gmail.com")).unwrap();

        let copied = clipboard.contents().unwrap();
        assert_eq!(copied.len(), 6);
        assert!(copied.chars().all(|c| c.is_ascii_digit()), "{copied:?}");
        assert!(!copied.contains("JBSWY3DP"));
        assert!(!copied.contains("otpauth"));
    }

    #[test]
    fn otp_code_returns_a_code_and_a_live_countdown() {
        let code = store().otp_code(&name_of("Email/gmail.com")).unwrap();

        assert_eq!(code.code.len(), 6);
        assert!(code.code.chars().all(|c| c.is_ascii_digit()));
        assert_eq!(code.period_secs, 30);
        assert!(
            (1..=30).contains(&code.valid_for_secs),
            "{}",
            code.valid_for_secs
        );
    }

    #[test]
    fn otp_code_reports_an_entry_that_has_no_otp() {
        match store().otp_code(&name_of("wifi")) {
            Err(Error::NoOtp { name }) => assert_eq!(name.as_str(), "wifi"),
            Err(other) => panic!("expected NoOtp, got {other:?}"),
            Ok(_) => panic!("expected NoOtp for an entry without an otpauth:// line"),
        }
    }

    #[test]
    fn clear_clipboard_wipes_it_on_demand() {
        let (core, clipboard, _) = core_with_clipboard(&[("wifi", "correct horse")]);
        core.copy_password(&name_of("wifi")).unwrap();

        core.clear_clipboard().unwrap();

        assert_eq!(clipboard.contents(), None);
    }

    /// The IPC-facing half of the copy path: a receipt describes the timer, not
    /// the value.
    #[test]
    fn the_serialized_receipt_carries_no_value() {
        let (core, _, _) = core_with_clipboard(&[("wifi", "correct horse")]);
        let receipt = core.copy_password(&name_of("wifi")).unwrap();

        let json = serde_json::to_string(&receipt).unwrap();

        assert_eq!(json, r#"{"clearsInSecs":20}"#);
        assert!(!json.contains("correct horse"));
    }

    /// Invariant 5 at the boundary: the string the webview receives for a
    /// failed reveal names the entry and nothing else.
    #[test]
    fn a_serialized_error_carries_no_plaintext() {
        let Err(err) = store().reveal_field(&name_of("Email/gmail.com"), 9) else {
            panic!("expected an error");
        };
        assert_eq!(
            serde_json::to_string(&err).unwrap(),
            r#""entry Email/gmail.com has no field at index 9""#
        );
    }
}
