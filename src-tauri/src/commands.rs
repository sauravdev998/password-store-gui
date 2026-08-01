//! The `#[tauri::command]` surface — the only door between the webview and the
//! core.
//!
//! Three rules govern everything here:
//!
//! - **Metadata by default.** [`show_entry`] returns shape, never content. The
//!   only values that cross into the webview are the ones a user asked to see,
//!   one at a time, through a `reveal_*` command (Invariant 2). [`reveal`] is
//!   the single place a [`Secret`] becomes a `String`.
//! - **Nothing decrypted is kept.** A command decrypts, answers, and drops the
//!   plaintext before it returns. There is no cache in Phase 1 — which is also
//!   why there is nothing for Invariant 7's auto-lock to clear yet.
//! - **No `prs-lib` type appears in a signature** (ADR-4). The commands speak
//!   only in our own domain types.
//!
//! The command functions themselves are thin: the logic lives on [`Core`], so
//! it can be tested against a fake store and a fake backend without standing up
//! a Tauri app.

use tauri::State;

use crate::crypto::{Gpg, PrsGpg};
use crate::error::{Error, Result};
use crate::secret::Secret;
use crate::store::{Entry, EntryMetadata, EntryName, PrsStore, Store, Tree};

/// What every command needs: a store to read and a backend to decrypt with.
///
/// Both are opened per command rather than once at startup. That is
/// deliberate — each can fail for a reason the user can fix while the app is
/// running (no store directory yet, no `gpg` on `PATH`), and reopening means
/// the fix takes effect on the next click instead of the next launch. Neither
/// is expensive: opening the store is a `canonicalize`, and the `gpg` probe
/// hits the thread-local context cache in `crypto::prs` after the first call.
///
/// Holds no decrypted state, so it is `Send + Sync` without a lock.
pub struct Core {
    store: StoreFactory,
    gpg: GpgFactory,
}

type StoreFactory = Box<dyn Fn() -> Result<Box<dyn Store>> + Send + Sync>;
type GpgFactory = Box<dyn Fn() -> Result<Box<dyn Gpg>> + Send + Sync>;

impl Core {
    /// The real store — `PASSWORD_STORE_DIR`, else `~/.password-store` — read
    /// through the user's `gpg`.
    pub fn new() -> Self {
        Self::from_factories(
            Box::new(|| Ok(Box::new(PrsStore::open_default()?))),
            Box::new(|| Ok(Box::new(PrsGpg::new()?))),
        )
    }

    /// Seam for the tests below: any [`Store`] and any [`Gpg`].
    fn from_factories(store: StoreFactory, gpg: GpgFactory) -> Self {
        Self { store, gpg }
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
// seed, and what a user actually wants to see is the six-digit code. Phase 2
// computes that in the core and sends only the code.

#[cfg(test)]
// Test code handles fixtures, never real secrets: the plaintexts below are
// literals, not decrypted content.
#[allow(clippy::unwrap_used)]
mod tests {
    use std::collections::BTreeMap;
    use std::path::{Path, PathBuf};

    use super::*;
    use crate::store::{tree, Recipients};

    /// Root the fakes agree on. No file is ever opened under it.
    const ROOT: &str = "/store";

    /// A store whose entries are held in memory.
    ///
    /// `secret_path` returns a path that need not exist, since [`FakeGpg`]
    /// never opens it — together they model the store and the backend agreeing
    /// on a name, which is the only contract [`Core::entry`] depends on.
    struct FakeStore {
        root: PathBuf,
        names: Vec<EntryName>,
    }

    impl Store for FakeStore {
        fn root(&self) -> &Path {
            &self.root
        }

        fn tree(&self) -> Result<Tree> {
            Ok(Tree {
                nodes: tree::build(&self.names),
                unsupported: Vec::new(),
            })
        }

        fn secret_path(&self, name: &EntryName) -> Result<PathBuf> {
            if self.names.contains(name) {
                Ok(name.to_secret_path(&self.root))
            } else {
                Err(Error::EntryNotFound { name: name.clone() })
            }
        }

        fn recipients(&self, _name: &EntryName) -> Result<Recipients> {
            unimplemented!("Phase 1 never writes")
        }
    }

    /// A backend that "decrypts" by looking the path up in a table.
    struct FakeGpg {
        plaintexts: BTreeMap<PathBuf, &'static str>,
    }

    impl Gpg for FakeGpg {
        fn decrypt_file(&self, path: &Path) -> Result<Secret> {
            match self.plaintexts.get(path) {
                Some(text) => Ok(Secret::from_slice(text.as_bytes())),
                None => Err(Error::Decrypt { path: path.into() }),
            }
        }
    }

    /// A core over the given `name -> plaintext` pairs.
    fn core(entries: &[(&'static str, &'static str)]) -> Core {
        let names: Vec<EntryName> = entries.iter().map(|(name, _)| name_of(name)).collect();
        let plaintexts: BTreeMap<PathBuf, &'static str> = entries
            .iter()
            .map(|(name, text)| (name_of(name).to_secret_path(Path::new(ROOT)), *text))
            .collect();

        Core::from_factories(
            Box::new(move || {
                Ok(Box::new(FakeStore {
                    root: PathBuf::from(ROOT),
                    names: names.clone(),
                }))
            }),
            Box::new(move || {
                Ok(Box::new(FakeGpg {
                    plaintexts: plaintexts.clone(),
                }))
            }),
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
        let core = Core::from_factories(
            Box::new(|| {
                Ok(Box::new(FakeStore {
                    root: PathBuf::from(ROOT),
                    names: vec![name_of("Email/gmail.com"), name_of("wifi")],
                }))
            }),
            Box::new(|| {
                Err(Error::GpgUnavailable {
                    reason: "listing must not decrypt".into(),
                })
            }),
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
