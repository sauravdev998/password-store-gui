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

use std::path::{Path, PathBuf};
use std::sync::Arc;

use serde::Serialize;
use tauri::State;

use crate::clipboard::Clipboard;
use crate::crypto::{Gpg, KeyIds, KeyInfo, PrsGpg};
use crate::error::{Error, Result};
use crate::generate;
use crate::git::{Change, GitRepo, Revision, SyncOutcome, SyncStatus, Vcs};
use crate::otp::{Otp, OtpCode};
use crate::secret::Secret;
use crate::settings::{Effective, Settings, SettingsFile};
use crate::store::{gpg_id, Entry, EntryMetadata, EntryName, PrsStore, Recipients, Store, Tree};

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
/// Settings are the one thing kept rather than re-derived, and only because
/// they are a file the user edits through this app rather than a condition of
/// the machine. What they *say* is still consulted per command, so a change
/// takes effect on the next click like everything else here.
///
/// Holds no decrypted state, so it is `Send + Sync` without a lock.
pub struct Core {
    store: StoreFactory,
    root: RootFactory,
    gpg: GpgFactory,
    git: VcsFactory,
    clipboard: Clipboard,
    settings: Arc<SettingsFile>,
}

type StoreFactory = Box<dyn Fn() -> Result<Box<dyn Store>> + Send + Sync>;

/// Where the store is, for the commands that cannot open one.
///
/// Everything else reaches the root through [`Store::root`], which is only
/// answerable once the directory exists. Onboarding's whole subject is the case
/// where it does not (ADR-7), so it needs the path on its own — and it must be
/// **the same path** the store factory would open, or a test pointed at a
/// fixture would create a store in the developer's home instead.
type RootFactory = Box<dyn Fn() -> Result<PathBuf> + Send + Sync>;
type GpgFactory = Box<dyn Fn() -> Result<Box<dyn Gpg>> + Send + Sync>;

/// Opens the store's repository, if it has one.
///
/// `Option` rather than `Result` because a store with no git repository is the
/// ordinary case, not a failure — `pass git init` is optional and most stores
/// never run it.
type VcsFactory = Box<dyn Fn(&Path) -> Option<Box<dyn Vcs>> + Send + Sync>;

impl Core {
    /// The real store — `PASSWORD_STORE_DIR`, else `~/.password-store` — read
    /// through the user's `gpg`, copying to the system clipboard.
    pub fn new() -> Self {
        Self::with_clipboard(Clipboard::system())
    }

    /// The real store and backend, with a clipboard of the caller's choosing.
    ///
    /// Exists for the integration tests, and the reason is not tidiness. A
    /// clipboard is shared mutable state belonging to the user's desktop
    /// session, not to the process: a test that copied through
    /// [`Core::new`] would overwrite whatever the developer had on it — and
    /// since a Wayland or X11 clipboard is served by the process that set it,
    /// would take the value away entirely when the test process exited. CI
    /// cannot catch that, because CI has no display server for the copy to
    /// succeed on. So the seam is here rather than left to be remembered.
    pub fn with_clipboard(clipboard: Clipboard) -> Self {
        let settings = Arc::new(SettingsFile::user());
        let for_store = Arc::clone(&settings);
        let for_root = Arc::clone(&settings);
        Self::from_parts(
            // The root is asked for per command rather than captured, so
            // pointing the app at another store in Settings takes effect on the
            // next click — the same property opening the store per command
            // already buys for a store that did not exist yet.
            Box::new(move || Ok(Box::new(PrsStore::open(&for_store.store_root()?)?))),
            Box::new(move || for_root.store_root()),
            Box::new(|| Ok(Box::new(PrsGpg::new()?))),
            Box::new(real_git),
            clipboard,
            settings,
        )
    }

    /// A core over the store at `root`, rather than the default location.
    ///
    /// Phase 5's settings will want this for a user-configured store path. The
    /// integration tests want it sooner, and for a sharper reason: the only
    /// other way to point a `Core` at a fixture is `PASSWORD_STORE_DIR`, and
    /// setting that means `std::env::set_var` — process-global mutation that
    /// races anything else in the binary, and which **edition 2024 makes
    /// `unsafe`**. This crate forbids `unsafe_code` across every target and
    /// `forbid` cannot be locally allowed, so on the day the edition is bumped
    /// that call site stops compiling. A parameter has none of those problems.
    /// Settings are [`SettingsFile::ephemeral`] here for the same reason the
    /// clipboard is a parameter: a test must not read the developer's own
    /// configuration and must certainly not write it. It also makes the root
    /// unambiguous — an explicit root outranks even `PASSWORD_STORE_DIR`, so a
    /// variable in the developer's shell cannot redirect a test at their real
    /// store.
    pub fn with_store_root(root: impl Into<PathBuf>, clipboard: Clipboard) -> Self {
        let root = root.into();
        let for_root = root.clone();
        Self::from_parts(
            Box::new(move || Ok(Box::new(PrsStore::open(&root)?))),
            // The same path, deliberately: onboarding creates the store rather
            // than opening it, so it reads this instead of `Store::root` — and
            // if the two could disagree, a test pointed at a fixture would
            // create a store in the developer's own home.
            Box::new(move || Ok(for_root.clone())),
            Box::new(|| Ok(Box::new(PrsGpg::new()?))),
            Box::new(real_git),
            clipboard,
            Arc::new(SettingsFile::ephemeral()),
        )
    }

    /// Seam for the tests below: any [`Store`], any [`Gpg`], any history, any
    /// clipboard, any settings.
    fn from_parts(
        store: StoreFactory,
        root: RootFactory,
        gpg: GpgFactory,
        git: VcsFactory,
        clipboard: Clipboard,
        settings: Arc<SettingsFile>,
    ) -> Self {
        Self {
            store,
            root,
            gpg,
            git,
            clipboard,
            settings,
        }
    }

    /// Every setting as it stands, with what decided each one (ADR-11).
    pub fn settings(&self) -> Effective {
        self.settings.effective()
    }

    /// Replace the configured settings, and report them as they now stand.
    pub fn set_settings(&self, next: Settings) -> Result<Effective> {
        self.settings.set(next)
    }

    /// How a generated password should be shaped before the form adjusts it.
    pub fn generate_defaults(&self) -> generate::Recipe {
        self.settings.recipe()
    }

    /// Wipe the clipboard if it still holds a password we put there.
    ///
    /// The app's way out (Invariant 6): see
    /// [`Clipboard::clear_if_outstanding`] for why this is not
    /// [`Core::clear_clipboard`].
    pub fn release_clipboard(&self) {
        self.clipboard.clear_if_outstanding();
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

    /// The entry's plaintext, whole and unparsed — what the edit form loads.
    ///
    /// The one command that returns more than a single value, and the only path
    /// by which an `otpauth://` URI can reach the webview. Both are deliberate.
    /// Invariant 2 permits what the user explicitly reveals, and editing an
    /// entry *is* asking for its whole text: `pass edit` opens the decrypted
    /// file in `$EDITOR`, and there is no smaller request that can be served —
    /// [`Core::edit`] replaces the entire body, so writing one requires having
    /// read one. Splitting it into per-field edits would mean holding the
    /// unedited remainder decrypted between commands, which is the cache Phase 1
    /// deliberately does not have.
    ///
    /// It is not the OTP row's reveal and must not be used as one: that row
    /// exists so the *code* can be had without the seed. This is reached only
    /// by opening an editor on the entry, and the form that receives it drops it
    /// when it closes.
    pub fn reveal_entry(&self, name: &EntryName) -> Result<String> {
        reveal(&self.plaintext(name)?)
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

    /// Whether the store keeps a git history.
    ///
    /// A capability probe, not Phase 4's status: the interface has to be able
    /// to say what deleting an entry actually costs, and "still recoverable
    /// from the history" is true of a versioned store and false of every other
    /// one. Saying the wrong one of those would be exactly the failure §4.1
    /// principle 5 is about. Cheap — a repository discovery and nothing else.
    pub fn has_history(&self) -> Result<bool> {
        let store = (self.store)()?;
        Ok((self.git)(store.root()).is_some())
    }

    /// Where the store stands relative to its remote, or `None` when it keeps
    /// no history at all.
    ///
    /// Reads no entry and touches no network: it reports the distance to the
    /// remote as of the last fetch, so the interface can draw an indicator on
    /// arrival without that being an operation which can hang or prompt.
    pub fn sync_status(&self) -> Result<Option<SyncStatus>> {
        let store = (self.store)()?;
        (self.git)(store.root())
            .map(|repo| repo.status())
            .transpose()
    }

    /// Fetch, merge, push — the one command that reaches the network.
    ///
    /// A store with no repository and a store whose branch tracks nothing give
    /// the same answer, [`SyncOutcome::NoRemote`], because they are the same
    /// answer: there is nothing to sync with. Neither is a failure.
    pub fn sync(&self) -> Result<SyncOutcome> {
        let store = (self.store)()?;
        match (self.git)(store.root()) {
            Some(repo) => repo.sync(),
            None => Ok(SyncOutcome::NoRemote),
        }
    }

    /// The commits that touched `name`, newest first.
    ///
    /// Nothing is decrypted, so opening a history costs no pinentry (§4.1
    /// principle 1). It deliberately does not check that the entry currently
    /// exists: a history is about a name, and the version worth recovering is
    /// often the one from before a deletion. An unversioned store has an empty
    /// history rather than an error, for the same reason [`Core::sync`] treats
    /// one as having no remote.
    pub fn history(&self, name: &EntryName) -> Result<Vec<Revision>> {
        let store = (self.store)()?;
        match (self.git)(store.root()) {
            Some(repo) => repo.history(name),
            None => Ok(Vec::new()),
        }
    }

    /// An entry's whole plaintext as it was at `revision` (ADR-10).
    ///
    /// The second command that returns a whole body, and it is the same
    /// exception [`Core::reveal_entry`] is: there is no smaller request to
    /// serve, because the shape of an old version is only knowable by
    /// decrypting it and the reason to ask is to see what it said. Reached only
    /// by choosing a specific commit from a list that itself decrypted nothing,
    /// so the decrypt is as deliberate as opening the editor is.
    pub fn reveal_revision(&self, name: &EntryName, revision: &str) -> Result<String> {
        reveal(&self.revision(name, revision)?)
    }

    /// Copy the password a past version held, without showing it.
    ///
    /// The recovery path in its usual shape — "the new one does not work, give
    /// me the old one" — served the way every other copy is: the value goes to
    /// the clipboard from inside the core and never reaches the webview.
    pub fn copy_revision_password(&self, name: &EntryName, revision: &str) -> Result<CopyReceipt> {
        let entry = Entry::parse(self.revision(name, revision)?)?;
        self.copy(entry.password())
    }

    /// Decrypt `name` as it was at `revision`.
    ///
    /// The ciphertext comes out of a git object rather than off disk, which is
    /// why this goes through [`Gpg::decrypt`] instead of `decrypt_file`. The
    /// backend's pathless failure is replaced here, where the entry is known.
    fn revision(&self, name: &EntryName, revision: &str) -> Result<Secret> {
        let store = (self.store)()?;
        // No history means no version to ask for. The webview only offers this
        // from a list the same repository produced, so reaching it is a
        // malformed request rather than something a user can do.
        let repo = (self.git)(store.root()).ok_or(Error::NoSuchRevision)?;
        let ciphertext = repo.blob_at(name, revision)?;

        (self.gpg)()?
            .decrypt(&ciphertext)
            .map_err(|_| Error::DecryptRevision { name: name.clone() })
    }

    /// Create a new entry from the text the user typed.
    ///
    /// Refuses to overwrite: replacing an existing entry is [`Core::edit`], and
    /// keeping them apart is what stops a mistyped name from silently
    /// destroying a password.
    pub fn insert(&self, name: &EntryName, body: &Secret) -> Result<WriteReceipt> {
        let store = (self.store)()?;
        if store.contains(name) {
            return Err(Error::EntryExists { name: name.clone() });
        }
        self.write(&*store, name, body)?;
        Ok(self.record(&*store, Change::Insert(name)))
    }

    /// Replace an existing entry's contents.
    pub fn edit(&self, name: &EntryName, body: &Secret) -> Result<WriteReceipt> {
        let store = (self.store)()?;
        if !store.contains(name) {
            return Err(Error::EntryNotFound { name: name.clone() });
        }
        self.write(&*store, name, body)?;
        Ok(self.record(&*store, Change::Edit(name)))
    }

    /// Create an entry whose password is generated here.
    ///
    /// The password never leaves the core on this path: what comes back is the
    /// same [`CopyReceipt`] a copy returns, so the common case — generate, then
    /// paste it into the site that asked for it — happens without the value
    /// being rendered anywhere. To see it, the user reveals it like any other.
    /// The receipt is optional because the write is the primary effect and the
    /// copy is not: on a machine with no display server the clipboard fails,
    /// and reporting that as a failed *generate* would tell the user their
    /// entry was not created when it was — leaving them to retry into an
    /// `EntryExists`. So a clipboard that will not open yields `None`, and the
    /// UI simply omits the "on the clipboard" notice.
    pub fn generate(
        &self,
        name: &EntryName,
        recipe: generate::Recipe,
        body: Option<&Secret>,
    ) -> Result<WriteReceipt> {
        let store = (self.store)()?;
        if store.contains(name) {
            return Err(Error::EntryExists { name: name.clone() });
        }

        let password = generate::password(recipe)?;
        let entry = match body {
            // The generated password becomes the first line, and whatever the
            // form collected follows it — the same layout the parser reads back.
            Some(rest) => {
                let mut joined = Vec::with_capacity(password.len() + rest.len() + 1);
                joined.extend_from_slice(password.expose());
                joined.push(b'\n');
                joined.extend_from_slice(rest.expose());
                Secret::new(joined)
            }
            None => Secret::from_slice(password.expose()),
        };

        self.write(&*store, name, &entry)?;
        let mut receipt = self.record(&*store, Change::Generate(name));
        receipt.clipboard = self.copy(&password).ok();
        Ok(receipt)
    }

    /// Delete an entry.
    pub fn remove(&self, name: &EntryName) -> Result<WriteReceipt> {
        let store = (self.store)()?;
        store.remove(name)?;
        Ok(self.record(&*store, Change::Remove(name)))
    }

    /// Move an entry to a new name.
    pub fn rename(&self, from: &EntryName, to: &EntryName) -> Result<WriteReceipt> {
        let store = (self.store)()?;
        if self.same_recipients(&*store, from, to)? {
            store.rename_file(from, to)?;
        } else {
            // Across a recipient boundary the ciphertext cannot simply move:
            // the destination's `.gpg-id` names a different audience
            // (Invariant 8), so the entry is decrypted and encrypted again for
            // it. The source is removed only once the new file exists.
            self.reencrypt(&*store, from, to)?;
            store.remove(from)?;
        }
        Ok(self.record(&*store, Change::Rename { from, to }))
    }

    /// Copy an entry to a new name, leaving the original.
    ///
    /// Named apart from [`Core::copy`], which is the clipboard: on this surface
    /// "copy" already means something, and the two must not read alike.
    pub fn copy_entry(&self, from: &EntryName, to: &EntryName) -> Result<WriteReceipt> {
        let store = (self.store)()?;
        if self.same_recipients(&*store, from, to)? {
            store.copy_file(from, to)?;
        } else {
            self.reencrypt(&*store, from, to)?;
        }
        Ok(self.record(&*store, Change::Copy { from, to }))
    }

    /// The keys currently able to open a folder's entries, and where that was
    /// decided.
    ///
    /// Decrypts nothing: it reads the `.gpg-id` the walk-up lands on and asks
    /// the keyring about each id. Opening the panel therefore costs no pinentry
    /// and no key tap, the same property `entry_history` has (§4.1 principle 1).
    pub fn folder_keys(&self, folder: Option<&EntryName>) -> Result<FolderKeys> {
        let store = (self.store)()?;
        let root = store.root();

        let Some(source) = gpg_id::nearest_gpg_id_in(root, folder) else {
            // A store with no `.gpg-id` anywhere is not broken, it is
            // uninitialized — the state a directory made by hand is in. Saying
            // "no keys are set" is the truth; an error would suggest a failure.
            return Ok(FolderKeys {
                folder: folder.cloned(),
                keys: Vec::new(),
                source: None,
                inherited: false,
                entries: 0,
            });
        };

        let recipients = gpg_id::read(&source)?;
        let gpg = (self.gpg)()?;
        let source_folder = gpg_id::folder_of(root, &source);

        Ok(FolderKeys {
            folder: folder.cloned(),
            keys: recipients
                .ids
                .iter()
                .map(|id| describe(&*gpg, id))
                .collect(),
            inherited: source_folder.as_ref() != folder,
            entries: gpg_id::governed_by(root, source_folder.as_ref(), &store.entries()?).len(),
            source: source_folder,
        })
    }

    /// What changing a folder's keys to `ids` would do, before doing any of it.
    ///
    /// **Decrypts nothing** (ADR-13). Every proposed id is resolved against the
    /// keyring, and each governed entry's actual recipients are read out of its
    /// ciphertext's packet headers — so the count of entries this would rewrite
    /// is a fact rather than an estimate, and the user is told the price before
    /// being asked to pay it (§4.1 principle 1).
    pub fn plan_recipients(
        &self,
        folder: Option<&EntryName>,
        ids: &[String],
    ) -> Result<RecipientPlan> {
        let store = (self.store)()?;
        let gpg = (self.gpg)()?;
        self.plan(&*store, &*gpg, folder, ids)
    }

    /// Change the keys a folder's entries are encrypted to, re-encrypting them.
    ///
    /// Invariant 8's second sentence, which nothing implemented before this
    /// (ADR-13). The operation is **all or nothing**: every affected entry is
    /// decrypted and encrypted again into a staging file first, and only once
    /// every one of them has succeeded is anything moved into place. A failure
    /// during the expensive phase — a cancelled pinentry, a key that cannot be
    /// read, a full disk — leaves the store byte-identical, including the
    /// `.gpg-id`. `pass init` converts in place and leaves whatever it managed,
    /// which on a store whose files are all ciphertext is a store half its
    /// owner can read.
    pub fn set_recipients(
        &self,
        folder: Option<&EntryName>,
        ids: &[String],
    ) -> Result<WriteReceipt> {
        let store = (self.store)()?;
        let gpg = (self.gpg)()?;
        let root = store.root();

        // Refuses an id the keyring cannot resolve, before anything is written.
        // ADR-6's rule: fail loudly and by name, where `find_public_keys` failed
        // silently and encrypted to fewer people than asked.
        let plan = self.plan(&*store, &*gpg, folder, ids)?;

        let path = gpg_id::path_in(root, folder);
        let recipients = Recipients {
            ids: ids.to_vec(),
            source: path.clone(),
        };

        // The expensive, reversible phase. Nothing the store shows has changed
        // when this returns, whichever way it returns.
        let staged = stage(&*store, &*gpg, &plan.reencrypts, &recipients)?;

        // Past here only renames and one small write remain. The `.gpg-id` goes
        // down first so that the store's stated authorization is never *behind*
        // the files: a crash between these two leaves entries the new keys can
        // already read, which re-running repairs and `plan_recipients` can see.
        gpg_id::write(&path, ids)?;
        commit_staged(staged)?;

        Ok(self.record(
            &*store,
            Change::SetRecipients {
                folder,
                ids,
                reencrypted: &plan.reencrypts,
            },
        ))
    }

    /// The shared body of [`Core::plan_recipients`] and [`Core::set_recipients`],
    /// so the change that is described and the change that is made are computed
    /// by one piece of code rather than two that must agree.
    fn plan(
        &self,
        store: &dyn Store,
        gpg: &dyn Gpg,
        folder: Option<&EntryName>,
        ids: &[String],
    ) -> Result<RecipientPlan> {
        let root = store.root();
        if ids.is_empty() {
            return Err(Error::EmptyRecipients {
                path: gpg_id::path_in(root, folder),
            });
        }

        // Resolved rather than described: an id that does not resolve stops the
        // whole plan here, so a change is never *reported* as possible when
        // making it would fail partway.
        let keys: Vec<KeyInfo> = ids
            .iter()
            .map(|id| gpg.describe_key(id))
            .collect::<Result<_>>()?;

        // What a ciphertext must name for the entry to be readable by everyone
        // the store lists, and by nobody it does not.
        let wanted: Vec<&KeyIds> = keys.iter().map(|key| &key.keys).collect();
        let permitted: KeyIds = wanted.iter().flat_map(|set| set.iter()).cloned().collect();

        let path = gpg_id::path_in(root, folder);
        // The entries this change would reach: those the `.gpg-id` being written
        // will govern once it exists — which is not the same as those governed
        // today, because writing one into a folder that had none moves its
        // subtree out from under whatever governs it now.
        let mut governed = gpg_id::governed_by(root, folder, &store.entries()?);
        // The store walk yields whatever order the filesystem does. Sorted here
        // because this list is shown to the user before they agree to the
        // change, and an arbitrary order would reshuffle between two readings of
        // the same pending change. It also fixes the order entries are rewritten
        // in, which is what makes a partial failure reproducible.
        governed.sort();

        let mut reencrypts = Vec::new();
        let mut unchanged = 0;
        for name in governed {
            let secret = store.secret_path(&name)?;
            if is_current(gpg, &secret, &wanted, &permitted)? {
                unchanged += 1;
            } else {
                reencrypts.push(name);
            }
        }

        Ok(RecipientPlan {
            folder: folder.cloned(),
            locks_you_out: !keys.iter().any(|key| key.usable_here),
            keys,
            reencrypts,
            unchanged,
            creates_boundary: !path.is_file(),
        })
    }

    /// What onboarding needs to know about this machine (ADR-7).
    ///
    /// **Deliberately not routed through `(self.store)()`.** That factory fails
    /// when the store directory does not exist, which is precisely the state
    /// this answers about — so the store root comes from the settings directly
    /// and the directory is inspected rather than opened.
    ///
    /// Nothing here decrypts, and nothing raises a prompt: reading the secret
    /// keyring is a public-metadata question (§4.1 principle 1), and the whole
    /// point of asking it is to know what to offer before the user has agreed
    /// to anything.
    pub fn setup_status(&self) -> Result<SetupStatus> {
        let store_path = (self.root)()?;

        // Asked apart from the store, because the two failures are independent
        // and have different remedies: a machine can have a perfectly good
        // store and no GnuPG, and telling someone to install Gpg4win when what
        // they need is a store would be §4.1 principle 5 backwards.
        let (gpg_problem, keys) = match (self.gpg)() {
            // A listing that fails yields no keys rather than an error: the
            // only way it can fail is one that would already have failed above,
            // and the safe direction is offering to make a key rather than
            // refusing to show the ones that are there.
            Ok(gpg) => (None, gpg.usable_keys().unwrap_or_default()),
            Err(err) => (Some(err.to_string()), Vec::new()),
        };

        Ok(SetupStatus {
            store: store_state(&store_path),
            store_path,
            gpg_problem,
            keys,
            git_identity: crate::git::has_identity(),
        })
    }

    /// Make a new key pair, with the passphrase prompt left to the agent.
    ///
    /// A thin pass-through on purpose: everything that makes this safe is in
    /// [`Gpg::generate_key`] and its argument list, where a test can see it.
    pub fn create_key(&self, name: &str, email: &str) -> Result<KeyInfo> {
        (self.gpg)()?.generate_key(name, email)
    }

    /// Create the store: the directory, and the `.gpg-id` naming its keys.
    ///
    /// `pass init` on a machine that has none, and no more than that (ADR-7).
    /// Like [`Core::setup_status`] it does not open the store first, since the
    /// store is what it is about to make.
    pub fn init_store(&self, ids: &[String], versioned: bool) -> Result<WriteReceipt> {
        let root = (self.root)()?;

        // The wizard only appears when there is no store, so this is not
        // reachable from it — but the command is callable regardless, and
        // refusing here is what stops a second `.gpg-id` from re-pointing a
        // populated store at one key without the re-encryption
        // [`Core::set_recipients`] would have done for it (Invariant 8).
        if matches!(store_state(&root), StoreState::Ready) {
            return Err(Error::StoreExists { path: root });
        }

        let gpg = (self.gpg)()?;
        // Refused by name before anything is written — ADR-6's rule, and it
        // matters more here than anywhere: a store created around a key that
        // does not resolve is one whose every future write fails, with nothing
        // on screen to say why.
        for id in ids {
            gpg.describe_key(id)?;
        }

        // `atomic::write` makes the directory on the way, so this one call is
        // both halves of `pass init` on a machine with no store. No
        // `.gpg-id.sig`: `pass` writes one only under
        // `PASSWORD_STORE_SIGNING_KEY`, and a signature the CLI is not
        // configured to check is a file every other client ignores.
        gpg_id::write(&gpg_id::path_in(&root, None), ids)?;

        Ok(WriteReceipt {
            // A history that could not be started is news about the history,
            // not about the store — which exists and is usable either way. Same
            // shape, and the same reason, as a mutation's failed commit.
            commit: versioned.then(|| self.initial_commit(&root)),
            clipboard: None,
        })
    }

    /// Put a brand-new store under version control, and record its contents.
    fn initial_commit(&self, root: &Path) -> Commit {
        let change = Change::InitStore;
        let committed = self
            .repository(root)
            .and_then(|repo| repo.commit(&change.message(), &change.paths()));

        match committed {
            Ok(()) => Commit::Committed,
            Err(err) => Commit::Failed(err.to_string()),
        }
    }

    /// The repository for a store being created, making one if there is none.
    ///
    /// A store created *inside* something already versioned — a dotfiles
    /// checkout — is versioned by that repository, which is what the factory
    /// finds and what every later write will use. Initializing a second one
    /// nested inside it would give the store a history no other client looks
    /// at.
    fn repository(&self, root: &Path) -> Result<Box<dyn Vcs>> {
        match (self.git)(root) {
            Some(repo) => Ok(repo),
            None => Ok(Box::new(GitRepo::init(root)?)),
        }
    }

    /// Record a completed mutation in the store's history.
    ///
    /// Infallible by design. Everything it could report has already happened on
    /// disk, so a commit that does not go through is news about the *history*,
    /// not about the entry — and returning `Err` here would tell the user their
    /// password was not saved when it was. The outcome rides back in the
    /// receipt and the interface says which of the two is true (§4.1
    /// principle 5).
    fn record(&self, store: &dyn Store, change: Change<'_>) -> WriteReceipt {
        let commit = (self.git)(store.root()).map(|repo| {
            match repo.commit(&change.message(), &change.paths()) {
                Ok(()) => Commit::Committed,
                Err(err) => Commit::Failed(err.to_string()),
            }
        });
        WriteReceipt {
            commit,
            clipboard: None,
        }
    }

    /// Whether two names are governed by the same `.gpg-id` file.
    ///
    /// Compared by the file the walk-up landed on rather than by the ids it
    /// holds: two `.gpg-id` files listing the same recipients today are still
    /// two separate decisions, and a move between them should produce a file
    /// encrypted under the destination's.
    fn same_recipients(&self, store: &dyn Store, from: &EntryName, to: &EntryName) -> Result<bool> {
        Ok(store.recipients(from)?.source == store.recipients(to)?.source)
    }

    /// Decrypt `from` and write it to `to` under `to`'s own recipients.
    fn reencrypt(&self, store: &dyn Store, from: &EntryName, to: &EntryName) -> Result<()> {
        if store.contains(to) {
            return Err(Error::EntryExists { name: to.clone() });
        }
        let source = store.secret_path(from)?;
        let plaintext = (self.gpg)()?.decrypt_file(&source)?;
        self.write(store, to, &plaintext)
    }

    /// The single place a [`Secret`] is encrypted into the store.
    ///
    /// Recipients always come from the store's own walk-up for the name being
    /// written, never from the name it came from — that is Invariant 8, and
    /// routing every write through here is what makes it one rule rather than
    /// six call sites that each have to remember it.
    fn write(&self, store: &dyn Store, name: &EntryName, body: &Secret) -> Result<()> {
        let recipients = store.recipients(name)?;
        let path = name.to_secret_path(store.root());
        (self.gpg)()?.encrypt_file(&path, &recipients, body)
    }

    /// Decrypt `name` and parse it.
    ///
    /// The returned [`Entry`] holds the whole plaintext, so it is built to
    /// serve one request and dropped with it — never stored, never returned
    /// past this module.
    fn entry(&self, name: &EntryName) -> Result<Entry> {
        Entry::parse(self.plaintext(name)?)
    }

    /// Decrypt `name`, unparsed.
    fn plaintext(&self, name: &EntryName) -> Result<Secret> {
        let path = (self.store)()?.secret_path(name)?;
        (self.gpg)()?.decrypt_file(&path)
    }

    /// The single place a [`Secret`] reaches the clipboard.
    ///
    /// The counterpart to [`reveal`]: that one is where a secret becomes a
    /// string for the webview, this one is where a secret leaves the core
    /// without becoming one.
    fn copy(&self, secret: &Secret) -> Result<CopyReceipt> {
        // Read now rather than at startup: the window is a setting, and the one
        // the user is owed is the one in force when they pressed Copy.
        let clip_time = self.settings.clip_time();
        Ok(CopyReceipt {
            clears_in_secs: self.clipboard.copy(secret, clip_time)?.as_secs(),
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

/// What a mutation tells the webview: what happened *around* the write.
///
/// Nothing about what was written, for the same reason [`CopyReceipt`] says
/// nothing about what was copied. The write itself is reported by the command
/// returning `Ok` at all — everything here is a side effect that can fail
/// without the entry failing with it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct WriteReceipt {
    /// What became of the store's history. `None` when the store is not a git
    /// repository, which is the ordinary case rather than a problem.
    pub commit: Option<Commit>,
    /// Only `generate` fills this: the password it made went straight to the
    /// clipboard, never through the webview.
    pub clipboard: Option<CopyReceipt>,
}

/// Whether the change reached the store's git history.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase", tag = "status", content = "reason")]
pub enum Commit {
    Committed,
    /// The entry was written; the commit was not made. Carries a secret-free
    /// explanation — see [`crate::error::Error::Git`] for why git's own
    /// messages are safe to relay when the crypto layer's are not.
    Failed(String),
}

/// What onboarding found on this machine (ADR-7).
///
/// Three independent facts rather than one verdict, because the three states
/// Phase 7 covers — no usable `gpg`, no key, no store — are independent and
/// have different remedies. Deciding which screen to show is the interface's
/// job; saying what is true is this one's.
///
/// Nothing here is secret. A public key's user id and fingerprint are metadata
/// (see [`KeyInfo`]), and the rest is a path and two booleans.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct SetupStatus {
    /// Where the store is, or would be — after `PASSWORD_STORE_DIR` and the
    /// configured path have had their say (ADR-11). Shown, because a user
    /// about to have a directory created for them should see which one.
    pub store_path: PathBuf,

    pub store: StoreState,

    /// Why GnuPG is unusable, or `None` when it is fine.
    ///
    /// A string rather than a flag: it carries
    /// [`crate::error::Error::GpgUnavailable`]'s reason, which is safe here for
    /// the same narrow cause it is safe there — it is raised while *building* a
    /// context, before any ciphertext has been read.
    pub gpg_problem: Option<String>,

    /// Keys already on this machine that could back a store.
    ///
    /// Offered before generation is (ADR-7). Empty is the ordinary state of a
    /// machine that has never used GnuPG, and the only state that needs a key
    /// made for it.
    pub keys: Vec<KeyInfo>,

    /// Whether git could make a commit if it were asked to.
    ///
    /// What defaults the offer to version the new store. A repository created
    /// for a machine with no identity turns every later save into the
    /// failed-commit warning, so the checkbox follows this rather than a
    /// default that suits a developer's own machine.
    pub git_identity: bool,
}

/// How far along the store at a given path is.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub enum StoreState {
    /// Nothing at that path.
    Missing,
    /// A directory holding no entries and no `.gpg-id` — including one the user
    /// made by hand before opening this app.
    Empty,
    /// A store to open rather than to create.
    Ready,
}

/// Which of the three states the store at `root` is in.
///
/// The boundary is ADR-7's, and the interesting edge is the one that looks like
/// an omission: a directory holding **entries but no `.gpg-id`** counts as
/// `Ready`. It is not an uninitialized store, it is a store whose keys are
/// unset — `folder_keys` already reports it that way and the keys panel already
/// fixes it (ADR-13). Two screens for one state would be two answers to it.
fn store_state(root: &Path) -> StoreState {
    if !root.is_dir() {
        return StoreState::Missing;
    }
    if gpg_id::nearest_gpg_id_in(root, None).is_some() {
        return StoreState::Ready;
    }

    match PrsStore::open(root).and_then(|store| store.tree()) {
        // Unsupported names count as contents: they are files this app cannot
        // read but `pass` may well be able to, and treating the directory as
        // empty because of them would offer to set up a store over somebody
        // else's (§4.1 principle 3).
        Ok(tree) if tree.nodes.is_empty() && tree.unsupported.is_empty() => StoreState::Empty,
        Ok(_) => StoreState::Ready,
        // A directory we could not look inside is not an empty one. Guessing
        // `Empty` here is the single mistake in this function that could put a
        // `.gpg-id` into a store that already had contents.
        Err(_) => StoreState::Ready,
    }
}

/// The keys able to open a folder's entries, and where that was decided.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct FolderKeys {
    /// The folder asked about. `None` is the store root.
    pub folder: Option<EntryName>,

    /// The keys in force, in the order the `.gpg-id` lists them.
    ///
    /// Empty means no `.gpg-id` governs this folder at all — an uninitialized
    /// store rather than a broken one.
    pub keys: Vec<KeyInfo>,

    /// The folder whose `.gpg-id` decided this. `None` is the store root's.
    pub source: Option<EntryName>,

    /// Whether that decision was made somewhere above this folder.
    ///
    /// Carried rather than left for the webview to derive by comparing `folder`
    /// with `source`: the two are equal for the root in both directions, since
    /// `None == None`, and a UI that got that wrong would offer to "change" keys
    /// it was only inheriting.
    pub inherited: bool,

    /// How many entries that decision governs.
    pub entries: usize,
}

/// What changing a folder's keys would do, computed without decrypting.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct RecipientPlan {
    /// The folder whose keys would change. `None` is the store root.
    pub folder: Option<EntryName>,

    /// The proposed keys, each resolved against the keyring.
    ///
    /// Every one of them resolved, or there would be no plan — an id the
    /// keyring cannot place is refused here rather than at encrypt time
    /// (ADR-6, F-8).
    pub keys: Vec<KeyInfo>,

    /// The entries that would be decrypted and encrypted again, by name.
    ///
    /// Names rather than a count, because this is what the interface has to
    /// show before asking: the cost of this change is one decrypt each, which
    /// on a machine with a security key is one tap each (§4.1 principle 1).
    pub reencrypts: Vec<EntryName>,

    /// Entries already encrypted to exactly these keys, which are left alone.
    ///
    /// The same skip `pass`'s `reencrypt_path` makes. Adding a key that is
    /// already there is then free, and says so.
    pub unchanged: usize,

    /// Whether no proposed key is one this machine can decrypt with.
    ///
    /// The irreversible mistake: `pass init` to a key you do not hold locks you
    /// out of every entry in the subtree, and says nothing. This is what lets
    /// the interface say it first (ADR-13).
    pub locks_you_out: bool,

    /// Whether this would put a `.gpg-id` where there was none, splitting the
    /// folder off from whatever governs it now.
    pub creates_boundary: bool,
}

/// Suffix for a re-encrypted entry waiting to be moved into place.
///
/// Deliberately not ending in `.gpg`: the store walker matches that, and a
/// staging file must not appear in the tree even for the moment it exists.
const STAGING_SUFFIX: &str = ".pgs-staged";

/// One re-encrypted entry: where it is now, and where it belongs.
type Staged = Vec<(PathBuf, PathBuf)>;

/// Re-encrypt every entry to `recipients`, writing none of them into place.
///
/// The reversible half of a recipient change. Each entry is decrypted and
/// encrypted again beside itself, so a failure part-way through — the likely
/// one, since this is the phase that needs a secret key and may raise a
/// pinentry — leaves every file in the store exactly as it was. What it returns
/// is the list of moves that would complete the change.
///
/// One plaintext is live at a time and dropped before the next is read; the
/// staging files hold ciphertext only, so Invariant 1 is untouched.
fn stage(
    store: &dyn Store,
    gpg: &dyn Gpg,
    entries: &[EntryName],
    recipients: &Recipients,
) -> Result<Staged> {
    let mut staged: Staged = Vec::new();

    for name in entries {
        let result = store.secret_path(name).and_then(|target| {
            let staging = staging_path(&target);
            let plaintext = gpg.decrypt_file(&target)?;
            gpg.encrypt_file(&staging, recipients, &plaintext)?;
            Ok((staging, target))
        });

        match result {
            Ok(pair) => staged.push(pair),
            Err(err) => {
                // Nothing has been moved into place yet, so discarding what was
                // written restores the store byte for byte. A failed
                // `encrypt_file` leaves nothing of its own: it writes through a
                // temporary that is removed when the persist does not happen.
                for (staging, _) in &staged {
                    let _ = std::fs::remove_file(staging);
                }
                return Err(err);
            }
        }
    }

    Ok(staged)
}

/// Move every staged entry into place.
///
/// Each rename is atomic on its own and within one directory, so an entry is
/// never absent or half-written. The sweep as a whole is not atomic — there is
/// no filesystem operation that would make it so — which is why it runs last,
/// with nothing left that can fail for an interesting reason. An interruption
/// here leaves some entries converted and some not, which is a state
/// [`Core::plan_recipients`] can see and re-running the change repairs.
fn commit_staged(staged: Staged) -> Result<()> {
    for (staging, target) in staged {
        std::fs::rename(&staging, &target).map_err(|err| Error::io(&target, err))?;
    }
    Ok(())
}

/// Where an entry's re-encrypted ciphertext waits.
///
/// Beside the entry itself, so the rename that completes the change stays
/// within one filesystem and is therefore atomic.
fn staging_path(target: &Path) -> PathBuf {
    let mut path = target.to_path_buf().into_os_string();
    path.push(STAGING_SUFFIX);
    PathBuf::from(path)
}

/// Whether a ciphertext is already encrypted to exactly the right keys.
///
/// Invariant 8 in both directions, which is also what makes it the skip test:
/// everyone the store lists must be able to read the entry, and nobody else.
/// Those are ADR-6's F-8 and F-9 respectively, asked of a file that already
/// exists rather than of a write about to happen.
///
/// A recipient counts as able to read when **any one** of their encryption
/// subkeys is named. `gpg` encrypts to the newest usable subkey rather than to
/// all of them, so requiring the whole set — as `pass` effectively does by
/// comparing sorted lists — reports a key with two encryption subkeys as
/// permanently out of date, and re-encrypts the entry every single time.
fn is_current(gpg: &dyn Gpg, path: &Path, wanted: &[&KeyIds], permitted: &KeyIds) -> Result<bool> {
    let actual = gpg.encrypted_to(path)?;
    let everyone_listed_can_read = wanted.iter().all(|keys| !keys.is_disjoint(&actual));
    let nobody_else_can = actual.is_subset(permitted);
    Ok(everyone_listed_can_read && nobody_else_can)
}

/// Describe a key for display, falling back to the bare id.
///
/// Unlike [`Core::plan`], a failure here is not fatal: a `.gpg-id` may list
/// someone whose public key was never imported — the ordinary state of a store
/// shared with another person — and refusing to show the folder's keys because
/// one of them is unknown would hide the very thing the user needs to see. What
/// is shown is the id the store spells, with no label and `usable_here` false,
/// which is exactly what is true about it.
///
/// A *change* still refuses such an id, because encrypting to it would fail.
fn describe(gpg: &dyn Gpg, id: &str) -> KeyInfo {
    gpg.describe_key(id).unwrap_or_else(|_| KeyInfo {
        id: id.to_owned(),
        label: None,
        fingerprint: None,
        usable_here: false,
        keys: KeyIds::new(),
    })
}

/// The real repository, discovered from the store root.
fn real_git(root: &Path) -> Option<Box<dyn Vcs>> {
    GitRepo::discover(root).map(|repo| Box::new(repo) as Box<dyn Vcs>)
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

/// Load an entry's whole plaintext into the edit form.
///
/// The one reveal that returns more than a single value; see
/// [`Core::reveal_entry`] for why editing is the request that justifies it.
/// Call it from opening an editor and from nowhere else.
#[tauri::command]
pub fn reveal_entry(name: EntryName, core: State<'_, Core>) -> Result<String> {
    core.reveal_entry(&name)
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

/// Whether the store keeps a git history, so the interface can say what a
/// deletion costs. Reads no entry and decrypts nothing.
#[tauri::command]
pub fn store_has_history(core: State<'_, Core>) -> Result<bool> {
    core.has_history()
}

/// Where the store stands relative to its remote. `null` when it keeps no
/// history. Local only — no network, no decrypt.
#[tauri::command]
pub fn sync_status(core: State<'_, Core>) -> Result<Option<SyncStatus>> {
    core.sync_status()
}

/// Fetch, merge and push. The only command in the app that reaches the network,
/// and the only one that needs the user's `git` (ADR-9).
#[tauri::command]
pub fn sync_store(core: State<'_, Core>) -> Result<SyncOutcome> {
    core.sync()
}

/// The commits that touched an entry, newest first. Decrypts nothing.
#[tauri::command]
pub fn entry_history(name: EntryName, core: State<'_, Core>) -> Result<Vec<Revision>> {
    core.history(&name)
}

/// A past version of an entry, whole. The history counterpart to
/// [`reveal_entry`], and the same deliberate exception — see ADR-10.
#[tauri::command]
pub fn reveal_revision(name: EntryName, revision: String, core: State<'_, Core>) -> Result<String> {
    core.reveal_revision(&name, &revision)
}

/// Copy the password a past version held, without it passing through the
/// webview.
#[tauri::command]
pub fn copy_revision_password(
    name: EntryName,
    revision: String,
    core: State<'_, Core>,
) -> Result<CopyReceipt> {
    core.copy_revision_password(&name, &revision)
}

// The mutation commands are the one direction in which plaintext travels *into*
// the core, and that is not a hole in Invariant 2 — it is where a new secret
// comes from. A password the user just typed exists in the webview because they
// typed it; the invariant constrains what comes back out. Two consequences the
// frontend owns: the form field holding it lives no longer than the form, and
// the `String` serde builds on this side is not zeroized before it is dropped
// (the same residual as ADR-4a F-4). Everything after [`body`] is a `Secret`.

/// Wrap an inbound entry body, which is where core custody begins.
fn body(text: String) -> Secret {
    Secret::new(text.into_bytes())
}

/// Create an entry. Fails rather than overwriting an existing one.
#[tauri::command]
pub fn insert_entry(
    name: EntryName,
    content: String,
    core: State<'_, Core>,
) -> Result<WriteReceipt> {
    core.insert(&name, &body(content))
}

/// Replace an existing entry's contents.
#[tauri::command]
pub fn edit_entry(name: EntryName, content: String, core: State<'_, Core>) -> Result<WriteReceipt> {
    core.edit(&name, &body(content))
}

/// Create an entry with a generated password, and put that password on the
/// clipboard without ever sending it to the webview.
#[tauri::command]
pub fn generate_entry(
    name: EntryName,
    recipe: generate::Recipe,
    content: Option<String>,
    core: State<'_, Core>,
) -> Result<WriteReceipt> {
    let rest = content.map(body);
    core.generate(&name, recipe, rest.as_ref())
}

/// Delete an entry.
#[tauri::command]
pub fn remove_entry(name: EntryName, core: State<'_, Core>) -> Result<WriteReceipt> {
    core.remove(&name)
}

/// Move an entry, re-encrypting if the destination has different recipients.
#[tauri::command]
pub fn rename_entry(from: EntryName, to: EntryName, core: State<'_, Core>) -> Result<WriteReceipt> {
    core.rename(&from, &to)
}

/// Copy an entry, re-encrypting if the destination has different recipients.
#[tauri::command]
pub fn copy_entry(from: EntryName, to: EntryName, core: State<'_, Core>) -> Result<WriteReceipt> {
    core.copy_entry(&from, &to)
}

/// The generation defaults, so the dialog opens on what `pass` would do.
/// Which keys can open a folder's entries. Decrypts nothing.
#[tauri::command]
pub fn folder_keys(folder: Option<EntryName>, core: State<'_, Core>) -> Result<FolderKeys> {
    core.folder_keys(folder.as_ref())
}

/// What changing a folder's keys would cost, before it is changed. Decrypts
/// nothing — see [`Core::plan_recipients`].
#[tauri::command]
pub fn plan_recipients(
    folder: Option<EntryName>,
    ids: Vec<String>,
    core: State<'_, Core>,
) -> Result<RecipientPlan> {
    core.plan_recipients(folder.as_ref(), &ids)
}

/// Change a folder's keys, re-encrypting the entries they govern (Invariant 8).
#[tauri::command]
pub fn set_recipients(
    folder: Option<EntryName>,
    ids: Vec<String>,
    core: State<'_, Core>,
) -> Result<WriteReceipt> {
    core.set_recipients(folder.as_ref(), &ids)
}

/// What onboarding found on this machine (ADR-7). Decrypts nothing.
#[tauri::command]
pub fn setup_status(core: State<'_, Core>) -> Result<SetupStatus> {
    core.setup_status()
}

/// Make a new key pair. The passphrase prompt is the agent's, never ours.
#[tauri::command]
pub fn create_key(name: String, email: String, core: State<'_, Core>) -> Result<KeyInfo> {
    core.create_key(&name, &email)
}

/// Create the store directory and its `.gpg-id`, optionally under git.
#[tauri::command]
pub fn init_store(
    ids: Vec<String>,
    versioned: bool,
    core: State<'_, Core>,
) -> Result<WriteReceipt> {
    core.init_store(&ids, versioned)
}

#[tauri::command]
pub fn generate_defaults(core: State<'_, Core>) -> generate::Recipe {
    core.generate_defaults()
}

/// Every setting, with what decided it. Carries no store content.
#[tauri::command]
pub fn get_settings(core: State<'_, Core>) -> Effective {
    core.settings()
}

/// Replace the configured settings.
///
/// Takes the whole set rather than one field, so what the webview sends is
/// exactly what the file ends up holding and a value it omits is one the user
/// cleared. Returns the settings as they now stand — which is not necessarily
/// what was sent, since an environment variable still outranks them (ADR-11).
#[tauri::command]
pub fn set_settings(settings: Settings, core: State<'_, Core>) -> Result<Effective> {
    core.set_settings(settings)
}

#[cfg(test)]
// Test code handles fixtures, never real secrets: the plaintexts below are
// literals, not decrypted content.
#[allow(clippy::unwrap_used)]
mod tests {
    use std::collections::{BTreeMap, BTreeSet};
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

        fn entries(&self) -> Result<Vec<EntryName>> {
            Ok(self.names())
        }

        fn secret_path(&self, name: &EntryName) -> Result<PathBuf> {
            if self.names().contains(name) {
                Ok(name.to_secret_path(&self.root))
            } else {
                Err(Error::EntryNotFound { name: name.clone() })
            }
        }

        /// Every entry is governed by the root `.gpg-id`, except one directory
        /// that has its own — so a test can drive both sides of the "does this
        /// move cross a recipient boundary" question.
        fn recipients(&self, name: &EntryName) -> Result<Recipients> {
            let dir = if name.as_str().starts_with(WALLED) {
                self.root.join(WALLED)
            } else {
                self.root.clone()
            };
            Ok(Recipients {
                ids: vec![fake_recipient(name.as_str()).to_owned()],
                source: dir.join(crate::store::gpg_id::GPG_ID_FILE),
            })
        }

        fn contains(&self, name: &EntryName) -> bool {
            self.names().contains(name)
        }

        fn remove(&self, name: &EntryName) -> Result<()> {
            let path = self.secret_path(name)?;
            lock(&self.gpg.plaintexts).remove(&path);
            lock(&self.gpg.encrypted).remove(&path);
            Ok(())
        }

        fn rename_file(&self, from: &EntryName, to: &EntryName) -> Result<()> {
            self.copy_file(from, to)?;
            self.remove(from)
        }

        fn copy_file(&self, from: &EntryName, to: &EntryName) -> Result<()> {
            let source = self.secret_path(from)?;
            if self.contains(to) {
                return Err(Error::EntryExists { name: to.clone() });
            }
            let mut table = lock(&self.gpg.plaintexts);
            let Some(text) = table.get(&source).cloned() else {
                return Err(Error::EntryNotFound { name: from.clone() });
            };
            let target = to.to_secret_path(&self.root);
            table.insert(target.clone(), text);
            // The ciphertext moves as-is, so who it is encrypted to moves with
            // it — this path is only taken when both ends share a `.gpg-id`.
            let keys = lock(&self.gpg.encrypted).get(&source).cloned();
            if let Some(keys) = keys {
                lock(&self.gpg.encrypted).insert(target, keys);
            }
            Ok(())
        }
    }

    /// The id [`FakeStore`] reports for every entry, so a test can tell what a
    /// write was encrypted to apart from what it contained.
    const RECIPIENT: &str = "fake-key";

    /// A directory with its own `.gpg-id`, and the id it names.
    const WALLED: &str = "Work/";
    const WALLED_RECIPIENT: &str = "work-key";

    /// The recipient id governing `name` in the fake store.
    ///
    /// Shared by [`FakeStore::recipients`] and [`FakeGpg::with`] so the store's
    /// idea of who should be able to read an entry and the backend's idea of who
    /// can cannot drift apart except when a test makes them.
    fn fake_recipient(name: &str) -> &'static str {
        if name.starts_with(WALLED) {
            WALLED_RECIPIENT
        } else {
            RECIPIENT
        }
    }

    /// The key a recipient id resolves to in the fake.
    ///
    /// Deliberately a *different string* from the id itself, as it is in
    /// reality — a `.gpg-id` names a user id or a fingerprint, a ciphertext
    /// names an encryption subkey. Keeping them distinct here is what stops a
    /// test from passing because the two happened to be equal.
    fn fake_key(id: &str) -> String {
        format!("key-of-{id}")
    }

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
        /// The keys each path is encrypted to, which is what a recipient change
        /// reads to decide whether an entry needs rewriting at all.
        encrypted: Arc<Mutex<BTreeMap<PathBuf, KeyIds>>>,
        /// Ids this backend refuses to resolve, so a test can drive the refusal
        /// path without needing a keyring that lacks a key.
        unresolvable: Arc<Mutex<BTreeSet<String>>>,
        /// Ids this machine holds no secret key for, so a test can drive the
        /// lockout warning without deleting a key from a keyring.
        foreign: Arc<Mutex<BTreeSet<String>>>,
        /// Ids this machine holds a *secret* key for, which is what onboarding
        /// offers before it offers to make one. Empty by default: a machine
        /// that has never used GnuPG is the state Phase 7 is about.
        on_keyring: Arc<Mutex<BTreeSet<String>>>,
        /// User ids `generate_key` was asked for, so a test can tell a key that
        /// was made from one that was already there.
        generated: Arc<Mutex<Vec<String>>>,
    }

    /// One encryption: where it went, and to whom.
    type Write = (PathBuf, Vec<String>);

    impl FakeGpg {
        fn with(entries: &[(&str, &str)], root: &Path) -> Self {
            let plaintexts: BTreeMap<_, _> = entries
                .iter()
                .map(|(name, text)| (name_of(name).to_secret_path(root), (*text).to_owned()))
                .collect();
            // Seeded entries start encrypted to exactly what governs them, which
            // is the ordinary state of a store nobody has changed the keys of.
            let encrypted = entries
                .iter()
                .map(|(name, _)| {
                    (
                        name_of(name).to_secret_path(root),
                        std::iter::once(fake_key(fake_recipient(name))).collect(),
                    )
                })
                .collect();
            Self {
                plaintexts: Arc::new(Mutex::new(plaintexts)),
                written_to: Arc::new(Mutex::new(Vec::new())),
                encrypted: Arc::new(Mutex::new(encrypted)),
                unresolvable: Arc::new(Mutex::new(BTreeSet::new())),
                foreign: Arc::new(Mutex::new(BTreeSet::new())),
                on_keyring: Arc::new(Mutex::new(BTreeSet::new())),
                generated: Arc::new(Mutex::new(Vec::new())),
            }
        }

        /// Paths currently holding ciphertext, as [`FakeStore`] sees them.
        fn paths(&self) -> Vec<PathBuf> {
            lock(&self.plaintexts).keys().cloned().collect()
        }
    }

    impl Gpg for FakeGpg {
        /// The identity, which is the honest fake: this backend's "ciphertext"
        /// is the plaintext, so a blob handed straight to it comes back as
        /// itself. That is what lets the history tests drive a real decrypt
        /// path without a key.
        fn decrypt(&self, ciphertext: &[u8]) -> Result<Secret> {
            Ok(Secret::from_slice(ciphertext))
        }

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
            lock(&self.encrypted).insert(
                path.to_path_buf(),
                recipients.ids.iter().map(|id| fake_key(id)).collect(),
            );
            Ok(())
        }

        fn describe_key(&self, id: &str) -> Result<KeyInfo> {
            if lock(&self.unresolvable).contains(id) {
                return Err(Error::UnknownKey { id: id.to_owned() });
            }
            Ok(KeyInfo {
                id: id.to_owned(),
                label: Some(format!("Fake {id}")),
                fingerprint: None,
                // Every key is one the fake user can decrypt with unless a test
                // says otherwise, which is the ordinary state of a store.
                usable_here: !lock(&self.foreign).contains(id),
                keys: std::iter::once(fake_key(id)).collect(),
            })
        }

        fn encrypted_to(&self, path: &Path) -> Result<KeyIds> {
            lock(&self.encrypted)
                .get(path)
                .cloned()
                .ok_or_else(|| Error::UnreadableCiphertext {
                    path: path.to_path_buf(),
                })
        }

        /// Whatever a test put on the fake keyring — empty by default, which is
        /// the machine onboarding exists for.
        fn usable_keys(&self) -> Result<Vec<KeyInfo>> {
            lock(&self.on_keyring)
                .iter()
                .map(|id| self.describe_key(id))
                .collect()
        }

        /// Records the request and puts the key on the fake keyring. No
        /// passphrase is involved here for the same reason none is involved in
        /// the real one: the agent owns it, and this fake has no agent.
        fn generate_key(&self, name: &str, email: &str) -> Result<KeyInfo> {
            let id = format!("{name} <{email}>");
            lock(&self.generated).push(id.clone());
            lock(&self.on_keyring).insert(id.clone());
            self.describe_key(&id)
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

    /// One recorded commit: the message, and the paths it was asked to stage.
    type Recorded = (String, Vec<PathBuf>);

    /// A history that records what it was asked to commit rather than writing
    /// one, so a test can read the message and the paths without a repository.
    #[derive(Clone, Default)]
    struct FakeVcs {
        commits: Arc<Mutex<Vec<Recorded>>>,
        /// When set, every commit fails with it — the store *is* versioned but
        /// git will not take the change.
        refuses: Option<&'static str>,
        /// Past versions: `(entry, revision id, the body that version held)`.
        ///
        /// The body is stored as-is because [`FakeGpg::decrypt`] is the
        /// identity — so what `blob_at` hands back is what a reveal should
        /// produce, which is the property these tests are checking.
        past: Arc<Mutex<Vec<(String, String, String)>>>,
        /// What `status` and `sync` report. Neither has anything to derive an
        /// answer from without a repository, so a test states it.
        status: Option<SyncStatus>,
        outcome: Option<SyncOutcome>,
    }

    impl FakeVcs {
        /// Record that `entry` held `body` at `revision`.
        fn with_past(self, entry: &str, revision: &str, body: &str) -> Self {
            lock(&self.past).push((entry.to_owned(), revision.to_owned(), body.to_owned()));
            self
        }
    }

    impl Vcs for FakeVcs {
        fn commit(&self, message: &str, paths: &[PathBuf]) -> Result<()> {
            if let Some(reason) = self.refuses {
                return Err(Error::Git {
                    reason: reason.to_owned(),
                });
            }
            lock(&self.commits).push((message.to_owned(), paths.to_vec()));
            Ok(())
        }

        fn status(&self) -> Result<SyncStatus> {
            Ok(self.status.clone().unwrap_or(SyncStatus {
                branch: Some("main".to_owned()),
                tracking: None,
                uncommitted: 0,
            }))
        }

        fn history(&self, name: &EntryName) -> Result<Vec<Revision>> {
            Ok(lock(&self.past)
                .iter()
                .filter(|(entry, ..)| entry == name.as_str())
                .map(|(_, id, _)| Revision {
                    id: id.clone(),
                    summary: format!("Edit password for {name} using Password Store."),
                    author: "Test".to_owned(),
                    committed_at: 0,
                    change: crate::git::RevisionKind::Modified,
                })
                .collect())
        }

        fn blob_at(&self, name: &EntryName, revision: &str) -> Result<Vec<u8>> {
            lock(&self.past)
                .iter()
                .find(|(entry, id, _)| entry == name.as_str() && id == revision)
                .map(|(.., body)| body.as_bytes().to_vec())
                .ok_or(Error::NoSuchRevision)
        }

        fn sync(&self) -> Result<SyncOutcome> {
            Ok(self.outcome.clone().unwrap_or(SyncOutcome::NoRemote))
        }
    }

    /// A core over in-memory fakes, with the handles a test needs to see what
    /// reached the clipboard, what was encrypted, and what was committed.
    struct Parts {
        core: Core,
        clipboard: StubBackend,
        scheduler: StubScheduler,
        gpg: FakeGpg,
        git: FakeVcs,
    }

    /// A core over the given `name -> plaintext` pairs, plus the handles a test
    /// needs to see what reached the clipboard and to fire its timer.
    fn core_with_clipboard(
        entries: &[(&'static str, &'static str)],
    ) -> (Core, StubBackend, StubScheduler) {
        let parts = core_with_parts(entries);
        (parts.core, parts.clipboard, parts.scheduler)
    }

    /// As [`core_with_clipboard`], with every fake exposed.
    fn core_with_parts(entries: &[(&'static str, &'static str)]) -> Parts {
        core_with_git(entries, FakeVcs::default())
    }

    /// A core whose store is versioned by `git`.
    fn core_with_git(entries: &[(&'static str, &'static str)], git: FakeVcs) -> Parts {
        core_from(entries, {
            let git = git.clone();
            Box::new(move |_| Some(Box::new(git.clone())))
        })
        .with_git(git)
    }

    /// A core whose store is not a git repository at all — the ordinary case.
    fn core_without_git(entries: &[(&'static str, &'static str)]) -> Parts {
        core_from(entries, Box::new(|_| None))
    }

    fn core_from(entries: &[(&'static str, &'static str)], git: VcsFactory) -> Parts {
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
            // The same root the fake store reports, so the setup commands and
            // the store cannot disagree about which directory is the store.
            Box::new(|| Ok(PathBuf::from(ROOT))),
            Box::new(move || Ok(Box::new(command_gpg.clone()))),
            git,
            Clipboard::new(Box::new(backend.clone()), Box::new(scheduler.clone())),
            Arc::new(settings_with_clip_time(CLIP_TIME)),
        );
        Parts {
            core,
            clipboard: backend,
            scheduler,
            gpg,
            git: FakeVcs::default(),
        }
    }

    impl Parts {
        fn with_git(mut self, git: FakeVcs) -> Self {
            self.git = git;
            self
        }
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
        )
    }

    /// In-memory settings with a clip window a test can assert on.
    ///
    /// Deliberately *configured* rather than left at the default: it is what
    /// makes `clears_in_secs` a check that the setting reaches the clipboard
    /// (ADR-11) rather than a check that two constants are still equal.
    fn settings_with_clip_time(clip_time: Duration) -> SettingsFile {
        let settings = SettingsFile::ephemeral();
        settings
            .set(Settings {
                clip_time_secs: Some(clip_time.as_secs()),
                ..Settings::default()
            })
            .unwrap();
        settings
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
            Box::new(|| Ok(PathBuf::from(ROOT))),
            Box::new(|| {
                Err(Error::GpgUnavailable {
                    reason: "listing must not decrypt".into(),
                })
            }),
            Box::new(|_| None),
            unused_clipboard(),
            Arc::new(SettingsFile::ephemeral()),
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

    /// The edit form's load: everything, verbatim, including the `otpauth://`
    /// line no other command will hand over. Editing is the request that earns
    /// it — the body cannot be rewritten without having been read.
    #[test]
    fn reveal_entry_returns_the_whole_plaintext_unparsed() {
        assert_eq!(
            store().reveal_entry(&name_of("Email/gmail.com")).unwrap(),
            GMAIL
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

    // --- mutations -------------------------------------------------------

    /// What an entry now holds, for readable assertions.
    fn stored(gpg: &FakeGpg, name: &str) -> Option<String> {
        lock(&gpg.plaintexts)
            .get(&name_of(name).to_secret_path(Path::new(ROOT)))
            .cloned()
    }

    /// Who each write went to, in order.
    fn writes(gpg: &FakeGpg) -> Vec<(String, Vec<String>)> {
        lock(&gpg.written_to)
            .iter()
            .map(|(path, ids)| {
                let name = EntryName::from_secret_path(Path::new(ROOT), path)
                    .map(|n| n.as_str().to_owned())
                    .unwrap_or_default();
                (name, ids.clone())
            })
            .collect()
    }

    #[test]
    fn insert_creates_an_entry_and_the_tree_shows_it() {
        let Parts { core, gpg, .. } = core_with_parts(&[("wifi", "correct horse")]);
        let name = name_of("Email/gmail.com");

        core.insert(&name, &Secret::from_slice(b"hunter2\nuser: alice"))
            .unwrap();

        assert_eq!(
            stored(&gpg, "Email/gmail.com").as_deref(),
            Some("hunter2\nuser: alice")
        );
        assert_eq!(
            core.metadata(&name).unwrap().fields,
            vec!["user".to_owned()]
        );
    }

    /// A mistyped name must not silently destroy the password already there.
    #[test]
    fn insert_refuses_to_overwrite() {
        let Parts { core, gpg, .. } = core_with_parts(&[("wifi", "correct horse")]);

        match core.insert(&name_of("wifi"), &Secret::from_slice(b"clobbered")) {
            Err(Error::EntryExists { name }) => assert_eq!(name.as_str(), "wifi"),
            Err(other) => panic!("expected EntryExists, got {other:?}"),
            Ok(_) => panic!("insert must not overwrite an existing entry"),
        }
        assert_eq!(stored(&gpg, "wifi").as_deref(), Some("correct horse"));
    }

    #[test]
    fn edit_replaces_the_whole_body_and_requires_the_entry_to_exist() {
        let Parts { core, gpg, .. } = core_with_parts(&[("wifi", "correct horse\nuser: alice")]);

        core.edit(&name_of("wifi"), &Secret::from_slice(b"new-password"))
            .unwrap();
        assert_eq!(stored(&gpg, "wifi").as_deref(), Some("new-password"));

        match core.edit(&name_of("absent"), &Secret::from_slice(b"x")) {
            Err(Error::EntryNotFound { name }) => assert_eq!(name.as_str(), "absent"),
            Err(other) => panic!("expected EntryNotFound, got {other:?}"),
            Ok(_) => panic!("edit must not create an entry"),
        }
    }

    /// The staleness test a recipient change skips entries on, in both of the
    /// directions Invariant 8 has. Driving it directly rather than through
    /// `plan_recipients` is deliberate: this is the rule that decides whether an
    /// entry is decrypted at all, and a test of it should not be able to pass
    /// because the plan around it filtered the entry out for another reason.
    #[test]
    fn an_entry_is_current_only_when_exactly_the_listed_keys_can_read_it() {
        let gpg = FakeGpg::default();
        let path = PathBuf::from("/store/wifi.gpg");

        let ada = keys(&["ADA1"]);
        let bob = keys(&["BOB1"]);
        let wanted = vec![&ada, &bob];
        let permitted = keys(&["ADA1", "BOB1"]);

        let encrypted_to = |ids: &[&str]| {
            lock(&gpg.encrypted).insert(path.clone(), keys(ids));
            is_current(&gpg, &path, &wanted, &permitted).unwrap()
        };

        assert!(encrypted_to(&["ADA1", "BOB1"]), "exactly the listed keys");

        assert!(
            !encrypted_to(&["ADA1"]),
            "F-8: Bob is listed in the .gpg-id but cannot read the entry"
        );
        assert!(
            !encrypted_to(&["ADA1", "BOB1", "EVE1"]),
            "F-9: Eve can read the entry and is listed nowhere"
        );
    }

    /// `gpg` encrypts to a key's newest usable encryption subkey rather than to
    /// all of them. Requiring the whole set — which is what comparing sorted
    /// lists amounts to, and what `pass` does — would report a key with two
    /// encryption subkeys as permanently out of date and re-encrypt every entry
    /// under it on every change, each one a decrypt the user did not ask for.
    #[test]
    fn one_of_a_keys_encryption_subkeys_is_enough() {
        let gpg = FakeGpg::default();
        let path = PathBuf::from("/store/wifi.gpg");
        let ada = keys(&["ADA_RETIRED", "ADA_CURRENT"]);

        lock(&gpg.encrypted).insert(path.clone(), keys(&["ADA_CURRENT"]));

        assert!(is_current(&gpg, &path, &[&ada], &ada).unwrap());
    }

    fn keys(ids: &[&str]) -> KeyIds {
        ids.iter().map(|id| (*id).to_owned()).collect()
    }

    /// Invariant 8: a write is encrypted to the recipients of the name being
    /// written, resolved by the store's own walk-up.
    #[test]
    fn a_write_uses_the_recipients_of_its_own_directory() {
        let Parts { core, gpg, .. } = core_with_parts(&[]);

        core.insert(&name_of("loose"), &Secret::from_slice(b"a"))
            .unwrap();
        core.insert(&name_of("Work/intranet"), &Secret::from_slice(b"b"))
            .unwrap();

        assert_eq!(
            writes(&gpg),
            vec![
                ("loose".to_owned(), vec![RECIPIENT.to_owned()]),
                (
                    "Work/intranet".to_owned(),
                    vec![WALLED_RECIPIENT.to_owned()]
                ),
            ]
        );
    }

    #[test]
    fn remove_deletes_the_entry() {
        let Parts { core, gpg, .. } = core_with_parts(&[("wifi", "correct horse"), ("keep", "x")]);

        core.remove(&name_of("wifi")).unwrap();

        assert_eq!(stored(&gpg, "wifi"), None);
        assert_eq!(stored(&gpg, "keep").as_deref(), Some("x"));
        assert!(matches!(
            core.remove(&name_of("wifi")),
            Err(Error::EntryNotFound { .. })
        ));
    }

    /// Within one `.gpg-id` the ciphertext moves as it is: no decrypt, so no
    /// pinentry for what the user experiences as a rename.
    #[test]
    fn rename_within_a_recipient_boundary_does_not_re_encrypt() {
        let Parts { core, gpg, .. } = core_with_parts(&[("wifi", "correct horse")]);

        core.rename(&name_of("wifi"), &name_of("Home/wifi"))
            .unwrap();

        assert_eq!(stored(&gpg, "wifi"), None);
        assert_eq!(stored(&gpg, "Home/wifi").as_deref(), Some("correct horse"));
        assert!(
            writes(&gpg).is_empty(),
            "a move within one .gpg-id must not re-encrypt"
        );
    }

    /// Across one it cannot: the destination names a different audience, so the
    /// entry is decrypted and encrypted again for it (Invariant 8).
    #[test]
    fn rename_across_a_recipient_boundary_re_encrypts_to_the_destination() {
        let Parts { core, gpg, .. } = core_with_parts(&[("wifi", "correct horse")]);

        core.rename(&name_of("wifi"), &name_of("Work/wifi"))
            .unwrap();

        assert_eq!(stored(&gpg, "wifi"), None);
        assert_eq!(stored(&gpg, "Work/wifi").as_deref(), Some("correct horse"));
        assert_eq!(
            writes(&gpg),
            vec![("Work/wifi".to_owned(), vec![WALLED_RECIPIENT.to_owned()])]
        );
    }

    #[test]
    fn copy_leaves_the_original_and_re_encrypts_across_a_boundary() {
        let Parts { core, gpg, .. } = core_with_parts(&[("wifi", "correct horse")]);

        core.copy_entry(&name_of("wifi"), &name_of("Work/wifi"))
            .unwrap();

        assert_eq!(stored(&gpg, "wifi").as_deref(), Some("correct horse"));
        assert_eq!(stored(&gpg, "Work/wifi").as_deref(), Some("correct horse"));
        assert_eq!(
            writes(&gpg),
            vec![("Work/wifi".to_owned(), vec![WALLED_RECIPIENT.to_owned()])]
        );
    }

    /// Both directions of a move must refuse an occupied name, whether or not
    /// they take the re-encrypting path.
    #[test]
    fn a_move_onto_an_existing_entry_is_refused() {
        let Parts { core, gpg, .. } =
            core_with_parts(&[("wifi", "keep me"), ("other", "b"), ("Work/taken", "c")]);

        for (from, to) in [("wifi", "other"), ("wifi", "Work/taken")] {
            match core.rename(&name_of(from), &name_of(to)) {
                Err(Error::EntryExists { name }) => assert_eq!(name.as_str(), to),
                Err(other) => panic!("expected EntryExists, got {other:?}"),
                Ok(_) => panic!("moving onto {to} must be refused"),
            }
        }
        assert_eq!(stored(&gpg, "wifi").as_deref(), Some("keep me"));
        assert_eq!(stored(&gpg, "other").as_deref(), Some("b"));
        assert_eq!(stored(&gpg, "Work/taken").as_deref(), Some("c"));
    }

    /// The generate path's whole point: the password is stored and copied
    /// without ever being returned.
    #[test]
    fn generate_stores_a_password_and_copies_it_without_returning_it() {
        let Parts {
            core,
            clipboard,
            gpg,
            ..
        } = core_with_parts(&[]);
        let name = name_of("Email/new");

        let receipt = core
            .generate(
                &name,
                generate::Recipe {
                    length: 20,
                    symbols: false,
                },
                Some(&Secret::from_slice(b"user: alice")),
            )
            .unwrap();

        // `Some` because the stub clipboard always opens; the `None` arm is the
        // no-display-server case, where the entry is still created.
        let clip = receipt.clipboard.unwrap();
        assert_eq!(clip.clears_in_secs, CLIP_TIME.as_secs());

        let body = stored(&gpg, "Email/new").unwrap();
        let (password, rest) = body.split_once('\n').unwrap();
        assert_eq!(password.len(), 20);
        assert!(password.chars().all(|c| c.is_ascii_alphanumeric()));
        assert_eq!(rest, "user: alice");

        // What reached the clipboard is the password, and the receipt said
        // nothing about it.
        assert_eq!(clipboard.contents().as_deref(), Some(password));
        assert!(!serde_json::to_string(&receipt).unwrap().contains(password));
    }

    #[test]
    fn generate_refuses_to_overwrite_and_writes_nothing_when_it_does() {
        let Parts {
            core,
            clipboard,
            gpg,
            ..
        } = core_with_parts(&[("wifi", "correct horse")]);

        match core.generate(&name_of("wifi"), generate::Recipe::default(), None) {
            Err(Error::EntryExists { name }) => assert_eq!(name.as_str(), "wifi"),
            Err(other) => panic!("expected EntryExists, got {other:?}"),
            Ok(_) => panic!("generate must not overwrite an existing entry"),
        }
        assert_eq!(stored(&gpg, "wifi").as_deref(), Some("correct horse"));
        assert_eq!(
            clipboard.contents(),
            None,
            "a refused generate copies nothing"
        );
    }

    // --- history ---------------------------------------------------------

    /// Every commit the fake history recorded: message, then the paths it was
    /// asked to stage, with separators normalised so the assertions read the
    /// same on every platform.
    fn commits(git: &FakeVcs) -> Vec<(String, Vec<String>)> {
        lock(&git.commits)
            .iter()
            .map(|(message, paths)| {
                let paths = paths
                    .iter()
                    .map(|path| path.to_string_lossy().replace('\\', "/"))
                    .collect();
                (message.clone(), paths)
            })
            .collect()
    }

    #[test]
    fn has_history_answers_for_both_kinds_of_store() {
        assert!(!core_without_git(&[]).core.has_history().unwrap());
        assert!(core_with_git(&[], FakeVcs::default())
            .core
            .has_history()
            .unwrap());
    }

    /// A store that was never `pass git init`ed has no history to fail at, and
    /// the receipt says so rather than implying something went wrong.
    #[test]
    fn a_store_without_git_records_nothing_and_reports_nothing() {
        let Parts { core, .. } = core_without_git(&[]);

        let receipt = core
            .insert(&name_of("wifi"), &Secret::from_slice(b"correct horse"))
            .unwrap();

        assert_eq!(receipt.commit, None);
        assert_eq!(
            serde_json::to_string(&receipt).unwrap(),
            r#"{"commit":null,"clipboard":null}"#
        );
    }

    /// The messages are a compatibility surface: a store's history is shared
    /// with the CLI, so `git log` must not betray which client wrote what.
    #[test]
    fn every_mutation_is_recorded_in_the_words_pass_uses() {
        let git = FakeVcs::default();
        let Parts { core, .. } = core_with_git(&[], git.clone());

        core.insert(&name_of("wifi"), &Secret::from_slice(b"correct horse"))
            .unwrap();
        core.edit(&name_of("wifi"), &Secret::from_slice(b"new horse"))
            .unwrap();
        core.copy_entry(&name_of("wifi"), &name_of("spare"))
            .unwrap();
        core.rename(&name_of("spare"), &name_of("Home/spare"))
            .unwrap();
        core.remove(&name_of("Home/spare")).unwrap();

        assert_eq!(
            commits(&git),
            vec![
                (
                    "Add given password for wifi to store.".to_owned(),
                    vec!["wifi.gpg".to_owned()]
                ),
                (
                    "Edit password for wifi using Password Store.".to_owned(),
                    vec!["wifi.gpg".to_owned()]
                ),
                (
                    "Copy wifi to spare.".to_owned(),
                    vec!["spare.gpg".to_owned()]
                ),
                (
                    "Rename spare to Home/spare.".to_owned(),
                    vec!["spare.gpg".to_owned(), "Home/spare.gpg".to_owned()]
                ),
                (
                    "Remove Home/spare from store.".to_owned(),
                    vec!["Home/spare.gpg".to_owned()]
                ),
            ]
        );
    }

    #[test]
    fn a_generated_entry_is_recorded_as_generated() {
        let git = FakeVcs::default();
        let Parts { core, .. } = core_with_git(&[], git.clone());

        let receipt = core
            .generate(&name_of("Email/new"), generate::Recipe::default(), None)
            .unwrap();

        assert_eq!(receipt.commit, Some(Commit::Committed));
        assert_eq!(
            commits(&git),
            vec![(
                "Add generated password for Email/new.".to_owned(),
                vec!["Email/new.gpg".to_owned()]
            )]
        );
    }

    /// The whole reason the outcome rides in a receipt instead of an `Err`: the
    /// entry *was* written. Failing the command would tell the user their
    /// password was not saved and send them back to retry into an
    /// `EntryExists`.
    #[test]
    fn a_refused_commit_does_not_fail_the_write() {
        let git = FakeVcs {
            refuses: Some("no signature"),
            ..FakeVcs::default()
        };
        let Parts { core, gpg, .. } = core_with_git(&[], git);

        let receipt = core
            .insert(&name_of("wifi"), &Secret::from_slice(b"correct horse"))
            .unwrap();

        assert_eq!(stored(&gpg, "wifi").as_deref(), Some("correct horse"));
        match receipt.commit {
            Some(Commit::Failed(reason)) => assert!(reason.contains("no signature"), "{reason}"),
            other => panic!("expected a failed commit, got {other:?}"),
        }
    }

    /// A receipt describes what happened around the write, never what was
    /// written — the same rule [`CopyReceipt`] follows.
    #[test]
    fn the_serialized_write_receipt_carries_no_value() {
        let Parts { core, .. } = core_with_git(&[], FakeVcs::default());

        let receipt = core
            .insert(&name_of("wifi"), &Secret::from_slice(b"correct horse"))
            .unwrap();

        let json = serde_json::to_string(&receipt).unwrap();
        assert_eq!(
            json,
            r#"{"commit":{"status":"committed"},"clipboard":null}"#
        );
        assert!(!json.contains("correct horse"));
    }

    // --- sync and per-entry history --------------------------------------

    /// A store with no repository has nothing to say about a remote, and the
    /// interface needs to be able to tell that apart from "in step".
    #[test]
    fn sync_status_is_absent_for_a_store_with_no_history() {
        assert_eq!(core_without_git(&[]).core.sync_status().unwrap(), None);
    }

    #[test]
    fn sync_status_reports_the_distance_to_the_remote() {
        let git = FakeVcs {
            status: Some(SyncStatus {
                branch: Some("main".to_owned()),
                tracking: Some(crate::git::Tracking {
                    upstream: "origin/main".to_owned(),
                    ahead: 2,
                    behind: 1,
                }),
                uncommitted: 0,
            }),
            ..FakeVcs::default()
        };
        let Parts { core, .. } = core_with_git(&[], git);

        let status = core.sync_status().unwrap().unwrap();
        let tracking = status.tracking.unwrap();

        assert_eq!(tracking.upstream, "origin/main");
        assert_eq!((tracking.ahead, tracking.behind), (2, 1));
    }

    /// A store that is not shared, and a store that is not versioned at all,
    /// are the same answer: there is nothing to sync with, and neither is a
    /// failure the user has to do something about.
    #[test]
    fn syncing_a_store_with_nothing_to_sync_with_is_not_a_failure() {
        assert_eq!(
            core_without_git(&[]).core.sync().unwrap(),
            SyncOutcome::NoRemote
        );
        assert_eq!(
            core_with_git(&[], FakeVcs::default()).core.sync().unwrap(),
            SyncOutcome::NoRemote
        );
    }

    /// The frontend's `SyncOutcome` type mirrors this shape by hand, so the
    /// wire form is pinned rather than left to drift.
    #[test]
    fn the_serialized_sync_outcome_names_its_case() {
        let synced = SyncOutcome::Synced {
            pulled: 2,
            pushed: 1,
        };
        assert_eq!(
            serde_json::to_string(&synced).unwrap(),
            r#"{"status":"synced","pulled":2,"pushed":1}"#
        );
        assert_eq!(
            serde_json::to_string(&SyncOutcome::NoRemote).unwrap(),
            r#"{"status":"noRemote"}"#
        );
        assert_eq!(
            serde_json::to_string(&SyncOutcome::Conflicted {
                entries: vec!["Email/gmail.com".to_owned()],
            })
            .unwrap(),
            r#"{"status":"conflicted","entries":["Email/gmail.com"]}"#
        );
    }

    #[test]
    fn an_unversioned_store_has_an_empty_history_rather_than_an_error() {
        let Parts { core, .. } = core_without_git(&[("wifi", "correct horse")]);

        assert!(core.history(&name_of("wifi")).unwrap().is_empty());
    }

    /// Listing a history decrypts nothing, which is what makes opening one free
    /// of a pinentry the user did not ask for (§4.1 principle 1).
    #[test]
    fn listing_a_history_never_decrypts() {
        let git = FakeVcs::default().with_past("wifi", "abc123", "old horse");
        // A backend that fails if it is used at all, so a decrypt on this path
        // would fail the test rather than pass unnoticed.
        let core = Core::from_parts(
            Box::new(|| {
                Ok(Box::new(FakeStore {
                    root: PathBuf::from(ROOT),
                    gpg: FakeGpg::default(),
                }))
            }),
            Box::new(|| Ok(PathBuf::from(ROOT))),
            Box::new(|| {
                Err(Error::GpgUnavailable {
                    reason: "listing a history must not decrypt".into(),
                })
            }),
            Box::new(move |_| Some(Box::new(git.clone()))),
            unused_clipboard(),
            Arc::new(SettingsFile::ephemeral()),
        );

        let history = core.history(&name_of("wifi")).unwrap();

        assert_eq!(history.len(), 1);
        assert_eq!(history[0].id, "abc123");
    }

    /// ADR-10: choosing a specific commit is the request that earns a whole
    /// body, the same way choosing Edit is in ADR-8.
    #[test]
    fn reveal_revision_returns_the_body_that_version_held() {
        let git = FakeVcs::default().with_past("wifi", "abc123", "old horse\nuser: alice");
        let Parts { core, .. } = core_with_git(&[("wifi", "correct horse")], git);

        assert_eq!(
            core.reveal_revision(&name_of("wifi"), "abc123").unwrap(),
            "old horse\nuser: alice"
        );
        // The current entry is untouched by having looked at an old one.
        assert_eq!(
            core.reveal_password(&name_of("wifi")).unwrap(),
            "correct horse"
        );
    }

    /// The recovery path in its usual shape, served like every other copy: the
    /// old password reaches the clipboard without reaching the caller.
    #[test]
    fn copy_revision_password_copies_the_old_first_line_and_not_the_rest() {
        let git = FakeVcs::default().with_past("wifi", "abc123", "old horse\nuser: alice");
        let Parts {
            core, clipboard, ..
        } = core_with_git(&[("wifi", "correct horse")], git);

        let receipt = core
            .copy_revision_password(&name_of("wifi"), "abc123")
            .unwrap();

        assert_eq!(receipt.clears_in_secs, CLIP_TIME.as_secs());
        assert_eq!(clipboard.contents().as_deref(), Some("old horse"));
        assert!(!serde_json::to_string(&receipt)
            .unwrap()
            .contains("old horse"));
    }

    /// The id arrives back over IPC, so it is checked rather than trusted —
    /// and an unversioned store has no version to give at all.
    #[test]
    fn a_revision_the_history_does_not_have_is_refused() {
        let git = FakeVcs::default().with_past("wifi", "abc123", "old horse");
        let Parts { core, .. } = core_with_git(&[("wifi", "correct horse")], git);

        assert!(matches!(
            core.reveal_revision(&name_of("wifi"), "nope"),
            Err(Error::NoSuchRevision)
        ));
        assert!(matches!(
            core_without_git(&[("wifi", "correct horse")])
                .core
                .reveal_revision(&name_of("wifi"), "abc123"),
            Err(Error::NoSuchRevision)
        ));
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

    // ---- Onboarding (Phase 7, ADR-7) ------------------------------------
    //
    // These are the only tests here whose root is a real directory, because
    // they are the only commands that *make* one — `store_state` asks the
    // filesystem and `init_store` writes to it. Everything else stays a fake:
    // no `gpg` runs, and the generation path's own safety is pinned in
    // `crypto/gnupg.rs`, where the argument list can be read without a
    // pinentry to answer.

    /// A core rooted at a real path, with a fake backend and history.
    fn core_rooted_at(root: &Path, git: Option<FakeVcs>) -> (Core, FakeGpg) {
        let gpg = FakeGpg::default();
        let command_gpg = gpg.clone();
        let store_gpg = gpg.clone();
        let store_root = root.to_path_buf();
        let root_again = root.to_path_buf();

        let core = Core::from_parts(
            Box::new(move || {
                Ok(Box::new(FakeStore {
                    root: store_root.clone(),
                    gpg: store_gpg.clone(),
                }))
            }),
            Box::new(move || Ok(root_again.clone())),
            Box::new(move || Ok(Box::new(command_gpg.clone()))),
            match git {
                Some(git) => Box::new(move |_| Some(Box::new(git.clone()))),
                // No repository, and none to be made: `GitRepo::init` would
                // reach the real git2, which these tests have no business
                // doing.
                None => Box::new(|_| None),
            },
            unused_clipboard(),
            Arc::new(SettingsFile::ephemeral()),
        );
        (core, gpg)
    }

    /// The root `.gpg-id` of a store at `root`, as written.
    fn gpg_id_of(root: &Path) -> String {
        std::fs::read_to_string(root.join(".gpg-id")).unwrap()
    }

    #[test]
    fn a_path_with_nothing_at_it_is_a_store_to_create() {
        let dir = tempfile::tempdir().unwrap();
        assert_eq!(store_state(&dir.path().join("nope")), StoreState::Missing);
    }

    #[test]
    fn an_empty_directory_is_a_store_to_create() {
        let dir = tempfile::tempdir().unwrap();
        assert_eq!(store_state(dir.path()), StoreState::Empty);
    }

    /// ADR-7's trigger boundary, and the edge that looks like an omission: a
    /// directory holding entries but no `.gpg-id` is **not** offered to
    /// onboarding. It is a store whose keys are unset, which the keys panel
    /// already fixes (ADR-13) — and creating one over it would write a
    /// `.gpg-id` its existing entries are not encrypted to, without the
    /// re-encryption `set_recipients` would have done.
    #[test]
    fn a_directory_holding_entries_is_a_store_to_open_not_one_to_create() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join("wifi.gpg"), b"ciphertext").unwrap();

        assert_eq!(store_state(dir.path()), StoreState::Ready);
    }

    #[test]
    fn a_directory_with_a_gpg_id_is_already_a_store() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join(".gpg-id"), b"key\n").unwrap();

        assert_eq!(store_state(dir.path()), StoreState::Ready);
    }

    /// A file this app cannot name is still somebody's entry (§4.1
    /// principle 3). Reading the directory as empty because of it would offer
    /// to set up a store over a store.
    ///
    /// `$` rather than a control character: both are `Tree::unsupported`, but
    /// only one of them is a file name Windows will let the test create.
    #[test]
    fn a_directory_holding_only_unusable_names_is_not_empty() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join("wi$fi.gpg"), b"ciphertext").unwrap();

        assert_ne!(store_state(dir.path()), StoreState::Empty);
    }

    /// The whole of `pass init` on a machine with no store: the directory and
    /// the `.gpg-id`, byte for byte what `printf '%s\n'` would have written,
    /// and nothing else at all — no `.gpg-id.sig`, no file of ours.
    #[test]
    fn init_creates_the_directory_and_writes_the_gpg_id() {
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path().join("password-store");
        let (core, _) = core_rooted_at(&root, None);

        let receipt = core
            .init_store(&["ada@example.invalid".to_owned()], false)
            .unwrap();

        assert_eq!(gpg_id_of(&root), "ada@example.invalid\n");
        assert_eq!(receipt.commit, None, "nothing was asked to be versioned");

        let left: Vec<_> = std::fs::read_dir(&root)
            .unwrap()
            .map(|entry| entry.unwrap().file_name())
            .collect();
        assert_eq!(left, vec![std::ffi::OsString::from(".gpg-id")]);
    }

    #[test]
    fn init_writes_every_key_it_was_given() {
        let dir = tempfile::tempdir().unwrap();
        let (core, _) = core_rooted_at(dir.path(), None);

        core.init_store(&["ada".to_owned(), "bob".to_owned()], false)
            .unwrap();

        assert_eq!(gpg_id_of(dir.path()), "ada\nbob\n");
    }

    /// ADR-6's rule, and it matters more here than anywhere else: a store
    /// created around a key that does not resolve is one whose every future
    /// write fails. Refused by name, and **nothing is left behind** — not even
    /// the directory, since the refusal happens before the write that would
    /// have created it.
    #[test]
    fn init_refuses_a_key_that_does_not_resolve_and_writes_nothing() {
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path().join("password-store");
        let (core, gpg) = core_rooted_at(&root, None);
        lock(&gpg.unresolvable).insert("ghost".to_owned());

        match core.init_store(&["ghost".to_owned()], false) {
            Err(Error::UnknownKey { id }) => assert_eq!(id, "ghost"),
            other => panic!("expected UnknownKey, got {other:?}"),
        }
        assert!(!root.exists(), "a refused setup left a directory behind");
    }

    #[test]
    fn init_refuses_a_store_that_already_exists() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join(".gpg-id"), b"someone-else\n").unwrap();
        let (core, _) = core_rooted_at(dir.path(), None);

        match core.init_store(&["ada".to_owned()], false) {
            Err(Error::StoreExists { path }) => assert_eq!(path, dir.path()),
            other => panic!("expected StoreExists, got {other:?}"),
        }
        assert_eq!(
            gpg_id_of(dir.path()),
            "someone-else\n",
            "a refused setup rewrote the store's keys"
        );
    }

    #[test]
    fn init_refuses_to_create_a_store_with_no_keys() {
        let dir = tempfile::tempdir().unwrap();
        let (core, _) = core_rooted_at(dir.path(), None);

        assert!(matches!(
            core.init_store(&[], false),
            Err(Error::EmptyRecipients { .. })
        ));
    }

    /// `pass git init`'s own wording, and the `.gpg-id` staged by name — a
    /// store's history is shared with the CLI, so `git log` should not betray
    /// which client wrote it.
    #[test]
    fn a_versioned_setup_commits_in_pass_s_words() {
        let dir = tempfile::tempdir().unwrap();
        let git = FakeVcs::default();
        let (core, _) = core_rooted_at(dir.path(), Some(git.clone()));

        let receipt = core.init_store(&["ada".to_owned()], true).unwrap();

        assert_eq!(receipt.commit, Some(Commit::Committed));
        let commits = lock(&git.commits);
        assert_eq!(commits.len(), 1);
        assert_eq!(commits[0].0, "Add current contents of password store.");
        assert_eq!(commits[0].1, vec![PathBuf::from(".gpg-id")]);
    }

    /// The store exists either way, so a history that could not be started is
    /// news about the history — the same shape as a mutation's failed commit,
    /// and for the same reason.
    #[test]
    fn a_history_that_cannot_be_started_does_not_fail_the_setup() {
        let dir = tempfile::tempdir().unwrap();
        let git = FakeVcs {
            refuses: Some("git does not know who you are"),
            ..FakeVcs::default()
        };
        let (core, _) = core_rooted_at(dir.path(), Some(git));

        let receipt = core.init_store(&["ada".to_owned()], true).unwrap();

        assert!(matches!(receipt.commit, Some(Commit::Failed(_))));
        assert_eq!(
            gpg_id_of(dir.path()),
            "ada\n",
            "the store must exist even when its history does not"
        );
    }

    /// A machine that has never used GnuPG: the state Phase 7 is about, and
    /// one the status has to report as a fact rather than as a failure.
    #[test]
    fn setup_status_reports_a_machine_with_nothing_on_it() {
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path().join("password-store");
        let (core, _) = core_rooted_at(&root, None);

        let status = core.setup_status().unwrap();

        assert_eq!(status.store, StoreState::Missing);
        assert_eq!(status.store_path, root);
        assert_eq!(status.gpg_problem, None);
        assert!(status.keys.is_empty(), "nothing should be offered yet");
    }

    /// A key already on the keyring is offered, which is what stops onboarding
    /// making a second one for somebody who has one (ADR-7).
    #[test]
    fn setup_status_offers_a_key_that_is_already_there() {
        let dir = tempfile::tempdir().unwrap();
        let (core, gpg) = core_rooted_at(dir.path(), None);
        lock(&gpg.on_keyring).insert("ada@example.invalid".to_owned());

        let status = core.setup_status().unwrap();

        assert_eq!(status.store, StoreState::Empty);
        assert_eq!(status.keys.len(), 1);
        assert_eq!(status.keys[0].id, "ada@example.invalid");
        assert!(status.keys[0].usable_here);
    }

    /// Missing GnuPG is reported *beside* the store rather than instead of it:
    /// the two failures are independent and have different remedies, and a
    /// user told to install Gpg4win when what they need is a store has been
    /// sent to fix the wrong thing (§4.1 principle 5).
    #[test]
    fn setup_status_reports_a_missing_gpg_without_losing_the_store() {
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path().to_path_buf();
        let core = Core::from_parts(
            Box::new(|| {
                Err(Error::GpgUnavailable {
                    reason: "cannot find binary path".into(),
                })
            }),
            Box::new(move || Ok(root.clone())),
            Box::new(|| {
                Err(Error::GpgUnavailable {
                    reason: "cannot find binary path".into(),
                })
            }),
            Box::new(|_| None),
            unused_clipboard(),
            Arc::new(SettingsFile::ephemeral()),
        );

        let status = core.setup_status().unwrap();

        assert_eq!(
            status.gpg_problem.as_deref(),
            Some("no usable GnuPG installation: cannot find binary path")
        );
        assert!(status.keys.is_empty());
        assert_eq!(
            status.store,
            StoreState::Empty,
            "the store is still knowable"
        );
    }

    /// The key made is the key offered next: onboarding writes what
    /// `create_key` reports straight into the `.gpg-id`, so a key that did not
    /// come back describable would produce a store nothing can write to.
    #[test]
    fn a_created_key_is_one_the_store_can_be_built_on() {
        let dir = tempfile::tempdir().unwrap();
        let (core, gpg) = core_rooted_at(dir.path(), None);

        let key = core
            .create_key("Ada Lovelace", "ada@example.invalid")
            .unwrap();
        assert!(key.usable_here);
        assert_eq!(lock(&gpg.generated).len(), 1);

        core.init_store(std::slice::from_ref(&key.id), false)
            .unwrap();
        assert_eq!(gpg_id_of(dir.path()), format!("{}\n", key.id));
    }
}
