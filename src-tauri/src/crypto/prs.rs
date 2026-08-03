//! `prs-lib`-backed [`Gpg`] implementation, over the `backend-gnupg-bin`
//! backend: it spawns the user's `gpg`, pipes stdin to stdout, and touches no
//! temporary file (ADR-4a, Invariant 1).
//!
//! The only module besides `store/prs.rs` allowed to name a `prs-lib` type
//! (ADR-4). Several of that crate's behaviours are deliberately bypassed here:
//!
//! - `crypto::Config.gpg_tty` adds `--pinentry-mode loopback`, which would put
//!   passphrase handling in our process (F-2). We build the config ourselves so
//!   the flag has no route to being set; [`tests`] pins that.
//! - `crypto::Config.verbose` makes the crate `eprintln!` raw gpg stdout on a
//!   non-zero exit, and a partial decrypt failure can leave plaintext in that
//!   stdout (F-3). Never set it. Note it writes to stderr directly rather than
//!   through `log`, so the `debug_assertions`-gated log sink would not have
//!   caught it.
//! - `can_decrypt` decrypts a real secret and inspects the plaintext as a `&str`
//!   without zeroizing it (F-5). Never call it.
//! - `IsContext::decrypt_file` swallows the path on a read error, so we read the
//!   ciphertext ourselves and keep a path in the error.

use std::cell::RefCell;
use std::fs;
use std::path::Path;

use prs_lib::crypto::prelude::*;
use prs_lib::crypto::{Config, Context, Proto};
use prs_lib::Ciphertext;

use crate::crypto::{gnupg, Gpg, KeyIds, KeyInfo};
use crate::error::{Error, Result};
use crate::secret::Secret;
use crate::store::Recipients;

/// Decryption through the user's `gpg` binary.
pub struct PrsGpg {
    /// Zero-sized; existence of a value is the proof that [`PrsGpg::new`]
    /// found a usable `gpg`.
    _validated: (),
}

impl PrsGpg {
    /// Check that a usable `gpg` is installed.
    ///
    /// Called at startup so a missing or too-old GnuPG is one clear error then,
    /// rather than a surprise on the first reveal. It also pre-validates the
    /// F-7 panic sites: `raw_cmd.rs` does `cmd.spawn().unwrap()`, which would
    /// abort the app if the binary were absent, and building a context is what
    /// rules that out.
    pub fn new() -> Result<Self> {
        with_context(|_| Ok(()))?;
        // The write path resolves `gpg` itself (ADR-6), so its precondition is
        // checked here too rather than first failing on a save.
        gnupg::bin()?;
        Ok(Self { _validated: () })
    }
}

impl Gpg for PrsGpg {
    fn decrypt(&self, ciphertext: &[u8]) -> Result<Secret> {
        with_context(|context| {
            let plaintext = context
                .decrypt(Ciphertext::from(ciphertext.to_vec()))
                // The source is dropped on purpose. ADR-4a found the variants
                // reachable here carry only an exit status, but this is the one
                // path where plaintext exists in the process, so the error
                // leaving it is secret-free by construction rather than by
                // audit. What the user needs — a bad passphrase, a cancelled
                // pinentry, a missing secret key — gpg has already told them
                // through its own prompt.
                .map_err(|_| Error::DecryptBlob)?;

            // The copy out of `prs-lib`'s buffer and into ours is the seam
            // ADR-4 asks for: `Plaintext` is zeroized as it drops at the end of
            // this closure, and no `prs-lib` type leaves this module.
            Ok(Secret::from_slice(plaintext.unsecure_ref()))
        })
    }

    fn decrypt_file(&self, path: &Path) -> Result<Secret> {
        let ciphertext = fs::read(path).map_err(|source| Error::io(path, source))?;
        // The pathless failure above becomes one that names the file. Nothing
        // else is carried across: the discarded error held only an exit status,
        // and this is the path where plaintext exists in the process.
        self.decrypt(&ciphertext)
            .map_err(|_| Error::Decrypt { path: path.into() })
    }

    /// Delegated to [`gnupg`] rather than to `prs-lib` — ADR-6, and the module
    /// doc above lists the three behaviours that force it. Nothing about this
    /// path touches the `prs-lib` context.
    fn encrypt_file(&self, path: &Path, recipients: &Recipients, plaintext: &Secret) -> Result<()> {
        gnupg::encrypt_to_file(path, recipients, plaintext)
    }

    /// Delegated to [`gnupg`] for ADR-6's reason, one step further: both of
    /// these read the same keyring the encrypt path resolves `--recipient`
    /// against, so they must be the same binary asking. Neither decrypts.
    fn describe_key(&self, id: &str) -> Result<KeyInfo> {
        let bin = gnupg::bin()?;
        gnupg::describe_key(&bin, id, &gnupg::secret_keys(&bin)?)
    }

    fn encrypted_to(&self, path: &Path) -> Result<KeyIds> {
        gnupg::encrypted_to(&gnupg::bin()?, path)
    }

    /// Also [`gnupg`], and for onboarding's sake it must be the *same* binary:
    /// the key offered here is the one about to be written into a `.gpg-id` and
    /// resolved again by the encrypt path (ADR-7).
    fn usable_keys(&self) -> Result<Vec<KeyInfo>> {
        gnupg::usable_keys(&gnupg::bin()?)
    }

    fn generate_key(&self, name: &str, email: &str) -> Result<KeyInfo> {
        gnupg::generate_key(&gnupg::bin()?, name, email)
    }
}

/// Crypto configuration for every call we make.
///
/// Built here rather than taken from `prs_lib::CONFIG` so the two dangerous
/// flags are set to `false` at a site we own and test, not inherited from a
/// dependency's default that a future version could change.
fn config() -> Config {
    Config {
        proto: Proto::Gpg,
        // F-2 / Invariant 3: `true` adds `--pinentry-mode loopback`.
        gpg_tty: false,
        // F-3 / Invariant 5: `true` prints raw gpg stdout, which can hold
        // plaintext after a partial decrypt failure.
        verbose: false,
    }
}

thread_local! {
    /// Cached context for the calling thread.
    ///
    /// Building one runs `which gpg` and spawns `gpg --version`, which is not
    /// worth repeating per decrypt. It is thread-local rather than shared
    /// because `prs_lib::crypto::Context` is a `Box<dyn IsContext>` with no
    /// `Send` bound, so it cannot live in the app's shared state — and
    /// `unsafe_code` is forbidden, so we do not get to assert otherwise.
    ///
    /// It holds no secret: a `gnupg_bin` context is the `gpg` path plus the two
    /// flags in [`config`].
    static CONTEXT: RefCell<Option<Context>> = const { RefCell::new(None) };
}

/// Run `f` with this thread's crypto context, creating it on first use.
fn with_context<T>(f: impl FnOnce(&mut Context) -> Result<T>) -> Result<T> {
    CONTEXT.with(|slot| {
        let mut slot = slot.borrow_mut();
        if slot.is_none() {
            *slot = Some(new_context()?);
        }
        match slot.as_mut() {
            Some(context) => f(context),
            // Assigned immediately above, and nothing can clear it in between:
            // `slot` is borrowed exclusively for this scope.
            None => Err(Error::GpgUnavailable {
                reason: "crypto context went missing".into(),
            }),
        }
    })
}

/// Build a crypto context, or say why we cannot.
fn new_context() -> Result<Context> {
    prs_lib::crypto::context(&config()).map_err(|err| Error::GpgUnavailable {
        reason: describe(&err),
    })
}

/// Flatten a `prs-lib` context error into a message.
///
/// Interpolating a dependency's error text is normally exactly what Invariant 5
/// forbids. It is safe at this one site because of *when* it runs: context
/// creation only ever reports a failure to locate `gpg`, or its `--version`
/// output. It happens before any ciphertext has been read, so there is no
/// plaintext in the process for the message to capture. Do not reuse this for
/// an error raised on the decrypt path.
fn describe(err: &(dyn std::error::Error + 'static)) -> String {
    let mut message = err.to_string();
    let mut source = err.source();
    while let Some(err) = source {
        message.push_str(": ");
        message.push_str(&err.to_string());
        source = err.source();
    }
    message
}

#[cfg(test)]
// Test code handles fixtures, never real secrets. The round-trip against a real
// `gpg` and a throwaway key lives in `tests/gpg_roundtrip.rs`, which needs an
// isolated `GNUPGHOME` and so must run in its own process.
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;

    /// F-2 and F-3. Both flags are pinned here rather than trusted to their
    /// defaults, because both are public fields on a dependency's struct and a
    /// future version could change what `Config::from` yields.
    #[test]
    fn the_config_never_enables_loopback_pinentry_or_verbose_output() {
        let config = config();

        assert!(
            !config.gpg_tty,
            "gpg_tty passes --pinentry-mode loopback, moving passphrase handling \
             into our process (Invariant 3, ADR-4a F-2)"
        );
        assert!(
            !config.verbose,
            "verbose eprintln!s raw gpg stdout, which can hold plaintext after a \
             partial decrypt failure (Invariant 5, ADR-4a F-3)"
        );
        assert_eq!(config.proto, Proto::Gpg);
    }

    /// A missing file must fail before `gpg` is ever spawned, so the error is
    /// ours and carries the path rather than being `prs-lib`'s pathless
    /// `Err::ReadFile`.
    #[test]
    fn a_missing_ciphertext_file_is_an_io_error_with_its_path() {
        let dir = tempfile::tempdir().unwrap();
        let missing = dir.path().join("absent.gpg");

        // Constructed directly: reading the file happens before any context is
        // built, so this test does not need `gpg` on the machine.
        let gpg = PrsGpg { _validated: () };

        // Matched arm by arm rather than debug-printing the `Result`: `Secret`
        // has no `Debug`, which is the point of it having none.
        match gpg.decrypt_file(&missing) {
            Err(Error::Io { path, .. }) => assert_eq!(path, missing),
            Err(other) => panic!("expected an Io error, got {other:?}"),
            Ok(_) => panic!("expected an Io error for a missing file"),
        }
    }
}
