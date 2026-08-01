//! Encryption: our own `gpg` invocation.
//!
//! Decryption is wrapped from `prs-lib` (see [`super::prs`]); encryption is not,
//! and the asymmetry is deliberate. Decrypting has no flag-compatibility
//! surface — `gpg --decrypt` reads what the file says it is. Encrypting is the
//! opposite: the argument list *is* the access-control decision, so who ends up
//! able to read the entry is decided by the flags below. Three `prs-lib`
//! behaviours make its encrypt path unusable for us (`PLAN.md` ADR-6, F-8/9/10):
//!
//! - `Recipients::from` + `find_public_keys` resolve `.gpg-id` ids by
//!   normalized-fingerprint substring, need 8 characters, and **silently skip**
//!   what they cannot match — so a `.gpg-id` line that is a user id, which
//!   `pass` supports and `store/gpg_id.rs` deliberately preserves verbatim,
//!   would drop that recipient without a word (F-8, Invariant 8).
//! - `raw::encrypt` omits `--no-encrypt-to`, so an `encrypt-to` line in the
//!   user's `gpg.conf` silently adds a recipient the `.gpg-id` never authorized
//!   (F-9, Invariant 8 in the other direction).
//! - `raw::encrypt` writes the whole plaintext to the child's stdin before
//!   reading a byte of its stdout, which deadlocks once the ciphertext outgrows
//!   the pipe buffer (F-10).
//!
//! So we spawn `gpg` ourselves, with `pass`'s flag set, and hand it the
//! recipient ids exactly as the `.gpg-id` spells them — which is what makes
//! fingerprints, key ids, and user ids all work, since resolving them is `gpg`'s
//! job and it fails loudly when it cannot.
//!
//! No passphrase is involved: encrypting to a public key never needs one, so
//! Invariant 3 is untouched and `--pinentry-mode` is never set here either.

use std::io::Write;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};

use crate::error::{Error, Result};
use crate::secret::Secret;
use crate::store::Recipients;

/// The binary we look for, matching what `prs-lib`'s context resolves.
#[cfg(not(windows))]
const BIN_NAME: &str = "gpg";
#[cfg(windows)]
const BIN_NAME: &str = "gpg.exe";

/// Locate the user's `gpg`.
///
/// Resolved with `which` against the same name `prs-lib`'s `find_gpg_bin` uses,
/// so the binary that encrypts an entry is the one that will decrypt it — on a
/// machine with more than one GnuPG this is the difference between a store that
/// round-trips and one that does not.
pub fn bin() -> Result<PathBuf> {
    which::which(BIN_NAME).map_err(|err| Error::GpgUnavailable {
        reason: err.to_string(),
    })
}

/// Encrypt `plaintext` to `recipients` and write the ciphertext to `path`.
///
/// The write is atomic: the ciphertext lands in a temporary file in the target's
/// own directory and is renamed over it, so an interrupted write cannot truncate
/// an existing entry into an unreadable one. The temporary file holds ciphertext
/// only — Invariant 1 is about plaintext, which never leaves the pipe.
pub fn encrypt_to_file(path: &Path, recipients: &Recipients, plaintext: &Secret) -> Result<()> {
    let bin = bin()?;
    verify_recipients(&bin, recipients)?;
    let ciphertext = encrypt(&bin, recipients, plaintext)?;
    write_atomically(path, &ciphertext)
}

/// Check that `gpg` can resolve every recipient before we encrypt to any.
///
/// Invariant 8 is "encrypt to the recipients from the nearest `.gpg-id`" — all
/// of them. `--batch` already makes `gpg` fail rather than half-encrypt, so this
/// pass exists for the error message: it can name the id that does not resolve
/// and the file that asked for it, where the failed encrypt could only say that
/// something went wrong.
fn verify_recipients(bin: &Path, recipients: &Recipients) -> Result<()> {
    // `raw::encrypt` asserts on an empty list (ADR-4a F-7) and `gpg` with no
    // `--recipient` would encrypt to nothing; `gpg_id::read` already rejects an
    // empty `.gpg-id`, so this is belt and braces at the site that would abort.
    if recipients.ids.is_empty() {
        return Err(Error::EmptyRecipients {
            path: recipients.source.clone(),
        });
    }

    for id in &recipients.ids {
        let output = Command::new(bin)
            .args(["--batch", "--quiet", "--utf8-strings"])
            .args(["--list-keys", "--with-colons"])
            .arg("--")
            .arg(id)
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .output()
            .map_err(|err| Error::io(bin, err))?;

        if !output.status.success() {
            return Err(Error::UnknownRecipient {
                id: id.clone(),
                gpg_id: recipients.source.clone(),
            });
        }
    }
    Ok(())
}

/// Run `gpg`, returning the ciphertext.
fn encrypt(bin: &Path, recipients: &Recipients, plaintext: &Secret) -> Result<Vec<u8>> {
    let mut command = Command::new(bin);
    command
        .args([
            "--batch",
            "--yes",
            "--quiet",
            // Recipient ids come from a `.gpg-id` a human wrote; a user id may
            // hold non-ASCII, and without this `gpg` reads the argument in the
            // local encoding instead.
            "--utf8-strings",
            // `pass` sets this. Compressing before encrypting makes the
            // ciphertext's length a function of the plaintext's redundancy.
            "--compress-algo=none",
            // F-9, Invariant 8: without it an `encrypt-to` line in the user's
            // `gpg.conf` adds a recipient the store never authorized, and the
            // resulting file looks entirely normal.
            "--no-encrypt-to",
            // The `.gpg-id` *is* the store's authorization decision, so the web
            // of trust is a second gate here rather than the relevant one — and
            // the way `gpg` asks about an untrusted key is an interactive
            // prompt, which a GUI with no TTY cannot answer. `prs` makes the
            // same choice; with `--batch` the alternative is not a prompt but a
            // refusal to encrypt to a key the user deliberately listed.
            "--trust-model",
            "always",
        ])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::null());

    for id in &recipients.ids {
        command.arg("--recipient").arg(id);
    }
    // Ends option parsing, so a recipient id beginning with `-` is a recipient
    // and not a flag.
    command.arg("--encrypt").arg("--");

    let mut child = command.spawn().map_err(|err| Error::io(bin, err))?;
    let Some(mut stdin) = child.stdin.take() else {
        // Only reachable if the pipe above was not set up; killing the child
        // rather than leaking it, since it would otherwise wait on stdin.
        let _ = child.kill();
        return Err(Error::Encrypt);
    };

    // The plaintext is fed on its own thread while this one drains stdout.
    // Doing it in sequence is F-10: `gpg` stops reading stdin once its unread
    // stdout fills the pipe buffer, and both sides then wait forever. Scoped so
    // the thread can borrow the plaintext rather than needing a second copy of
    // it.
    let (fed, output) = std::thread::scope(|scope| {
        let feeder = scope.spawn(move || {
            let result = stdin.write_all(plaintext.expose());
            // Explicit, though the drop at the end of this closure would do it:
            // `gpg` waits for EOF on stdin before it finishes.
            drop(stdin);
            result
        });
        let output = child.wait_with_output();
        // A panic in the feeder becomes an error rather than propagating: this
        // thread holds no secret buffer, but unwinding past one is the thing
        // `panic = "abort"` exists to prevent, and an `Err` says the same.
        let fed = feeder
            .join()
            .unwrap_or(Err(std::io::ErrorKind::Other.into()));
        (fed, output)
    });

    fed.map_err(|_| Error::Encrypt)?;
    let output = output.map_err(|err| Error::io(bin, err))?;

    // `gpg`'s own output is dropped rather than wrapped, the same way
    // `Error::Decrypt` drops it. Encryption failures are about keys rather than
    // content, but this is a path with a live plaintext on it, so the error
    // leaving it is secret-free by construction rather than by audit.
    if !output.status.success() || output.stdout.is_empty() {
        return Err(Error::Encrypt);
    }
    Ok(output.stdout)
}

/// Write `ciphertext` to `path` via a temporary file in the same directory.
///
/// Same directory so the rename is on one filesystem, and therefore atomic. The
/// temporary is created `0600` by `tempfile` on Unix and keeps those bits when
/// it is persisted — tighter than the umask-derived permissions `pass` leaves,
/// which is the right direction for a password store.
fn write_atomically(path: &Path, ciphertext: &[u8]) -> Result<()> {
    let dir = path.parent().ok_or(Error::Encrypt)?;
    std::fs::create_dir_all(dir).map_err(|err| Error::io(dir, err))?;

    // The prefix keeps the temporary out of the tree even while it exists: the
    // store walker matches `*.gpg`, and this is neither that nor hidden-adjacent
    // enough to be mistaken for one.
    let mut file = tempfile::Builder::new()
        .prefix(".pgs-tmp-")
        .tempfile_in(dir)
        .map_err(|err| Error::io(dir, err))?;

    file.write_all(ciphertext)
        .map_err(|err| Error::io(path, err))?;
    // Durability before the rename: a rename that wins the race to disk against
    // its own file contents would leave a valid name over an empty entry.
    file.as_file()
        .sync_all()
        .map_err(|err| Error::io(path, err))?;

    file.persist(path)
        .map_err(|err| Error::io(path, err.error))?;
    Ok(())
}

#[cfg(test)]
// Test code handles fixtures, never real secrets. The round trip against a real
// `gpg` lives in `tests/gpg_roundtrip.rs`, which needs an isolated `GNUPGHOME`.
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;

    fn recipients(ids: &[&str]) -> Recipients {
        Recipients {
            ids: ids.iter().map(|id| (*id).to_owned()).collect(),
            source: PathBuf::from("/store/.gpg-id"),
        }
    }

    /// An empty recipient list must be refused here rather than reaching `gpg`,
    /// which would otherwise encrypt to nobody (Invariant 8, ADR-4a F-7).
    #[test]
    fn refuses_to_encrypt_to_nobody() {
        let empty = recipients(&[]);
        match verify_recipients(Path::new("/nonexistent/gpg"), &empty) {
            Err(Error::EmptyRecipients { path }) => {
                assert_eq!(path, PathBuf::from("/store/.gpg-id"));
            }
            Err(other) => panic!("expected EmptyRecipients, got {other:?}"),
            Ok(()) => panic!("an empty recipient list must not be accepted"),
        }
    }

    /// Invariant 5: neither failure a write can report says anything about what
    /// was being written.
    #[test]
    fn the_write_errors_carry_no_content() {
        assert_eq!(Error::Encrypt.to_string(), "failed to encrypt");

        let unknown = Error::UnknownRecipient {
            id: "me@example.com".to_owned(),
            gpg_id: PathBuf::from("/store/.gpg-id"),
        };
        assert_eq!(
            unknown.to_string(),
            "no public key for recipient me@example.com, listed in /store/.gpg-id"
        );
    }

    #[test]
    fn an_atomic_write_replaces_the_previous_ciphertext() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("gmail.com.gpg");

        write_atomically(&path, b"first").unwrap();
        assert_eq!(std::fs::read(&path).unwrap(), b"first");

        write_atomically(&path, b"second-and-longer").unwrap();
        assert_eq!(std::fs::read(&path).unwrap(), b"second-and-longer");

        // The temporary is gone: nothing but the entry itself is left behind.
        let left: Vec<_> = std::fs::read_dir(dir.path())
            .unwrap()
            .map(|e| e.unwrap().file_name())
            .collect();
        assert_eq!(left, vec![std::ffi::OsString::from("gmail.com.gpg")]);
    }

    #[test]
    fn an_atomic_write_creates_missing_directories() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("Email").join("work").join("corp.gpg");

        write_atomically(&path, b"ciphertext").unwrap();

        assert_eq!(std::fs::read(&path).unwrap(), b"ciphertext");
    }

    /// The file must not be group- or world-readable, whatever the umask says.
    #[cfg(unix)]
    #[test]
    fn a_written_entry_is_private_to_its_owner() {
        use std::os::unix::fs::PermissionsExt;

        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("wifi.gpg");
        write_atomically(&path, b"ciphertext").unwrap();

        let mode = std::fs::metadata(&path).unwrap().permissions().mode();
        assert_eq!(mode & 0o077, 0, "mode was {:o}", mode & 0o777);
    }
}
