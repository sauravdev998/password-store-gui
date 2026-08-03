//! Shared harness for the integration tests: a real `gpg` and a throwaway key.
//!
//! `PLAN.md` §8 asks for an ephemeral `GNUPGHOME`, a generated test key, and a
//! real round trip. `GNUPGHOME` is process-global, so each test binary that
//! uses this must contain exactly **one** `#[test]` — otherwise two tests race
//! on the variable.
//!
//! The key is generated with `%no-protection`, so no passphrase and no pinentry
//! are involved. That is a property of the fixture, not a loophole in
//! Invariant 3: we still never pass a passphrase, and `--pinentry-mode` is
//! never set (ADR-4a F-2).

// Compiled into each test binary, and no one binary uses all of it.
#![allow(dead_code)]
// Test-only: the harness captures these, and a silent skip is worse than a
// noisy one when the reason is "this machine has no gpg".
#![allow(clippy::print_stdout, clippy::print_stderr)]
// Test code handles fixtures, never real secrets: the key below is generated
// into a temporary directory and discarded with it.
#![allow(clippy::unwrap_used)]

use std::fs;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};

use tempfile::TempDir;

/// The test key's user id, and so the `.gpg-id` a fixture store lists.
pub const RECIPIENT: &str = "test@example.invalid";

/// Batch parameters for one throwaway key.
fn key_params(email: &str) -> String {
    format!(
        "\
Key-Type: eddsa
Key-Curve: ed25519
Subkey-Type: ecdh
Subkey-Curve: cv25519
Name-Real: Password Store GUI Test
Name-Email: {email}
Expire-Date: 0
%no-protection
%commit
"
    )
}

/// An isolated GnuPG home with one generated key.
pub struct GpgFixture {
    gpg_bin: PathBuf,
    /// Dropped last, after [`Drop`] has stopped the agent holding it open.
    home: TempDir,
}

impl GpgFixture {
    /// Build the fixture, or `None` when this machine has no `gpg`.
    ///
    /// Sets `GNUPGHOME` for the whole process: the backend spawns `gpg` as a
    /// child, which inherits our environment, so this must happen before the
    /// first decrypt.
    pub fn new() -> Option<Self> {
        let bin = if cfg!(windows) { "gpg.exe" } else { "gpg" };
        let gpg_bin = which::which(bin).ok()?;

        let home = tempfile::tempdir().unwrap();
        harden(home.path());
        // Process-global mutation, kept in a single place. Safe because a
        // binary using this holds one test.
        //
        // The reason this could not be a per-command `.env()` was `prs-lib`,
        // which built its own `Command` for `gpg` and offered no hook to add a
        // variable to it. ADR-4b removed that constraint — every spawn is ours
        // now — but the variable stays process-global on purpose: `gpg` spawns
        // `gpg-agent`, which outlives the command and must find the same home,
        // and threading an environment through every call site would buy
        // nothing a test binary holding one test needs.
        //
        // Note for whoever bumps the crate to edition 2024: this call becomes
        // `unsafe` there, and `unsafe_code = "forbid"` in `Cargo.toml` covers
        // every target and cannot be locally allowed. The fix at that point is
        // to move the lint out of `[lints.rust]` and into a `#![forbid(...)]`
        // in `src/lib.rs`, so it still guards the code that handles secrets
        // while leaving the test harness able to do this.
        std::env::set_var("GNUPGHOME", home.path());

        let fixture = Self { gpg_bin, home };
        fixture.add_key(RECIPIENT);
        Some(fixture)
    }

    /// Generate another throwaway key, returning the id a `.gpg-id` would list.
    ///
    /// A store with a second recipient is what a recipient change is *for*, so
    /// testing one needs a keyring with more than the single key the read and
    /// write tests get by with.
    pub fn add_key(&self, email: &str) -> String {
        let params = self.home().join(format!("key-params-{email}.txt"));
        fs::write(&params, key_params(email)).unwrap();

        let output = Command::new(&self.gpg_bin)
            .args(["--batch", "--quiet", "--generate-key"])
            .arg(&params)
            .output()
            .unwrap();
        assert!(
            output.status.success(),
            "key generation failed: {}",
            String::from_utf8_lossy(&output.stderr)
        );
        email.to_owned()
    }

    /// Delete a key's *secret* half, leaving its public key on the keyring.
    ///
    /// What a store shared with another person looks like from this side: their
    /// key can be encrypted to, and their entries cannot be read. It is also the
    /// only way to make a decrypt fail on demand, which is what the rollback
    /// test needs.
    pub fn forget_secret_key(&self, email: &str) {
        // `--delete-secret-keys` refuses a user id in batch mode and insists on
        // a fingerprint, so resolve one first.
        let fingerprint = self.fingerprint_of(email);
        let output = Command::new(&self.gpg_bin)
            .args(["--batch", "--yes", "--delete-secret-keys"])
            .arg(&fingerprint)
            .output()
            .unwrap();
        assert!(
            output.status.success(),
            "could not delete the secret key: {}",
            String::from_utf8_lossy(&output.stderr)
        );
    }

    /// The primary key fingerprint for a user id.
    pub fn fingerprint_of(&self, email: &str) -> String {
        let output = Command::new(&self.gpg_bin)
            .args(["--batch", "--with-colons", "--list-keys"])
            .arg(email)
            .output()
            .unwrap();
        assert!(
            output.status.success(),
            "no key for {email}: {}",
            String::from_utf8_lossy(&output.stderr)
        );

        // The `fpr` immediately after `pub` is the primary key's; later ones
        // belong to subkeys.
        let listing = String::from_utf8_lossy(&output.stdout);
        let mut seen_pub = false;
        for line in listing.lines() {
            let fields: Vec<&str> = line.split(':').collect();
            match fields.first() {
                Some(&"pub") => seen_pub = true,
                Some(&"fpr") if seen_pub => return fields[9].to_owned(),
                _ => {}
            }
        }
        panic!("no fingerprint found for {email}");
    }

    /// Whether `gpg` can decrypt this file with the keys currently held.
    ///
    /// Asked of the real binary rather than of our own code, so "the other
    /// person can now read it" is a fact about the ciphertext and not about
    /// what we believe we wrote.
    pub fn can_decrypt(&self, path: &Path) -> bool {
        Command::new(&self.gpg_bin)
            .args(["--batch", "--quiet", "--decrypt"])
            .arg(path)
            .output()
            .map(|output| output.status.success())
            .unwrap_or(false)
    }

    pub fn home(&self) -> &Path {
        self.home.path()
    }

    /// Encrypt `plaintext` to the test key, writing the ciphertext to `out`.
    pub fn encrypt(&self, plaintext: &[u8], out: &Path) {
        let mut child = Command::new(&self.gpg_bin)
            .args(["--batch", "--yes", "--quiet", "--trust-model", "always"])
            .args(["--recipient", RECIPIENT])
            .arg("--encrypt")
            .arg("--output")
            .arg(out)
            .stdin(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .unwrap();
        child.stdin.as_mut().unwrap().write_all(plaintext).unwrap();
        let output = child.wait_with_output().unwrap();
        assert!(
            output.status.success(),
            "encryption failed: {}",
            String::from_utf8_lossy(&output.stderr)
        );
    }

    /// Decrypt `path` with the real `gpg`, independently of our own code.
    ///
    /// The other direction from [`GpgFixture::encrypt`]: it is what lets a test
    /// assert that a file *we* wrote is readable by the tool the store belongs
    /// to, rather than only by us.
    pub fn decrypt(&self, path: &Path) -> Vec<u8> {
        let output = Command::new(&self.gpg_bin)
            .args(["--batch", "--quiet", "--decrypt"])
            .arg(path)
            .output()
            .unwrap();
        assert!(
            output.status.success(),
            "decryption failed: {}",
            String::from_utf8_lossy(&output.stderr)
        );
        output.stdout
    }

    /// Recipient key ids a ciphertext is encrypted to, as `gpg` reports them.
    ///
    /// Used to check Invariant 8 from the outside: what the file says, not what
    /// we believe we asked for.
    pub fn recipients_of(&self, path: &Path) -> Vec<String> {
        let output = Command::new(&self.gpg_bin)
            .args(["--batch", "--list-packets"])
            .arg(path)
            .output()
            .unwrap();
        // A `:pubkey enc packet:` line per recipient, each ending in its key id.
        String::from_utf8_lossy(&output.stdout)
            .lines()
            .filter(|line| line.trim_start().starts_with(":pubkey enc packet:"))
            .filter_map(|line| line.rsplit_once("keyid "))
            .map(|(_, id)| id.trim().to_owned())
            .collect()
    }
}

impl Drop for GpgFixture {
    /// Stop the agent this `GNUPGHOME` started, so the temporary directory can
    /// be removed and no daemon outlives the test.
    fn drop(&mut self) {
        let _ = Command::new("gpgconf").arg("--kill").arg("all").status();
    }
}

/// `gpg` warns loudly about a world-readable home; make it 0700 on Unix.
fn harden(home: &Path) {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(home, fs::Permissions::from_mode(0o700)).unwrap();
    }
    #[cfg(not(unix))]
    let _ = home;
}

/// Every file and directory under `root`, relative and sorted.
///
/// Used to assert Invariant 1: reading a store must leave the directory exactly
/// as it found it.
pub fn snapshot(root: &Path) -> Vec<PathBuf> {
    let mut found = Vec::new();
    walk(root, root, &mut found);
    found.sort();
    found
}

fn walk(root: &Path, dir: &Path, found: &mut Vec<PathBuf>) {
    for entry in fs::read_dir(dir).unwrap() {
        let path = entry.unwrap().path();
        found.push(path.strip_prefix(root).unwrap().to_path_buf());
        if path.is_dir() {
            walk(root, &path, found);
        }
    }
}
