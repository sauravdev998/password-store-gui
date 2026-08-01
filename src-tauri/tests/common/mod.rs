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

const KEY_PARAMS: &str = "\
Key-Type: eddsa
Key-Curve: ed25519
Subkey-Type: ecdh
Subkey-Curve: cv25519
Name-Real: Password Store GUI Test
Name-Email: test@example.invalid
Expire-Date: 0
%no-protection
%commit
";

/// The test key's user id, and so the `.gpg-id` a fixture store lists.
pub const RECIPIENT: &str = "test@example.invalid";

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
        // The one piece of process-global mutation in the suite, kept in a
        // single place. Safe because a binary using this holds one test.
        std::env::set_var("GNUPGHOME", home.path());

        let fixture = Self { gpg_bin, home };
        fixture.generate_key();
        Some(fixture)
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

    fn generate_key(&self) {
        let params = self.home().join("key-params.txt");
        fs::write(&params, KEY_PARAMS).unwrap();

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
