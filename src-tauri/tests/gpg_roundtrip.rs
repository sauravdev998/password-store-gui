//! Decryption against a real `gpg` and a throwaway key.
//!
//! `PLAN.md` §8 asks for this: an ephemeral `GNUPGHOME`, a generated test key,
//! and a real round trip. It lives in its own integration-test binary because
//! `GNUPGHOME` is process-global — the unit tests must not see it, and the
//! whole file is one `#[test]` so nothing races on the variable.
//!
//! The key is generated with `%no-protection`, so no passphrase and no pinentry
//! are involved. That is a property of the fixture, not a loophole in
//! Invariant 3: we still never pass a passphrase, and `--pinentry-mode` is
//! never set (ADR-4a F-2).

// Test-only: the harness captures these, and a silent skip is worse than a
// noisy one when the reason is "this machine has no gpg".
#![allow(clippy::print_stdout, clippy::print_stderr)]
// Test code handles fixtures, never real secrets: the key below is generated
// into a temporary directory and discarded with it.
#![allow(clippy::unwrap_used)]

use std::fs;
use std::io::Write;
use std::path::Path;
use std::process::{Command, Stdio};

use password_store_gui_lib::crypto::{Gpg, PrsGpg};
use password_store_gui_lib::error::Error;

/// Plaintext with the shape a real entry has: password first, then fields.
const PLAINTEXT: &[u8] = b"correct-horse-battery-staple\nurl: example.com\nuser: alice\n";

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

const RECIPIENT: &str = "test@example.invalid";

#[test]
fn decrypts_a_secret_written_by_the_real_gpg() {
    let Some(gpg_bin) = find_gpg() else {
        println!("skipping: no gpg on PATH");
        return;
    };

    let home = tempfile::tempdir().unwrap();
    harden(home.path());

    // Must be set before the first `PrsGpg` call: the backend spawns `gpg` as a
    // child, which inherits our environment.
    set_gnupg_home(home.path());

    generate_key(&gpg_bin, home.path());

    let store = tempfile::tempdir().unwrap();
    let secret_path = store.path().join("gmail.com.gpg");
    encrypt(&gpg_bin, PLAINTEXT, &secret_path);

    let gpg = match PrsGpg::new() {
        Ok(gpg) => gpg,
        Err(err) => panic!("building a crypto context failed: {err}"),
    };

    // The round trip itself.
    let secret = match gpg.decrypt_file(&secret_path) {
        Ok(secret) => secret,
        Err(err) => panic!("decrypt failed: {err}"),
    };
    assert_eq!(secret.expose(), PLAINTEXT);
    assert_eq!(
        secret.expose_str().unwrap().lines().next().unwrap(),
        "correct-horse-battery-staple",
    );

    // Invariant 1: decrypting leaves nothing behind. Only the ciphertext we put
    // there may exist in the store directory.
    let left_behind: Vec<_> = fs::read_dir(store.path())
        .unwrap()
        .map(|entry| entry.unwrap().file_name())
        .collect();
    assert_eq!(
        left_behind,
        vec![secret_path.file_name().unwrap()],
        "decryption must not write a temporary file"
    );

    // A file that is not ciphertext fails as our typed error, carrying only the
    // path — gpg's own output never reaches it (Invariant 5).
    let garbage = store.path().join("garbage.gpg");
    fs::write(&garbage, b"this is not an OpenPGP message").unwrap();
    match gpg.decrypt_file(&garbage) {
        Err(Error::Decrypt { path }) => {
            assert_eq!(path, garbage);
            let message = Error::Decrypt { path: garbage }.to_string();
            assert!(
                !message.contains("gpg:") && !message.contains("decryption failed"),
                "the error must not carry gpg's output: {message}"
            );
        }
        Err(other) => panic!("expected a Decrypt error, got {other}"),
        Ok(_) => panic!("garbage must not decrypt"),
    }

    // Stop the agent this GNUPGHOME started, so the temp dir can be removed and
    // no daemon outlives the test.
    let _ = Command::new("gpgconf").arg("--kill").arg("all").status();
}

fn find_gpg() -> Option<std::path::PathBuf> {
    let bin = if cfg!(windows) { "gpg.exe" } else { "gpg" };
    which::which(bin).ok()
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

/// Point `gpg` at the throwaway home.
///
/// Isolated in a function so the one piece of process-global mutation in the
/// suite is easy to find. Safe here: this binary runs a single test.
fn set_gnupg_home(home: &Path) {
    std::env::set_var("GNUPGHOME", home);
}

fn generate_key(gpg_bin: &Path, home: &Path) {
    let params = home.join("key-params.txt");
    fs::write(&params, KEY_PARAMS).unwrap();

    let output = Command::new(gpg_bin)
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

fn encrypt(gpg_bin: &Path, plaintext: &[u8], out: &Path) {
    let mut child = Command::new(gpg_bin)
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
