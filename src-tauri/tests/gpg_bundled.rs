//! ADR-14's two claims about which `gpg` runs, against a real one.
//!
//! 1. **A system GnuPG wins.** Someone who already has one keeps their agent,
//!    pinentry, keyring and smartcard, and our bundled copy stays out of the
//!    way. Getting this backwards would stand a second `gpg-agent` version up
//!    against the user's own `~/.gnupg`.
//! 2. **A binary at a bundled path is usable.** Not merely findable: it has to
//!    decrypt an entry the `pass` CLI wrote, or the fallback is decoration.
//!
//! Which of the two the resolver *demonstrates* depends on the machine, and the
//! test says which it saw rather than quietly proving less than it looks like.
//! Claim 2 is checked either way, by driving the bundled path directly.
//!
//! The ordering itself is unit-tested in `crypto::gnupg`; what needs a real
//! `gpg` is that the chosen binary works.
//!
//! Its own binary for two reasons, both process-global: `GNUPGHOME`, as with
//! every other fixture test, and `PATH`, which this scrubs.

// Test-only: the harness captures these, and a silent skip is worse than a noisy
// one when the reason is "this machine has no gpg".
#![allow(clippy::print_stdout, clippy::print_stderr)]
// Test code handles fixtures, never real secrets: the key is generated into a
// temporary directory and discarded with it.
#![allow(clippy::unwrap_used)]

mod common;

use std::fs;
use std::path::{Path, PathBuf};

use password_store_gui_lib::crypto::gnupg;

const PLAINTEXT: &[u8] = b"correct-horse-battery-staple\nurl: example.com\n";

/// The file name the resolver looks for, matching `crypto::gnupg`.
const BIN_NAME: &str = if cfg!(windows) { "gpg.exe" } else { "gpg" };

#[test]
fn the_bundled_gpg_is_a_working_fallback_and_not_a_preference() {
    // Built first, while `PATH` still works: the fixture resolves `gpg` itself
    // and generates the throwaway key we are about to encrypt to.
    let Some(fixture) = common::GpgFixture::new() else {
        println!("skipping: no gpg on PATH");
        return;
    };

    let staging = tempfile::tempdir().unwrap();
    let Some(root) = bundle_root(staging.path()) else {
        println!("skipping: no way to stage a bundled gpg on this platform");
        return;
    };
    let bundled = root.join("gnupg").join("bin").join(BIN_NAME);

    // An entry written by the *system* `gpg`, before anything is scrubbed. This
    // is the ciphertext a `pass` user would already have on disk.
    let entry = staging.path().join("entry.gpg");
    fixture.encrypt(PLAINTEXT, &entry);

    // Process-global, like the fixture's `GNUPGHOME`, and safe for the same
    // reason: this binary holds exactly one test. Scrubbed rather than having
    // one entry removed, so nothing on this machine satisfies the lookup by
    // accident.
    std::env::set_var("PATH", "");

    gnupg::set_bundled_root(root.clone());

    let resolved = match gnupg::bin() {
        Ok(path) => path,
        Err(err) => panic!("nothing resolved with an empty PATH and a bundle present: {err}"),
    };

    // `PATH` is empty, so whatever answered came from a known install location
    // (which are absolute, and so unaffected by the scrub) or from the bundle.
    // Both outcomes are correct; they prove different halves of ADR-14.
    if resolved == bundled {
        println!(
            "this machine has no GnuPG in a known install location: the bundled copy resolved"
        );
    } else {
        println!(
            "a system GnuPG at {} won, as ADR-14 requires",
            resolved.display()
        );
        assert!(
            !resolved.starts_with(&root),
            "a system GnuPG must outrank the bundled one"
        );
    }

    // Claim 2, checked unconditionally by naming the binary rather than letting
    // the resolver pick: a `gpg` living at a bundled path reads an entry the
    // system one wrote. That is the whole of what the fallback has to do.
    let plaintext = match gnupg::decrypt_file(&bundled, &entry) {
        Ok(secret) => secret,
        Err(err) => panic!("the bundled gpg could not decrypt a real entry: {err}"),
    };
    assert_eq!(plaintext.expose(), PLAINTEXT);
}

/// Produce a directory holding `gnupg/bin/<gpg>`, or `None` if we cannot.
///
/// Two strategies, because "a relocated `gpg`" means different things per
/// platform:
///
/// - Where CI (or a developer) has already run `scripts/fetch-gnupg.sh`, the
///   real staged tree is right there in the crate. That is the *actual* bundle —
///   the DLLs and `share/` a Windows GnuPG needs, or on macOS a tree built
///   somewhere that no longer exists — so it is the better test wherever it
///   exists. **On macOS it is the only check of ADR-14's relocation that runs
///   unattended:** the decrypt below needs `gpg-agent`, `gpg` can only find it
///   through the staged `bin/gpgconf.ctl`, and a broken `rootdir` therefore
///   fails here rather than in front of a user.
/// - Otherwise, on Unix, copy the system `gpg`. A lone GnuPG binary works there
///   because its helper paths are compiled in rather than resolved beside the
///   executable — which is exactly what the staged tree has to work *around*,
///   and why a bare copy is a fair stand-in for the fallback but not for the
///   bundle. It carries no `gpgconf.ctl`, so the relocation variable
///   `crypto::gnupg` sets for it goes unread, as it does for a system GnuPG.
///
/// A bare copy on Windows would be neither, so that case returns `None` and the
/// test skips rather than asserting something untrue.
fn bundle_root(staging: &Path) -> Option<PathBuf> {
    let staged = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    if staged.join("gnupg").join("bin").join(BIN_NAME).is_file() {
        return Some(staged);
    }

    if cfg!(windows) {
        return None;
    }

    let system = which::which(BIN_NAME).ok()?;
    let bin_dir = staging.join("gnupg").join("bin");
    fs::create_dir_all(&bin_dir).unwrap();
    let copy = bin_dir.join(BIN_NAME);
    // `fs::copy` carries the mode across on Unix, so the copy stays executable.
    fs::copy(&system, &copy).unwrap();
    Some(staging.to_path_buf())
}
