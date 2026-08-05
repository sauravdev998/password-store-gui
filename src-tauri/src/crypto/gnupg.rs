//! The whole `Gpg` backend: our own `gpg` invocation, for every operation.
//!
//! Encryption and decryption arrived here by different routes, and both are
//! worth keeping straight because they explain why the flag lists below look
//! the way they do.
//!
//! **Encryption was never `prs-lib`'s** (ADR-6). Decrypting has no
//! flag-compatibility surface — `gpg --decrypt` reads what the file says it is.
//! Encrypting is the opposite: the argument list *is* the access-control
//! decision, so who ends up able to read the entry is decided by the flags
//! below. Three `prs-lib` behaviours make its encrypt path unusable for us
//! (`PLAN.md` ADR-6, F-8/9/10):
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
//!
//! **Decryption stopped being `prs-lib`'s** in ADR-4b, for an unrelated reason:
//! ADR-14 bundles a GnuPG, and `prs-lib` cannot be told which binary to run.
//! Its `find_gpg_bin` is a private `which::which("gpg")` with no environment
//! override, so a bundled `gpg` off `PATH` is unreachable through it — and the
//! one workaround, mutating `PATH` with `std::env::set_var`, is process-global
//! and `unsafe` under edition 2024, which this crate forbids. Owning decryption
//! makes [`bin`] the single place a `gpg` path is chosen, which is what
//! `resolve` needs to be true. The three `prs-lib` behaviours the old
//! `crypto/prs.rs` existed to route around — `gpg_tty` forcing loopback
//! pinentry (F-2), `verbose` printing raw `gpg` stdout that can hold plaintext
//! (F-3), and `can_decrypt` inspecting a decrypted secret as a `&str` without
//! zeroizing it (F-5) — are now unreachable rather than merely avoided.

use std::collections::BTreeSet;
use std::fs;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::sync::{Mutex, OnceLock};

use crate::crypto::{Gpg, KeyIds, KeyInfo};
use crate::error::{Error, Result};
use crate::secret::Secret;
use crate::store::Recipients;

/// The binary we look for.
#[cfg(not(windows))]
const BIN_NAME: &str = "gpg";
#[cfg(windows)]
const BIN_NAME: &str = "gpg.exe";

/// The oldest GnuPG we will drive, as `(major, minor)`.
///
/// Inherited from `prs-lib`'s `test_gpg_compat`, which ADR-4b removed along with
/// the rest of its context handling. 2.0 is where `gpg-agent` became mandatory
/// rather than optional, which is to say where Invariant 3 became something the
/// binary can actually honour.
const MINIMUM_VERSION: (u32, u32) = (2, 0);

/// Where a bundled GnuPG lives, once the app has told us (ADR-14).
///
/// A `OnceLock` rather than a setting because it is neither: the bundle
/// directory is a fixed property of the installation and cannot change while the
/// process runs, so resolving it once at startup is not the thing `CLAUDE.md`
/// warns against. Everything that *can* change — whether a system `gpg` exists,
/// and which one — is still resolved per call in [`bin`].
///
/// Left unset under `cargo test` and in `pnpm tauri dev`, where there is no
/// bundle; resolution then falls through to `PATH` exactly as it did before.
static BUNDLED_ROOT: OnceLock<PathBuf> = OnceLock::new();

/// Record where the bundled GnuPG tree was installed.
///
/// Called once from the Tauri `setup` hook. A second call is ignored rather than
/// panicking: there is only one right answer and the first caller had it.
pub fn set_bundled_root(root: PathBuf) {
    let _ = BUNDLED_ROOT.set(root);
}

/// The variable a bundled GnuPG's `gpgconf.ctl` expands to find its own tree.
///
/// **The macOS half of ADR-14 rests on this**, and it is the one thing the
/// Windows bundle needed no help with. A Windows GnuPG locates its root from the
/// running `.exe`; a Unix one has its directories compiled in at build time, so
/// a `gpg` copied into an app bundle goes looking for `gpg-agent`, `scdaemon`
/// and the pinentry wherever it was *built*. GnuPG's own answer is a
/// `gpgconf.ctl` file beside `gpgconf`, read relative to the running binary
/// (`common/homedir.c:unix_rootdir`), whose values may contain `${VARIABLE}`
/// expanded from the environment. `scripts/fetch-gnupg.sh` writes that file with
/// this name in it; setting it here is the other half of the contract, and
/// [`tests::the_relocation_variable_matches_the_one_the_script_writes`] is what
/// keeps a rename on either side from being silent.
///
/// The value is a path, not store data — Invariant 5 is untouched.
const BUNDLE_ROOT_VAR: &str = "PASSWORD_STORE_GUI_GNUPG_ROOT";

/// Build a [`Command`] for `bin`, telling it where it lives if it is ours.
///
/// **Every `gpg` this module spawns goes through here**, for the same reason
/// [`bin`] is the only resolver (ADR-4b): a binary launched without the variable
/// would search the build machine's directories, and the failure — a `gpg` that
/// starts, then cannot reach its agent — looks nothing like its cause.
///
/// The child's environment rather than ours: `std::env::set_var` is process-
/// global, races every other thread, and is `unsafe` under edition 2024, which
/// this crate forbids. ADR-4b closed that door for `PATH` and it stays closed
/// here.
///
/// `gpg` spawns `gpg-agent` itself, which inherits this and so reads the same
/// `gpgconf.ctl` — which is what lets the agent find the bundled pinentry.
///
/// A system `gpg` gets nothing added, and the Windows bundle is unaffected in
/// practice: no `gpgconf.ctl` is written there, so nothing expands the variable.
fn gpg(bin: &Path) -> Command {
    let mut command = Command::new(bin);
    if let Some(root) = relocation_root(BUNDLED_ROOT.get().map(PathBuf::as_path), bin) {
        command.env(BUNDLE_ROOT_VAR, root);
    }
    command
}

/// The `rootdir` a bundled `bin` should be told, or `None` if it is not ours.
///
/// Split from [`gpg`] with the bundle root passed in so it can be asserted
/// in a test: reading the `OnceLock` here would make that test set a
/// process-global every other test in the binary would then see.
///
/// The answer is the directory *holding* `bin/`, because that is what a
/// `gpgconf.ctl` `rootdir` means and what [`bundled_bin`] builds its path from.
fn relocation_root(bundled_root: Option<&Path>, bin: &Path) -> Option<PathBuf> {
    let root = bundled_root?.join("gnupg");
    bin.starts_with(&root).then_some(root)
}

/// Locate a usable `gpg` (ADR-14).
///
/// **This is the only place in the crate that decides which binary to run.**
/// Before ADR-4b it was not: `prs-lib` resolved its own for the decrypt path,
/// and the two agreeing was a property maintained by hand — on a machine with
/// more than one GnuPG, the difference between a store that round-trips and one
/// that does not. Now the encrypt path, the decrypt path and every key query
/// come through here.
///
/// The order is the system's first and ours last, which is ADR-14's central
/// choice: a user with a working GnuPG keeps their agent, pinentry, keyring and
/// smartcard exactly as they had them, and the bundled copy only runs when
/// nothing else answered. That is also what keeps two `gpg-agent` versions from
/// meeting over one `~/.gnupg`.
///
/// Every candidate is *probed*, not merely found. That restores the version gate
/// ADR-4b cost us, and it is the same mechanism that steps over a binary which
/// resolves but does not work — Git for Windows' MSYS2 `gpg.exe`, which reads
/// `GNUPGHOME` as an MSYS path, being the case CI already documents.
///
/// Resolved per call, deliberately: installing GnuPG while the app is open takes
/// effect on the next click rather than the next launch.
pub fn bin() -> Result<PathBuf> {
    let bundled = bundled_bin();
    let mut rejected = 0usize;

    for candidate in candidates_with(bundled.clone()) {
        match probe(&candidate) {
            Ok(()) => return Ok(candidate),
            Err(()) => rejected += 1,
        }
    }

    // Both halves of this are `gpg` paths and version numbers, which are not
    // store data — Invariant 5 is untouched. It says which of the two failures
    // happened, because the fixes are opposite: one is "install GnuPG", the
    // other is "the GnuPG you have is too old or does not run".
    Err(Error::GpgUnavailable {
        reason: if rejected == 0 {
            // Only claims the bundle was searched when there was one to search.
            // On Linux there never is (ADR-14), and telling a user we looked
            // inside the app for something that was never put there sends them
            // to inspect the wrong thing.
            format!(
                "no {BIN_NAME} on PATH{}",
                if bundled.is_some() {
                    ", in the usual install locations, or bundled with this app"
                } else {
                    " or in the usual install locations"
                }
            )
        } else {
            format!(
                "found {rejected} {BIN_NAME} {}, but {} run and report GnuPG \
                 {}.{} or newer",
                if rejected == 1 { "binary" } else { "binaries" },
                if rejected == 1 {
                    "it does not"
                } else {
                    "none of them"
                },
                MINIMUM_VERSION.0,
                MINIMUM_VERSION.1,
            )
        },
    })
}

/// The bundled `gpg`, if this installation actually carries one.
///
/// `None` covers three cases that are all the same to a caller: Linux, which is
/// not bundled for; a development build, where nothing was staged; and a damaged
/// bundle whose binary is missing. Checking for the file rather than trusting
/// [`BUNDLED_ROOT`] is what keeps [`bin`]'s error from claiming we searched a
/// bundle that was never there — the resource directory resolves on every
/// platform, bundle or no bundle.
///
/// `bin/` beside `share/` is the layout GnuPG's own Windows distribution unpacks
/// to and the one `scripts/fetch-gnupg.sh` reproduces; GnuPG locates its helpers
/// relative to the running executable, so the structure is load-bearing rather
/// than cosmetic.
fn bundled_bin() -> Option<PathBuf> {
    let candidate = BUNDLED_ROOT.get()?.join("gnupg").join("bin").join(BIN_NAME);
    candidate.is_file().then_some(candidate)
}

/// The candidate list, with the bundled binary passed in rather than read.
///
/// A parameter so the ordering — the whole of ADR-14's "system first" — can be
/// asserted in a test. Reading the `OnceLock` here instead would make that test
/// set a process-global that every other test in the binary would then see.
///
/// Ordinary duplicates are expected: the `PATH` hit is usually one of the known
/// locations too. They cost nothing but a repeated `--version`, and only when
/// the first candidate was already rejected.
fn candidates_with(bundled: Option<PathBuf>) -> Vec<PathBuf> {
    let mut found = Vec::new();

    // The user's own `PATH`, first and unconditionally.
    if let Ok(path) = which::which(BIN_NAME) {
        found.push(path);
    }

    found.extend(install_locations());

    // Ours, last.
    found.extend(bundled);

    found
}

/// Where each platform's GnuPG installers actually put the binary.
///
/// A `PATH` lookup misses these more often than not: Gpg4win does not add itself
/// to `PATH` for GUI processes, and a macOS app launched from Finder inherits a
/// `PATH` with neither Homebrew prefix on it.
fn install_locations() -> Vec<PathBuf> {
    #[cfg(windows)]
    {
        // Gpg4win installs 32-bit by default, so the x86 tree is the likelier
        // of the two even on a 64-bit machine.
        ["ProgramFiles(x86)", "ProgramFiles"]
            .iter()
            .filter_map(std::env::var_os)
            .map(|prefix| {
                PathBuf::from(prefix)
                    .join("GnuPG")
                    .join("bin")
                    .join(BIN_NAME)
            })
            .collect()
    }

    #[cfg(target_os = "macos")]
    {
        [
            // GPG Suite, which is what gpgtools.org installs.
            "/usr/local/MacGPG2/bin/gpg",
            // Homebrew on Apple silicon, then on Intel, then MacPorts.
            "/opt/homebrew/bin/gpg",
            "/usr/local/bin/gpg",
            "/opt/local/bin/gpg",
        ]
        .iter()
        .map(PathBuf::from)
        .collect()
    }

    #[cfg(all(unix, not(target_os = "macos")))]
    {
        ["/usr/bin/gpg", "/usr/local/bin/gpg"]
            .iter()
            .map(PathBuf::from)
            .collect()
    }
}

/// Check that `candidate` runs and is a GnuPG new enough to drive.
///
/// The failure carries nothing: [`bin`] only counts these, and the one thing
/// worth saying — that a binary was found and rejected — is a count. Running
/// `--version` is also the cheapest way to find out that a path exists and is
/// not usable, which no amount of inspecting the filesystem establishes.
fn probe(candidate: &Path) -> std::result::Result<(), ()> {
    if VERIFIED.lock().is_ok_and(|seen| seen.contains(candidate)) {
        return Ok(());
    }

    let output = gpg(candidate)
        .arg("--version")
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .output()
        .map_err(|_| ())?;

    if !output.status.success() {
        return Err(());
    }

    // Lossy is right here: this is `gpg`'s own banner, never store content, and
    // a non-UTF-8 byte in it should not stop us reading the version out of it.
    let banner = String::from_utf8_lossy(&output.stdout);
    match banner.lines().next().and_then(parse_version) {
        Some(version) if version >= MINIMUM_VERSION => {
            if let Ok(mut seen) = VERIFIED.lock() {
                seen.insert(candidate.to_path_buf());
            }
            Ok(())
        }
        _ => Err(()),
    }
}

/// Paths already known to be a usable GnuPG.
///
/// [`bin`] runs on every command and every key query — `plan_recipients` calls
/// it once per entry in a subtree — and without this each of those would spawn
/// `gpg --version` first. `prs-lib` cached the equivalent check in a
/// thread-local context; losing that with ADR-4b should not cost a subprocess
/// per operation.
///
/// **Successes only**, which is what makes it safe against the property ADR-14
/// keeps: a path that failed is re-probed every time, so installing GnuPG — or
/// repairing one — while the app is open still takes effect on the next click.
/// The narrow thing this gets wrong is a working `gpg` replaced mid-session by a
/// broken one at the same path, which is not a state worth a subprocess per
/// call to detect.
///
/// It holds `gpg` paths, which are not store data.
static VERIFIED: Mutex<BTreeSet<PathBuf>> = Mutex::new(BTreeSet::new());

/// Pull `(major, minor)` out of `gpg --version`'s first line.
///
/// Deliberately looser than `prs-lib`'s `test_gpg_compat`, which stripped the
/// literal prefix `"gpg (GnuPG) "` and so rejected GPG Suite outright — it
/// announces itself as `gpg (GnuPG/MacGPG2) 2.2.41`. ADR-14 puts GPG Suite in
/// the list of installations we look for, which would be pointless if the probe
/// then turned it away.
fn parse_version(line: &str) -> Option<(u32, u32)> {
    let line = line.trim();
    if !line.starts_with("gpg ") {
        return None;
    }

    // The version is the last field on the line in every spelling of the banner
    // seen so far; the parenthesized part in the middle is what varies.
    let mut parts = line.rsplit(' ').next()?.split('.');
    let major = parts.next()?.parse().ok()?;
    let minor = parts.next().unwrap_or("0").parse().ok()?;
    Some((major, minor))
}

/// The argument list for a decryption, pinned so a test can read it.
///
/// Short, because decryption has no access-control surface to get wrong — the
/// ciphertext names its own recipients and algorithms. What matters is what is
/// *absent*: no `--pinentry-mode`, no `--passphrase` in any spelling. The
/// passphrase is `gpg-agent`'s (Invariant 3), and
/// [`tests::the_decrypt_arguments_never_handle_a_passphrase`] keeps it that way.
///
/// `--batch` is here for ADR-7's reason, which applies to every spawn in a
/// windowed process and not just to key generation: it governs `gpg`'s own
/// prompts, which have no terminal to appear on, and it does **not** suppress
/// the agent's pinentry — which decryption needs. `pass` passes it too.
/// `prs-lib` did not, which is a difference in our favour: without it `gpg` can
/// try to ask a question no GUI can answer.
///
/// Unlike the encrypt path there is no `--utf8-strings`: that governs how `gpg`
/// reads string *arguments*, and this invocation has none. The plaintext comes
/// back over a pipe as bytes and is never decoded here.
const DECRYPT_ARGV: [&str; 3] = ["--batch", "--quiet", "--decrypt"];

/// Decrypt `ciphertext` in memory.
///
/// Nothing is written to disk on the way: the ciphertext goes in over a pipe and
/// the plaintext comes back over one (Invariant 1), landing directly in a
/// [`Secret`] so it is zeroized when dropped.
pub fn decrypt(bin: &Path, ciphertext: &[u8]) -> Result<Secret> {
    let mut child = gpg(bin)
        .args(DECRYPT_ARGV)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        // Dropped rather than captured, and this is the sharper case of the two:
        // a *partial* decrypt failure can leave plaintext in what `gpg` prints
        // (ADR-4a F-3, which is exactly the bug `prs-lib`'s `verbose` flag has).
        // There is nothing here worth the risk of holding it.
        .stderr(Stdio::null())
        .spawn()
        .map_err(|err| Error::io(bin, err))?;

    let Some(mut stdin) = child.stdin.take() else {
        // Only reachable if the pipe above was not set up; killing the child
        // rather than leaking it, since it would otherwise wait on stdin.
        let _ = child.kill();
        return Err(Error::DecryptBlob);
    };

    // The same shape as `encrypt`, with the roles reversed, and for the same
    // reason (F-10): feeding stdin to completion before reading stdout deadlocks
    // once the unread output fills the pipe buffer. Here it is the *plaintext*
    // that fills it, so the deadlock is a hang with a secret in a kernel buffer.
    let (fed, output) = std::thread::scope(|scope| {
        let feeder = scope.spawn(move || {
            let result = stdin.write_all(ciphertext);
            // Explicit, though the drop at the end of this closure would do it:
            // `gpg` waits for EOF on stdin before it finishes.
            drop(stdin);
            result
        });
        let output = child.wait_with_output();
        // A panic in the feeder becomes an error rather than propagating, as in
        // `encrypt`: unwinding past a secret buffer is what `panic = "abort"`
        // exists to prevent, and an `Err` says the same thing.
        let fed = feeder
            .join()
            .unwrap_or(Err(std::io::ErrorKind::Other.into()));
        (fed, output)
    });

    let output = output.map_err(|err| Error::io(bin, err))?;

    // Wrapped **before** anything is checked. On a failed decrypt `gpg` can
    // still have written part of the plaintext to stdout, so the buffer is put
    // in a zeroizing container on every path rather than only the happy one.
    let plaintext = Secret::new(output.stdout);

    fed.map_err(|_| Error::DecryptBlob)?;
    if !output.status.success() {
        // The exit status is dropped on purpose, as ADR-4a decided for this
        // path: it is the one place where plaintext exists in the process, so
        // the error leaving it is secret-free by construction rather than by
        // audit. What the user needs to know — a bad passphrase, a cancelled
        // pinentry, a missing secret key — `gpg` has already told them through
        // its own prompt.
        return Err(Error::DecryptBlob);
    }

    Ok(plaintext)
}

/// Decrypt the file at `path`.
///
/// The ciphertext is read here rather than handed to `gpg` as an argument so
/// that a read failure can name the file. `prs-lib`'s `decrypt_file` swallowed
/// the path, which is why this indirection existed before ADR-4b too.
pub fn decrypt_file(bin: &Path, path: &Path) -> Result<Secret> {
    let ciphertext = fs::read(path).map_err(|source| Error::io(path, source))?;
    // The pathless failure becomes one that names the file. Nothing else is
    // carried across — the discarded error held only an exit status, and this is
    // the path where plaintext exists in the process.
    decrypt(bin, &ciphertext).map_err(|_| Error::Decrypt { path: path.into() })
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
        let output = gpg(bin)
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

/// What a recipient id resolves to on this machine's keyring.
///
/// **Decrypts nothing and needs no secret key.** It reads the public keyring
/// only, so it costs no pinentry and no security-key tap — which is what makes
/// it usable for a question asked *before* the user has committed to anything
/// (§4.1 principle 1). Every spelling a `.gpg-id` may use resolves the same
/// way, because resolving it is `gpg`'s job and not ours (ADR-6): a bare email,
/// a full user id, a long key id, a fingerprint, and an `0x`-prefixed key id
/// all land on the same subkey.
///
/// An id `gpg` cannot resolve is an error rather than a description with no
/// keys in it. Returning nothing would be F-8 rebuilt by hand — the silent drop
/// that encrypts an entry to fewer people than the store demands.
pub fn describe_key(bin: &Path, id: &str, secret: &KeyIds) -> Result<KeyInfo> {
    let output = gpg(bin)
        .args(["--batch", "--quiet", "--utf8-strings"])
        .args(["--with-colons", "--list-keys"])
        // Ends option parsing, so an id beginning with `-` is an id.
        .arg("--")
        .arg(id)
        .stdin(Stdio::null())
        .stderr(Stdio::null())
        .output()
        .map_err(|err| Error::io(bin, err))?;

    if !output.status.success() {
        return Err(Error::UnknownKey { id: id.to_owned() });
    }

    let mut info = parse_key_listing(&String::from_utf8_lossy(&output.stdout), id);
    if info.keys.is_empty() {
        // A key that resolves but can encrypt to nothing — every encryption
        // subkey revoked or expired. `gpg` would refuse the encrypt later; this
        // says so now, with the id in hand to name.
        return Err(Error::UnusableKey { id: id.to_owned() });
    }
    info.usable_here = !info.keys.is_disjoint(secret);
    Ok(info)
}

/// The encryption subkeys this machine holds a secret key for.
///
/// Read once per operation rather than per id: it is the whole keyring, and the
/// question asked of it — "would this change leave the user unable to read their
/// own store?" — is asked about a set, not about one key.
///
/// A smartcard's key counts. `gpg` lists a stub for it exactly as it lists a key
/// on disk, which is the answer we want: the user can decrypt with it, given
/// the card. §4.1 principle 1 calls a security key a confirmed operating
/// condition, not a hypothetical.
pub fn secret_keys(bin: &Path) -> Result<KeyIds> {
    let output = gpg(bin)
        .args(["--batch", "--quiet", "--utf8-strings"])
        .args(["--with-colons", "--list-secret-keys"])
        .stdin(Stdio::null())
        .stderr(Stdio::null())
        .output()
        .map_err(|err| Error::io(bin, err))?;

    // A keyring with no secret key at all exits non-zero, which is a state
    // rather than a failure: it is what a machine that has only ever been
    // written to looks like.
    if !output.status.success() {
        return Ok(KeyIds::new());
    }

    Ok(parse_subkeys(
        &String::from_utf8_lossy(&output.stdout),
        "ssb",
    ))
}

/// Pull the label, fingerprint and encryption subkeys out of a key listing.
///
/// The colon format is documented and stable, which is why it is parsed rather
/// than the human listing: field 1 is the record type, 2 the validity, 5 the key
/// id, 10 the user id and 12 the capabilities. The `fpr` immediately after a
/// `pub` is the primary key's; the ones after a `sub` belong to that subkey and
/// are skipped, which is why this tracks the record it is inside rather than
/// taking the first `fpr` it sees.
///
/// An id that matches more than one key contributes all of their subkeys, and
/// the first key's label. That is the honest reading of an ambiguous id, and
/// `gpg` refuses to encrypt to one anyway.
fn parse_key_listing(listing: &str, id: &str) -> KeyInfo {
    let mut info = KeyInfo {
        id: id.to_owned(),
        label: None,
        fingerprint: None,
        usable_here: false,
        keys: KeyIds::new(),
    };
    let mut in_primary = false;

    for fields in listing
        .lines()
        .map(|line| line.split(':').collect::<Vec<_>>())
    {
        match fields.first() {
            Some(&"pub") => in_primary = true,
            Some(&"fpr") if in_primary => {
                if info.fingerprint.is_none() {
                    info.fingerprint = fields.get(9).map(|fpr| (*fpr).to_owned());
                }
                in_primary = false;
            }
            Some(&"uid") if info.label.is_none() => {
                info.label = fields
                    .get(9)
                    .map(|uid| unescape_colon_field(uid))
                    .filter(|uid| !uid.is_empty());
            }
            Some(&"sub") => in_primary = false,
            _ => {}
        }
    }

    info.keys = parse_subkeys(listing, "sub");
    info
}

/// Encryption-capable subkey ids of the given record type (`sub` or `ssb`).
///
/// A subkey counts when it can encrypt (`e`) and is not invalid, disabled or
/// revoked — the same three exclusions `pass`'s own `reencrypt_path` makes, so
/// the two agree about which keys a `.gpg-id` line means.
fn parse_subkeys(listing: &str, record: &str) -> KeyIds {
    listing
        .lines()
        .map(|line| line.split(':').collect::<Vec<_>>())
        .filter(|fields| fields.first() == Some(&record) && fields.len() > 11)
        .filter(|fields| fields[11].contains('e'))
        .filter(|fields| !fields[1].contains(['i', 'd', 'r']))
        .map(|fields| fields[4].to_owned())
        .filter(|id| !id.is_empty())
        .collect()
}

/// Undo the colon format's `\x3a` escaping of a colon inside a user id.
///
/// `gpg` escapes only that one character in this field, so this is the whole
/// rule rather than a subset of one.
fn unescape_colon_field(field: &str) -> String {
    field.replace("\\x3a", ":")
}

/// The subkeys a ciphertext on disk is actually encrypted to.
///
/// The counterpart to [`encryption_keys`]: that one says who the store *wants*
/// to be able to read an entry, this one says who *can*. Comparing them is how
/// a recipient change knows which entries it has to touch.
///
/// **Decrypts nothing.** `--list-packets` parses the file's structure and stops;
/// it reports the recipient key ids even for ciphertext this machine holds no
/// secret key for, so an entry the user cannot read is still one they can be
/// told about. It is also not localized, unlike the `gpg: public key is …` line
/// `pass` greps for, which a non-English locale would change out from under us.
pub fn encrypted_to(bin: &Path, path: &Path) -> Result<KeyIds> {
    let output = gpg(bin)
        .args(["--batch", "--quiet", "--list-packets"])
        .arg("--")
        .arg(path)
        .stdin(Stdio::null())
        .stderr(Stdio::null())
        .output()
        .map_err(|err| Error::io(bin, err))?;

    // **The exit status is deliberately ignored.** `--list-packets` walks into
    // the encrypted data packet after listing the recipients and exits 2 with
    // "decryption failed: No secret key" when it cannot open it — which is the
    // expected outcome for exactly the entries this matters most for, the ones
    // encrypted to somebody else. The recipient packets are already on stdout by
    // then. What decides success here is whether we could read the recipient
    // list, so that is what is checked.
    let keys = parse_packet_keyids(&String::from_utf8_lossy(&output.stdout));

    if keys.is_empty() {
        // No recipient packet at all: the file is not OpenPGP ciphertext, or is
        // unreadable. Not `Error::Decrypt` — nothing was decrypted and no key
        // was involved, so reporting a key problem would send the user looking
        // in the wrong place (§4.1 principle 5).
        return Err(Error::UnreadableCiphertext {
            path: path.to_path_buf(),
        });
    }
    Ok(keys)
}

/// Pull recipient key ids out of a `--list-packets` listing.
///
/// One `:pubkey enc packet:` line per recipient, each ending in `keyid <id>`. A
/// ciphertext written with `--throw-keyids` reports all-zero ids; those are kept
/// rather than dropped, so a hidden recipient reads as a key the store does not
/// list instead of as no recipient at all — the direction that reports a problem
/// rather than concealing one.
fn parse_packet_keyids(listing: &str) -> KeyIds {
    listing
        .lines()
        .map(str::trim_start)
        .filter(|line| line.starts_with(":pubkey enc packet:"))
        .filter_map(|line| line.rsplit_once("keyid "))
        .map(|(_, id)| id.trim().to_owned())
        .filter(|id| !id.is_empty())
        .collect()
}

/// Run `gpg`, returning the ciphertext.
fn encrypt(bin: &Path, recipients: &Recipients, plaintext: &Secret) -> Result<Vec<u8>> {
    let mut command = gpg(bin);
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

/// Write `ciphertext` to `path`, replacing it only once the write succeeded.
///
/// Delegated to [`crate::atomic`], which is also what a `.gpg-id` and the
/// settings file go through — an interrupted write that truncates an entry into
/// something that decrypts nowhere is the failure all three are avoiding.
fn write_atomically(path: &Path, ciphertext: &[u8]) -> Result<()> {
    crate::atomic::write(path, ciphertext)
}

/// How long a generated key lasts: not a fixed term (ADR-7).
///
/// Deliberately against `gpg`'s own habit of proposing two years. An expired key
/// still **decrypts** — what expiry stops is being *encrypted to*. So a term
/// here would hand this app's primary user a store they can read and cannot
/// write, on a date they will not remember, and the repair
/// (`gpg --edit-key … expire`) is a terminal session, which is the one thing
/// they do not have. §4.1 principle 5 says name the fix; better still is not to
/// build the trap.
const EXPIRY: &str = "never";

/// Create a new key pair, with the passphrase prompt left to the agent.
///
/// **This is the sharpest Invariant 3 site in the codebase**, and ADR-7 settled
/// it by probing a real `gpg` rather than by reasoning:
///
/// - `--batch` **does not suppress the pinentry.** It governs `gpg`'s own
///   prompts; the new key's passphrase belongs to `gpg-agent`, which asks
///   regardless. A dismissed prompt exits non-zero and leaves **no key behind**,
///   so a refusal here is a clean no-op rather than a half-made key.
/// - Omitting `--batch` does not "let the user be asked" — it fails with
///   `cannot open '/dev/tty'` *before the agent is ever reached*, because `gpg`
///   wants to print its "Continue? (y/N)" confirmation to a terminal a windowed
///   process does not have.
///
/// So `--batch` is required, and Invariant 3 is satisfied by it rather than
/// despite it. Nothing here passes `--passphrase`, sets `--pinentry-mode`, or
/// writes `%no-protection`; [`tests::the_generate_arguments_never_handle_a_passphrase`]
/// is what keeps it that way.
pub fn generate_key(bin: &Path, name: &str, email: &str) -> Result<KeyInfo> {
    let uid = build_uid(name, email)?;

    let output = gpg(bin)
        .args(generate_argv(&uid))
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        // `gpg`'s human-readable half is dropped: it is localized, so nothing
        // can be decided from it, and everything worth deciding is on the
        // status pipe below in a form that does not move between locales.
        .stderr(Stdio::null())
        .output()
        .map_err(|err| Error::io(bin, err))?;

    let status = String::from_utf8_lossy(&output.stdout);

    let Some(fingerprint) = key_created(&status) else {
        // A dismissed pinentry is not a failure to report as one: nothing is
        // broken and nothing was created, and the user knows what they just
        // clicked. Telling the two apart is what makes the difference sayable
        // (§4.1 principle 5).
        return Err(if cancelled(&status) {
            Error::KeyGenerationCancelled
        } else {
            Error::KeyGeneration
        });
    };

    // Described rather than assumed, and by fingerprint rather than by the user
    // id just typed. Two reasons: `describe_key` refuses a key with no usable
    // encryption subkey, so a key that could not back a store is caught here
    // instead of at the first save; and a fingerprint is unambiguous where an
    // email is not, which matters because this string is about to be written
    // into a `.gpg-id` and resolved again on every future write.
    describe_key(bin, &fingerprint, &secret_keys(bin)?)
}

/// The argument list [`generate_key`] runs.
///
/// Split out so a unit test can read it without a keyring, a pinentry, or a
/// `gpg` — which is the only way this path is checkable in CI at all, since a
/// real generation raises a prompt no unattended runner can answer (ADR-7).
fn generate_argv(uid: &str) -> Vec<String> {
    [
        "--batch",
        "--quiet",
        // The user id is free text a human typed, and may hold non-ASCII.
        "--utf8-strings",
        // The machine-readable channel: `KEY_CREATED` carries the fingerprint,
        // and an `ERROR` line carries a numeric code. Both are stable across
        // locales, unlike the messages on stderr.
        "--status-fd",
        "1",
        "--quick-generate-key",
        uid,
        // The algorithm and usage `gpg` itself would choose. Naming one would
        // pin a decision that ages: on 2.4 this yields an ed25519 primary with a
        // cv25519 encryption subkey, which is the `sub …:e:` record
        // `parse_subkeys` looks for, and a later GnuPG may prefer better.
        "default",
        "default",
        EXPIRY,
    ]
    .iter()
    .map(|arg| (*arg).to_owned())
    .collect()
}

/// The fingerprint `gpg` reports for a key it just made.
///
/// `KEY_CREATED <type> <fingerprint>`, where the type is `B` for a primary key
/// generated with its subkeys.
fn key_created(status: &str) -> Option<String> {
    status
        .lines()
        .filter_map(|line| line.trim_end().strip_prefix("[GNUPG:] KEY_CREATED "))
        .filter_map(|rest| rest.split_whitespace().nth(1))
        .map(str::to_owned)
        .next()
}

/// Whether the run ended because somebody dismissed the pinentry.
///
/// A GPG error code is `(source << 24) | code`; the low half is what matters,
/// and 99 is `GPG_ERR_CANCELED` with 100 `GPG_ERR_FULLY_CANCELED`. Read as a
/// number rather than grepped for "cancelled", which would be a different word
/// on a machine with a different locale.
fn cancelled(status: &str) -> bool {
    status
        .lines()
        .filter_map(|line| line.trim_end().strip_prefix("[GNUPG:] ERROR "))
        .filter_map(|rest| rest.split_whitespace().nth(1))
        .filter_map(|code| code.parse::<u32>().ok())
        .any(|code| matches!(code & 0xFFFF, 99 | 100))
}

/// Assemble and check the `Name <email>` a generated key carries.
///
/// Validated here rather than left to `gpg`, which reports every malformed user
/// id as a bare `Invalid user ID` with nothing said about which half was wrong —
/// and the wizard has two fields it could be pointing at (§4.1 principle 5).
/// Neither error echoes what was typed: unlike a `.gpg-id` id, it is still in
/// the box in front of the user.
fn build_uid(name: &str, email: &str) -> Result<String> {
    let name = name.trim();
    let email = email.trim();

    // `<` and `>` delimit the email and `(` and `)` the comment field, so a
    // name holding one would produce a user id that parses as something else.
    // A leading `-` would be read as an option, which is why every other
    // argument site here ends option parsing with `--`; this one cannot,
    // because `--quick-generate-key` takes its operands positionally.
    if name.is_empty()
        || name.starts_with('-')
        || name.contains(['<', '>', '(', ')'])
        || name.chars().any(char::is_control)
    {
        return Err(Error::InvalidKeyName);
    }

    let valid_email = match email.split_once('@') {
        Some((local, domain)) => {
            !local.is_empty()
                && !domain.is_empty()
                && !email.contains(['<', '>', '(', ')'])
                && !email.chars().any(|c| c.is_control() || c.is_whitespace())
        }
        None => false,
    };
    if !valid_email {
        return Err(Error::InvalidKeyEmail);
    }

    Ok(format!("{name} <{email}>"))
}

/// Every key on this machine that could back a store.
///
/// Read off the **secret** keyring, so every key here is one the user can
/// decrypt with — which is what makes offering them the right first move in
/// onboarding (ADR-7). Making a second key for somebody who already has one is
/// how a store ends up encrypted to a key they never backed up.
///
/// A key with no usable encryption subkey is left out rather than offered and
/// then refused: written into a `.gpg-id` it would produce a store `gpg` will
/// not encrypt to, which is [`Error::UnusableKey`] arriving at the worst moment.
pub fn usable_keys(bin: &Path) -> Result<Vec<KeyInfo>> {
    let output = gpg(bin)
        .args(["--batch", "--quiet", "--utf8-strings"])
        .args(["--with-colons", "--list-secret-keys"])
        .stdin(Stdio::null())
        .stderr(Stdio::null())
        .output()
        .map_err(|err| Error::io(bin, err))?;

    // An empty secret keyring exits non-zero, and that is the state onboarding
    // exists for rather than a failure to report.
    if !output.status.success() {
        return Ok(Vec::new());
    }

    Ok(parse_secret_keys(&String::from_utf8_lossy(&output.stdout)))
}

/// Split a secret-key listing into one [`KeyInfo`] per key.
///
/// [`parse_key_listing`] answers about a single id and folds every match
/// together, which is right for "what does this `.gpg-id` line mean" and wrong
/// here: this is a list the user picks *one* of, so the keys have to stay apart.
///
/// The id is the fingerprint, because that is what will be written into a
/// `.gpg-id` — an email can come to match two keys later, a fingerprint cannot.
fn parse_secret_keys(listing: &str) -> Vec<KeyInfo> {
    // The flag rides beside each key rather than in it: a primary key that is
    // expired or revoked has to be dropped *with* its subkeys, and by the time
    // those are read the `sec` line is gone.
    let mut keys: Vec<(KeyInfo, bool)> = Vec::new();
    let mut in_primary = false;

    for fields in listing
        .lines()
        .map(|line| line.split(':').collect::<Vec<_>>())
    {
        match fields.first() {
            Some(&"sec") => {
                let valid = fields
                    .get(1)
                    .is_none_or(|validity| !validity.contains(['i', 'd', 'r', 'e']));
                keys.push((
                    KeyInfo {
                        id: String::new(),
                        label: None,
                        fingerprint: None,
                        // Off the secret keyring by definition: a smartcard's
                        // stub counts, which is the answer §4.1 principle 1
                        // wants since the user can decrypt with it given the
                        // card.
                        usable_here: true,
                        keys: KeyIds::new(),
                    },
                    valid,
                ));
                in_primary = true;
            }
            Some(&"fpr") if in_primary => {
                if let (Some((key, _)), Some(fpr)) = (keys.last_mut(), fields.get(9)) {
                    if key.fingerprint.is_none() {
                        key.fingerprint = Some((*fpr).to_owned());
                        key.id = (*fpr).to_owned();
                    }
                }
                in_primary = false;
            }
            Some(&"uid") => {
                if let (Some((key, _)), Some(uid)) = (keys.last_mut(), fields.get(9)) {
                    if key.label.is_none() {
                        key.label = Some(unescape_colon_field(uid)).filter(|uid| !uid.is_empty());
                    }
                }
            }
            Some(&"ssb") => {
                in_primary = false;
                // The same three exclusions `parse_subkeys` makes, applied to
                // the secret keyring's own record type.
                if fields.len() > 11
                    && fields[11].contains('e')
                    && !fields[1].contains(['i', 'd', 'r'])
                {
                    if let (Some((key, _)), Some(id)) = (keys.last_mut(), fields.get(4)) {
                        if !id.is_empty() {
                            key.keys.insert((*id).to_owned());
                        }
                    }
                }
            }
            _ => {}
        }
    }

    keys.into_iter()
        .filter(|(key, valid)| *valid && !key.id.is_empty() && !key.keys.is_empty())
        .map(|(key, _)| key)
        .collect()
}

/// The [`Gpg`] backend: GnuPG, driven as a subprocess.
///
/// One implementation for every operation as of ADR-4b. It was two — `PrsGpg`
/// held decryption and delegated the rest here — and the split is gone because
/// bundling needs a single answer to "which binary?", which two resolvers
/// cannot give.
pub struct Gnupg {
    /// Zero-sized; the existence of a value is the proof that [`Gnupg::new`]
    /// found a usable GnuPG.
    _validated: (),
}

impl Gnupg {
    /// Check that a usable `gpg` is installed.
    ///
    /// Called when the backend is built, so a missing or too-old GnuPG is one
    /// clear error at that point rather than a surprise on the first reveal.
    /// Every method resolves again for itself, which is not a redundancy: this
    /// is a gate, and those are the per-call resolution ADR-14 keeps so that
    /// installing GnuPG mid-session works.
    pub fn new() -> Result<Self> {
        bin()?;
        Ok(Self { _validated: () })
    }
}

impl Gpg for Gnupg {
    fn decrypt(&self, ciphertext: &[u8]) -> Result<Secret> {
        decrypt(&bin()?, ciphertext)
    }

    fn decrypt_file(&self, path: &Path) -> Result<Secret> {
        decrypt_file(&bin()?, path)
    }

    fn encrypt_file(&self, path: &Path, recipients: &Recipients, plaintext: &Secret) -> Result<()> {
        encrypt_to_file(path, recipients, plaintext)
    }

    fn describe_key(&self, id: &str) -> Result<KeyInfo> {
        let bin = bin()?;
        describe_key(&bin, id, &secret_keys(&bin)?)
    }

    fn encrypted_to(&self, path: &Path) -> Result<KeyIds> {
        encrypted_to(&bin()?, path)
    }

    fn usable_keys(&self) -> Result<Vec<KeyInfo>> {
        usable_keys(&bin()?)
    }

    fn generate_key(&self, name: &str, email: &str) -> Result<KeyInfo> {
        generate_key(&bin()?, name, email)
    }
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

    /// Captured from `gpg --with-colons --list-keys` (GnuPG 2.4.9). Two primary
    /// keys, each with one encryption subkey.
    const KEY_LISTING: &str = "\
pub:u:255:22:A927E66374D6E7FE:1785695396:::u:::scaESCA:::::ed25519:::0:
fpr:::::::::5669E864B1BBDD28ACC242F7A927E66374D6E7FE:
uid:u::::1785695396::08AB80EE7A442010C6165E878ABABF2C61CDBAAF::Test a <a@example.invalid>::::::::::0:
sub:u:255:18:7298DC4C15400BE4:1785695396::::::e:::::cv25519::
fpr:::::::::B5C2C23E0A47A9840E49F9027298DC4C15400BE4:
pub:u:255:22:82C1CC4A844CD7E5:1785695396:::u:::scaESCA:::::ed25519:::0:
sub:u:255:18:D55B72C81442235B:1785695396::::::e:::::cv25519::
";

    fn keys(ids: &[&str]) -> KeyIds {
        ids.iter().map(|id| (*id).to_owned()).collect()
    }

    /// The primary key signs but cannot encrypt, so a ciphertext never names
    /// it — taking the `pub` line's id would compare against something that is
    /// never in a recipient packet, and every entry would read as stale.
    #[test]
    fn only_encryption_subkeys_count_as_recipients() {
        let info = parse_key_listing(KEY_LISTING, "a@example.invalid");
        assert_eq!(info.keys, keys(&["7298DC4C15400BE4", "D55B72C81442235B"]));
    }

    /// The `fpr` after a `sub` belongs to that subkey. Taking the first `fpr`
    /// seen would be right here only by accident of ordering; taking the one
    /// that follows `pub` is right by construction.
    #[test]
    fn the_label_and_fingerprint_come_from_the_primary_key() {
        let info = parse_key_listing(KEY_LISTING, "a@example.invalid");
        assert_eq!(info.id, "a@example.invalid");
        assert_eq!(info.label.as_deref(), Some("Test a <a@example.invalid>"));
        assert_eq!(
            info.fingerprint.as_deref(),
            Some("5669E864B1BBDD28ACC242F7A927E66374D6E7FE"),
            "took a subkey's fingerprint instead of the primary key's"
        );
    }

    /// A key that is not on the keyring still describes itself by the id the
    /// store spells, so the interface can name it rather than showing a blank.
    #[test]
    fn an_unlisted_key_keeps_the_id_it_was_asked_about() {
        let info = parse_key_listing("", "absent@example.invalid");
        assert_eq!(info.id, "absent@example.invalid");
        assert_eq!(info.label, None);
        assert_eq!(info.fingerprint, None);
        assert!(info.keys.is_empty());
    }

    #[test]
    fn a_colon_in_a_user_id_is_unescaped() {
        let listing = "\
pub:u:255:22:A927E66374D6E7FE:1:::u:::scaESCA:::::ed25519:::0:
uid:u::::1::08AB80EE::Weird\\x3aName <w@example.invalid>::::::::::0:
";
        assert_eq!(
            parse_key_listing(listing, "w").label.as_deref(),
            Some("Weird:Name <w@example.invalid>")
        );
    }

    /// The same three exclusions `pass`'s `reencrypt_path` makes, so the two
    /// agree about which keys a `.gpg-id` line means.
    #[test]
    fn revoked_disabled_and_signing_only_subkeys_are_skipped() {
        let listing = "\
sub:r:255:18:0000000000000001:1::::::e:::::cv25519::
sub:d:255:18:0000000000000002:1::::::e:::::cv25519::
sub:i:255:18:0000000000000003:1::::::e:::::cv25519::
sub:u:255:22:0000000000000004:1::::::s:::::ed25519::
sub:u:255:18:0000000000000005:1::::::e:::::cv25519::
";
        assert_eq!(parse_subkeys(listing, "sub"), keys(&["0000000000000005"]));
    }

    /// The secret keyring uses `ssb` where the public one uses `sub`. Reading
    /// the wrong record would report every key as one the user cannot decrypt
    /// with, and so warn about a lockout on every change.
    #[test]
    fn secret_subkeys_are_a_different_record_type() {
        let listing = "\
sec:u:255:22:A927E66374D6E7FE:1785695396:::u:::scaESCA:::+::ed25519:::0:
ssb:u:255:18:7298DC4C15400BE4:1785695396::::::e:::+::cv25519::
";
        assert_eq!(parse_subkeys(listing, "ssb"), keys(&["7298DC4C15400BE4"]));
        assert!(parse_subkeys(listing, "sub").is_empty());
    }

    #[test]
    fn a_listing_with_no_usable_subkey_yields_nothing() {
        assert!(parse_subkeys("", "sub").is_empty());
        assert!(
            parse_subkeys("pub:u:255:22:A927E66374D6E7FE:1::::::scaESCA::\n", "sub").is_empty()
        );
    }

    /// Captured from `gpg --list-packets` on a file encrypted to two keys.
    #[test]
    fn recipient_key_ids_come_off_the_packet_listing() {
        let listing = "\
# off=0 ctb=85 tag=1 hlen=3 plen=118
:pubkey enc packet: version 3, algo 18, keyid 7298DC4C15400BE4
\tdata: [263 bits]
:pubkey enc packet: version 3, algo 18, keyid D55B72C81442235B
\tdata: [262 bits]
:encrypted data packet:
\tlength: 76
";
        assert_eq!(
            parse_packet_keyids(listing),
            keys(&["7298DC4C15400BE4", "D55B72C81442235B"])
        );
    }

    /// `--throw-keyids` hides the recipient behind an all-zero id. Keeping it
    /// means such an entry reads as encrypted to a key the store does not list,
    /// which is a reported problem rather than a concealed one.
    #[test]
    fn a_hidden_recipient_is_kept_rather_than_dropped() {
        let listing = ":pubkey enc packet: version 3, algo 18, keyid 0000000000000000\n";
        assert_eq!(parse_packet_keyids(listing), keys(&["0000000000000000"]));
    }

    /// **Invariant 3, and the only place in CI it can be checked.**
    ///
    /// A real generation raises a pinentry no unattended runner can answer, and
    /// the two ways to avoid that — `--passphrase` and `--pinentry-mode
    /// loopback` — are exactly what §4 forbids. So the argument list is the
    /// thing under test: if a future change reaches for either flag to make the
    /// path testable, it fails here rather than shipping.
    #[test]
    fn the_generate_arguments_never_handle_a_passphrase() {
        let argv = generate_argv("Ada <ada@example.invalid>");

        for forbidden in ["--passphrase", "--passphrase-fd", "--passphrase-file"] {
            assert!(
                !argv.iter().any(|arg| arg.starts_with(forbidden)),
                "{forbidden} would put the new key's passphrase in our process (Invariant 3)"
            );
        }
        assert!(
            !argv.iter().any(|arg| arg.starts_with("--pinentry-mode")),
            "--pinentry-mode loopback routes the prompt through us (Invariant 3, F-2)"
        );
        assert!(
            !argv.iter().any(|arg| arg.contains("no-protection")),
            "%no-protection would create a key with no passphrase at all"
        );
        assert!(
            argv.iter().any(|arg| arg == "--batch"),
            "--batch is required, and ADR-7 is why: without it gpg dies on \
             /dev/tty before gpg-agent is ever reached, so the pinentry never \
             appears at all"
        );
    }

    /// The same guard as the generation one, on the path ADR-4b took over from
    /// `prs-lib`. It matters more here, not less: `prs-lib`'s `gpg_tty` config
    /// set `--pinentry-mode loopback` on *this* invocation (F-2), so the flag
    /// this asserts absent is one the code we replaced could actually reach.
    #[test]
    fn the_decrypt_arguments_never_handle_a_passphrase() {
        let argv = DECRYPT_ARGV;

        for forbidden in ["--passphrase", "--passphrase-fd", "--passphrase-file"] {
            assert!(
                !argv.iter().any(|arg| arg.starts_with(forbidden)),
                "{forbidden} would put the entry's passphrase in our process \
                 (Invariant 3)"
            );
        }
        assert!(
            !argv.iter().any(|arg| arg.starts_with("--pinentry-mode")),
            "--pinentry-mode loopback routes the prompt through us (Invariant 3, F-2)"
        );
        assert!(
            argv.contains(&"--batch"),
            "--batch keeps gpg's own prompts off a terminal this process does \
             not have; it does not suppress the agent's pinentry, which \
             decryption needs (ADR-7)"
        );
    }

    /// ADR-14's central choice, and the one worth a test rather than a comment:
    /// a machine that already has GnuPG keeps using it, and ours is the last
    /// resort. Getting this backwards would stand a second `gpg-agent` version
    /// up against the user's own `~/.gnupg`.
    #[test]
    fn the_bundled_gpg_is_the_last_candidate_tried() {
        let bundled = PathBuf::from("/opt/example-app/resources/gnupg/bin").join(BIN_NAME);
        let candidates = candidates_with(Some(bundled.clone()));

        assert_eq!(
            candidates.last(),
            Some(&bundled),
            "the bundled gpg must sort last, after PATH and every known install \
             location (ADR-14)"
        );
        assert_eq!(
            candidates.iter().filter(|c| **c == bundled).count(),
            1,
            "the bundled tree should contribute exactly one candidate"
        );
    }

    /// The other half: with no bundle — `cargo test`, `pnpm tauri dev`, and
    /// Linux, which ADR-14 does not bundle for — resolution is what it always
    /// was, and nothing points at a directory that does not exist.
    #[test]
    fn without_a_bundle_only_the_system_is_searched() {
        let candidates = candidates_with(None);

        assert!(
            !candidates.is_empty(),
            "the known install locations are unconditional, so the list is \
             never empty even where gpg is absent"
        );
    }

    /// The macOS half of ADR-14: a bundled `gpg` is told where its own tree is,
    /// because on Unix it cannot work that out for itself.
    ///
    /// The root is the directory holding `bin/`, which is what a `gpgconf.ctl`
    /// `rootdir` means. Handing it `bin/` itself would send `gpg` looking for
    /// `bin/bin/gpg-agent`, and the resulting failure — a `gpg` that starts and
    /// then cannot reach its agent — names nothing that would lead here.
    #[test]
    fn the_bundled_gpg_is_told_which_tree_it_belongs_to() {
        let resources = PathBuf::from("/Applications/Password Store.app/Contents/Resources");
        let bundled = resources.join("gnupg").join("bin").join(BIN_NAME);

        assert_eq!(
            relocation_root(Some(&resources), &bundled),
            Some(resources.join("gnupg")),
            "the rootdir is the directory holding bin/, not bin/ itself"
        );
    }

    /// The other direction, and the one that would be a bug rather than a
    /// missing feature: pointing somebody's own GnuPG at our tree would have it
    /// run our `gpg-agent` and our pinentry against their keyring, which is
    /// precisely the mixed-version hazard ADR-14's ordering exists to avoid.
    #[test]
    fn a_system_gpg_is_never_relocated() {
        let resources = PathBuf::from("/Applications/Password Store.app/Contents/Resources");

        for system in ["/opt/homebrew/bin/gpg", "/usr/local/MacGPG2/bin/gpg"] {
            assert_eq!(
                relocation_root(Some(&resources), Path::new(system)),
                None,
                "{system} is not ours to relocate"
            );
        }

        // No bundle at all: `cargo test`, `pnpm tauri dev`, and Linux.
        assert_eq!(
            relocation_root(None, Path::new("/usr/bin/gpg")),
            None,
            "with no bundle there is no tree to point at"
        );
    }

    /// **A contract split across two languages, so neither side can be renamed
    /// quietly.** `scripts/fetch-gnupg.sh` writes the variable into the
    /// `gpgconf.ctl` it stages; this module sets it. If they disagree, the
    /// expansion yields an empty `rootdir`, `gpg` falls back to the paths
    /// compiled in on the build machine, and every operation fails somewhere far
    /// from the cause.
    #[test]
    fn the_relocation_variable_matches_the_one_the_script_writes() {
        let script = include_str!("../../../scripts/fetch-gnupg.sh");

        assert!(
            script.contains(&format!("MAC_ROOT_VAR='{BUNDLE_ROOT_VAR}'")),
            "{BUNDLE_ROOT_VAR} is not the name scripts/fetch-gnupg.sh stages"
        );
    }

    /// Looser than `prs-lib`'s `test_gpg_compat`, on purpose: it stripped the
    /// literal `"gpg (GnuPG) "` and so turned GPG Suite away, which ADR-14
    /// explicitly goes looking for.
    #[test]
    fn the_version_probe_reads_every_spelling_of_the_banner() {
        assert_eq!(parse_version("gpg (GnuPG) 2.4.5"), Some((2, 4)));
        assert_eq!(
            parse_version("gpg (GnuPG/MacGPG2) 2.2.41"),
            Some((2, 2)),
            "GPG Suite announces itself this way, and prs-lib rejected it"
        );
        assert_eq!(parse_version("  gpg (GnuPG) 2.5.21  "), Some((2, 5)));

        assert_eq!(parse_version("gpg (GnuPG) 1.4.23"), Some((1, 4)));
        assert!(
            (1, 4) < MINIMUM_VERSION,
            "GnuPG 1.x parses, and is then rejected by the floor rather than by \
             the parser — it predates a mandatory gpg-agent, which is what \
             Invariant 3 rests on"
        );
    }

    /// A probe that accepted anything runnable would defeat the point: the
    /// binary this steps over is a real one (Git for Windows' MSYS2 `gpg.exe`),
    /// not a hypothetical.
    #[test]
    fn the_version_probe_rejects_what_is_not_a_gnupg_banner() {
        assert_eq!(parse_version(""), None);
        assert_eq!(parse_version("bash: gpg: command not found"), None);
        assert_eq!(
            parse_version("gpgconf (GnuPG) 2.4.5"),
            None,
            "another GnuPG tool is not the one we drive"
        );
        assert_eq!(parse_version("gpg (GnuPG) unknown"), None);
    }

    /// A missing file must fail before `gpg` is ever spawned, so the error is
    /// ours and names the path. Carried over from `crypto/prs.rs`, which ADR-4b
    /// deleted: `prs-lib`'s own `decrypt_file` swallowed the path, and this is
    /// the test that kept us from inheriting that.
    #[test]
    fn a_missing_ciphertext_file_is_an_io_error_with_its_path() {
        let dir = tempfile::tempdir().unwrap();
        let missing = dir.path().join("absent.gpg");

        // The read happens before the binary is touched, so this test needs no
        // `gpg` on the machine and the path below is never executed.
        match decrypt_file(Path::new("/nonexistent/gpg"), &missing) {
            Err(Error::Io { path, .. }) => assert_eq!(path, missing),
            // Matched arm by arm rather than debug-printing the `Result`:
            // `Secret` has no `Debug`, which is the point of it having none.
            Err(other) => panic!("expected an Io error, got {other:?}"),
            Ok(_) => panic!("expected an Io error for a missing file"),
        }
    }

    /// ADR-7: an expired key still decrypts but can no longer be encrypted to,
    /// so a term here yields a store that can be read and not written — and the
    /// repair is a terminal session this app's user does not have.
    #[test]
    fn the_generated_key_never_expires() {
        assert_eq!(
            generate_argv("Ada <ada@example.invalid>").last().unwrap(),
            "never"
        );
    }

    /// Captured from `gpg --status-fd 1 --quick-generate-key` (GnuPG 2.4.9).
    #[test]
    fn the_new_keys_fingerprint_comes_off_the_status_pipe() {
        let status = "\
[GNUPG:] PINENTRY_LAUNCHED 3
[GNUPG:] KEY_CONSIDERED EF35CE385109C088C07F4A66AB496E22CB423BC4 0
[GNUPG:] KEY_CREATED B EF35CE385109C088C07F4A66AB496E22CB423BC4
";
        assert_eq!(
            key_created(status).as_deref(),
            Some("EF35CE385109C088C07F4A66AB496E22CB423BC4")
        );
        assert!(!cancelled(status));
    }

    /// The other captured run: pinentry dismissed. Nothing was created, and
    /// saying "it failed" would describe a fault where there was a choice.
    #[test]
    fn a_dismissed_pinentry_is_told_apart_from_a_failure() {
        let dismissed = "\
[GNUPG:] PINENTRY_LAUNCHED 3
[GNUPG:] ERROR key_generate 83886179
[GNUPG:] KEY_NOT_CREATED
[GNUPG:] FAILURE gpg-exit 33554433
";
        assert_eq!(key_created(dismissed), None);
        assert!(
            cancelled(dismissed),
            "83886179 & 0xFFFF is 99, GPG_ERR_CANCELED"
        );

        // A malformed user id produces no ERROR line at all, only a failure —
        // which must not be reported to the user as their own cancellation.
        let rejected = "[GNUPG:] FAILURE gpg-exit 33554433\n";
        assert_eq!(key_created(rejected), None);
        assert!(!cancelled(rejected));
    }

    #[test]
    fn a_user_id_is_assembled_from_a_name_and_an_email() {
        assert_eq!(
            build_uid("  Ada Lovelace  ", " ada@example.invalid ").unwrap(),
            "Ada Lovelace <ada@example.invalid>"
        );
    }

    /// The angle brackets delimit the email and the parentheses the comment
    /// field, so a name holding either would produce a user id that parses as
    /// something other than what was typed. A leading `-` would be read as an
    /// option: `--quick-generate-key` takes its operands positionally, so
    /// unlike every other `gpg` call here this one cannot end option parsing
    /// with `--`.
    #[test]
    fn a_name_that_would_reshape_the_user_id_is_refused() {
        for bad in [
            "",
            "   ",
            "-r",
            "Ada <ada@example.invalid>",
            "Ada (work)",
            "Ada\nEve",
        ] {
            assert!(
                matches!(
                    build_uid(bad, "ada@example.invalid"),
                    Err(Error::InvalidKeyName)
                ),
                "{bad:?} should not be accepted as a name"
            );
        }
    }

    #[test]
    fn an_address_that_is_not_one_is_refused() {
        for bad in [
            "",
            "ada",
            "@example.invalid",
            "ada@",
            "ada @example.invalid",
            "a@b>c",
        ] {
            assert!(
                matches!(build_uid("Ada", bad), Err(Error::InvalidKeyEmail)),
                "{bad:?} should not be accepted as an email"
            );
        }
        assert!(
            build_uid("Ada", "ada@localhost").is_ok(),
            "a dotless host is a host"
        );
    }

    /// Captured from `gpg --with-colons --list-secret-keys`: one ordinary key,
    /// one whose only subkey signs, and one expired primary.
    const SECRET_LISTING: &str = "\
sec:u:255:22:A927E66374D6E7FE:1785695396:::u:::scESC:::+::ed25519:::0:
fpr:::::::::5669E864B1BBDD28ACC242F7A927E66374D6E7FE:
grp:::::::::6F4B154B24823B5E4641DDBDDB598D8A5CAB0F1B:
uid:u::::1785695396::08AB80EE::Ada Lovelace <ada@example.invalid>::::::::::0:
ssb:u:255:18:7298DC4C15400BE4:1785695396::::::e:::+::cv25519::
fpr:::::::::B5C2C23E0A47A9840E49F9027298DC4C15400BE4:
sec:u:255:22:1111111111111111:1785695396:::u:::scESC:::+::ed25519:::0:
fpr:::::::::1111111111111111111111111111111111111111:
uid:u::::1785695396::08AB80EE::Signs Only <sign@example.invalid>::::::::::0:
ssb:u:255:22:2222222222222222:1785695396::::::s:::+::ed25519::
sec:e:255:22:3333333333333333:1785695396:::u:::scESC:::+::ed25519:::0:
fpr:::::::::3333333333333333333333333333333333333333:
uid:e::::1785695396::08AB80EE::Long Gone <gone@example.invalid>::::::::::0:
ssb:e:255:18:4444444444444444:1785695396::::::e:::+::cv25519::
";

    /// Only the first key can back a store. A signing-only key written into a
    /// `.gpg-id` produces a store `gpg` refuses to encrypt to, and an expired
    /// one the same — offering either would be offering a choice that fails at
    /// the first save.
    #[test]
    fn only_keys_that_could_actually_back_a_store_are_offered() {
        let keys = parse_secret_keys(SECRET_LISTING);

        assert_eq!(keys.len(), 1, "offered: {:?}", keys);
        assert_eq!(keys[0].id, "5669E864B1BBDD28ACC242F7A927E66374D6E7FE");
        assert_eq!(
            keys[0].label.as_deref(),
            Some("Ada Lovelace <ada@example.invalid>")
        );
        assert_eq!(keys[0].keys, keys_of(&["7298DC4C15400BE4"]));
        assert!(keys[0].usable_here, "it came off the secret keyring");
    }

    /// The id must be the fingerprint, because it is about to be written into a
    /// `.gpg-id` and resolved again on every future write: an email can come to
    /// match two keys, a fingerprint cannot.
    #[test]
    fn an_offered_key_is_identified_by_its_fingerprint() {
        let keys = parse_secret_keys(SECRET_LISTING);
        assert_eq!(Some(&keys[0].id), keys[0].fingerprint.as_ref());
    }

    #[test]
    fn an_empty_secret_keyring_offers_nothing() {
        assert!(parse_secret_keys("").is_empty());
    }

    fn keys_of(ids: &[&str]) -> KeyIds {
        ids.iter().map(|id| (*id).to_owned()).collect()
    }

    /// Invariant 5, for the three errors the inspection path can raise: none
    /// says anything about an entry's contents.
    #[test]
    fn the_inspection_errors_carry_no_content() {
        assert_eq!(
            Error::UnknownKey {
                id: "me@example.com".to_owned()
            }
            .to_string(),
            "no public key for me@example.com"
        );
        assert_eq!(
            Error::UnusableKey {
                id: "me@example.com".to_owned()
            }
            .to_string(),
            "me@example.com has no usable encryption key: it may have expired or been revoked"
        );
        assert_eq!(
            Error::UnreadableCiphertext {
                path: PathBuf::from("/store/wifi.gpg")
            }
            .to_string(),
            "/store/wifi.gpg could not be read as an encrypted entry"
        );
    }
}
