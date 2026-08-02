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

use crate::crypto::{KeyIds, KeyInfo};
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
    let output = Command::new(bin)
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
    let output = Command::new(bin)
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
    let output = Command::new(bin)
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

/// Write `ciphertext` to `path`, replacing it only once the write succeeded.
///
/// Delegated to [`crate::atomic`], which is also what a `.gpg-id` and the
/// settings file go through — an interrupted write that truncates an entry into
/// something that decrypts nowhere is the failure all three are avoiding.
fn write_atomically(path: &Path, ciphertext: &[u8]) -> Result<()> {
    crate::atomic::write(path, ciphertext)
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
