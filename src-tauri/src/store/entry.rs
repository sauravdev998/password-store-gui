//! The decrypted entry model (`PLAN.md` §6).
//!
//! A `pass` entry is a free-form text file with one convention: the **first
//! line is the password**, and the lines after it are `key: value` pairs by
//! custom rather than by rule. So this parser is deliberately conservative —
//! anything it cannot read as a field stays intact in [`Entry::notes`] instead
//! of being reinterpreted or dropped. Round-tripping is a Phase 3 concern, but
//! [`Entry::raw`] keeps the original bytes so an edit never has to be
//! reconstructed from the parse.
//!
//! Everything derived from the plaintext is a [`Secret`] with one documented
//! exception: field *keys* (see [`Field::key`]). [`Entry`] therefore implements
//! no `Serialize` — the only thing that crosses IPC is [`EntryMetadata`],
//! which by construction holds no values (Invariant 2).

use serde::Serialize;

use crate::error::Result;
use crate::secret::Secret;

/// URI scheme that marks a line as a one-time-password source.
///
/// Phase 2 parses the URI itself; here it only decides which line is the OTP.
const OTPAUTH_SCHEME: &str = "otpauth://";

/// A decrypted store entry.
///
/// Holds no path: the caller asked for a name and still knows it. Short-lived
/// like everything wrapping a [`Secret`] — build one to serve a command, then
/// drop it.
pub struct Entry {
    raw: Secret,
    password: Secret,
    fields: Vec<Field>,
    otp: Option<Secret>,
    notes: Option<Secret>,
}

/// A `key: value` line.
pub struct Field {
    /// The label left of the colon.
    ///
    /// The one piece of plaintext-derived data held outside a [`Secret`], and a
    /// deliberate exception to Invariant 4: the UI has to render field labels
    /// to offer a reveal at all, so a key is treated as metadata rather than as
    /// secret material. The cost is that a key is a plain `String` and is freed
    /// without being wiped. Keep the exception to keys — a value never becomes
    /// a `String`.
    key: String,
    value: Secret,
}

impl Field {
    pub fn key(&self) -> &str {
        &self.key
    }

    /// Borrow the field's value. A reveal or a clipboard copy, nothing else.
    pub fn value(&self) -> &Secret {
        &self.value
    }
}

impl Entry {
    /// Parse decrypted bytes into the entry model.
    ///
    /// Takes the [`Secret`] by value and keeps it: the parse borrows from it,
    /// and copying the pieces out would otherwise leave the original as a
    /// second live copy the caller has to remember to drop.
    ///
    /// Fails only if the plaintext is not UTF-8, and the error says just that —
    /// no offset, no excerpt (see [`crate::secret::NotUtf8`]).
    pub fn parse(raw: Secret) -> Result<Self> {
        let mut password = Secret::from_slice(b"");
        let mut fields = Vec::new();
        let mut otp = None;
        let notes;

        // Scoped so every borrow of `raw` ends before `raw` is moved into the
        // entry: the parse holds `&str`s into the plaintext, and each piece it
        // keeps is copied into its own buffer.
        {
            let mut note_lines = Vec::new();
            let text = raw.expose_str()?;
            // `split` always yields at least one item, so an empty plaintext
            // parses as an entry with an empty password rather than failing.
            let mut lines = text.split('\n').map(strip_cr);

            if let Some(first) = lines.next() {
                password = Secret::from_slice(first.as_bytes());
            }

            for line in lines {
                if let Some(uri) = otp_uri(line) {
                    // First one wins; a second `otpauth://` line is kept as a
                    // note rather than silently discarded.
                    if otp.is_none() {
                        otp = Some(Secret::from_slice(uri.as_bytes()));
                        continue;
                    }
                }

                match split_field(line) {
                    Some((key, value)) => fields.push(Field {
                        key: key.to_owned(),
                        value: Secret::from_slice(value.as_bytes()),
                    }),
                    None => note_lines.push(line),
                }
            }

            notes = join_notes(&note_lines);
        }

        Ok(Self {
            raw,
            password,
            fields,
            otp,
            notes,
        })
    }

    /// The first line. Empty when the entry starts with a blank line — `pass`
    /// permits it, so this is not an error.
    pub fn password(&self) -> &Secret {
        &self.password
    }

    /// The `key: value` lines, in file order.
    ///
    /// Order is the identity: keys may repeat, so the index is what a reveal
    /// request refers to, not the key.
    pub fn fields(&self) -> &[Field] {
        &self.fields
    }

    /// The field at `index`, matching [`EntryMetadata::fields`].
    pub fn field(&self, index: usize) -> Option<&Field> {
        self.fields.get(index)
    }

    /// The first `otpauth://` URI, whether it was a bare line or a field value.
    ///
    /// Secret because the URI embeds the shared TOTP seed — it is a credential,
    /// not a label.
    pub fn otp(&self) -> Option<&Secret> {
        self.otp.as_ref()
    }

    /// Lines that are neither a field nor the OTP, joined with `\n` and with
    /// leading and trailing blank lines removed.
    ///
    /// Kept because free text in an entry is content: dropping it would make
    /// the GUI show less than the file holds.
    pub fn notes(&self) -> Option<&Secret> {
        self.notes.as_ref()
    }

    /// The undivided plaintext, exactly as decrypted.
    pub fn raw(&self) -> &Secret {
        &self.raw
    }

    /// The serializable view: shape without content.
    pub fn metadata(&self) -> EntryMetadata {
        EntryMetadata {
            has_password: !self.password.is_empty(),
            fields: self.fields.iter().map(|f| f.key.clone()).collect(),
            has_otp: self.otp.is_some(),
            has_notes: self.notes.is_some(),
        }
    }
}

/// What an entry contains, without what it contains.
///
/// The only part of a decrypted entry allowed to cross IPC unprompted
/// (Invariant 2). Every field here is a shape — a count, a flag, a label — so
/// adding a variant that carries a value is a security bug. Values leave the
/// core one at a time, through an explicit reveal.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct EntryMetadata {
    /// Whether the first line is non-empty.
    pub has_password: bool,

    /// Field keys in file order; the index addresses a reveal.
    pub fields: Vec<String>,

    pub has_otp: bool,
    pub has_notes: bool,
}

/// Drop a trailing `\r` so a CRLF store parses like an LF one (§11).
fn strip_cr(line: &str) -> &str {
    line.strip_suffix('\r').unwrap_or(line)
}

/// Split a `key: value` line.
///
/// The separator is a colon **followed by whitespace or end of line**, which is
/// what keeps a bare `https://example.com` from parsing as key `https`. The
/// cost is that `key:value` with no space reads as free text; that is the safer
/// direction to be wrong in, since a mis-split value would show up under a
/// label the file never gave it.
fn split_field(line: &str) -> Option<(&str, &str)> {
    let (key, rest) = line.split_once(':')?;
    let key = key.trim();
    if key.is_empty() {
        return None;
    }
    if !rest.is_empty() && !rest.starts_with(char::is_whitespace) {
        return None;
    }
    Some((key, rest.trim_start()))
}

/// The `otpauth://` URI on this line, bare or as a field value.
fn otp_uri(line: &str) -> Option<&str> {
    let trimmed = line.trim();
    if trimmed.starts_with(OTPAUTH_SCHEME) {
        return Some(trimmed);
    }
    let (_, value) = split_field(line)?;
    let value = value.trim_end();
    value.starts_with(OTPAUTH_SCHEME).then_some(value)
}

/// Join note lines, dropping leading and trailing blank ones but keeping the
/// blank lines between them — the paragraph breaks are the author's.
fn join_notes(lines: &[&str]) -> Option<Secret> {
    let non_blank = |line: &&str| !line.trim().is_empty();
    let first = lines.iter().position(non_blank)?;
    let last = lines.iter().rposition(non_blank)?;
    Some(Secret::new(lines[first..=last].join("\n").into_bytes()))
}

#[cfg(test)]
// Test code handles fixtures, never real secrets: the strings below are
// literals, not decrypted content.
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;
    use crate::error::Error;

    fn parse(text: &str) -> Entry {
        Entry::parse(Secret::from_slice(text.as_bytes())).unwrap()
    }

    /// Field keys and values as strings, for readable assertions.
    fn fields(entry: &Entry) -> Vec<(&str, &str)> {
        entry
            .fields()
            .iter()
            .map(|f| (f.key(), f.value().expose_str().unwrap()))
            .collect()
    }

    fn text(secret: Option<&Secret>) -> Option<&str> {
        secret.map(|s| s.expose_str().unwrap())
    }

    #[test]
    fn first_line_is_the_password() {
        let entry = parse("hunter2\nurl: example.com\n");
        assert_eq!(entry.password().expose_str().unwrap(), "hunter2");
        assert_eq!(fields(&entry), vec![("url", "example.com")]);
    }

    #[test]
    fn a_lone_line_is_a_password_with_nothing_else() {
        let entry = parse("hunter2");
        assert_eq!(entry.password().expose_str().unwrap(), "hunter2");
        assert!(entry.fields().is_empty());
        assert!(entry.otp().is_none());
        assert!(entry.notes().is_none());
    }

    #[test]
    fn a_field_like_first_line_is_still_the_password() {
        let entry = parse("password: hunter2\nuser: alice");
        assert_eq!(entry.password().expose_str().unwrap(), "password: hunter2");
        assert_eq!(fields(&entry), vec![("user", "alice")]);
    }

    #[test]
    fn empty_plaintext_parses_to_an_empty_entry() {
        let entry = parse("");
        assert!(entry.password().is_empty());
        assert!(entry.fields().is_empty());
        assert!(!entry.metadata().has_password);
    }

    #[test]
    fn a_blank_first_line_is_an_empty_password_not_an_error() {
        let entry = parse("\nuser: alice");
        assert!(entry.password().is_empty());
        assert_eq!(fields(&entry), vec![("user", "alice")]);
    }

    #[test]
    fn crlf_parses_like_lf() {
        let entry = parse("hunter2\r\nuser: alice\r\n");
        assert_eq!(entry.password().expose_str().unwrap(), "hunter2");
        assert_eq!(fields(&entry), vec![("user", "alice")]);
        assert!(entry.notes().is_none());
    }

    #[test]
    fn a_bare_url_is_not_a_field() {
        let entry = parse("hunter2\nhttps://example.com/login");
        assert!(entry.fields().is_empty());
        assert_eq!(text(entry.notes()), Some("https://example.com/login"));
    }

    #[test]
    fn a_colon_without_a_space_is_not_a_separator() {
        let entry = parse("hunter2\nuser:alice\n12:30 standup");
        assert!(entry.fields().is_empty());
        assert_eq!(text(entry.notes()), Some("user:alice\n12:30 standup"));
    }

    #[test]
    fn a_key_may_contain_spaces_and_a_value_may_contain_colons() {
        let entry = parse("hunter2\nSecurity question 1: born in: Oslo");
        assert_eq!(
            fields(&entry),
            vec![("Security question 1", "born in: Oslo")]
        );
    }

    #[test]
    fn a_key_with_no_value_is_an_empty_field() {
        let entry = parse("hunter2\nnote:\nuser:   ");
        assert_eq!(fields(&entry), vec![("note", ""), ("user", "")]);
    }

    #[test]
    fn a_missing_key_is_not_a_field() {
        let entry = parse("hunter2\n: orphaned");
        assert!(entry.fields().is_empty());
        assert_eq!(text(entry.notes()), Some(": orphaned"));
    }

    #[test]
    fn duplicate_keys_are_kept_in_order() {
        let entry = parse("hunter2\nurl: a\nurl: b");
        assert_eq!(fields(&entry), vec![("url", "a"), ("url", "b")]);
        assert_eq!(entry.field(1).unwrap().value().expose_str().unwrap(), "b");
        assert!(entry.field(2).is_none());
    }

    #[test]
    fn only_the_separator_whitespace_is_stripped_from_a_value() {
        let entry = parse("hunter2\nkey:    spaced out   ");
        assert_eq!(fields(&entry), vec![("key", "spaced out   ")]);
    }

    #[test]
    fn a_bare_otpauth_line_becomes_the_otp() {
        let entry = parse("hunter2\notpauth://totp/ACME?secret=JBSWY3DP\nuser: alice");
        assert_eq!(
            text(entry.otp()),
            Some("otpauth://totp/ACME?secret=JBSWY3DP")
        );
        assert_eq!(fields(&entry), vec![("user", "alice")]);
        assert!(entry.notes().is_none());
    }

    #[test]
    fn an_otpauth_field_value_becomes_the_otp_and_not_a_field() {
        let entry = parse("hunter2\n2fa: otpauth://totp/ACME?secret=JBSWY3DP");
        assert_eq!(
            text(entry.otp()),
            Some("otpauth://totp/ACME?secret=JBSWY3DP")
        );
        assert!(entry.fields().is_empty());
    }

    #[test]
    fn a_second_otpauth_line_is_kept_as_a_note() {
        let entry = parse("hunter2\notpauth://totp/A\notpauth://totp/B");
        assert_eq!(text(entry.otp()), Some("otpauth://totp/A"));
        assert_eq!(text(entry.notes()), Some("otpauth://totp/B"));
    }

    #[test]
    fn notes_keep_interior_blanks_and_drop_surrounding_ones() {
        let entry = parse("hunter2\n\nfirst para\n\nsecond para\n\n");
        assert_eq!(text(entry.notes()), Some("first para\n\nsecond para"));
    }

    #[test]
    fn notes_between_fields_stay_in_order() {
        let entry = parse("hunter2\nuser: alice\nfree text\nurl: example.com");
        assert_eq!(
            fields(&entry),
            vec![("user", "alice"), ("url", "example.com")]
        );
        assert_eq!(text(entry.notes()), Some("free text"));
    }

    #[test]
    fn raw_keeps_the_plaintext_verbatim() {
        let raw = "hunter2\r\nuser: alice\n\n";
        let entry = parse(raw);
        assert_eq!(entry.raw().expose_str().unwrap(), raw);
    }

    #[test]
    fn non_utf8_plaintext_is_rejected_without_quoting_it() {
        // Not `unwrap_err()`: that needs `Debug` on the `Ok` type, and `Entry`
        // holds `Secret`s so it deliberately has none (Invariant 4). A test
        // that stopped compiling here would be reporting the invariant, not a
        // bug — reach for a `match`, never for a `#[derive(Debug)]`.
        let Err(err) = Entry::parse(Secret::from_slice(&[0xff, 0xfe])) else {
            panic!("expected non-UTF-8 plaintext to be rejected");
        };
        assert!(matches!(err, Error::NotUtf8(_)));
        assert_eq!(err.to_string(), "decrypted content is not valid UTF-8");
    }

    #[test]
    fn metadata_describes_the_shape() {
        let entry = parse("hunter2\nuser: alice\nurl: example.com\notpauth://totp/A\nnote");
        assert_eq!(
            entry.metadata(),
            EntryMetadata {
                has_password: true,
                fields: vec!["user".to_owned(), "url".to_owned()],
                has_otp: true,
                has_notes: true,
            }
        );
    }

    #[test]
    fn metadata_serializes_keys_but_no_values() {
        let entry = parse("hunter2\nuser: alice\notpauth://totp/A?secret=JBSWY3DP\nprivate note");
        let json = serde_json::to_string(&entry.metadata()).unwrap();

        assert_eq!(
            json,
            r#"{"hasPassword":true,"fields":["user"],"hasOtp":true,"hasNotes":true}"#
        );
        for secret in ["hunter2", "alice", "JBSWY3DP", "private note"] {
            assert!(
                !json.contains(secret),
                "metadata leaked {secret:?} across the IPC boundary"
            );
        }
    }
}
