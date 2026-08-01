//! Password generation.
//!
//! Mirrors `pass generate`: alphanumerics by default, punctuation unless the
//! caller asks for `--no-symbols`, and a length taken from
//! `PASSWORD_STORE_GENERATED_LENGTH` when it is set.
//!
//! Randomness comes from the OS through `getrandom` rather than from a seeded
//! generator, and characters are chosen by rejection sampling rather than by
//! `%`: taking a byte modulo a 62-character alphabet would make the first
//! `256 % 62` characters measurably likelier than the rest, which is a bias in
//! exactly the value that must not have one. The generated password is a
//! [`Secret`] from the moment it exists — it is never a `String` inside the
//! core, and reaches the user only through the same reveal and copy paths as a
//! stored one.

use zeroize::Zeroize;

use crate::error::{Error, Result};
use crate::secret::Secret;

/// Environment variable `pass` uses to override the generated length.
pub const LENGTH_ENV: &str = "PASSWORD_STORE_GENERATED_LENGTH";

/// `pass`'s own default length.
pub const DEFAULT_LENGTH: usize = 25;

/// Bounds on a caller-supplied length.
///
/// The floor is not a policy about what is secure — it is the point below which
/// a "generated password" is not one. The ceiling only stops a typo from asking
/// for a megabyte.
pub const MIN_LENGTH: usize = 8;
pub const MAX_LENGTH: usize = 256;

/// Always available: what `pass generate --no-symbols` restricts to.
const ALPHANUMERIC: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";

/// Added unless symbols are turned off. ASCII punctuation, matching the
/// `[:punct:]` half of `pass`'s default character set.
const SYMBOLS: &[u8] = b"!\"#$%&'()*+,-./:;<=>?@[\\]^_`{|}~";

/// How a password should be built.
///
/// Carries no secret — it describes the shape of a password, not one — so
/// unlike most of what the core holds it is safe to `Serialize` and `Debug`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Deserialize, serde::Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Recipe {
    /// Characters to produce.
    pub length: usize,
    /// Whether punctuation may appear.
    pub symbols: bool,
}

impl Default for Recipe {
    /// `pass`'s defaults, with nothing configured.
    ///
    /// The length the app actually offers comes from
    /// [`crate::settings::SettingsFile::recipe`], which layers
    /// [`LENGTH_ENV`] and the user's setting over this (ADR-11).
    fn default() -> Self {
        Self {
            length: DEFAULT_LENGTH,
            symbols: true,
        }
    }
}

/// Generate a password.
///
/// Fails only on a length outside [`MIN_LENGTH`]`..=`[`MAX_LENGTH`], or if the
/// OS refuses to provide entropy — which is not a condition to paper over with
/// a fallback generator.
pub fn password(recipe: Recipe) -> Result<Secret> {
    if !(MIN_LENGTH..=MAX_LENGTH).contains(&recipe.length) {
        return Err(Error::BadLength {
            min: MIN_LENGTH,
            max: MAX_LENGTH,
        });
    }

    let mut alphabet = ALPHANUMERIC.to_vec();
    if recipe.symbols {
        alphabet.extend_from_slice(SYMBOLS);
    }

    let mut out = vec![0u8; recipe.length];
    for slot in &mut out {
        *slot = pick(&alphabet)?;
    }

    // `Secret::new` copies and then wipes `out`, so the only surviving buffer is
    // the zeroizing one.
    Ok(Secret::new(out))
}

/// Choose one character uniformly.
///
/// Rejection sampling: bytes at or above the largest multiple of the alphabet
/// length that fits in 256 are discarded and redrawn, so every character is
/// equally likely. With a 94-character alphabet the rejection rate is under 27%,
/// so the loop terminates promptly with overwhelming probability.
fn pick(alphabet: &[u8]) -> Result<u8> {
    pick_from(alphabet, &mut os_byte)
}

/// [`pick`] over an arbitrary byte source.
///
/// Split out so the rejection rule can be tested by feeding it every byte value
/// rather than by sampling the OS and arguing about the histogram: with a
/// 62-character alphabet, one pass over `0..=255` must yield each character
/// exactly four times. That is a proof rather than a probability, and it cannot
/// fail intermittently the way a statistical version would.
fn pick_from(alphabet: &[u8], draw: &mut impl FnMut() -> Result<u8>) -> Result<u8> {
    let n = alphabet.len();
    // The alphabets above are compile-time constants well under 256, so this is
    // a guard on future edits rather than a reachable state.
    debug_assert!((1..=256).contains(&n));
    let limit = (256 - (256 % n)) as u16;

    loop {
        let byte = draw()?;
        if u16::from(byte) < limit {
            return Ok(alphabet[usize::from(byte) % n]);
        }
    }
}

/// One byte of OS entropy.
fn os_byte() -> Result<u8> {
    let mut buf = [0u8; 1];
    getrandom::fill(&mut buf).map_err(|_| Error::NoEntropy)?;
    let byte = buf[0];
    buf.zeroize();
    Ok(byte)
}

/// What `PASSWORD_STORE_GENERATED_LENGTH` says, if it says anything usable.
pub fn length_from_env() -> Option<usize> {
    parse_length(std::env::var_os(LENGTH_ENV))
}

/// The rule behind [`length_from_env`], separated so it is testable without
/// mutating process-global environment state.
///
/// An unparseable or out-of-range value yields `None` rather than failing: the
/// variable is the user's shell configuration, and refusing to generate at all
/// because of it would be a worse answer than `pass`'s. `None` then falls
/// through to whatever they configured in the app, and only then to the default
/// — so a typo in a profile does not silently discard a setting they made here
/// (ADR-11).
fn parse_length(value: Option<std::ffi::OsString>) -> Option<usize> {
    value
        .and_then(|raw| raw.into_string().ok())
        .and_then(|raw| raw.trim().parse::<usize>().ok())
        .filter(|length| (MIN_LENGTH..=MAX_LENGTH).contains(length))
}

#[cfg(test)]
// Test code handles fixtures, never real secrets: nothing generated here is
// stored anywhere.
#[allow(clippy::unwrap_used)]
mod tests {
    use std::collections::BTreeSet;
    use std::ffi::OsString;

    use super::*;

    fn generate(length: usize, symbols: bool) -> String {
        let secret = password(Recipe { length, symbols }).unwrap();
        secret.expose_str().unwrap().to_owned()
    }

    #[test]
    fn produces_a_password_of_the_requested_length() {
        for length in [MIN_LENGTH, 25, MAX_LENGTH] {
            assert_eq!(generate(length, true).chars().count(), length);
        }
    }

    #[test]
    fn without_symbols_only_alphanumerics_appear() {
        // One long draw rather than many short ones: a symbol slipping through
        // is a per-character bug, so the sample size is what finds it.
        let generated = generate(MAX_LENGTH, false);
        assert!(
            generated.chars().all(|c| c.is_ascii_alphanumeric()),
            "{generated}"
        );
    }

    #[test]
    fn with_symbols_the_alphabet_is_printable_ascii_without_spaces() {
        let generated = generate(MAX_LENGTH, true);
        assert!(
            generated
                .bytes()
                .all(|b| ALPHANUMERIC.contains(&b) || SYMBOLS.contains(&b)),
            "{generated}"
        );
        assert!(!generated.contains(' '));
    }

    #[test]
    fn rejects_a_length_outside_the_bounds() {
        for length in [0, MIN_LENGTH - 1, MAX_LENGTH + 1] {
            match password(Recipe {
                length,
                symbols: true,
            }) {
                Err(Error::BadLength { min, max }) => {
                    assert_eq!((min, max), (MIN_LENGTH, MAX_LENGTH));
                }
                Err(other) => panic!("expected BadLength, got {other:?}"),
                Ok(_) => panic!("length {length} must be refused"),
            }
        }
    }

    /// Not a randomness test — that belongs to the OS — but it would catch the
    /// failure that matters here: a generator stuck on one character, or one
    /// returning the same password twice.
    #[test]
    fn successive_passwords_differ_and_use_much_of_the_alphabet() {
        let first = generate(MAX_LENGTH, true);
        let second = generate(MAX_LENGTH, true);
        assert_ne!(first, second);

        let distinct: BTreeSet<u8> = first.bytes().collect();
        assert!(
            distinct.len() > 32,
            "only {} distinct bytes",
            distinct.len()
        );
    }

    /// The bias `pick` exists to avoid: with a 62-character alphabet, `byte % 62`
    /// would favour the first `256 % 62 = 8` characters by a factor of 5/4.
    ///
    /// Driven with every byte value in turn rather than with the OS, so the
    /// result is exact: 248 of the 256 values are accepted, and 248 / 62 is 4
    /// each. Deleting the rejection step turns four of these counts into five
    /// and fails the test every time, where a sampled version would only fail
    /// sometimes.
    #[test]
    fn the_alphabet_is_sampled_without_modulo_bias() {
        let mut next = 0u16;
        let mut draw = move || {
            let byte = next as u8;
            next += 1;
            Ok(byte)
        };

        let mut counts = [0usize; 62];
        // 248 accepted draws exhaust one pass over `0..=255`, rejections
        // included.
        for _ in 0..248 {
            let byte = pick_from(ALPHANUMERIC, &mut draw).unwrap();
            let index = ALPHANUMERIC.iter().position(|c| *c == byte).unwrap();
            counts[index] += 1;
        }

        assert_eq!(
            counts, [4usize; 62],
            "the alphabet is not sampled uniformly"
        );
    }

    /// The bytes the rejection step discards are the top of the range, so a
    /// source stuck there must not be mistaken for a working one.
    #[test]
    fn rejected_bytes_are_redrawn_rather_than_folded_in() {
        let mut draws = 0;
        // The first four are all above the 248 limit; only the fifth counts.
        let mut sequence = [255u8, 254, 250, 248, 61].into_iter();
        let mut draw = move || {
            draws += 1;
            assert!(draws <= 5, "the source was drained without a decision");
            Ok(sequence.next().unwrap_or(0))
        };

        assert_eq!(pick_from(ALPHANUMERIC, &mut draw).unwrap(), b'9');
    }

    #[test]
    fn the_length_variable_is_read_like_pass_reads_it() {
        assert_eq!(parse_length(None), None);
        assert_eq!(parse_length(Some(OsString::from("32"))), Some(32));
        assert_eq!(parse_length(Some(OsString::from("  32  "))), Some(32));
    }

    /// Nothing usable means "the variable did not decide this", which lets the
    /// user's own setting answer instead (ADR-11).
    #[test]
    fn an_unusable_length_variable_falls_back_rather_than_failing() {
        for raw in ["", "eleven", "0", "1", "999999"] {
            assert_eq!(parse_length(Some(OsString::from(raw))), None, "for {raw:?}");
        }
    }
}
