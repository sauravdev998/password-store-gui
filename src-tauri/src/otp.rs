//! One-time passwords from an entry's `otpauth://` URI.
//!
//! The URI is itself a credential — it carries the shared TOTP seed, which is
//! why `store::Entry` keeps it in a [`Secret`] and why there is no
//! `reveal_otp` command. What a user actually wants is the six digits, so the
//! code is computed here, in the core, and only the code crosses IPC
//! (Invariant 2).
//!
//! Time is a parameter rather than a global: [`Otp::code_at`] takes the Unix
//! second, so the RFC 6238 vectors are a test rather than a comment.

use std::time::{SystemTime, UNIX_EPOCH};

use serde::Serialize;
use totp_rs::TOTP;

use crate::error::{Error, Result};
use crate::secret::Secret;

/// A TOTP generator built from one entry's `otpauth://` URI.
///
/// No `Debug` — and here that is a promise rather than a compile error, unlike
/// everything wrapping a [`Secret`]: `totp_rs::TOTP` derives `Debug` and would
/// print the seed as a byte array. Do not derive one, and do not `{:?}` the
/// field. (The crate's `zeroize` feature is on, so the seed is wiped when this
/// drops.)
pub struct Otp {
    totp: TOTP,
}

impl Otp {
    /// Parse an `otpauth://totp/…` URI.
    ///
    /// The error deliberately carries nothing: `totp_rs::TotpUrlError` quotes
    /// the URI it rejected, and that URI holds the seed (Invariant 5).
    pub fn parse(uri: &Secret) -> Result<Self> {
        // Unchecked because the checked constructor enforces RFC 4226 §5.1's
        // 128-bit minimum seed, and real provisioning URIs are routinely
        // shorter — Google's are 80 bits. `pass otp` reads those, so we do too:
        // refusing them would be us disagreeing with the user's store, not with
        // an attacker.
        let totp = TOTP::from_url_unchecked(uri.expose_str()?).map_err(|_| Error::InvalidOtpUri)?;

        // A `period=0` URI would make every code eternal and the countdown a
        // division by zero. Rejected here so nothing downstream has to ask.
        if totp.step == 0 {
            return Err(Error::InvalidOtpUri);
        }

        Ok(Self { totp })
    }

    /// The code for the current wall-clock time.
    pub fn code(&self) -> Result<OtpCode> {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_err(|_| Error::SystemClock)?;
        Ok(self.code_at(now.as_secs()))
    }

    /// The code for a given Unix second, and how much of its window is left.
    pub fn code_at(&self, unix_time: u64) -> OtpCode {
        let period = self.totp.step;
        OtpCode {
            code: self.totp.generate(unix_time),
            // Non-zero: `period` divides the second's remainder, and
            // [`Otp::parse`] rejects a zero period.
            valid_for_secs: period - unix_time % period,
            period_secs: period,
        }
    }
}

/// A generated code and its lifetime.
///
/// This one is serialized to the webview. Unlike the URI it came from, a code
/// is what the user is about to type into a login form and is worthless in half
/// a minute — but it is still a credential, so there is no `Debug` to put one
/// in a log line (Invariant 5), and the webview holds it under the same rule as
/// a revealed field: on screen or gone.
#[derive(Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct OtpCode {
    /// The digits, padded to the URI's `digits` parameter.
    pub code: String,

    /// Seconds until `code` is replaced.
    pub valid_for_secs: u64,

    /// The URI's `period`, so the UI can draw the countdown to scale.
    pub period_secs: u64,
}

#[cfg(test)]
// Test code handles fixtures, never real secrets: the seeds below are the
// published RFC 6238 vectors and throwaway literals.
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;

    /// RFC 6238 Appendix B: the ASCII seed `12345678901234567890`, base32'd,
    /// with 8 digits and SHA-1.
    const RFC_URI: &str = "otpauth://totp/ACME:alice?secret=GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ\
                           &issuer=ACME&digits=8";

    /// A real-world-shaped URI: 80-bit seed, defaults for everything else.
    const SHORT_SEED_URI: &str = "otpauth://totp/ACME:alice?secret=JBSWY3DPEHPK3PXP";

    fn otp(uri: &str) -> Otp {
        Otp::parse(&Secret::from_slice(uri.as_bytes())).unwrap()
    }

    fn rejects(uri: &str) {
        match Otp::parse(&Secret::from_slice(uri.as_bytes())) {
            Err(Error::InvalidOtpUri) => {}
            Err(other) => panic!("expected InvalidOtpUri for {uri:?}, got {other:?}"),
            Ok(_) => panic!("expected {uri:?} to be rejected"),
        }
    }

    /// The published vectors. If these pass, the implementation is TOTP and not
    /// something that merely looks like it.
    #[test]
    fn matches_the_rfc_6238_test_vectors() {
        let otp = otp(RFC_URI);

        for (time, expected) in [
            (59, "94287082"),
            (1_111_111_109, "07081804"),
            (1_111_111_111, "14050471"),
            (1_234_567_890, "89005924"),
            (2_000_000_000, "69279037"),
        ] {
            assert_eq!(otp.code_at(time).code, expected, "at t={time}");
        }
    }

    #[test]
    fn the_countdown_runs_to_the_end_of_the_period() {
        let otp = otp(SHORT_SEED_URI);

        // The default period is 30s, so a window opens on every multiple of 30.
        assert_eq!(otp.code_at(1_500).valid_for_secs, 30);
        assert_eq!(otp.code_at(1_501).valid_for_secs, 29);
        assert_eq!(otp.code_at(1_529).valid_for_secs, 1);
        assert_eq!(otp.code_at(1_530).valid_for_secs, 30);
        assert_eq!(otp.code_at(1_500).period_secs, 30);
    }

    #[test]
    fn the_code_is_stable_across_its_own_window_and_changes_after_it() {
        let otp = otp(SHORT_SEED_URI);

        assert_eq!(otp.code_at(1_500).code, otp.code_at(1_529).code);
        assert_ne!(otp.code_at(1_500).code, otp.code_at(1_530).code);
    }

    /// Interoperability over pedantry: `pass otp` reads an 80-bit seed, so a
    /// store that has one must not be unusable here.
    #[test]
    fn a_seed_shorter_than_the_rfc_minimum_is_accepted() {
        let code = otp(SHORT_SEED_URI).code_at(1_500);
        assert_eq!(code.code.len(), 6);
        assert!(code.code.chars().all(|c| c.is_ascii_digit()));
    }

    #[test]
    fn a_non_default_period_and_digit_count_are_honoured() {
        let otp = otp("otpauth://totp/ACME?secret=JBSWY3DPEHPK3PXP&period=60&digits=8");
        let code = otp.code_at(1_500);

        assert_eq!(code.code.len(), 8);
        assert_eq!(code.period_secs, 60);
        assert_eq!(code.valid_for_secs, 60);
    }

    #[test]
    fn a_sha256_uri_differs_from_the_sha1_default() {
        let sha1 = otp("otpauth://totp/ACME?secret=JBSWY3DPEHPK3PXP");
        let sha256 = otp("otpauth://totp/ACME?secret=JBSWY3DPEHPK3PXP&algorithm=SHA256");

        assert_ne!(sha1.code_at(1_500).code, sha256.code_at(1_500).code);
    }

    /// HOTP is counter-based, not time-based; there is no code to compute from
    /// a clock, so this is a rejection rather than a silent wrong answer.
    #[test]
    fn an_hotp_uri_is_rejected() {
        rejects("otpauth://hotp/ACME?secret=JBSWY3DPEHPK3PXP&counter=1");
    }

    #[test]
    fn a_malformed_uri_is_rejected() {
        for uri in [
            "",
            "not a uri",
            "https://example.com",
            "otpauth://totp/ACME",             // no secret
            "otpauth://totp/ACME?secret=====", // not base32
            "otpauth://totp/ACME?secret=JBSWY3DPEHPK3PXP&period=0",
        ] {
            rejects(uri);
        }
    }

    /// Invariant 5: the whole reason [`Error::InvalidOtpUri`] carries no
    /// payload is that the URI it would carry contains the seed.
    #[test]
    fn a_rejected_uri_is_never_quoted_back() {
        let uri = "otpauth://totp/ACME?secret=JBSWY3DPEHPK3PXP&period=0";
        let Err(err) = Otp::parse(&Secret::from_slice(uri.as_bytes())) else {
            panic!("expected a zero period to be rejected");
        };

        // The message names the *scheme* — it has to, to be useful — but
        // nothing that came out of this particular URI.
        let message = serde_json::to_string(&err).unwrap();
        for fragment in ["JBSWY3DPEHPK3PXP", "ACME", "period", "secret="] {
            assert!(
                !message.contains(fragment),
                "the error quoted {fragment:?} back from the URI"
            );
        }
    }

    #[test]
    fn a_non_utf8_uri_is_rejected_without_quoting_it() {
        let Err(err) = Otp::parse(&Secret::from_slice(&[0xff, 0xfe])) else {
            panic!("expected non-UTF-8 to be rejected");
        };
        assert!(matches!(err, Error::NotUtf8(_)));
    }

    /// The serialized payload is the code and the countdown — never the seed,
    /// the issuer, or the account the URI named.
    #[test]
    fn the_serialized_code_carries_nothing_from_the_uri() {
        let code = otp(RFC_URI).code_at(59);
        let json = serde_json::to_string(&code).unwrap();

        assert_eq!(
            json,
            r#"{"code":"94287082","validForSecs":1,"periodSecs":30}"#
        );
        for fragment in ["GEZDGNBV", "ACME", "alice", "otpauth"] {
            assert!(
                !json.contains(fragment),
                "the payload leaked {fragment:?} from the URI"
            );
        }
    }
}
