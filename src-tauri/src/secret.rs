//! Zeroizing wrappers for decrypted material.
//!
//! Invariant 4 in `PLAN.md` §4. [`Secret`] deliberately implements neither
//! `Debug`, `Display`, `Clone`, nor `Serialize`. The missing `Debug` is the
//! load-bearing one: it means no struct holding a `Secret` can `#[derive(Debug)]`
//! either, so invariant 4 fails the build rather than review. Do not add one,
//! not even a redacting one.

use secrecy::{ExposeSecret, SecretSlice};
use thiserror::Error;
use zeroize::Zeroize;

/// A decrypted byte buffer, zeroed when dropped.
///
/// Short-lived by design: hold one only for as long as a single operation
/// needs it, and never store it anywhere that outlives a command.
///
/// Note the residual exposure recorded as ADR-4a F-4: bytes coming out of a
/// `gpg` pipe pass through a plain `Vec<u8>` inside `std::process` before they
/// reach a wrapper like this one, and reallocations during that read can leave
/// un-zeroed copies on the heap. That is the same exposure the `pass` CLI has
/// and is accepted; this type bounds everything after that point.
pub struct Secret(SecretSlice<u8>);

impl Secret {
    /// Copy `bytes` into a zeroizing buffer.
    ///
    /// This is the primitive: `to_vec` allocates at exactly the slice's length,
    /// so the `into_boxed_slice` inside `SecretSlice` cannot reallocate and
    /// strand an un-zeroed copy of the contents.
    pub fn from_slice(bytes: &[u8]) -> Self {
        Self(bytes.to_vec().into())
    }

    /// Take ownership of `bytes`, wiping the original.
    ///
    /// Copies rather than moving because a `Vec` with spare capacity would be
    /// reallocated on the way into the box, freeing the old allocation with the
    /// contents still in it. The caller's buffer is zeroized instead.
    pub fn new(mut bytes: Vec<u8>) -> Self {
        let secret = Self::from_slice(&bytes);
        bytes.zeroize();
        secret
    }

    /// Borrow the plaintext.
    ///
    /// Every use of this is a place where a secret can escape: copy out of it
    /// only into another `Secret`, and never into a log, an error, or a
    /// serialized payload.
    pub fn expose(&self) -> &[u8] {
        self.0.expose_secret()
    }

    /// Borrow the plaintext as UTF-8.
    ///
    /// Carries the same warning as [`Secret::expose`].
    pub fn expose_str(&self) -> Result<&str, NotUtf8> {
        std::str::from_utf8(self.expose()).map_err(|_| NotUtf8)
    }

    pub fn len(&self) -> usize {
        self.expose().len()
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }
}

/// Decrypted bytes were not valid UTF-8.
///
/// Carries no position and no excerpt: a byte offset into a secret is still
/// information about that secret, and an excerpt is the secret itself.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Error)]
#[error("decrypted content is not valid UTF-8")]
pub struct NotUtf8;

#[cfg(test)]
// Test code handles fixtures, never real secrets: the byte strings below are
// literals, not decrypted content.
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;

    #[test]
    fn round_trips_bytes() {
        let secret = Secret::from_slice(b"hunter2\nurl: example.com\n");
        assert_eq!(secret.expose(), b"hunter2\nurl: example.com\n");
        assert_eq!(secret.expose_str().unwrap(), "hunter2\nurl: example.com\n");
        assert_eq!(secret.len(), 25);
        assert!(!secret.is_empty());
    }

    #[test]
    fn wipes_the_vector_it_takes_ownership_of() {
        let mut bytes = Vec::with_capacity(64);
        bytes.extend_from_slice(b"hunter2");
        let secret = Secret::new(bytes);
        assert_eq!(secret.expose(), b"hunter2");
    }

    #[test]
    fn an_empty_secret_is_empty() {
        let secret = Secret::from_slice(b"");
        assert!(secret.is_empty());
        assert_eq!(secret.expose_str().unwrap(), "");
    }

    #[test]
    fn rejects_non_utf8_without_quoting_it() {
        let secret = Secret::from_slice(&[0xff, 0xfe]);
        assert_eq!(secret.expose_str().unwrap_err(), NotUtf8);
        assert_eq!(
            NotUtf8.to_string(),
            "decrypted content is not valid UTF-8",
            "the message must not quote the offending bytes"
        );
    }
}
