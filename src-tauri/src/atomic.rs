//! Atomic file writes.
//!
//! Three things this app writes want the same guarantee for three different
//! reasons, so the rule lives here once rather than in each of them:
//!
//! - **Ciphertext** (ADR-6). `pass` writes an entry in place, so an interrupted
//!   write there truncates it into a file that decrypts nowhere.
//! - **`.gpg-id`** (ADR-13). A truncated recipients file is worse than a
//!   truncated entry: it is the store's access-control decision, and a partial
//!   read of it would encrypt the next write to fewer people than the store
//!   demands.
//! - **Settings** (ADR-11). Not precious, but a half-written file fails to parse
//!   on the next launch, which the user experiences as their settings vanishing.
//!
//! Nothing here is about secrecy: Invariant 1 is about plaintext, and none of
//! the three is plaintext. The temporary holds exactly what the destination will
//! hold.

use std::io::Write;
use std::path::Path;

use crate::error::{Error, Result};

/// Prefix for the temporary file.
///
/// It keeps the temporary out of the tree even while it exists: the store walker
/// matches `*.gpg`, and this is neither that nor hidden-adjacent enough to be
/// mistaken for one.
const TEMP_PREFIX: &str = ".pgs-tmp-";

/// Write `contents` to `path`, replacing it only once the write has succeeded.
///
/// The temporary goes in the destination's own directory so the rename is
/// within one filesystem and therefore atomic. On Unix `tempfile` creates it
/// `0600` and persisting keeps those bits — tighter than the umask-derived
/// permissions `pass` leaves, which is the right direction for a password
/// store.
pub fn write(path: &Path, contents: &[u8]) -> Result<()> {
    let dir = path.parent().unwrap_or_else(|| Path::new("."));
    std::fs::create_dir_all(dir).map_err(|err| Error::io(dir, err))?;

    let mut file = tempfile::Builder::new()
        .prefix(TEMP_PREFIX)
        .tempfile_in(dir)
        .map_err(|err| Error::io(dir, err))?;

    file.write_all(contents)
        .map_err(|err| Error::io(path, err))?;
    // Durability before the rename: a rename that wins the race to disk against
    // its own file contents would leave a valid name over an empty file.
    file.as_file()
        .sync_all()
        .map_err(|err| Error::io(path, err))?;

    file.persist(path)
        .map_err(|err| Error::io(path, err.error))?;
    Ok(())
}

#[cfg(test)]
// Test code handles fixtures, never real secrets.
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;

    #[test]
    fn replaces_previous_contents() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("gmail.com.gpg");

        write(&path, b"first").unwrap();
        assert_eq!(std::fs::read(&path).unwrap(), b"first");

        write(&path, b"second-and-longer").unwrap();
        assert_eq!(std::fs::read(&path).unwrap(), b"second-and-longer");

        // The temporary is gone: nothing but the file itself is left behind.
        let left: Vec<_> = std::fs::read_dir(dir.path())
            .unwrap()
            .map(|e| e.unwrap().file_name())
            .collect();
        assert_eq!(left, vec![std::ffi::OsString::from("gmail.com.gpg")]);
    }

    #[test]
    fn creates_missing_directories() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("Email").join("work").join("corp.gpg");

        write(&path, b"ciphertext").unwrap();

        assert_eq!(std::fs::read(&path).unwrap(), b"ciphertext");
    }

    /// The file must not be group- or world-readable, whatever the umask says.
    #[cfg(unix)]
    #[test]
    fn a_written_file_is_private_to_its_owner() {
        use std::os::unix::fs::PermissionsExt;

        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("wifi.gpg");
        write(&path, b"ciphertext").unwrap();

        let mode = std::fs::metadata(&path).unwrap().permissions().mode();
        assert_eq!(mode & 0o077, 0, "mode was {:o}", mode & 0o777);
    }
}
