//! Anything that talks to the store's remote: the user's own `git`, spawned.
//!
//! **ADR-9.** The line this module draws is that `git2` does what the app does
//! on its own — read the history, record a mutation — and the `git` binary does
//! anything that reaches the network. The reason is the same one Invariant 3
//! gives for passphrases: an SSH key passphrase, an HTTPS token, a hardware
//! key's touch and a 2FA prompt are the user's credentials, and the way not to
//! mishandle them is not to handle them. `git` already knows how — their
//! credential helper, `ssh-agent`, `~/.ssh/config`, the platform keychain — and
//! spawning it means all of that keeps working without us implementing, storing
//! or prompting for any of it.
//!
//! The cost is that syncing needs `git` installed, which reading and writing do
//! not (libgit2 is vendored). That is [`Error::GitBinaryMissing`], and it says
//! which part is unavailable rather than implying the store is broken.
//!
//! Two rules for everything below:
//!
//! - **Never wait on a terminal.** There is none. `GIT_TERMINAL_PROMPT=0` turns
//!   what would be an indefinite hang into a fast, explainable failure.
//! - **Redact before relaying.** `git`'s own output is safe as far as the
//!   *store* goes — Invariant 1 means everything it touches is ciphertext — but
//!   a remote URL can carry a token, and git quotes the URL back when it fails.
//!   See [`redact`].

use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};

use crate::error::{Error, Result};

/// Longest `git` message we relay.
///
/// A failing fetch can print a great deal — every ref it considered, a whole
/// server-side hook's output — and none of it belongs in a one-line notice.
/// The head of the message is the part that says what went wrong.
const MAX_MESSAGE: usize = 2000;

/// What a `git` invocation did.
pub struct Run {
    /// Whether it exited zero.
    pub ok: bool,
    /// Its output, redacted and trimmed. Empty when it said nothing.
    pub message: String,
}

/// The user's `git`.
pub struct Git {
    bin: PathBuf,
}

impl Git {
    /// Locate `git`, or report that syncing is unavailable.
    ///
    /// Resolved per sync rather than at startup, for the same reason
    /// `commands::Core` opens the store per command: installing `git` is a fix
    /// the user can apply while the app is running, and it should take effect
    /// on the next click.
    pub fn locate() -> Result<Self> {
        which::which("git")
            .map(|bin| Self { bin })
            .map_err(|_| Error::GitBinaryMissing)
    }

    /// Run `git`, treating a non-zero exit as an error.
    pub fn run(&self, workdir: &Path, args: &[&str]) -> Result<String> {
        let run = self.try_run(workdir, args)?;
        if run.ok {
            Ok(run.message)
        } else {
            Err(Error::GitSync {
                reason: describe(&run.message),
            })
        }
    }

    /// Run `git`, reporting a non-zero exit rather than failing on it.
    ///
    /// The caller wants this when a failure is a state rather than a fault — a
    /// merge that hit a conflict is the store telling us something, not `git`
    /// going wrong.
    pub fn try_run(&self, workdir: &Path, args: &[&str]) -> Result<Run> {
        let output = Command::new(&self.bin)
            .args(args)
            .current_dir(workdir)
            // The whole reason a hang is possible: with a terminal, `git` will
            // sit forever asking for a username on an HTTPS remote that has no
            // credential helper. There is no terminal here, so this turns that
            // into an immediate failure with a message that names it.
            //
            // `GIT_ASKPASS` and `SSH_ASKPASS` are deliberately *not* touched:
            // those are the graphical prompts, and they are exactly the thing
            // ADR-9 chose this path to keep working.
            .env("GIT_TERMINAL_PROMPT", "0")
            // Nothing to read and nothing to say interactively.
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .output()
            .map_err(|err| Error::GitSync {
                // An OS-level spawn failure, after `which` already found the
                // binary. Its message is the operating system's, not git's.
                reason: err.to_string(),
            })?;

        // git says almost everything on stderr, including progress; stdout is
        // the fallback for the few subcommands that report on it.
        let mut message = String::from_utf8_lossy(&output.stderr).trim().to_owned();
        if message.is_empty() {
            message = String::from_utf8_lossy(&output.stdout).trim().to_owned();
        }

        Ok(Run {
            ok: output.status.success(),
            message: redact(&message),
        })
    }
}

/// Turn `git`'s output into something worth showing, never an empty string.
///
/// §4.1 principle 5: a bare "operation failed" is not allowed, and a `git` that
/// exited non-zero without saying anything would produce exactly that.
fn describe(message: &str) -> String {
    if message.is_empty() {
        "git exited with an error but reported nothing".to_owned()
    } else {
        let mut message = message.to_owned();
        if message.len() > MAX_MESSAGE {
            message.truncate(
                // Truncate on a character boundary; git's output is UTF-8 in
                // practice but the lossy conversion above does not promise it
                // lands anywhere in particular.
                (0..=MAX_MESSAGE)
                    .rev()
                    .find(|at| message.is_char_boundary(*at))
                    .unwrap_or(0),
            );
            message.push('…');
        }
        message
    }
}

/// Strip credentials out of any URL in `text`.
///
/// This is not about the store's secrets — Invariant 1 means everything `git`
/// touches is ciphertext, which is what makes relaying its output safe at all.
/// It is about the *other* credential in play: a remote configured as
/// `https://user:token@host/repo` puts a token in the repository's config, and
/// `git` quotes the URL back when a fetch or a push fails. Without this that
/// token would travel into an error message, onto the screen, and into whatever
/// the user pastes into a bug report.
///
/// A bare `user@host` is left alone: it carries no secret, and redacting it
/// would make an ordinary ssh remote unreadable in the one message that is
/// meant to help.
fn redact(text: &str) -> String {
    let mut out = String::with_capacity(text.len());
    let mut rest = text;

    while let Some(scheme_end) = rest.find("://") {
        let after = scheme_end + "://".len();
        out.push_str(&rest[..after]);
        rest = &rest[after..];

        // The authority runs to the first separator or whitespace. Anything
        // past that is a path, and an `@` in a path is not userinfo.
        let authority_end = rest
            .find(|c: char| {
                matches!(c, '/' | '?' | '#' | '\'' | '"' | '`' | '<' | '>') || c.is_whitespace()
            })
            .unwrap_or(rest.len());

        if let Some(at) = rest[..authority_end].rfind('@') {
            if rest[..at].contains(':') {
                out.push_str("***@");
                rest = &rest[at + 1..];
            }
        }
    }

    out.push_str(rest);
    out
}

#[cfg(test)]
// Test code handles fixtures, never real secrets: the tokens below are literals
// invented for the test, not anything read out of a store.
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;

    #[test]
    fn a_token_in_a_remote_url_is_redacted() {
        assert_eq!(
            redact("fatal: could not read from 'https://alice:ghp_secret@github.com/a/b.git'"),
            "fatal: could not read from 'https://***@github.com/a/b.git'"
        );
    }

    /// An ssh remote's user is not a credential, and leaving it makes the
    /// message readable — which is the whole point of relaying it.
    #[test]
    fn a_bare_user_is_left_alone() {
        assert_eq!(
            redact("fatal: 'ssh://git@github.com/a/b.git' not found"),
            "fatal: 'ssh://git@github.com/a/b.git' not found"
        );
        assert_eq!(redact("git@github.com:a/b.git"), "git@github.com:a/b.git");
    }

    #[test]
    fn every_url_in_a_message_is_redacted() {
        assert_eq!(
            redact("https://a:b@one.example/x and https://c:d@two.example/y"),
            "https://***@one.example/x and https://***@two.example/y"
        );
    }

    /// An `@` after the host belongs to the path, not to a credential.
    #[test]
    fn an_at_sign_in_a_path_is_not_userinfo() {
        assert_eq!(
            redact("https://example.com/a:b@c/d.git"),
            "https://example.com/a:b@c/d.git"
        );
    }

    #[test]
    fn text_without_a_url_is_unchanged() {
        let message = "error: Your local changes would be overwritten by merge.";
        assert_eq!(redact(message), message);
    }

    /// §4.1 principle 5: a failure that says nothing is not an acceptable
    /// message, so the silent case gets words rather than an empty notice.
    #[test]
    fn a_silent_failure_still_says_something() {
        assert!(!describe("").is_empty());
    }

    #[test]
    fn a_long_message_is_cut_to_its_useful_head() {
        let long = "x".repeat(MAX_MESSAGE * 2);
        let described = describe(&long);

        assert!(described.starts_with("xxx"));
        assert!(described.ends_with('…'));
        assert!(described.chars().count() <= MAX_MESSAGE + 1);
    }

    /// Truncation must not split a character, which a byte-wise cut would.
    #[test]
    fn a_long_message_of_wide_characters_is_cut_on_a_boundary() {
        let described = describe(&"é".repeat(MAX_MESSAGE));

        assert!(described.ends_with('…'));
        assert!(described.len() <= MAX_MESSAGE + '…'.len_utf8());
    }
}
