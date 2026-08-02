//! User settings, and how they sit beside `pass`'s own environment variables.
//!
//! Three of the six settings here are things `pass` already lets a user decide
//! from the environment: where the store is, how long the clipboard holds a
//! password, and how long a generated one is. **Where the environment says
//! something, it wins** (ADR-11). A `PASSWORD_STORE_DIR` in a shell profile is
//! the user's decision about which store is theirs, and the CLI obeys it — if a
//! setting here silently overrode it, this app and their terminal would be
//! looking at two different stores while both claimed to be looking at "the"
//! store. The other three (idle lock, lock on blur, open on select) have no
//! environment counterpart, so the question does not arise for them.
//!
//! What that costs is a user who changes a setting and sees nothing happen, and
//! [`Effective`] is the answer to it: every value comes back with the [`Source`]
//! that decided it, so the interface can show an environment-pinned value as
//! fixed and say what is pinning it (§4.1 principle 5) rather than offering a
//! control that does nothing.
//!
//! Nothing here is a secret. The file holds a path, four numbers and two
//! booleans — no entry name, no recipient, and by construction nothing
//! decrypted — so unlike the rest of the core it is ordinary configuration and
//! is written to disk without qualm (Invariant 1 is about plaintext).

use std::path::{Path, PathBuf};
use std::sync::{Mutex, MutexGuard, PoisonError};
use std::time::Duration;

use serde::{Deserialize, Serialize};

use crate::clipboard::{self, DEFAULT_CLIP_TIME};
use crate::error::{Error, Result};
use crate::generate::{self, DEFAULT_LENGTH, MAX_LENGTH, MIN_LENGTH};
use crate::store;

/// Directory under the platform's config location.
const CONFIG_DIR: &str = "password-store-gui";

/// The settings file itself.
const CONFIG_FILE: &str = "settings.json";

/// How long the window may sit untouched before it locks.
///
/// Fifteen minutes is a compromise between the two failure modes: short enough
/// that a walked-away-from desk does not keep a revealed password on screen,
/// long enough that reading a password out of the window and typing it
/// somewhere else does not race the timer.
pub const DEFAULT_LOCK_AFTER: Duration = Duration::from_secs(15 * 60);

/// Whether leaving the window hides what is revealed in it, by default.
///
/// On, because Invariant 7 names blur alongside the idle timeout. It is a
/// setting rather than a rule because re-revealing costs a decrypt: for a user
/// whose key is a file behind a cached agent that is free, and for a user
/// holding a security key it is another tap (§4.1 principle 1). The second user
/// is the one this switch exists for.
pub const DEFAULT_LOCK_ON_BLUR: bool = true;

/// Ceiling on the idle timeout, in seconds. A day, past which "auto-lock" is
/// not a description of anything.
pub const MAX_LOCK_AFTER_SECS: u64 = 24 * 60 * 60;

/// Ceiling on the clipboard window, in seconds.
///
/// An hour. `pass` imposes none, but it parks the value in a subshell it
/// expects to be killed with the terminal; ours outlives nothing, so a window
/// long enough to be forgotten about is a window that defeats Invariant 6.
pub const MAX_CLIP_TIME_SECS: u64 = 60 * 60;

/// What the user has configured, and only that.
///
/// Every field is `Option` and absent means *not set here* — which is what lets
/// the environment and the built-in defaults show through in [`Effective`]. A
/// field set to its default value is still a decision, and stays recorded as
/// one.
///
/// Unknown fields are ignored rather than rejected, so a file written by a
/// later version still loads.
#[derive(Debug, Clone, Default, PartialEq, Eq, Deserialize, Serialize)]
#[serde(rename_all = "camelCase", default)]
pub struct Settings {
    /// Store location. Overridden by `PASSWORD_STORE_DIR`.
    pub store_dir: Option<PathBuf>,
    /// Clipboard window in seconds. Overridden by `PASSWORD_STORE_CLIP_TIME`.
    pub clip_time_secs: Option<u64>,
    /// Generated password length. Overridden by
    /// `PASSWORD_STORE_GENERATED_LENGTH`.
    pub generated_length: Option<usize>,
    /// Idle seconds before the window locks; `0` never locks.
    pub lock_after_secs: Option<u64>,
    /// Whether leaving the window hides what is revealed in it.
    pub lock_on_blur: Option<bool>,
    /// Whether selecting an entry decrypts it (§4.1 principle 1, Open
    /// Decision 8).
    pub open_on_select: Option<bool>,
}

/// Which of the three possible answers decided a value.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub enum Source {
    /// A `pass` environment variable. Wins, and cannot be changed from here.
    Environment,
    /// The user set it in this app.
    Configured,
    /// Nobody set it; this is the built-in.
    Default,
}

/// A resolved value together with what decided it.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Decided<T> {
    pub value: T,
    pub source: Source,
}

impl<T> Decided<T> {
    /// Take the first answer that exists, in precedence order.
    fn resolve(env: Option<T>, configured: Option<T>, fallback: T) -> Self {
        match (env, configured) {
            (Some(value), _) => Self {
                value,
                source: Source::Environment,
            },
            (None, Some(value)) => Self {
                value,
                source: Source::Configured,
            },
            (None, None) => Self {
                value: fallback,
                source: Source::Default,
            },
        }
    }
}

/// Every setting as it currently stands, with its provenance.
///
/// This is what the webview gets. It carries no secret: a store path, four
/// numbers, two booleans, and — when something went wrong reading the file —
/// the reason, which describes a config file and never an entry.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Effective {
    pub store_dir: Decided<String>,
    pub clip_time_secs: Decided<u64>,
    pub generated_length: Decided<usize>,
    pub lock_after_secs: Decided<u64>,
    pub lock_on_blur: Decided<bool>,
    pub open_on_select: Decided<bool>,
    /// What the user has actually configured, underneath all of the above.
    ///
    /// The settings form edits *this*, not the resolved values, and the
    /// difference matters in exactly one case: a setting the environment is
    /// overriding still has a configured value behind it. Without this the form
    /// would have no way to see that value, and saving any unrelated change
    /// would quietly erase it — so unsetting `PASSWORD_STORE_DIR` would reveal
    /// not the path the user chose but nothing at all.
    pub configured: Settings,
    /// Where settings are written, for the interface to name. `None` when this
    /// core has nowhere to write them — the tests, and a machine with no
    /// config directory.
    pub path: Option<String>,
    /// Why the settings file was not used, when it exists and could not be
    /// read.
    ///
    /// Present so a user whose settings appear to have reverted is told why
    /// rather than left to guess (§4.1 principle 5). A missing file is not a
    /// problem and leaves this `None`.
    pub problem: Option<String>,
}

/// The settings file, loaded once and kept.
///
/// Held by `commands::Core` and consulted per command, the same way the store
/// and the `gpg` backend are: a setting changed while the app runs takes effect
/// on the next click.
///
/// The environment, by contrast, is read at the moment of use rather than
/// captured at startup — it costs nothing, and it means a value is never stale
/// in the one direction that matters, where the variable is what is in charge.
pub struct SettingsFile {
    /// `None` for an in-memory core: nothing to read, nothing to write.
    path: Option<PathBuf>,
    state: Mutex<State>,
}

struct State {
    settings: Settings,
    problem: Option<String>,
}

impl SettingsFile {
    /// The real settings file, under the platform's config directory.
    ///
    /// Never fails: a missing file, an unreadable one and a machine with no
    /// config directory all yield the defaults, because none of them is a
    /// reason to refuse to open a password store. An unreadable *existing* file
    /// is remembered so [`Effective::problem`] can report it.
    pub fn user() -> Self {
        let path = config_path();
        let (settings, problem) = match path.as_deref().map(read) {
            Some(Ok(settings)) => (settings, None),
            Some(Err(problem)) => (Settings::default(), Some(problem)),
            None => (Settings::default(), None),
        };
        Self {
            path,
            state: Mutex::new(State { settings, problem }),
        }
    }

    /// Settings that live only in memory.
    ///
    /// For the tests, and for the same reason [`crate::commands::Core::with_clipboard`]
    /// exists: a test must not read the developer's own configuration, and must
    /// certainly not write it. Also used by any core pointed at an explicit
    /// store root, where the location is already decided.
    pub fn ephemeral() -> Self {
        Self {
            path: None,
            state: Mutex::new(State {
                settings: Settings::default(),
                problem: None,
            }),
        }
    }

    fn state(&self) -> MutexGuard<'_, State> {
        // A poisoned lock means a thread panicked holding it; release builds
        // abort on panic, so this is a debug-only question. What is guarded is
        // a plain struct with no half-built state to inherit, and refusing to
        // read settings ever again is strictly worse than carrying on.
        self.state.lock().unwrap_or_else(PoisonError::into_inner)
    }

    /// What the user has configured, without the environment or the defaults.
    pub fn configured(&self) -> Settings {
        self.state().settings.clone()
    }

    /// Every setting as it stands, with what decided each one.
    pub fn effective(&self) -> Effective {
        let state = self.state();
        resolve(
            &state.settings,
            &Environment::current(),
            store::home_dir(),
            self.path.as_deref(),
            state.problem.clone(),
        )
    }

    /// Replace the configured settings and write them out.
    ///
    /// Validated first, so a refusal leaves both the file and the running app
    /// exactly as they were. A core with nowhere to write keeps the change in
    /// memory rather than failing: the setting still works for this session,
    /// which is a better answer than refusing it.
    pub fn set(&self, next: Settings) -> Result<Effective> {
        let mut state = self.state();
        let next = keep_unrepresentable_path(next, &state.settings);
        validate(&next)?;

        if let Some(path) = self.path.as_deref() {
            write(path, &next)?;
        }
        state.settings = next;
        // Whatever went wrong before is moot: the file on disk is now ours.
        state.problem = None;

        Ok(resolve(
            &state.settings,
            &Environment::current(),
            store::home_dir(),
            self.path.as_deref(),
            None,
        ))
    }

    /// Where the store is: `PASSWORD_STORE_DIR`, else the configured path, else
    /// `~/.password-store`.
    pub fn store_root(&self) -> Result<PathBuf> {
        store::resolve_root(
            Environment::current().store_dir,
            self.state().settings.store_dir.clone(),
            store::home_dir(),
        )
    }

    /// How long a copied password survives on the clipboard.
    pub fn clip_time(&self) -> Duration {
        Duration::from_secs(
            Decided::resolve(
                Environment::current().clip_time_secs,
                self.state().settings.clip_time_secs,
                DEFAULT_CLIP_TIME.as_secs(),
            )
            .value,
        )
    }

    /// How a generated password should be shaped, before the form adjusts it.
    pub fn recipe(&self) -> generate::Recipe {
        generate::Recipe {
            length: Decided::resolve(
                Environment::current().generated_length,
                self.state().settings.generated_length,
                DEFAULT_LENGTH,
            )
            .value,
            symbols: true,
        }
    }
}

impl Default for SettingsFile {
    fn default() -> Self {
        Self::user()
    }
}

/// What `pass`'s variables say right now.
///
/// A field is `None` when the variable is unset, empty, or unreadable — an
/// unparseable value falls through to the next answer rather than to the
/// built-in default, so a typo in a shell profile does not silently discard a
/// setting the user made here.
struct Environment {
    store_dir: Option<std::ffi::OsString>,
    clip_time_secs: Option<u64>,
    generated_length: Option<usize>,
}

impl Environment {
    fn current() -> Self {
        Self {
            store_dir: std::env::var_os(store::STORE_DIR_ENV).filter(|dir| !dir.is_empty()),
            clip_time_secs: clipboard::clip_time_from_env().map(|time| time.as_secs()),
            generated_length: generate::length_from_env(),
        }
    }
}

/// The whole precedence rule, in one function with no I/O in it.
///
/// Separated from [`SettingsFile`] so ADR-11 is a unit test rather than
/// something to be checked by reading.
fn resolve(
    settings: &Settings,
    env: &Environment,
    home: Option<PathBuf>,
    path: Option<&Path>,
    problem: Option<String>,
) -> Effective {
    let store_dir = store::resolve_root(env.store_dir.clone(), settings.store_dir.clone(), home)
        .map(|root| root.to_string_lossy().into_owned())
        .unwrap_or_default();

    Effective {
        store_dir: Decided {
            value: store_dir,
            source: match (&env.store_dir, &settings.store_dir) {
                (Some(_), _) => Source::Environment,
                (None, Some(_)) => Source::Configured,
                (None, None) => Source::Default,
            },
        },
        clip_time_secs: Decided::resolve(
            env.clip_time_secs,
            settings.clip_time_secs,
            DEFAULT_CLIP_TIME.as_secs(),
        ),
        generated_length: Decided::resolve(
            env.generated_length,
            settings.generated_length,
            DEFAULT_LENGTH,
        ),
        // No environment counterpart, so these are only ever set here.
        lock_after_secs: Decided::resolve(
            None,
            settings.lock_after_secs,
            DEFAULT_LOCK_AFTER.as_secs(),
        ),
        lock_on_blur: Decided::resolve(None, settings.lock_on_blur, DEFAULT_LOCK_ON_BLUR),
        open_on_select: Decided::resolve(None, settings.open_on_select, false),
        configured: settings.clone(),
        path: path.map(|path| path.to_string_lossy().into_owned()),
        problem,
    }
}

/// Refuse a setting that cannot work, by name.
///
/// Every message here says which setting and what the bounds are, rather than
/// "invalid settings" (§4.1 principle 5). The store path is checked hardest,
/// because it is the one whose failure looks like an empty store rather than
/// like a mistake.
fn validate(settings: &Settings) -> Result<()> {
    if let Some(dir) = settings.store_dir.as_deref() {
        if !dir.is_dir() {
            return Err(Error::StoreNotFound {
                path: dir.to_path_buf(),
            });
        }
    }

    if let Some(length) = settings.generated_length {
        if !(MIN_LENGTH..=MAX_LENGTH).contains(&length) {
            return Err(Error::BadLength {
                min: MIN_LENGTH,
                max: MAX_LENGTH,
            });
        }
    }

    if let Some(secs) = settings.clip_time_secs {
        if secs > MAX_CLIP_TIME_SECS {
            return Err(Error::BadDuration {
                setting: "the time before the clipboard is cleared",
                max: MAX_CLIP_TIME_SECS,
            });
        }
    }

    if let Some(secs) = settings.lock_after_secs {
        if secs > MAX_LOCK_AFTER_SECS {
            return Err(Error::BadDuration {
                setting: "the time before the window locks",
                max: MAX_LOCK_AFTER_SECS,
            });
        }
    }

    Ok(())
}

/// Keep a store path that cannot survive the round trip to the webview.
///
/// [`Effective`] renders the path with `to_string_lossy`, so a path that is not
/// valid UTF-8 comes back changed through no fault of the user. When the
/// incoming string is exactly what we rendered, nothing was edited and the
/// original `PathBuf` is kept — the store the user is actually using does not
/// quietly become a different one because they opened Settings and pressed
/// Save.
fn keep_unrepresentable_path(mut next: Settings, current: &Settings) -> Settings {
    if let (Some(incoming), Some(existing)) =
        (next.store_dir.as_deref(), current.store_dir.as_ref())
    {
        if incoming.as_os_str() == existing.to_string_lossy().as_ref() {
            next.store_dir = Some(existing.clone());
        }
    }
    next
}

/// Where the settings file lives, if the platform has a config directory.
fn config_path() -> Option<PathBuf> {
    dirs::config_dir().map(|dir| dir.join(CONFIG_DIR).join(CONFIG_FILE))
}

/// Read the file, treating "not there" as "nothing configured".
///
/// The error is a `String` rather than an [`Error`] because it is not raised to
/// a caller: it rides along in [`Effective::problem`] so the interface can
/// mention it once. Both messages it can carry describe a config file.
fn read(path: &Path) -> std::result::Result<Settings, String> {
    let text = match std::fs::read_to_string(path) {
        Ok(text) => text,
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => return Ok(Settings::default()),
        Err(err) => return Err(format!("{} could not be read: {err}", path.display())),
    };
    serde_json::from_str(&text)
        .map_err(|err| format!("{} is not readable as settings: {err}", path.display()))
}

/// Write the file atomically, creating its directory.
///
/// Same discipline as a ciphertext write (ADR-6): into a temporary in the
/// destination's own directory, flushed and renamed over. Not because settings
/// are precious, but because a half-written file is one that fails to parse on
/// the next launch, and the user would experience that as their settings
/// vanishing.
fn write(path: &Path, settings: &Settings) -> Result<()> {
    let json = serde_json::to_vec_pretty(settings)
        .map_err(|err| Error::io(path, std::io::Error::other(err)))?;
    crate::atomic::write(path, &json)
}

#[cfg(test)]
// Test code handles fixtures, never real secrets.
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;

    fn env(store: Option<&str>, clip: Option<u64>, length: Option<usize>) -> Environment {
        Environment {
            store_dir: store.map(Into::into),
            clip_time_secs: clip,
            generated_length: length,
        }
    }

    fn nothing() -> Environment {
        env(None, None, None)
    }

    fn home() -> Option<PathBuf> {
        Some(PathBuf::from("/home/u"))
    }

    #[test]
    fn nothing_set_anywhere_is_the_built_in_defaults() {
        let out = resolve(&Settings::default(), &nothing(), home(), None, None);

        // Compared as a path, not as a string: this is the one effective value
        // built by joining rather than passed through, so its separator is the
        // platform's choice and none of this test's business.
        assert_eq!(
            Path::new(&out.store_dir.value),
            home().unwrap().join(".password-store"),
        );
        assert_eq!(out.store_dir.source, Source::Default);
        assert_eq!(out.clip_time_secs.value, DEFAULT_CLIP_TIME.as_secs());
        assert_eq!(out.clip_time_secs.source, Source::Default);
        assert_eq!(out.generated_length.value, DEFAULT_LENGTH);
        assert_eq!(out.lock_after_secs.value, DEFAULT_LOCK_AFTER.as_secs());
        assert_eq!(out.lock_on_blur.value, DEFAULT_LOCK_ON_BLUR);
        assert!(!out.open_on_select.value);
    }

    #[test]
    fn a_configured_value_beats_the_default() {
        let settings = Settings {
            clip_time_secs: Some(10),
            generated_length: Some(32),
            store_dir: Some(PathBuf::from("/srv/passwords")),
            ..Settings::default()
        };
        let out = resolve(&settings, &nothing(), home(), None, None);

        assert_eq!(out.clip_time_secs.value, 10);
        assert_eq!(out.clip_time_secs.source, Source::Configured);
        assert_eq!(out.generated_length.value, 32);
        assert_eq!(out.generated_length.source, Source::Configured);
        assert_eq!(out.store_dir.value, "/srv/passwords");
        assert_eq!(out.store_dir.source, Source::Configured);
    }

    /// ADR-11, the part that matters: a variable in the user's shell profile is
    /// the CLI's answer too, so it has to be ours.
    #[test]
    fn the_environment_beats_a_configured_value() {
        let settings = Settings {
            clip_time_secs: Some(10),
            generated_length: Some(32),
            store_dir: Some(PathBuf::from("/srv/passwords")),
            ..Settings::default()
        };
        let out = resolve(
            &settings,
            &env(Some("/mnt/shared/store"), Some(90), Some(40)),
            home(),
            None,
            None,
        );

        assert_eq!(out.store_dir.value, "/mnt/shared/store");
        assert_eq!(out.store_dir.source, Source::Environment);
        assert_eq!(out.clip_time_secs.value, 90);
        assert_eq!(out.clip_time_secs.source, Source::Environment);
        assert_eq!(out.generated_length.value, 40);
        assert_eq!(out.generated_length.source, Source::Environment);
    }

    /// The environment has nothing to say about these, so a setting is the
    /// whole answer and must not be reported as overridden.
    #[test]
    fn the_lock_settings_have_no_environment_to_lose_to() {
        let settings = Settings {
            lock_after_secs: Some(0),
            lock_on_blur: Some(false),
            open_on_select: Some(true),
            ..Settings::default()
        };
        let out = resolve(
            &settings,
            &env(Some("/mnt/shared/store"), Some(90), Some(40)),
            home(),
            None,
            None,
        );

        assert_eq!(out.lock_after_secs.value, 0);
        assert_eq!(out.lock_after_secs.source, Source::Configured);
        assert!(!out.lock_on_blur.value);
        assert_eq!(out.lock_on_blur.source, Source::Configured);
        assert!(out.open_on_select.value);
    }

    /// The settings form edits what was configured, so an overridden value has
    /// to survive being looked at: saving an unrelated change must not erase
    /// the store path the user chose just because a variable is winning today.
    #[test]
    fn a_value_the_environment_overrides_is_still_reported_as_configured() {
        let settings = Settings {
            store_dir: Some(PathBuf::from("/srv/passwords")),
            ..Settings::default()
        };
        let out = resolve(
            &settings,
            &env(Some("/mnt/shared/store"), None, None),
            home(),
            None,
            None,
        );

        assert_eq!(out.store_dir.value, "/mnt/shared/store");
        assert_eq!(out.store_dir.source, Source::Environment);
        assert_eq!(
            out.configured.store_dir,
            Some(PathBuf::from("/srv/passwords"))
        );
    }

    /// Setting a value to what the default already is is still a decision: it
    /// survives a change of default, which is the point of recording it.
    #[test]
    fn configuring_the_default_value_still_reads_as_configured() {
        let settings = Settings {
            lock_on_blur: Some(DEFAULT_LOCK_ON_BLUR),
            ..Settings::default()
        };
        let out = resolve(&settings, &nothing(), home(), None, None);

        assert_eq!(out.lock_on_blur.value, DEFAULT_LOCK_ON_BLUR);
        assert_eq!(out.lock_on_blur.source, Source::Configured);
    }

    #[test]
    fn a_store_path_that_is_not_a_directory_is_refused_by_name() {
        let settings = Settings {
            store_dir: Some(PathBuf::from("/nonexistent/store/for/this/test")),
            ..Settings::default()
        };
        assert!(matches!(
            validate(&settings),
            Err(Error::StoreNotFound { .. })
        ));
    }

    #[test]
    fn out_of_range_numbers_are_refused() {
        assert!(matches!(
            validate(&Settings {
                generated_length: Some(MAX_LENGTH + 1),
                ..Settings::default()
            }),
            Err(Error::BadLength { .. })
        ));
        assert!(matches!(
            validate(&Settings {
                clip_time_secs: Some(MAX_CLIP_TIME_SECS + 1),
                ..Settings::default()
            }),
            Err(Error::BadDuration { .. })
        ));
        assert!(matches!(
            validate(&Settings {
                lock_after_secs: Some(MAX_LOCK_AFTER_SECS + 1),
                ..Settings::default()
            }),
            Err(Error::BadDuration { .. })
        ));
    }

    /// Zero is meaningful at both ends: no clip window, and no idle lock.
    #[test]
    fn zero_is_a_setting_rather_than_an_error() {
        assert!(validate(&Settings {
            clip_time_secs: Some(0),
            lock_after_secs: Some(0),
            ..Settings::default()
        })
        .is_ok());
    }

    #[test]
    fn an_unedited_store_path_is_not_rewritten_through_a_lossy_render() {
        let current = Settings {
            store_dir: Some(PathBuf::from("/srv/passwords")),
            ..Settings::default()
        };
        let incoming = Settings {
            store_dir: Some(PathBuf::from("/srv/passwords")),
            clip_time_secs: Some(20),
            ..Settings::default()
        };
        let kept = keep_unrepresentable_path(incoming, &current);
        assert_eq!(kept.store_dir, current.store_dir);
        assert_eq!(kept.clip_time_secs, Some(20));
    }

    #[test]
    fn an_edited_store_path_is_taken() {
        let current = Settings {
            store_dir: Some(PathBuf::from("/srv/passwords")),
            ..Settings::default()
        };
        let incoming = Settings {
            store_dir: Some(PathBuf::from("/srv/other")),
            ..Settings::default()
        };
        let kept = keep_unrepresentable_path(incoming, &current);
        assert_eq!(kept.store_dir, Some(PathBuf::from("/srv/other")));
    }

    #[test]
    fn a_missing_file_is_not_a_problem() {
        let dir = tempfile::tempdir().unwrap();
        let settings = read(&dir.path().join("settings.json")).unwrap();
        assert_eq!(settings, Settings::default());
    }

    #[test]
    fn an_unreadable_file_is_reported_rather_than_swallowed() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("settings.json");
        std::fs::write(&path, b"{ not json").unwrap();

        let problem = read(&path).unwrap_err();
        assert!(problem.contains("settings.json"));
    }

    /// A file written by a later version must still load here.
    #[test]
    fn unknown_fields_are_ignored() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("settings.json");
        std::fs::write(&path, br#"{"clipTimeSecs": 12, "somethingNew": true}"#).unwrap();

        assert_eq!(read(&path).unwrap().clip_time_secs, Some(12));
    }

    #[test]
    fn settings_round_trip_through_the_file() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("nested").join("settings.json");
        let settings = Settings {
            clip_time_secs: Some(20),
            lock_after_secs: Some(0),
            open_on_select: Some(true),
            ..Settings::default()
        };

        write(&path, &settings).unwrap();
        assert_eq!(read(&path).unwrap(), settings);
    }

    #[test]
    fn an_ephemeral_file_keeps_a_change_without_writing_one() {
        let settings = SettingsFile::ephemeral();
        let out = settings
            .set(Settings {
                clip_time_secs: Some(7),
                ..Settings::default()
            })
            .unwrap();

        assert_eq!(out.path, None);
        assert_eq!(settings.configured().clip_time_secs, Some(7));
    }

    /// A refused change must not be half-applied.
    #[test]
    fn a_rejected_change_leaves_the_previous_settings_in_place() {
        let settings = SettingsFile::ephemeral();
        settings
            .set(Settings {
                clip_time_secs: Some(7),
                ..Settings::default()
            })
            .unwrap();

        assert!(settings
            .set(Settings {
                clip_time_secs: Some(30),
                generated_length: Some(MAX_LENGTH + 1),
                ..Settings::default()
            })
            .is_err());
        assert_eq!(settings.configured().clip_time_secs, Some(7));
    }
}
