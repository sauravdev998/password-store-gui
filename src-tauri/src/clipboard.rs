//! Copy-to-clipboard, in the core (Invariants 2 and 6).
//!
//! Invariant 2 is why this module exists at all: the copy happens in Rust so a
//! password can reach the clipboard without ever being serialized into the
//! webview. The frontend asks for a copy by *name*; the value it copies is one
//! the frontend never sees.
//!
//! Invariant 6 is the rest of it. A copied secret is wiped after
//! `PASSWORD_STORE_CLIP_TIME` (default 45s) — and only if the clipboard still
//! holds what we put there, so a value the user copied in the meantime is never
//! destroyed by our timer.
//!
//! What we keep in order to answer "is it still ours" is a **keyed hash of the
//! value, not the value**: `pass` parks a copy of the password in a background
//! subshell for the whole clip window, and a second live plaintext sitting in
//! memory for 45 seconds is exactly the kind of thing §4 exists to prevent.
//! [`Fingerprint`] is enough to recognise the value and not enough to recover
//! it.
//!
//! The one copy we do not control is the clipboard itself: handing bytes to the
//! OS means an allocation we cannot zeroize. That is inherent to having a
//! clipboard, and it is what the clear timer is for.

use std::collections::hash_map::RandomState;
use std::ffi::OsString;
use std::hash::BuildHasher;
use std::sync::{Arc, Mutex, MutexGuard, PoisonError};
use std::time::Duration;

// Same method, three traits: each platform seals its own extension to the `Set`
// builder. An OS with none of them is one we do not target (`PLAN.md` §1), and
// failing to compile there is the honest outcome.
#[cfg(target_os = "macos")]
use arboard::SetExtApple as SetExt;
#[cfg(target_os = "linux")]
use arboard::SetExtLinux as SetExt;
#[cfg(windows)]
use arboard::SetExtWindows as SetExt;

use crate::error::{Error, Result};
use crate::secret::Secret;

/// Environment variable `pass` uses for the clipboard window.
pub const CLIP_TIME_ENV: &str = "PASSWORD_STORE_CLIP_TIME";

/// `pass`'s own default, in seconds, when the variable is unset.
pub const DEFAULT_CLIP_TIME: Duration = Duration::from_secs(45);

/// The OS clipboard, as much of it as we use.
///
/// `&mut self` throughout because the platform handles behind it are not
/// shareable; [`Clipboard`] serializes access behind a mutex. The seam is here
/// so the auto-clear rule can be tested without a display server.
pub trait Backend: Send {
    fn set_text(&mut self, text: &str) -> Result<()>;

    /// What the clipboard holds now, or `None` if it holds no text.
    ///
    /// Returns a [`Secret`]: on the path that matters, what comes back is the
    /// password we put there a moment ago, so it is wiped like any other
    /// plaintext rather than left in a `String`.
    fn text(&mut self) -> Result<Option<Secret>>;

    fn clear(&mut self) -> Result<()>;
}

/// When a scheduled clear runs.
///
/// The seam exists so the tests can fire the timer instead of sleeping through
/// 45 seconds of it — the auto-clear rule is a security invariant, and it
/// deserves a deterministic test rather than a slow one.
pub trait Scheduler: Send + Sync {
    fn schedule(&self, delay: Duration, task: Box<dyn FnOnce() + Send + 'static>);
}

/// Copy with an auto-clear.
///
/// Cheap to clone-free: the app holds one, and every copy goes through it so
/// that at most one clip window is ever outstanding.
pub struct Clipboard {
    inner: Arc<Inner>,
}

/// The half a scheduled clear needs to reach after its delay, hence the `Arc`.
///
/// Note what is *not* here: the clip window. It is a setting the user can
/// change while the app runs (ADR-11), so it is passed to [`Clipboard::copy`]
/// by a caller that has just read it rather than captured here at startup,
/// where it would go stale the moment Settings was saved.
struct Inner {
    state: Mutex<State>,
    scheduler: Box<dyn Scheduler>,
}

struct State {
    backend: Box<dyn Backend>,

    /// Bumped by every copy and every manual clear.
    ///
    /// A scheduled clear carries the generation it was scheduled for and does
    /// nothing once that has moved on, so the first copy's timer cannot cut a
    /// second copy's window short.
    generation: u64,

    /// Fingerprint of the value we last put on the clipboard, while its timer
    /// is still outstanding.
    outstanding: Option<Fingerprint>,
}

impl Clipboard {
    /// The real clipboard.
    pub fn system() -> Self {
        Self::new(Box::new(SystemClipboard::new()), Box::new(Threads))
    }

    pub fn new(backend: Box<dyn Backend>, scheduler: Box<dyn Scheduler>) -> Self {
        Self {
            inner: Arc::new(Inner {
                state: Mutex::new(State {
                    backend,
                    generation: 0,
                    outstanding: None,
                }),
                scheduler,
            }),
        }
    }

    /// Put `secret` on the clipboard and schedule its removal after
    /// `clip_time`.
    ///
    /// Returns the window, so the caller can tell the user how long they have.
    pub fn copy(&self, secret: &Secret, clip_time: Duration) -> Result<Duration> {
        // A clipboard carries text; a non-UTF-8 secret has nothing to copy.
        let text = secret.expose_str()?;

        let generation = {
            let mut state = self.inner.state();
            // Before the bookkeeping: a write that fails leaves no phantom
            // timer behind, and nothing outstanding to clear.
            state.backend.set_text(text)?;
            state.generation = state.generation.wrapping_add(1);
            state.outstanding = Some(Fingerprint::of(secret.expose()));
            state.generation
        };

        let inner = Arc::clone(&self.inner);
        self.inner
            .scheduler
            .schedule(clip_time, Box::new(move || inner.clear_if_ours(generation)));

        Ok(clip_time)
    }

    /// Clear the clipboard now, whatever it holds.
    ///
    /// Unconditional, unlike the timer: a user who asks for the clipboard to be
    /// cleared means it even if they copied something else since. Any
    /// outstanding timer is cancelled by the generation bump.
    pub fn clear(&self) -> Result<()> {
        let mut state = self.inner.state();
        state.generation = state.generation.wrapping_add(1);
        state.outstanding = None;
        state.backend.clear()
    }

    /// Run the clip window's clear early, if it is still outstanding.
    ///
    /// This is [`Clipboard::clear`]'s careful sibling, and the difference is
    /// the whole point: it wipes the clipboard **only if it still holds what we
    /// put there**, exactly as the timer would have. That is what makes it safe
    /// to call at moments the user did not ask for a clear — on the way out of
    /// the app, which is the Phase 2 known limit this closes (Invariant 6's
    /// timer thread dies with the process, so quitting inside the window used
    /// to leave the password behind).
    ///
    /// Nothing happens when the window has already elapsed, or when the user
    /// has copied something else since. Unconditionally clearing at those
    /// moments would destroy clipboard contents that were never ours — which is
    /// the failure Invariant 6 is worded to avoid.
    pub fn clear_if_outstanding(&self) {
        let generation = self.inner.state().generation;
        self.inner.clear_if_ours(generation);
    }
}

impl Inner {
    fn state(&self) -> MutexGuard<'_, State> {
        // A poisoned lock means a thread panicked while holding it. Release
        // builds abort on panic, so this is a debug-build-only question — and
        // there, refusing to touch the clipboard ever again, including refusing
        // to clear it, is strictly worse than carrying on. Nothing guarded here
        // is an invariant a panic could have left half-built: a backend handle,
        // a counter, and a hash.
        self.state.lock().unwrap_or_else(PoisonError::into_inner)
    }

    /// The scheduled half of Invariant 6.
    fn clear_if_ours(&self, generation: u64) {
        let mut state = self.state();
        if state.generation != generation {
            // A later copy — or a manual clear — owns the clipboard now, and
            // brought its own timer.
            return;
        }
        let Some(fingerprint) = state.outstanding.take() else {
            return;
        };

        let current = state.backend.text();
        // Errors are dropped rather than reported: a timer thread has no caller
        // to return to, and a message describing what the clipboard holds is
        // the last thing this module should be producing (Invariant 5).
        if let Ok(Some(current)) = current {
            if fingerprint.matches(current.expose()) {
                let _ = state.backend.clear();
            }
        }
    }
}

/// A keyed hash of a copied value, so the auto-clear can tell "still ours" from
/// "the user copied something else" without keeping the value.
///
/// The key is a fresh [`RandomState`] per copy, making this a 64-bit keyed
/// SipHash — a recognizer, not a commitment anyone can invert or precompute. A
/// collision would mean clearing a clipboard we did not set, which is the
/// direction to be wrong in.
struct Fingerprint {
    keys: RandomState,
    hash: u64,
}

impl Fingerprint {
    fn of(bytes: &[u8]) -> Self {
        let keys = RandomState::new();
        let hash = keys.hash_one(bytes);
        Self { keys, hash }
    }

    fn matches(&self, bytes: &[u8]) -> bool {
        self.keys.hash_one(bytes) == self.hash
    }
}

/// What `PASSWORD_STORE_CLIP_TIME` says, if it says anything usable.
pub fn clip_time_from_env() -> Option<Duration> {
    parse_clip_time(std::env::var_os(CLIP_TIME_ENV))
}

/// The rule behind [`clip_time_from_env`], separated so it is testable without
/// mutating process-global environment state.
///
/// Anything unparseable yields `None` instead of erroring: the alternative to a
/// clip window is *no* clip window, and a typo in a shell profile must not be
/// what turns the auto-clear off. `None` falls through to the user's own
/// setting and only then to [`DEFAULT_CLIP_TIME`] (ADR-11). A deliberate `0` is
/// honoured — `pass` would `sleep 0` too — and clears at once.
fn parse_clip_time(var: Option<OsString>) -> Option<Duration> {
    var.as_ref()
        .and_then(|value| value.to_str())
        .and_then(|value| value.trim().parse::<u64>().ok())
        .map(Duration::from_secs)
}

/// A thread per outstanding copy: sleep, then run.
///
/// Simple on purpose — at most a handful are ever live, each sleeps and exits,
/// and a superseded one costs a generation check.
///
/// The thread dies with the process, which used to mean quitting inside the
/// clip window left the secret on the clipboard. [`Clipboard::clear_if_outstanding`]
/// closes that, called from the app's exit handler in `lib.rs`.
pub struct Threads;

impl Scheduler for Threads {
    fn schedule(&self, delay: Duration, task: Box<dyn FnOnce() + Send + 'static>) {
        std::thread::spawn(move || {
            std::thread::sleep(delay);
            task();
        });
    }
}

/// The platform clipboard, via `arboard`.
///
/// Opened on **first use** rather than at startup, for the same reason the
/// store and the `gpg` backend are (see `commands::Core`): a missing display
/// server is a condition the user can fix while the app runs, and it must not
/// stop the app from reading a store. Once opened the handle is kept, because
/// on X11 and Wayland the process that set the clipboard is the one that serves
/// it — dropping the handle would drop the value.
pub struct SystemClipboard(Option<arboard::Clipboard>);

impl SystemClipboard {
    pub fn new() -> Self {
        Self(None)
    }

    fn open(&mut self) -> Result<&mut arboard::Clipboard> {
        if self.0.is_none() {
            self.0 = Some(arboard::Clipboard::new().map_err(|_| Error::ClipboardUnavailable)?);
        }
        // Assigned immediately above; nothing can clear it in between, since
        // `self` is borrowed exclusively for this scope.
        self.0.as_mut().ok_or(Error::ClipboardUnavailable)
    }
}

impl Default for SystemClipboard {
    fn default() -> Self {
        Self::new()
    }
}

impl Backend for SystemClipboard {
    fn set_text(&mut self, text: &str) -> Result<()> {
        self.open()?
            .set()
            // Ask the platform's clipboard manager not to keep its own copy:
            // Windows' cloud clipboard and clipboard history, macOS' Universal
            // Clipboard, and the password-manager hint mime types on Wayland.
            // None of it is a guarantee — a manager may ignore the hint — but
            // without it a password can outlive our timer in someone else's
            // buffer, which is Invariant 6 defeated from the outside.
            .exclude_from_history()
            .text(text)
            .map_err(|_| Error::ClipboardWrite)
    }

    fn text(&mut self) -> Result<Option<Secret>> {
        match self.open()?.get_text() {
            Ok(text) => Ok(Some(Secret::new(text.into_bytes()))),
            // The clipboard is empty or holds an image. Not an error here: the
            // only caller is asking whether our value is still there, and this
            // answers no.
            Err(arboard::Error::ContentNotAvailable) => Ok(None),
            Err(_) => Err(Error::ClipboardRead),
        }
    }

    fn clear(&mut self) -> Result<()> {
        self.open()?.clear().map_err(|_| Error::ClipboardWrite)
    }
}

#[cfg(test)]
pub(crate) mod stub {
    //! Test doubles, shared with the tests in `commands.rs`.

    use std::sync::{Arc, Mutex};
    use std::time::Duration;

    use super::{Backend, Scheduler};
    use crate::error::Result;
    use crate::secret::Secret;

    /// A clipboard that is one `String`.
    #[derive(Clone, Default)]
    pub(crate) struct StubBackend(Arc<Mutex<Option<String>>>);

    impl StubBackend {
        /// What the clipboard holds, from the test's side.
        #[allow(clippy::unwrap_used)]
        pub(crate) fn contents(&self) -> Option<String> {
            self.0.lock().unwrap().clone()
        }

        /// Someone else copied something — the case the auto-clear must not
        /// stomp on.
        #[allow(clippy::unwrap_used)]
        pub(crate) fn overwrite(&self, text: &str) {
            *self.0.lock().unwrap() = Some(text.to_owned());
        }
    }

    #[allow(clippy::unwrap_used)]
    impl Backend for StubBackend {
        fn set_text(&mut self, text: &str) -> Result<()> {
            *self.0.lock().unwrap() = Some(text.to_owned());
            Ok(())
        }

        fn text(&mut self) -> Result<Option<Secret>> {
            Ok(self
                .0
                .lock()
                .unwrap()
                .clone()
                .map(|text| Secret::new(text.into_bytes())))
        }

        fn clear(&mut self) -> Result<()> {
            *self.0.lock().unwrap() = None;
            Ok(())
        }
    }

    type Task = Box<dyn FnOnce() + Send + 'static>;

    /// Holds scheduled clears until a test fires them.
    #[derive(Clone, Default)]
    pub(crate) struct StubScheduler(Arc<Mutex<Vec<Task>>>);

    impl StubScheduler {
        /// Run every clear scheduled so far, oldest first.
        ///
        /// Drains before running: a task locks the clipboard state, and one
        /// that scheduled another would otherwise deadlock on this mutex.
        #[allow(clippy::unwrap_used)]
        pub(crate) fn fire(&self) {
            let tasks: Vec<Task> = std::mem::take(&mut *self.0.lock().unwrap());
            for task in tasks {
                task();
            }
        }

        /// Run only the oldest outstanding clear, so a test can watch one timer
        /// expire while a later one is still live.
        #[allow(clippy::unwrap_used)]
        pub(crate) fn fire_oldest(&self) {
            let mut tasks = self.0.lock().unwrap();
            if tasks.is_empty() {
                return;
            }
            let task = tasks.remove(0);
            drop(tasks);
            task();
        }

        #[allow(clippy::unwrap_used)]
        pub(crate) fn pending(&self) -> usize {
            self.0.lock().unwrap().len()
        }
    }

    #[allow(clippy::unwrap_used)]
    impl Scheduler for StubScheduler {
        fn schedule(&self, _delay: Duration, task: Task) {
            self.0.lock().unwrap().push(task);
        }
    }
}

#[cfg(test)]
// Test code handles fixtures, never real secrets: the strings below are
// literals, not decrypted content.
#[allow(clippy::unwrap_used)]
mod tests {
    use super::stub::{StubBackend, StubScheduler};
    use super::*;

    const CLIP_TIME: Duration = Duration::from_secs(45);

    /// A clipboard over a stub backend whose timers a test fires by hand.
    fn clipboard() -> (Clipboard, StubBackend, StubScheduler) {
        let backend = StubBackend::default();
        let scheduler = StubScheduler::default();
        let clipboard = Clipboard::new(Box::new(backend.clone()), Box::new(scheduler.clone()));
        (clipboard, backend, scheduler)
    }

    fn secret(text: &str) -> Secret {
        Secret::from_slice(text.as_bytes())
    }

    #[test]
    fn copy_puts_the_value_on_the_clipboard_and_reports_the_window() {
        let (clipboard, backend, scheduler) = clipboard();

        let window = clipboard.copy(&secret("hunter2"), CLIP_TIME).unwrap();

        assert_eq!(window, CLIP_TIME);
        assert_eq!(backend.contents().as_deref(), Some("hunter2"));
        assert_eq!(scheduler.pending(), 1, "the copy must schedule its clear");
    }

    /// Invariant 6, the clearing half.
    #[test]
    fn the_timer_clears_a_value_that_is_still_ours() {
        let (clipboard, backend, scheduler) = clipboard();
        clipboard.copy(&secret("hunter2"), CLIP_TIME).unwrap();

        scheduler.fire();

        assert_eq!(backend.contents(), None);
    }

    /// Invariant 6, the half that matters more: the user's own clipboard is
    /// not ours to wipe.
    #[test]
    fn the_timer_leaves_a_value_the_user_copied_afterwards() {
        let (clipboard, backend, scheduler) = clipboard();
        clipboard.copy(&secret("hunter2"), CLIP_TIME).unwrap();

        backend.overwrite("a shopping list");
        scheduler.fire();

        assert_eq!(backend.contents().as_deref(), Some("a shopping list"));
    }

    /// The same value copied by someone else is indistinguishable from ours,
    /// and clearing it is the harmless direction — but a *different* value that
    /// happens to be there must survive, which is what the fingerprint buys.
    #[test]
    fn the_timer_leaves_a_clipboard_that_was_cleared_and_refilled() {
        let (clipboard, backend, scheduler) = clipboard();
        clipboard.copy(&secret("hunter2"), CLIP_TIME).unwrap();

        backend.overwrite("");
        scheduler.fire();

        assert_eq!(backend.contents().as_deref(), Some(""));
    }

    /// What the generation counter is for, isolated: the two copies have the
    /// same fingerprint, so nothing but the generation can tell the first
    /// copy's expired timer from the second copy's live one.
    #[test]
    fn re_copying_a_value_restarts_the_window_instead_of_inheriting_it() {
        let (clipboard, backend, scheduler) = clipboard();

        clipboard.copy(&secret("hunter2"), CLIP_TIME).unwrap();
        clipboard.copy(&secret("hunter2"), CLIP_TIME).unwrap();
        assert_eq!(scheduler.pending(), 2);

        scheduler.fire_oldest();
        assert_eq!(
            backend.contents().as_deref(),
            Some("hunter2"),
            "the first copy's timer must not cut the second copy's window short"
        );

        scheduler.fire_oldest();
        assert_eq!(backend.contents(), None, "the second copy's own timer runs");
    }

    /// The Phase 2 known limit, closed: quitting inside the clip window used to
    /// leave the password on the clipboard, because the timer thread dies with
    /// the process.
    #[test]
    fn an_early_clear_wipes_a_password_still_inside_its_window() {
        let (clipboard, backend, _scheduler) = clipboard();
        clipboard.copy(&secret("hunter2"), CLIP_TIME).unwrap();

        clipboard.clear_if_outstanding();

        assert_eq!(backend.contents(), None);
    }

    /// And the reason it is not just [`Clipboard::clear`]: on the way out of the
    /// app nobody asked for anything to be cleared, so a value that was never
    /// ours must survive.
    #[test]
    fn an_early_clear_leaves_a_value_the_user_copied_afterwards() {
        let (clipboard, backend, _scheduler) = clipboard();
        clipboard.copy(&secret("hunter2"), CLIP_TIME).unwrap();
        backend.overwrite("a shopping list");

        clipboard.clear_if_outstanding();

        assert_eq!(backend.contents().as_deref(), Some("a shopping list"));
    }

    #[test]
    fn an_early_clear_with_nothing_outstanding_does_nothing() {
        let (clipboard, backend, _scheduler) = clipboard();
        backend.overwrite("something the user copied");

        clipboard.clear_if_outstanding();

        assert_eq!(
            backend.contents().as_deref(),
            Some("something the user copied")
        );
    }

    /// Once the window has run its course the value is no longer ours to touch,
    /// so a later exit must not reach back and clear whatever replaced it.
    #[test]
    fn an_early_clear_after_the_window_already_fired_does_nothing() {
        let (clipboard, backend, scheduler) = clipboard();
        clipboard.copy(&secret("hunter2"), CLIP_TIME).unwrap();
        scheduler.fire();
        backend.overwrite("copied later");

        clipboard.clear_if_outstanding();

        assert_eq!(backend.contents().as_deref(), Some("copied later"));
    }

    #[test]
    fn clear_wipes_whatever_is_there() {
        let (clipboard, backend, _scheduler) = clipboard();
        backend.overwrite("something the user copied");

        clipboard.clear().unwrap();

        assert_eq!(backend.contents(), None);
    }

    #[test]
    fn clear_cancels_an_outstanding_timer() {
        let (clipboard, backend, scheduler) = clipboard();
        clipboard.copy(&secret("hunter2"), CLIP_TIME).unwrap();

        clipboard.clear().unwrap();
        backend.overwrite("copied after the clear");
        scheduler.fire();

        assert_eq!(
            backend.contents().as_deref(),
            Some("copied after the clear"),
            "the cancelled timer must not fire on a later value"
        );
    }

    #[test]
    fn a_write_that_fails_schedules_nothing() {
        struct Broken;
        impl Backend for Broken {
            fn set_text(&mut self, _text: &str) -> Result<()> {
                Err(Error::ClipboardWrite)
            }
            fn text(&mut self) -> Result<Option<Secret>> {
                Err(Error::ClipboardRead)
            }
            fn clear(&mut self) -> Result<()> {
                Err(Error::ClipboardWrite)
            }
        }

        let scheduler = StubScheduler::default();
        let clipboard = Clipboard::new(Box::new(Broken), Box::new(scheduler.clone()));

        assert!(matches!(
            clipboard.copy(&secret("hunter2"), CLIP_TIME),
            Err(Error::ClipboardWrite)
        ));
        assert_eq!(scheduler.pending(), 0);
    }

    #[test]
    fn a_non_utf8_secret_never_reaches_the_clipboard() {
        let (clipboard, backend, scheduler) = clipboard();

        assert!(matches!(
            clipboard.copy(&Secret::from_slice(&[0xff, 0xfe]), CLIP_TIME),
            Err(Error::NotUtf8(_))
        ));
        assert_eq!(backend.contents(), None);
        assert_eq!(scheduler.pending(), 0);
    }

    /// The real backend against the real clipboard.
    ///
    /// Ignored by default for two reasons: CI has no display server, and this
    /// trashes whatever the developer had copied. Run it by hand when touching
    /// [`SystemClipboard`] — it is the only thing that catches a platform where
    /// `exclude_from_history` or the Wayland data-control protocol is missing:
    ///
    /// ```sh
    /// cargo test -- --ignored the_system_clipboard
    /// ```
    #[test]
    #[ignore = "needs a display server, and overwrites the real clipboard"]
    fn the_system_clipboard_round_trips_and_clears() {
        let mut clipboard = SystemClipboard::new();

        clipboard.set_text("password-store-gui self test").unwrap();
        let read = clipboard.text().unwrap().unwrap();
        assert_eq!(read.expose(), b"password-store-gui self test");

        clipboard.clear().unwrap();
        assert!(
            clipboard.text().unwrap().is_none_or(|text| text.is_empty()),
            "the clipboard still holds the value after a clear"
        );
    }

    #[test]
    fn a_fingerprint_recognizes_its_own_bytes_and_nothing_else() {
        let fingerprint = Fingerprint::of(b"hunter2");

        assert!(fingerprint.matches(b"hunter2"));
        assert!(!fingerprint.matches(b"hunter3"));
        assert!(!fingerprint.matches(b""));
        assert!(!fingerprint.matches(b"hunter2 "));
    }

    #[test]
    fn the_clip_window_defaults_to_the_pass_default() {
        assert_eq!(parse_clip_time(None), None);
        assert_eq!(parse_clip_time(Some(OsString::new())), None);
    }

    #[test]
    fn the_clip_window_comes_from_the_environment_when_it_is_a_number() {
        assert_eq!(
            parse_clip_time(Some(OsString::from("10"))),
            Some(Duration::from_secs(10))
        );
        assert_eq!(
            parse_clip_time(Some(OsString::from(" 90 "))),
            Some(Duration::from_secs(90))
        );
    }

    /// A typo must not be what turns the auto-clear off.
    #[test]
    fn an_unusable_clip_time_falls_back_rather_than_disabling_the_clear() {
        for value in ["forever", "-1", "45s", "1.5"] {
            assert_eq!(
                parse_clip_time(Some(OsString::from(value))),
                None,
                "{value:?} must fall through rather than decide"
            );
        }
    }
}
