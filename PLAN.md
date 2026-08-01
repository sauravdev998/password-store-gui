# PLAN.md — Cross-Platform `pass` GUI Client

> Working plan for Claude Code. This is a living document: update the **Status**
> column as phases land, and record any deviation in **Architecture Decisions**.
> Treat the **Security Invariants** section as hard constraints, not suggestions.
>
> `PRODUCT.md` is the companion document: it owns audience, positioning, and
> product principles. This file owns scope, architecture, and phase status. Where
> they overlap, `PRODUCT.md` says *who and why*, `PLAN.md` says *what and how* —
> and a claim about what is built belongs here, not there.

---

## 1. What we're building

A native, fast GUI client for [`pass`](https://www.passwordstore.org/), the
standard Unix password manager, running on **Windows, macOS, and Linux**.

`pass` is not a database — it's a directory tree of GPG-encrypted files
(default `~/.password-store/`), optionally versioned with git. Our client is a
careful GUI over that format: it must stay **byte-compatible** with the on-disk
layout so a store edited by our app still works with the `pass` CLI, QtPass, the
mobile apps, etc.

### Who it's for (see `PRODUCT.md`)

The primary user **chose `pass`'s format but does not use the CLI and is not
going to**. They may not know what `gpg-agent`, a recipient, or a `.gpg-id` is;
some arrive with **no store and no GPG key at all**. Existing CLI users are a
real secondary audience — byte-compatibility is for them — but the interface is
not designed around them. **Where the two conflict, the CLI-averse user wins.**

This has teeth here, not just in `PRODUCT.md`: it is why failure messages must
name the actual problem and the actual fix (§4.1), why the format's concepts
have to surface in plain language rather than as `pass` jargon (§10.6), and why
onboarding from nothing is a committed feature rather than a nicety (§7,
Phase 7).

### Goals
- Interoperate perfectly with existing `pass` stores and GPG setups.
- Feel instant: fast tree browsing, fast decrypt, minimal memory footprint.
  *Unmeasured* — this is engineering intent, not a benchmarked claim (§7,
  "Not yet true").
- Ship a single small binary per platform.
- Never compromise on secret hygiene (see Security Invariants).
- Take a user from **nothing — no key, no store — to a working store without a
  terminal** (Phase 7, blocked on ADR-7).

### Non-goals (for v1)
- Cloud sync beyond git.
- Reimplementing OpenPGP ourselves (we drive the user's GPG; pure-Rust crypto is a later option).
- Browser autofill / extensions.
- Mobile.

---

## 2. Tech stack

| Layer | Choice | Notes |
|---|---|---|
| Shell | **Tauri 2.x** | Rust core + native webview; small binary; locked-down IPC. |
| Core | **Rust (stable)** | All sensitive logic lives here. |
| Frontend | **React 19 + TypeScript + Tailwind (v4) + Vite**, pnpm | Familiar stack; UI only, holds no long-lived secrets. |
| Crypto | **Shell out to the `gpg` binary** (default) | Uses the user's keyring, `gpg-agent`, pinentry, smartcards for free. |
| Git | **`git2`** (vendored libgit2) for local ops, the user's **`git`** spawned for the network | No system git needed to read or write a store; syncing needs it (ADR-9). |

### Rust crates (initial)
- `tauri` (2.x) + relevant plugins
- `prs-lib` (GPL-3) — store, recipients, GPG backends, git; wrapped, never exposed (ADR-4)
- `git2` — local git operations, `default-features = false` — settled by ADR-9:
  with the network half delegated to the `git` binary, libssh2 and OpenSSL are
  never needed
- `arboard` — clipboard (used from the core, not JS)
- `zeroize`, `secrecy` — wipe/guard plaintext
- `totp-rs` — TOTP from `otpauth://` URIs
- `dirs` — cross-platform home / store path resolution
- `walkdir` — store tree traversal
- `serde` / `serde_json` — command payloads
- `thiserror` — typed errors (never leak secrets into error messages)
- `which` — locate the `gpg` binary
- `notify` (optional) — watch the store for external changes

### Frontend deps (initial)
- `react`, `react-dom`, `@tauri-apps/api`
- Tailwind + a minimal component approach (no heavyweight UI kit)
- `zustand` or React context for app state (no secrets persisted)

---

## 3. Architecture Decisions (ADRs)

Record decisions here as they're made or changed.

- **ADR-1 — Tauri over pure-Rust GUI (egui/iced).** Keeps the React/TS skillset,
  and the Rust↔JS boundary is a security *feature*: plaintext can stay in Rust.
- **ADR-2 — Native reimplementation, not shelling to `pass`.** `pass` is a bash
  script and isn't native on Windows; we reimplement the format in Rust.
- **ADR-3 — GPG via the `gpg` binary by default.** GPGME's Rust bindings are
  painful on Windows (Gpg4win + `i686-pc-windows-gnu` target only). Shelling to
  `gpg` keeps agent/pinentry/smartcard support and avoids that build hell.
  GPGME and a pure-Rust `rpgp` backend are optional later backends behind a trait.
- **ADR-5 — Locked-down webview by default (Phase 0).** A strict CSP is set in
  `tauri.conf.json` (`default-src 'self'`, no `frame-src`/`object-src`, no
  `form-action`); the webview can reach nothing but our own IPC. `unsafe_code` is
  forbidden crate-wide and `unwrap_used`/`expect_used`/`dbg_macro`/`print_*` are
  clippy-enforced, so invariants 1–5 fail the build rather than review. Release
  builds use `panic = "abort"` + `strip` — no unwinding through secret buffers,
  no symbol names in the shipped binary. Logging is registered only under
  `debug_assertions`, so release builds have no log sink to leak into.
- **ADR-4 — RESOLVED: wrap [`prs-lib`](https://sr.ht/~timvisee/prs/) behind our
  own traits.** `prs-lib` (0.5.7) already implements store parsing, `.gpg-id`
  recipients, git, history, and exactly the backend set ADR-3 calls for
  (`backend-gnupg-bin` default, `backend-gpgme`, `backend-rpgpie` behind
  features). We depend on it, but define our own `Store`/`Gpg` traits and domain
  types in `store/` and `crypto/`; `prs-lib` types live only in the impl modules
  and never reach `commands.rs` or the frontend. That seam lets us replace any
  piece whose behavior conflicts with §4 without touching the command surface.
  **Consequences:**
  - `prs-lib` is **LGPL-3.0** (not GPL-3 as first recorded). We link it
    statically, which triggers LGPL §4's relinking obligation; shipping the app
    as **GPL-3.0-or-later** with published source satisfies it. `Cargo.toml`
    stays `GPL-3.0-or-later`.
  - `prs-lib` 0.5.7 is edition 2024, `rust-version = "1.88.0"`. Bump our
    `rust-version` (currently `1.77.2`) when the dependency is added.
  - Phases 2–4 become integration work rather than reimplementation.
  - **Audit against §4 completed — see ADR-4a.**

- **ADR-4a — `prs-lib` 0.5.7 §4 audit (2026-08-01).** Read of `types.rs`,
  `store.rs`, `crypto/{mod,store,recipients}.rs`, and the whole
  `crypto/backend/gnupg_bin/` tree, against the default feature set
  (`backend-gnupg-bin` only; `tomb`, `backend-gpgme`, `backend-rpgpie` off).

  **Clears §4 as-is:**
  - *Invariant 1 (no plaintext on disk).* Decrypt and encrypt are pure
    stdin→stdout pipes (`gnupg_bin/raw.rs:52-58`, `:28-46`). Every `fs::write`
    in the crate writes ciphertext, `.gpg-id` fingerprints, or exported
    **public** keys. No `tempfile`, no `temp_dir`, no `/dev/shm`. The Tomb
    feature (which mounts a LUKS volume) is off by default.
  - *Invariant 4 (zeroize).* `Plaintext`/`Ciphertext` wrap `secstr::SecVec<u8>`:
    zeroed on drop, and on Unix `mlock`ed with `MADV_DONTDUMP`. Neither derives
    `Debug`, `Display`, or `Serialize`, and the `From` conversions zeroize the
    source buffer. The crate carries quickcheck tests asserting zero-on-drop.
    Note: `secstr`'s memlock is a no-op on Windows — no anti-swap, no
    core-dump exclusion there.
  - *Invariant 5 (errors).* Every error variant carries only a status code,
    an `io::Error`, a path, or a fingerprint. None interpolate plaintext or raw
    gpg output.

  **Must be handled by our wrapper — findings:**
  - **F-1 (Invariant 8, blocks Phase 3).** `.gpg-id` resolution is
    **root-only**: `crypto/store.rs:19` is `store.root.join(".gpg-id")` and
    there is no walk-up anywhere in the crate. `Recipients::load` therefore
    always yields the store-root recipients, which silently mis-encrypts any
    entry under a subdirectory with its own `.gpg-id`. **We implement nearest-
    `.gpg-id` resolution ourselves in `store/`, and never use
    `Recipients::load`/`store_load_recipients` on a write path.**
  - **F-2 (Invariant 3).** `crypto::Config.gpg_tty` is a public bool that adds
    `--pinentry-mode loopback` (`gnupg_bin/raw_cmd.rs:105-112`). It defaults to
    `false` in both `Config::from` and the `crate::CONFIG` const, so the default
    path is safe — but our `crypto/prs.rs` must build the config itself and
    never surface the flag. Cover with a test.
  - **F-3 (Invariant 5).** `Config.verbose` makes the crate `eprintln!` raw gpg
    stdout/stderr on any non-zero exit (`raw_cmd.rs:127-155`); on a partial
    decrypt failure that stdout can hold plaintext. `log_cmd` also prints the
    full quoted command line. Never set `verbose`. Note it writes to **stderr
    directly, not via `log`**, so our `debug_assertions`-gated log sink does not
    contain it.
  - **F-4 (Invariant 1/4, residual, accepted).** Decrypted plaintext first
    lands in `std::process::Output.stdout` — a plain `Vec<u8>` grown from the
    pipe — before `Plaintext::from` copies it into a `SecVec` and zeroizes the
    original. Reallocations during that read leave un-zeroed copies on the heap.
    Not fixable without replacing `std::process` with a fixed pre-`mlock`ed read
    buffer. Accepted: it is the same exposure the `pass` CLI has.
  - **F-5.** `can_decrypt` / `store::can_decrypt` fully decrypt a real secret
    and inspect `Output.stdout`/`stderr` as `&str` with no zeroize. Do not call
    them; write our own store-readability probe if we need one.
  - **F-6 (path traversal).** `Store::find_at` (`root.join(path)`) and
    `normalize_secret_path` never reject `..`, and both `normalize_secret_path`
    and `Store::open` run the caller's string through `shellexpand::full`, which
    expands `~` and `$VAR`. Any entry name from the frontend must be validated
    (no `..`, not absolute, no `$`, no NUL) before it reaches either — our
    `store/` wrapper is the single choke point for that.
  - **F-7 (panics on the secret path).** `raw_cmd.rs:35-36`
    (`cmd.spawn().unwrap()`, `child.stdin.as_mut().unwrap()`), `raw.rs:29`
    (assert on empty recipients), `raw.rs:111,139` (`expect` on non-UTF-8 key
    data), `store.rs:176,238` (`parent().unwrap()`). Release builds already use
    `panic = "abort"`, so nothing unwinds through a secret buffer — but these
    abort the app. Our wrapper pre-validates (gpg binary present, recipient list
    non-empty, path well-formed) so we return a typed error instead.

  **Non-security gaps to fill ourselves:**
  - `PASSWORD_STORE_DIR` is never read; `STORE_DEFAULT_ROOT` is a hardcoded
    `~/.password-store`. We resolve the store path ourselves.
  - `SecretIter` is flat — it yields every `.gpg` file with a relative name and
    no directory nodes. We build the tree from those names.

  **Verdict:** wrap, as ADR-4 decided. Nothing found requires replacing the
  crypto path. F-1 and F-6 mean `store/` owns recipient resolution and name
  validation outright rather than delegating them.

- **ADR-6 — encryption is ours, decryption stays wrapped (2026-08-01).** The
  ADR-4a audit covered the read path. Auditing `prs-lib`'s *write* path for
  Phase 3 found three problems, and unlike the read-path findings these are not
  fixable from outside the crate. So `crypto/gnupg.rs` spawns `gpg` itself for
  encryption, while `crypto/prs.rs` keeps `prs-lib` for decryption. Both sit
  behind the same `Gpg` trait, which is the seam ADR-4 was built for: "replace
  any piece whose behavior conflicts with §4 without touching the command
  surface."

  **Why the asymmetry is the point, not an inconsistency:** decrypting has no
  flag-compatibility surface — `gpg --decrypt` reads what the file says it is.
  Encrypting has nothing but: the argument list *is* the access-control
  decision, so the flags below are what determine who can read the entry
  afterwards. That is §4 territory; reading is not.

  **Findings:**
  - **F-8 (Invariant 8).** `IsContext::encrypt` takes `Recipients`, a list of
    resolved `Key`s, and the only way to build one from `.gpg-id` text is
    `find_public_keys`. That matches by `util::fingerprints_equal`, which
    normalizes both sides, requires 8+ characters, and does a **substring**
    test — then `filter_map`s away every id it could not match, silently. A
    `.gpg-id` line that is a *user id* (`Me <me@example.com>`) matches no
    fingerprint at all, so that recipient is dropped and the entry is encrypted
    to fewer people than the store demands, with no error. `pass` supports user
    ids and `store/gpg_id.rs` already goes out of its way to preserve them
    verbatim, so this is not a corner case.
  - **F-9 (Invariant 8, the other direction).** `raw::encrypt` omits
    `--no-encrypt-to`, which `pass` sets. An `encrypt-to` line in the user's
    `gpg.conf` therefore adds a recipient the `.gpg-id` never authorized, and
    the resulting file looks entirely normal.
  - **F-10 (hang, plus a compatibility gap).** `gpg_stdin_output`
    (`raw_cmd.rs:35-44`) writes the whole stdin and only then calls
    `wait_with_output`. For decryption the plaintext is the *output*, so it is
    survivable; for encryption both sides are large, and once the unread
    ciphertext fills the stdout pipe buffer `gpg` stops reading stdin and the
    two deadlock. It also omits `--compress-algo=none`, which `pass` sets so
    that ciphertext length is not a function of plaintext redundancy.

  **Consequences:**
  - We pass recipient ids to `gpg --recipient` exactly as the `.gpg-id` spells
    them, which is what makes fingerprints, key ids, and user ids all work:
    resolving them is `gpg`'s job, and it fails loudly where `find_public_keys`
    failed silently. `verify_recipients` probes each id first so the error can
    name the id and the `.gpg-id` that listed it, rather than being a bare
    "encryption failed".
  - The plaintext is fed on a scoped thread while the main one drains stdout,
    so F-10 cannot recur. Scoped so the feeder borrows the `Secret` instead of
    needing a second copy of it.
  - `--trust-model always`, as `prs` uses and our own test fixture uses. The
    `.gpg-id` *is* the store's authorization decision, so the web of trust is a
    second gate rather than the relevant one — and the way `gpg` asks about an
    untrusted key is an interactive prompt a GUI with no TTY cannot answer.
    With `--batch` the alternative is not a prompt but a refusal to encrypt to
    a key the user deliberately listed. This is a deliberate deviation from
    `pass`, which sets no trust model.
  - Writes are atomic: ciphertext goes to a temporary file in the target's own
    directory and is renamed over it, after an `fsync`. `pass` writes in place,
    so an interrupted write there truncates the entry. The temporary holds
    ciphertext only — Invariant 1 is about plaintext, which never leaves the
    pipe. On Unix `tempfile` creates it `0600` and persisting keeps those bits,
    which is tighter than the umask-derived permissions `pass` leaves.
  - `prs-lib` is now used for decryption, the store walk, and nothing else. If
    a later phase finds a reason to own decryption too, dropping the dependency
    becomes a live option — but that is an ADR-4 reversal and needs its own
    entry, not a drive-by.

- **ADR-8 — the edit form reveals the whole entry (2026-08-01).** Phase 3's edit
  flow rests on `reveal_entry`, which returns an entire decrypted body across
  IPC. It is the only command that returns more than one value, and the only
  path by which an `otpauth://` URI — and so a TOTP seed — can reach the
  webview. That is a deliberate exception to §4.1 principle 2's "one field at a
  time", recorded rather than left to be discovered.

  **There is no smaller request to serve.** `Core::edit` replaces the whole
  body, so producing one means having read one. Both alternatives were
  rejected: per-field editing would have to hold the unedited remainder
  decrypted between commands — precisely the cache Phase 1 does not have and
  Invariant 7 would then have to clear — and rebuilding the body from the
  existing reveals is lossy, since the OTP line has no reveal by design and
  repeated keys and unparsed lines would have to round-trip byte-exactly.

  **It is still within Invariant 2,** which permits what the user explicitly
  reveals. Choosing "Edit" *is* the request, and `pass edit` answers the same
  request by opening the plaintext in `$EDITOR` — the same act with the same
  exposure. Nothing is decrypted until the dialog opens, so a pinentry raised
  here is one the user asked for (§4.1 principle 1).

  **Consequences:**
  - The dialog is mounted only while open. Closing it unmounts the component
    and the string goes with it; it is never lifted to a parent, a store, or
    `localStorage`.
  - `reveal_entry` must not be reused as the OTP row's reveal. That row exists
    so the code can be had without the seed, and `otp_code` is how.
  - The editor's textarea carries the same `bg-exposed` wash a revealed row
    does. The colour rule — warm means something is showing — holds here, at
    the largest scale it reaches anywhere in the app.

- **ADR-9 — `git2` for what we do ourselves, the user's `git` for the network
  (2026-08-02).** Resolves Open Decision 2 in the direction it leaned. Reading,
  writing and the store's local history run on vendored libgit2 and need no
  `git` installed; `fetch`, `merge` and `push` spawn the user's own binary.
  `git.rs` becomes `git/`, with `git/remote.rs` holding everything that spawns.

  **The argument is Invariant 3's, applied to a different credential.** An SSH
  key passphrase, an HTTPS token, a 2FA prompt and a hardware key's touch are
  the user's credentials, and the way not to mishandle them is not to handle
  them. `git` already knows how — their credential helper, `ssh-agent`,
  `~/.ssh/config`, the platform keychain — so spawning it means every one of
  those keeps working without us implementing, prompting for, or storing any of
  it. The alternative was `git2`'s credential callbacks, which would have meant
  turning on the network features (vendored libssh2 + OpenSSL) *and* writing our
  own passphrase prompt: a large build surface bought in exchange for the one
  thing §4 is most careful about.

  **Consequences:**
  - `git2` keeps `default-features = false`, which was previously a Phase 3
    expedient and is now the settled state.
  - Syncing needs `git` on `PATH`; nothing else does. That is
    `Error::GitBinaryMissing`, worded so it names which part is unavailable
    rather than implying the store is broken (§4.1 principle 5). It joins
    Gpg4win in §11 as a Windows prerequisite, but only for sharing a store.
  - `GIT_TERMINAL_PROMPT=0` on every spawn. With no terminal, `git` would
    otherwise block indefinitely asking for a username on an HTTPS remote with
    no credential helper. `GIT_ASKPASS`/`SSH_ASKPASS` are deliberately left
    alone — those are the graphical prompts this ADR exists to keep.
  - **`git`'s output is relayed, after redaction.** Relaying is safe as far as
    the store goes: Invariant 1 means everything git touches is ciphertext. The
    redaction is about the *other* credential — a remote may be configured as
    `https://user:token@host/repo`, and git quotes the URL back on failure, so
    `remote::redact` strips userinfo that carries a password. A bare `user@host`
    is left, since it is not a secret and removing it would make the one message
    meant to help unreadable.
  - *Not done:* there is no timeout on the spawn. A dead connection can leave a
    sync spinning until the OS gives up. Recorded rather than fixed, like the
    clipboard's quit-inside-the-window limit.

- **ADR-10 — a conflicted merge is rolled back, and reading a past version is
  ADR-8 again (2026-08-02).** Two decisions from Phase 4, both consequences of
  the format rather than of the interface.

  **The rollback.** `sync` fetches, merges, then pushes. It uses a real merge
  rather than `--ff-only`, because a store keeps one file per entry and two
  people changing two different entries merges cleanly — refusing that would
  report the ordinary case as a conflict. But when the merge *does* conflict it
  is aborted and the working tree restored, rather than left for the user to
  resolve. **An unresolved merge writes conflict markers into the conflicting
  files, and here every file is ciphertext**: the result decrypts nowhere — not
  here, not in the `pass` CLI, not on a phone — and a user who chose `pass` and
  does not use a terminal has no way back. So the store is returned to exactly
  what it was, byte for byte, and the interface names the entries and says
  plainly that nothing on this computer changed. This is a deliberate deviation
  from `pass git pull`, which leaves whatever git leaves.

  **Reading a past version** (`reveal_revision`) returns a whole decrypted body,
  and is the second exception to §4.1 principle 2's "one field at a time" —
  ADR-8's reasoning, unchanged: there is no smaller request to serve, because
  the point of asking is to see what the version *said*, and its shape is only
  knowable by decrypting it. It is reached only by choosing a specific commit
  from a list that itself decrypted nothing, so the decrypt is as deliberate as
  opening the editor. The same discipline applies: the dialog is mounted only
  while open, at most one version is open at a time, and the shown body carries
  the `bg-exposed` wash.

  **Consequences:**
  - `Gpg::decrypt(&[u8])` is added beside `decrypt_file`, because a version out
    of a git object was never a file. `decrypt_file` is now that method plus the
    read, which is what lets its error keep the path.
  - `copy_revision_password` exists so the ordinary recovery — "the new one does
    not work, give me the old one" — needs no reveal at all.
  - The revwalk sorts `TIME | TOPOLOGICAL`. Time alone is not enough and the
    case where it fails is not exotic: two commits made in the same second on
    two sides of a merge sort arbitrarily, so a synced store could show the
    commit that *created* an entry as newer than a change to it. Found by
    `tests/git_sync.rs`, not by reading.
  - `status` is local-only by design: it reports the distance to the remote as
    of the last fetch. An indicator the window draws on arrival must not be an
    operation that can hang, prompt, or fail on a train.

- **ADR-11 — settings are ours, but `pass`'s environment variables outrank them
  (2026-08-02).** Phase 5 adds `settings.rs`: a JSON file under the platform's
  config directory holding a store path, a clipboard window, a generated length,
  an idle timeout, a lock-on-blur switch and an open-on-select switch. Three of
  those six are things `pass` already lets a user set from the environment, and
  **where the environment says something it wins.**

  **The argument is byte-compatibility's, one level up.** `PASSWORD_STORE_DIR`
  in a shell profile is the user's decision about which store is theirs, and the
  CLI obeys it. If a setting here silently overrode it, this app and their
  terminal would be looking at two different directories while both called it
  "the store" — and the failure would present as an empty store rather than as a
  conflict. §4.1 principle 3 says the store is the user's; this is the same
  claim about where it is. An unparseable variable falls through to the setting
  rather than to the built-in default, so a typo in a profile cannot discard a
  choice made here.

  **Consequences:**
  - Every value crosses IPC as a `Decided<T>` — the value plus the `Source` that
    decided it. That exists so the settings panel can show an
    environment-pinned control as fixed and name the variable pinning it, rather
    than offering a box that does nothing (§4.1 principle 5). It is the one
    place the app spells a `PASSWORD_STORE_*` name out, and it earns that by
    Open Decision 6's own test: the user needs that exact string to act outside
    the app.
  - `Effective` also carries the raw `configured` set, and the form edits *that*
    rather than the resolved values. Without it, a setting the environment is
    overriding would have no value visible behind it, and saving any unrelated
    change would erase it — so unsetting the variable later would reveal not the
    path the user chose but nothing at all.
  - The clip window moved out of `Clipboard` and into `Clipboard::copy`'s
    arguments. It is a setting that can change while the app runs, and a module
    that schedules the clear must not be holding a copy of it from startup.
  - Settings are written atomically, like ciphertext (ADR-6) — not because they
    are precious, but because a half-written file fails to parse on the next
    launch, which the user experiences as their settings vanishing. A file that
    *does* fail to parse is reported in `Effective::problem` rather than
    silently replaced by defaults.
  - Nothing here is secret: a path, four numbers, two booleans. Invariant 1 is
    about plaintext, and this file has none.

- **ADR-12 — auto-lock: leaving the window and going idle are different events
  (2026-08-02).** Invariant 7 in a codebase where the core has no cache to
  clear. A reveal is its own decrypt and nothing survives the command that
  produced it, so everything holding plaintext is in the webview: a revealed
  row, the edit form's whole body (ADR-8), an opened past version (ADR-10). The
  two events act on them differently, and the asymmetry is the decision.

  - **Blur hides revealed values and nothing else.** It does not close a dialog,
    because switching windows to read something is an ordinary step in the
    middle of writing an entry, and closing the form would destroy work the user
    is in the middle of. It clears *values* without remounting the pane, so that
    a user with "open entries on select" turned on does not get a fresh decrypt
    — and therefore a pinentry prompt — for the act of alt-tabbing back (§4.1
    principle 1).
  - **Idle locks the window.** Dialogs close, the selection is dropped, and a
    lock screen says so. Unsaved input is lost, which is defensible only because
    idle means nobody has typed for minutes. Deselecting rather than remounting
    is what stops the unlock from decrypting on its own: the user picks the
    entry back up, and picking it up is the request.

  **Neither touches the clipboard**, and that is deliberate rather than an
  omission. Leaving the window is precisely when a copied password is about to
  be pasted — clearing on blur would break the feature copying exists for — and
  by the time the window has gone idle Invariant 6's timer has long since fired,
  so a clear there could only ever destroy something the user copied from
  somewhere else.

  **Neither flushes `gpg-agent`.** That cache belongs to the user's agent and
  their `default-cache-ttl`. Reaching in to reset it would be us managing a
  credential we deliberately do not handle, which is Invariant 3's whole
  argument.

  **Consequences:**
  - The Phase 2 known limit is closed: `Clipboard::clear_if_outstanding` runs
    the fingerprint check early from `RunEvent::Exit`, so quitting inside the
    clip window no longer leaves the password behind. It is the *conditional*
    clear — nobody asked for one on the way out, so a value that was never ours
    survives. A process killed outright still cannot be helped.
  - The lock screen is a real `<dialog>` on `showModal`, not an overlay div.
    Found by driving it: with a plain overlay the tree, the filter, Sync and
    Settings all stayed on the Tab order behind it, so a locked window could
    still be operated from the keyboard. On a screen whose entire job is that
    nothing is reachable, that is the bug.
  - It is not a password prompt and says so. The clearing already happened when
    the timer fired, and this app holds no passphrase to authenticate against
    (Invariant 3), so the screen reports what was done. Escape dismisses it like
    any other dialog.
  - Blur is the DOM `window` event rather than Tauri's `onFocusChanged`, so the
    same code path runs under `pnpm dev:mock` — which is the only way this
    frontend has ever been driven.

---

## 4. Security Invariants (hard constraints)

Claude Code must uphold all of these in every phase. A change that violates one
is a bug even if the feature "works."

1. **Plaintext never touches disk.** No temp files with secrets. If an editor
   flow is added, use tmpfs (`/dev/shm`) where available and shred, mirroring `pass`.
2. **Plaintext stays in Rust.** Decrypted secrets do not cross the IPC boundary
   into the webview unless the user explicitly reveals a field. **Copy-to-clipboard
   happens entirely in the Rust core** so the password never enters JS.
3. **Passphrases are never handled by us.** With the gpg-binary backend, let
   `gpg-agent` + pinentry prompt and cache. Do not use loopback pinentry.
4. **Zeroize.** Wrap secret buffers in `secrecy`/`zeroize`; never `Debug`/`Display` them.
5. **Never log secrets.** Errors, traces, and panics must not contain plaintext
   or passphrases. Redact by construction.
6. **Clipboard auto-clears** after `PASSWORD_STORE_CLIP_TIME` (default 45s), and
   only clears if the clipboard still holds the value we set.
7. **Auto-lock.** Clear any in-memory decrypted cache on idle timeout and on window blur (configurable).
8. **Respect the store's recipients.** On write, encrypt to the recipients from
   the nearest `.gpg-id` (walking up the tree). On recipient change, re-encrypt
   the whole affected subtree, matching `pass init`.

### 4.1 Product principles (from `PRODUCT.md`)

These are **not** part of the eight — that list is deliberately fixed, and
`CLAUDE.md` and `PRODUCT.md` both cite it by count. These bind design decisions
rather than secret handling, and a violation is a defect in the same way.

1. **A decrypt is expensive and always the user's choice.** Nothing decrypts
   **unrequested** — not speculatively, not on hover, not on a timer. **A
   pinentry prompt or a hardware-key tap the user did not ask for is a defect.**
   This is why the OTP row stays hidden until asked for (Phase 2), why nothing
   is cached between commands (Phase 1), and why hiding a revealed value on blur
   does not remount the pane that would re-fetch it (ADR-12). Smartcards are a
   *confirmed* operating condition, not a later concern.
   - *"Unrequested" rather than "on select"* — settled by Open Decision 8 in
     Phase 5. A standing opt-in is a request made once instead of per click, and
     the setting that carries it states its cost. The default stays off, which
     is what protects the user holding a security key.
2. **Hidden by default, revealed one field at a time.** A revealed value lives
   on screen and nowhere else — not in a store, not in a URL, not across a
   selection change. Implemented in Phase 1; overlaps Invariants 2 and 7.
   **Two commands return a whole body instead of one field, and both are
   recorded rather than left to be discovered:** the edit form (ADR-8) and
   reading a past version (ADR-10). Each is a request that has no smaller form,
   and each carries the same discipline — mounted only while open, gone when it
   closes.
3. **The store is the user's, not ours.** Every write stays byte-compatible with
   the CLI; nothing is added to the format for our convenience; **a name or file
   we cannot handle is shown as unusable rather than silently hidden**
   (`Tree::unsupported`, and `notes` retaining unparsed lines).
4. **The user does not have to know `pass` to use it.** Where the format's
   concepts must surface — recipients, sync state, missing keys — the interface
   explains what is happening in plain language and says what to do about it.
   How much vocabulary to expose, translate, or teach is open (§10.6).
5. **Say what is true, especially about failure.** Missing `gpg`, an
   unresolvable recipient, a diverged store: name the actual problem and the
   actual fix. **Never a bare "operation failed"** — and never a message that
   quotes a secret to be helpful (Invariant 5 governs the second half; this
   principle governs the first). `verify_recipients` naming the id and the
   `.gpg-id` that listed it (ADR-6) is the standard to match.

---

## 5. Repository layout

```
password-store-gui/
├── PLAN.md
├── PRODUCT.md                # audience, positioning, product principles
├── CLAUDE.md                 # conventions + commands for the agent (see §9)
├── package.json              # pnpm workspace root
├── vite.config.ts
├── src/                      # React / TS frontend (no long-lived secrets)
│   ├── main.tsx
│   ├── App.tsx
│   ├── components/           # Tree, EntryDetail, SettingsDialog, SyncPanel, ...
│   ├── hooks/                # useNow, useAutoLock (Invariant 7, ADR-12)
│   └── lib/                  # typed wrappers over Tauri commands; settings.ts
└── src-tauri/
    ├── Cargo.toml
    ├── tauri.conf.json
    └── src/
        ├── main.rs
        ├── lib.rs
        ├── store/            # our types + Store trait; name/gpg_id/tree/entry are
        │                     #   ours outright (F-1, F-6); prs.rs holds the impl
        ├── crypto/           # our Gpg trait; prs.rs wraps prs-lib for *decrypt*,
        │                     #   gnupg.rs spawns gpg for *encrypt* (ADR-6)
        ├── git/              # our Vcs trait; mod.rs is git2-backed and local
        │                     #   (commit, status, per-entry history, blobs),
        │                     #   remote.rs spawns the user's `git` (ADR-9)
        ├── settings.rs       # user settings; `pass`'s env vars win (ADR-11)
        ├── generate.rs       # password generation (CSPRNG, no modulo bias)
        ├── otp.rs            # otpauth:// parsing + TOTP with countdown
        ├── secret.rs         # zeroizing secret newtypes
        ├── clipboard.rs      # copy + auto-clear
        ├── commands.rs       # #[tauri::command] surface
        └── error.rs          # typed, secret-free errors
```

---

## 6. Core domain model

- **Store**: resolves `PASSWORD_STORE_DIR` or `~/.password-store`.
- **Node**: folder or entry; the path *is* the identity (e.g. `Email/gmail.com`).
- **Recipients**: resolved by walking up from an entry to the nearest `.gpg-id`.
- **Entry (decrypted)**: `{ password: <first line>, fields: [{key, value}], raw }`.
  Fields are parsed from `key: value` lines by convention; `otpauth://` lines feed OTP.
- **Secret**: zeroizing wrapper; short-lived; never serialized to the frontend
  except a single field on explicit reveal.

---

## 7. Implementation phases

> Update **Status**: ☐ todo · ◐ in progress · ☑ done

### Phase 0 — Scaffold & decision — Status: ☑
- ☑ Init Tauri 2 app with React + TS + Tailwind + Vite via pnpm.
- ☑ Window renders on Linux (verified); `core_version` round-trips over IPC under
  a strict CSP. macOS/Windows unverified locally — CI is the check.
- ☑ CI workflow (`.github/workflows/ci.yml`): fmt + clippy `-D warnings` + test +
  bundle on Linux/macOS/Windows. Written but not yet run — no remote configured.
- ☑ Add `CLAUDE.md` with conventions from §9.
- ☑ **ADR-4 resolved:** wrap `prs-lib` behind our own traits (see §3).

### Phase 1 — Read-only core — Status: ☑
- ☑ **Audit `prs-lib` against §4** (ADR-4) — done, findings in ADR-4a. Verdict:
  wrap. `store/` must own `.gpg-id` walk-up (F-1) and name validation (F-6).
- ☑ `store`: our `Store` trait + domain types; `prs-lib`-backed impl. Locate
  store (incl. `PASSWORD_STORE_DIR`, which `prs-lib` ignores), walk tree,
  resolve the nearest `.gpg-id` **ourselves** — `Recipients::load` is root-only
  (F-1). `EntryName` is the validation choke point for F-6 and constructs
  `prs_lib::Store` field-wise to bypass `shellexpand`. Names we reject surface
  as `Tree::unsupported` rather than disappearing from the tree.
- ☑ `crypto`: our `Gpg` trait; `prs-lib`'s `backend-gnupg-bin` behind it (spawns
  `gpg`, stdin→stdout, no disk). No `prs-lib` type crosses out of these modules.
  `crypto/prs.rs` builds `crypto::Config` itself so `gpg_tty` (F-2) and
  `verbose` (F-3) are `false` at a site we own and test. `secret.rs` holds
  `Secret`, which implements no `Debug` — so no struct containing one can
  derive it either, making Invariant 4 a compile error rather than a review
  note. `tests/gpg_roundtrip.rs` does the §8 round trip against a real `gpg`
  in an ephemeral `GNUPGHOME`.
  - *Note:* `prs_lib::crypto::Context` is a `Box<dyn IsContext>` with no `Send`
    bound, so it cannot live in Tauri's shared state and `unsafe_code` is
    forbidden. It is cached in a `thread_local!` instead — it holds no secret,
    only the `gpg` path and the two flags above.
- ☑ Parse decrypted plaintext into the Entry model (`store/entry.rs`). First
  line is the password; a field separator is a colon **followed by whitespace or
  end of line**, so a bare `https://…` line stays free text rather than becoming
  a `https` field. Unparsed lines survive as `notes` rather than being dropped,
  for the same reason `Tree::unsupported` exists. `otpauth://` (bare or as a
  field value) fills a dedicated slot for Phase 2. `Entry` holds `Secret`s and so
  has no `Debug`/`Serialize`; the only serializable view is `EntryMetadata`
  (flags plus field keys, no values), which is what `show_entry` will return.
  - *Deliberate Invariant 4 exception:* a field **key** is a plain `String`, not
    a `Secret` — the UI cannot offer a reveal without rendering the label. Keys
    only; a value never becomes a `String`.
- ☑ Commands (`commands.rs`): `list_tree`, `show_entry` (metadata only), and
  `reveal_password` / `reveal_field` / `reveal_notes` — one value per call, and
  `reveal()` is the single place a `Secret` becomes a `String`. The logic lives
  on `Core` and the `#[tauri::command]` fns are one-liners over it, so the whole
  surface is testable against a fake `Store` and a fake `Gpg`.
  - *No `reveal_otp`:* the `otpauth://` URI embeds the shared seed. Phase 2
    computes the code in the core and sends only the code.
  - `Core` opens the store and the backend **per command** rather than at
    startup: both fail for reasons the user can fix while the app runs (no store
    directory, no `gpg` on `PATH`), and reopening makes the fix take effect on
    the next click instead of the next launch. Cheap — a `canonicalize`, plus a
    `gpg` probe that hits the `thread_local` context cache.
  - Nothing decrypted is cached between commands, so a reveal is its own
    decrypt. That is also why Invariant 7 has nothing to clear yet.
- ☑ Frontend: `components/Tree.tsx` (recursive, expand/collapse, `unsupported`
  surfaced in a disclosure) + `components/EntryDetail.tsx` (metadata on select;
  every value **hidden by default** behind a per-row Reveal/Hide toggle). A
  revealed value lives only in `EntryDetail`'s local state: hiding deletes the
  slot, and `App` mounts the detail view with `key={name}` so switching entries
  unmounts it rather than carrying a revealed value across.
- ☑ **Definition of done** — covered by `tests/read_store.rs`, which drives the
  real command surface against a real `gpg` and a temp store: browse the tree,
  read metadata, reveal a password, a repeated-key field, and notes; assert the
  serialized metadata contains no value; assert the store directory is
  byte-identical before and after (Invariant 1) and that no file under it holds
  the plaintext. The GPG fixture is shared with `tests/gpg_roundtrip.rs` in
  `tests/common/`.
  - *Unverified locally:* the GUI itself has not been click-tested against a
    real store — the read path is covered at the core, not through the webview.

### Phase 2 — Clipboard & OTP — Status: ☑
- ☑ `clipboard`: the copy happens in the core (Invariant 2) and auto-clears
  after `PASSWORD_STORE_CLIP_TIME` — default 45s — **only if the clipboard still
  holds what we put there** (Invariant 6). Three decisions worth recording:
  - What we keep in order to answer "is it still ours" is a `RandomState`-keyed
    SipHash of the value, **not the value**. `pass` parks the password in a
    background subshell for the whole window; a second live plaintext sitting in
    memory for 45s is the kind of thing §4 exists to prevent. A hash collision
    would mean clearing a clipboard we did not set — the harmless direction.
  - A generation counter, bumped per copy and per manual clear, keeps a first
    copy's expired timer from cutting a second copy's window short. It earns its
    keep in the case the fingerprint cannot see: the *same* value copied twice.
  - `Backend` and `Scheduler` are traits, so the clear rule is a deterministic
    unit test instead of a 45-second sleep. `SystemClipboard` (`arboard`, no
    default features, `wayland-data-control` on) opens **lazily but is then
    kept** — unlike the store and the `gpg` backend, because on X11 and Wayland
    the process that set the clipboard is the one that serves it. Every write
    asks the platform to keep the value out of clipboard history: Windows'
    cloud clipboard, macOS' Universal Clipboard, the Wayland password-manager
    hint. All three platforms spell it `Set::exclude_from_history`.
  - *Known limit, closed in Phase 5:* the clear runs on a thread that dies with
    the process, so quitting inside the clip window left the secret on the
    clipboard. `Clipboard::clear_if_outstanding` now runs the same fingerprint
    check from the app's exit handler (ADR-12). A process killed outright —
    SIGKILL, a force quit, a crash — still never reaches it.
- ☑ `otp`: `otpauth://` → TOTP via `totp-rs` (`otpauth` + `zeroize` features
  only). Parsed with `from_url_unchecked` deliberately — the checked constructor
  enforces RFC 4226's 128-bit minimum seed and real provisioning URIs are
  routinely shorter (Google's are 80-bit); `pass otp` reads those, so refusing
  them would be us disagreeing with the user's store. `TotpUrlError` quotes the
  URI it rejected and that URI carries the seed, so `Error::InvalidOtpUri` has
  no payload at all (Invariant 5). `Otp` takes the Unix second as a parameter,
  which makes the RFC 6238 vectors a test rather than a comment.
- ☑ Commands: `copy_password` / `copy_field` / `copy_notes` / `copy_otp`, each
  returning a `CopyReceipt` that carries the clip window and nothing about the
  value, plus `otp_code` and `clear_clipboard`. `Core::copy` is the single place
  a `Secret` reaches the clipboard, mirroring `reveal`. Still no `reveal_otp`.
- ☑ Frontend: Copy beside Reveal on every row, and an OTP row that stays hidden
  until asked for, then counts down and refetches from the core as each window
  expires. Copying an OTP works *without* showing one, so the common case never
  renders a code. A notice at the foot of the detail view says what is on the
  clipboard, counts down with it, and offers "Clear now". `useNow` subtracts a
  stored deadline from the clock rather than decrementing a counter, so a
  suspend cannot leave a countdown claiming more life than there is.
  - *Why the OTP is hidden by default:* showing it means decrypting on select,
    which would pop a pinentry at a user who only clicked an entry to look at
    it — and again every period, for as long as they left it open.
- ☑ **Definition of done:** the clipboard rules are pinned against a stub
  backend and a hand-fired scheduler (clears what is ours, leaves what is not,
  cancels on a later copy); the OTP against the RFC 6238 vectors; and
  `tests/read_store.rs` now drives `otp_code` over real ciphertext and asserts
  the payload carries neither seed nor URI.
  - *Unverified in CI:* the real `SystemClipboard` has an `#[ignore]`d
    round-trip test — `cargo test --lib -- --ignored the_system_clipboard` —
    since CI has no display server. Run against a live Wayland session.
  - *Still unverified locally:* the GUI has not been click-tested against a real
    store; the copy and OTP paths are covered at the core, not through the
    webview.

### Phase 3 — Mutations — Status: ☑
- ☑ **Audit `prs-lib`'s write path against §4** — done, findings in ADR-6.
  Verdict: unlike the read path, this one cannot be made safe from outside the
  crate. `crypto/gnupg.rs` spawns `gpg` itself with `pass`'s flag set, passing
  `.gpg-id` ids through verbatim; `Gpg::encrypt_file` is the trait method, and
  the write is atomic. `tests/gpg_encrypt.rs` checks the result against a real
  `gpg`: it decrypts, it carries exactly the `.gpg-id`'s recipients and no
  others (F-9), an unresolvable recipient is refused by name before anything is
  written (F-8), and the store directory holds nothing but the ciphertext.
- ☑ `insert`, `edit`, `generate`, `rm`, `mv`, `cp` — each re-encrypting to the
  recipients of the name being *written*, resolved by our own walk-up.
  `Core::write` is the single site that does it, so Invariant 8 is one rule
  rather than six call sites that each have to remember it.
  - `insert` refuses to overwrite and `edit` refuses to create: keeping them
    apart is what stops a mistyped name from destroying a password. Same for
    `mv`/`cp` onto an occupied name.
  - `mv`/`cp` move the ciphertext as-is **only when source and destination
    resolve to the same `.gpg-id` file**, and decrypt/re-encrypt otherwise.
    Compared by the file the walk-up landed on, not by the ids in it: two
    `.gpg-id`s listing the same recipients today are still two decisions. The
    common case — renaming within a folder — therefore costs no pinentry.
  - `rm` prunes directories its entry emptied, as `pass` does; otherwise the
    tree would show a folder the user has no way to remove.
  - `generate` never returns the password. It writes the entry and puts the
    value on the clipboard, so the usual flow — generate, paste into the site
    asking for it — happens without it being rendered anywhere; to see it the
    user reveals it like any other. The receipt is **optional**: a machine with
    no display server fails the copy, and reporting that as a failed generate
    would tell the user their entry was not created when it was.
  - `generate.rs` mirrors `pass generate`, including
    `PASSWORD_STORE_GENERATED_LENGTH`. Entropy comes from the OS via
    `getrandom`, and characters are chosen by **rejection sampling**: `byte %
    62` would favour the first 8 characters of the alphabet by 5/4. The
    rejection rule is tested by feeding it every byte value rather than by
    sampling — one pass over `0..=255` must yield each character exactly four
    times, which is a proof instead of a probability that cannot fail
    intermittently.
  - Inbound plaintext is not a hole in Invariant 2: a password the user just
    typed is *in* the webview because they typed it, and the invariant governs
    what comes back out. `commands::body` is where core custody begins.
- ☑ Auto-commit to git after each mutation, in `pass`'s own wording — a store's
  history is shared with the CLI, so `git log` should not betray which client
  wrote which commit. `git.rs` discovers the repository by searching upward, as
  `pass`'s `set_git` does, so a store kept inside a dotfiles checkout is
  versioned by it here exactly as it is there. `git2` is taken with
  `default-features = false`: a commit is local, and the network features pull
  in libssh2 and OpenSSL for a question Open Decision 2 has not answered.
  - **A commit failure is not a write failure.** By the time git runs the entry
    is already encrypted on disk, so returning `Err` would tell the user their
    password was not saved when it was — and send them back to retry into an
    `EntryExists`. The outcome rides in a new `WriteReceipt`, which every
    mutation now returns, and the interface says which of the two happened.
    Same shape as `generate`'s optional clipboard receipt, same reason.
  - A store with no repository is the ordinary case, not a failure: the factory
    yields `Option`, and `commit: null` means "unversioned", not "went wrong".
  - `Error::Git` carries libgit2's own message, which the crypto layer's errors
    deliberately do not. Safe here by construction rather than by audit: git
    only ever reads and writes what is on disk, and Invariant 1 means what is on
    disk is ciphertext.
  - Staging is per-path, as `pass` does it, so a mutation never sweeps up
    unrelated work in the store. Committing an unchanged tree is skipped —
    `git commit` refuses an empty commit and the shared history should not
    accumulate ours.
- ☑ Frontend: new-entry dialog (generate or type, with length and punctuation
  options), edit, rename, duplicate, delete-with-confirm — all on the
  platform's `<dialog>`, which gives Escape, focus trapping and an inert
  background rather than reimplementing them.
  - Dialogs are **mounted only while open**. That is a security property, not a
    rendering choice: the edit form holds a whole decrypted entry (ADR-8), and
    unmounting is what guarantees the string leaves with the form.
  - Generating is the default and never renders the password: the core writes it
    and copies it, and the form says so before the fact. The clipboard notice
    moved up to `App` for this — a password on the system clipboard is a fact
    about the machine, not about whichever entry is on screen, and a generated
    one has no entry on screen at all when it lands.
  - A failed commit is the one notice that does not fade. It is the only place
    the divergence is ever mentioned.
  - `store_has_history` is a small read-only probe added for the delete
    confirmation: "still recoverable from the history" is true of a versioned
    store and false of every other one, and guessing which would be exactly the
    failure §4.1 principle 5 is about. Unknown reads as unversioned.
- ☑ **Definition of done:** an entry created here is readable by the `pass` CLI.
  `tests/write_store.rs` drives the real command surface against a real `gpg`
  and a temp store, then hands that store to the `pass` binary: insert, edit,
  generate, copy, rename and remove all round-trip, and `pass show` prints back
  exactly what we wrote. It also asserts no file under the store holds any
  plaintext (Invariant 1) and that nothing but ciphertext and `.gpg-id` is left
  behind. `pass` is skipped around where absent — it is a bash script and does
  not exist on Windows, which is why ADR-2 reimplements the format — so on
  Windows CI this degrades to our own round trip.
  - `tests/git_history.rs` is the same standard for the history: a real store in
    a real repository, driven through the command surface, then inspected with
    `git2` rather than through our own receipts. It asserts the log reads in
    `pass`'s words, that a rename removes the old path from the tree rather than
    only from the working directory, that nothing is left uncommitted, and that
    the blob the history holds decrypts back to what was written — so a store
    cloned from that repository is a store `pass` can use.
  - *Still unverified locally:* the GUI has not been click-tested against a real
    store. The mutation paths are covered at the core, not through the webview.

### Phase 4 — Git sync — Status: ☑
- ☑ **Open Decision 2 resolved (ADR-9):** `git2` for everything local, the
  user's own `git` spawned for anything that reaches the network. The reasoning
  is Invariant 3's, applied to a different credential — we do not handle their
  SSH passphrase or their token for the same reason we do not handle their GPG
  passphrase. `git.rs` becomes `git/`, with the spawning half in
  `git/remote.rs`.
- ☑ `status`: branch, upstream, ahead/behind, and a count of files the history
  does not have. **Local only** — it reads the remote-tracking ref rather than
  the remote, so the window can draw an indicator on arrival without that being
  an operation which can hang or prompt.
  - The uncommitted count is not redundant with Phase 3's auto-commit: it is
    exactly what a *failed* commit leaves behind, and a sync that pushed without
    mentioning it would leave the user believing those changes had gone out.
  - Scoped to the store's own prefix, so a store inside a dotfiles checkout does
    not report the user's unrelated work.
- ☑ `sync`: fetch → merge → push, in one command, with three answers that are
  states rather than failures — `NoRemote`, `UpToDate`, `Synced { pulled,
  pushed }` — and one that is neither, `Conflicted`.
  - **A conflicted merge is rolled back (ADR-10).** Conflict markers written
    into ciphertext produce a file that decrypts nowhere, so the store is
    restored byte for byte and the interface names the entries instead. The
    common case never reaches it: one file per entry means two people changing
    two different entries merges cleanly.
  - A store with no remote and a store with no repository give the same answer,
    because it is the same answer.
- ☑ Per-entry history: `entry_history` lists the commits that touched a name —
  message, author, date, and whether it was created, changed or deleted —
  **decrypting nothing**, so opening a history costs no pinentry and no key tap
  (§4.1 principle 1). A removal is listed rather than skipped: it is the commit
  before it that holds the version worth recovering.
- ☑ Reading a past version: `reveal_revision` decrypts one chosen commit's blob
  (ADR-10 — the same whole-body exception ADR-8 records), and
  `copy_revision_password` serves the ordinary recovery without a reveal at all.
  `Gpg::decrypt(&[u8])` was added for it, since a git blob was never a file.
- ☑ Frontend: a sync control in the sidebar with the ahead/behind indicator, the
  upstream named, and what pressing it may cost said *before* it is pressed; a
  history dialog per entry with per-version open and copy.
  - Results are raised to `App`'s notice bar rather than shown in the sidebar:
    a conflict names entries, that column is too narrow to name them in, and a
    conflict is the one result the user must not be able to miss. Same bar, same
    non-fading `warn` tone as a failed commit.
  - The history dialog holds **one** open version at a time — opening a second
    closes the first — and unmounts with the dialog, which is ADR-8's discipline
    applied to ADR-10's exception.
- ☑ **Definition of done:** `tests/git_sync.rs` stands up two real stores over a
  real `file://` remote with a real `gpg` behind both, and drives the command
  surface: a change made in one store reaches the other **and decrypts there**;
  two people changing different entries merges with nobody asked anything; two
  people changing the same entry is reported and leaves the store byte-identical
  and still decryptable by `gpg` itself. It then drives the history over real
  ciphertext — asserting the listing carries no plaintext, and that a version
  decrypted out of a git object matches what was written — and finally scans
  every file under both stores, `.git` included, for plaintext (Invariant 1).
  Skipped around where `git` is absent, as `pass` is in `write_store.rs`.
  - *Unverified:* every remote in the tests is a local path. Nothing here has
    been run against a real SSH or HTTPS remote, so the credential-helper
    behaviour ADR-9 is entirely built around is **argued, not demonstrated**.
    That is the largest gap in this phase.
  - *Also unverified:* the conflict path was driven through the stub in the
    webview, but a real conflicted sync has not been click-tested.

### Phase 5 — Hardening & packaging — Status: ◐

Three of the four items are done; packaging is not started and is the reason
this is not ☑.

- ☑ **Settings (ADR-11):** `settings.rs` holds store path, clip time, generated
  length, idle timeout, lock-on-blur and open-on-select, in a JSON file under
  the platform's config directory, written atomically. **`pass`'s environment
  variables outrank all of it**, and every value crosses IPC with the `Source`
  that decided it so the panel can show a pinned control as fixed and name the
  variable — the alternative being a box that silently does nothing.
  - The store root, the clip window and the generated length are read *per use*
    rather than captured, so a change takes effect on the next click. That is
    the same property opening the store per command already bought.
  - `Core::with_store_root` uses `SettingsFile::ephemeral`, for the reason
    `with_clipboard` exists: a test must not read the developer's own
    configuration and must certainly not write it. An explicit root also
    outranks `PASSWORD_STORE_DIR`, so a variable in the developer's shell cannot
    point a test at their real store.
  - `src/lib/prefs.ts` is gone. Its `localStorage` boolean was always a
    placeholder for this (Open Decision 8), and the store path was never
    something the webview could have told the core anyway.
- ☑ **Auto-lock (Invariant 7, ADR-12):** blur hides revealed values; idle closes
  everything to a lock screen. Neither touches the clipboard and neither flushes
  `gpg-agent` — see the ADR for why both are deliberate. Closes the Phase 2
  clipboard-on-quit limit along the way.
- ☑ **Global search:** a filter over entry *names*, in the sidebar, reachable
  with Cmd/Ctrl+F and cleared with Escape. It prunes the tree to the branches
  leading to a match and opens them, since a match inside a collapsed folder is
  a result the user cannot see.
  - **Names only, and not "optionally fields" as this line used to read.**
    Searching contents means decrypting every entry to answer a keystroke — a
    pinentry prompt per character, or a security key blinking through the
    alphabet. That is §4.1 principle 1's central case, not an edge of it. If it
    is ever wanted it has to be an explicit, one-shot, opt-in action with its
    cost stated, not a filter box.
- ☐ Per-OS packaging + code signing (see Cross-Platform Notes). Untouched.
  Blocked in practice on things this repo does not have: an Apple Developer ID,
  a Windows signing certificate, and any visual identity at all — the bundled
  icons are still Tauri's scaffold mark.
- ☑ **Definition of done, so far:** the precedence rule is a unit test rather
  than something to be checked by reading (`settings.rs` — environment beats
  configured beats default, a pinned value keeps the configured one behind it,
  a rejected change leaves the previous settings in place, and a file round
  trips). The early clipboard clear is pinned against the stub backend in
  `clipboard.rs`: it wipes a password still inside its window, and leaves a
  value the user copied afterwards, a window that already fired, and a clipboard
  with nothing outstanding.
  - *Driven in the webview on 2026-08-02*, through `pnpm dev:mock`: search
    (match, folder match, no match, Escape), the settings panel (a refused
    value, a saved value flowing through to the new-entry form's length, and the
    environment-pinned state under `?env=`), blur-clear, and the idle lock. It
    found two defects. The settings form's refusal message rendered at the
    bottom of a scrolling area, so pressing Save on a rejected value looked like
    pressing Save and nothing happening; it now sits outside the scroll, beside
    the button that caused it. And the lock screen was an overlay `div`, which
    left the tree, the filter, Sync and Settings on the Tab order behind it —
    it is a `<dialog>` on `showModal` now, verified inert by trying to focus
    through it.
  - *Not covered:* there is still no frontend test runner, so none of that is
    a regression test. The settings *file* is never written in any test that
    runs — `SettingsFile::ephemeral` deliberately has no path, and the atomic
    write is exercised only by `settings.rs`'s own round-trip test against a
    temp directory.

### Phase 6 — Optional / later — Status: ☐
- `rpgp` pure-Rust backend for a fully bundled build.
- Smartcard / YubiKey **verification** pass. Note the *design* constraint is
  already binding — §4.1 principle 1 exists because a hardware key is a
  confirmed operating condition, not a hypothetical. What is deferred is
  testing against real hardware, not designing for it.
- Multi-`.gpg-id` subfolder UX; recipient management + subtree re-encrypt UI.
- Import from other managers.

### Phase 7 — Onboarding: nothing → working store — Status: ☐ (blocked on ADR-7)

**Committed by `PRODUCT.md`, unscoped, and deliberately unsequenced.** Its
number is not its priority: it serves the *primary* user (§1), so it plausibly
outranks Phases 4–6. It is last in this list only because nothing about it is
decided yet, and the numbering above is load-bearing in code comments and
cross-references.

- A user with **no GPG key and no store** reaches a working store without a
  terminal: key generation, then the equivalent of `pass init`.
- **The Invariant 3 constraint is the whole design problem.** This does not
  conflict with "we never handle passphrases" *only so long as* key generation
  is driven through `gpg` with the platform pinentry prompting for the new key's
  passphrase — **never `--passphrase`, never `--pinentry-mode loopback`**, no
  exceptions for "just onboarding". A pinentry appearing as a separate OS-level
  window mid-wizard is expected behaviour, not a bug to design around.
- Detecting and explaining a missing/broken `gpg` is part of this, and is the
  sharpest test of §4.1 principle 5: "install Gpg4win" beats "gpg not found".
- **Needs ADR-7 before any code.** Open questions at minimum: which `gpg`
  invocations (`--full-generate-key` batch vs. `--quick-generate-key`), what we
  do on a machine with an existing key we did not create, whether `pass init`
  equivalence means writing `.gpg-id` ourselves (it does — `store/gpg_id.rs`
  already owns that format) and whether onboarding may create a git repo.

---

### Not yet true (do not claim)

`PRODUCT.md` lists these as absent; keeping them here stops a phase marker from
being read as more than it is:

- **No released build, no README, no screenshots, no project page, no logo.**
  The bundled icons are Tauri's scaffold mark and `public/favicon.svg` is the
  Vite default — placeholders, not identity.
- **No benchmarks**, despite speed being the positioning (§1).
- **No users, downloads, stars, or testimonials.**
- **No sync has ever run against a real remote.** `tests/git_sync.rs` drives two
  real repositories end to end, but every remote in it is a local path. The
  credential-helper behaviour ADR-9 is entirely built around — `ssh-agent`, a
  keychain, an HTTPS token, `GIT_TERMINAL_PROMPT=0` turning a hang into a
  message — is **argued from how `git` works, not demonstrated**. This is the
  largest unverified claim in Phase 4.
- **The GUI has never been click-tested against a real store.** Phases 1–4 are
  verified at the command surface by `src-tauri/tests/`, not through the webview.
  This is the single largest gap between "☑" and "works", and Phase 3 widened
  it: the mutation dialogs are the first screens that can *destroy* something.
  - **The webview half was driven on 2026-08-01, against a stub.** `pnpm
    dev:mock` serves the frontend with `@tauri-apps/api/core` aliased to
    `src/lib/mockInvoke.ts`, so every component is exercised through the real
    `commands.ts` wrappers. Tree, detail pane, reveal, copy, OTP, and all four
    mutation dialogs were driven end to end, including the refusal paths
    (`EntryExists`, a `..` name) and the failed-commit notice. It found one
    defect: the edit dialog's textarea was not getting the `bg-exposed` wash
    ADR-8 claims for it, because `inputClass` also sets a background and won on
    stylesheet order rather than class order.
  - **Phase 5's screens were driven the same way on 2026-08-02**: search in all
    four of its states, the settings panel including a refusal and an
    environment-pinned control, blur-clear, and the idle lock closing an open
    edit form. It found two defects — a refusal message rendered below the fold
    of a scrolling form, and a lock screen that left the app behind it on the
    Tab order. Both fixed; see Phase 5's definition of done.
  - **Phase 4's screens were driven the same way on 2026-08-02**: the sync panel
    in all four of its states (tracking with ahead/behind, no remote, no
    repository, uncommitted changes), a sync reporting each outcome including
    the conflict notice, and the history dialog — listing, opening a version,
    the one-at-a-time rule, and copying a past password. It found one defect
    too: every row claimed "Copied" after any one of them was, because the row
    matched on the clipboard notice's label rather than on the revision.
  - **It establishes nothing about the core, and the sentence above still
    stands.** No GnuPG runs, nothing is decrypted, no file is written, and the
    clipboard is a variable. The stub *mirrors* the Rust rules — the separator
    in `store/entry.rs`, the validation in `store/name.rs`, the refusals in
    `Core`, the strings in `error.rs` — rather than sharing them, so the two can
    drift; when they do, the Rust side is right. Every §4 invariant remains
    verified only at the command surface.
  - `scripts/make-fixture-store.sh` builds a throwaway store and `GNUPGHOME`
    with the same contents, for the un-stubbed path: point `pnpm tauri dev` at
    it to drive the real core. That run has not been done.
- **No frontend tests at all.** §8 asks for light component tests for the tree
  and the detail pane; there is no test runner in `package.json` to hold them.
  The mock harness above is a way to *drive* the frontend, not a test suite — it
  carries no assertions and nothing runs it in CI.

---

## 8. Testing strategy

- **Unit:** store tree parsing, `.gpg-id` resolution (nested), entry field parsing — with fixtures.
- **Integration:** spin up an ephemeral `GNUPGHOME`, generate a throwaway test key,
  create a temp store, and round-trip encrypt→decrypt and mutate→read-with-CLI.
  These must run in CI on all three OSes.
- **Cross-tool compatibility:** an entry written by our app must be readable by the
  real `pass` binary (guard with a CI check where `pass` is available).
- **Security checks:** assert no plaintext in serialized command outputs except the
  explicit reveal path; assert clipboard clears after timeout; grep logs for secrets in tests.
- **No test may touch the real clipboard.** It is shared state belonging to the
  user's desktop session, not to the process, and on Wayland and X11 the value
  is *served by the process that set it* — so a test that copies through
  `Core::new` does not merely overwrite what the developer had, it leaves them
  with an empty clipboard when the test process exits. CI cannot catch this:
  with no display server the copy fails and the test passes anyway. Build a
  `Core` with `Core::with_clipboard` and an in-process `Backend` instead; the
  `Backend`/`Scheduler` traits are public for exactly this.
- **Frontend:** light component tests for tree/detail; no secret ever stored in frontend state longer than a render.

---

## 9. Conventions for the agent (mirror into CLAUDE.md)

- Rust: `cargo fmt` + `cargo clippy -- -D warnings` clean before done. Errors via
  `thiserror`; **no `unwrap()` on paths that can carry secrets**.
- Never introduce a dependency that would move passphrase handling into our process
  without an explicit ADR update.
- Commits: small and scoped; conventional-commit style; never commit a real store,
  keys, or `.env`.
- When unsure whether something leaks a secret, treat it as if it does.
- Build/run commands: `pnpm tauri dev`, `pnpm tauri build`, `pnpm build`,
  `pnpm lint`; from `src-tauri`: `cargo test`, `cargo fmt --all`,
  `cargo clippy --all-targets -- -D warnings`.

---

## 10. Open decisions (resolve as you go)

1. ~~**ADR-4 — own core vs wrap `prs-lib`.**~~ Resolved: wrap it behind our own
   traits. See §3 ADR-4 for the consequences, including the required §4 audit.
2. ~~**Git network auth.**~~ **Resolved in Phase 4 (ADR-9): `git2` for local
   operations, the user's own `git` spawned for anything on the network.** The
   deciding argument was not simplicity but Invariant 3's, applied to a
   different credential: we do not prompt for their SSH passphrase or hold their
   token for the same reason we do not handle their GPG passphrase. `git2`'s
   network features stay off, and `git` becomes a prerequisite for syncing only.
3. ~~**Reveal policy.**~~ **Resolved in Phase 5 (ADR-12).** Reveal stays per
   field and a revealed value is still dropped on deselect. Auto-hide on blur is
   now real, on by default, and a setting — because re-revealing costs a
   decrypt, which is free behind a cached agent and another tap on a security
   key.
   **Re-hide after N seconds is deliberately not built.** The case it would
   serve — a screen left showing a password — is the idle lock's, and the idle
   lock already covers it without the cost. A per-reveal timer instead fires
   while the user is *actively reading*, so its most likely effect is a second
   pinentry prompt for a value that is on screen because it was just asked for.
   That is §4.1 principle 1 pointing the other way.
4. ~~**Clipboard mechanism.**~~ Resolved in Phase 2: core `arboard`, for the
   no-JS-plaintext property. Taken with `default-features = false` (the default
   set pulls in the `image` crate for clipboard images we never touch) plus
   `wayland-data-control`, so a native Wayland session does not have to go
   through XWayland.
5. **Onboarding scope (ADR-7).** Committed by `PRODUCT.md`, unscoped, blocking
   Phase 7. The hard edge is Invariant 3: pinentry-driven key generation only.
   See Phase 7 for the open questions.
6. ~~**How much `pass` vocabulary to expose.**~~ **Resolved with the Phase 3
   mutation UI (2026-08-01): translate by default; keep the format's own word
   only where the user needs that exact string to act, and gloss it there.**
   The rule, in three parts:
   - **Actions and things get plain words.** *Entry*, *folder*, *password*,
     *notes*, *one-time password*, *your store's history*. Not *secret*, not
     *node*, not *commit*.
   - **Concepts the format forces into view are described by what they do,
     never named.** Recipients → "the keys that can open it"; a differing
     `.gpg-id` → "if the new folder is protected by different keys, the entry is
     decrypted and encrypted again for them"; pinentry → "your system may ask
     for your passphrase, or your security key may need a touch"; clip time →
     "the clipboard clears in 45s". The user is never sent to a file they did
     not know existed.
   - **Two words stay untranslated,** because the user needs them to act outside
     the app: **store**, which is the product's name and every other client's,
     and **GnuPG**, which is the string they have to search for when it is
     missing or broken. Both appear beside an explanation on first use.
   - **Phase 5 adds a third case under the same test, not an exception to it:**
     the settings panel names `PASSWORD_STORE_DIR`, `PASSWORD_STORE_CLIP_TIME`
     and `PASSWORD_STORE_GENERATED_LENGTH` where one of them is overriding a
     control (ADR-11). The user needs that exact string to act — it is what they
     have to find and change in a shell profile — and it appears only on the
     control it has taken over, with what to do about it.

   What settles it is §4.1 principle 4 plus the audience test in §1: where the
   CLI-averse user and the CLI user conflict, the CLI-averse user wins, and the
   CLI user loses nothing here — the *store* is unchanged, only the labels over
   it. Byte-compatibility is a property of the files, not of the wording.
7. **Accessibility.** No product-specific standard has been committed
   (`PRODUCT.md`). Sensible defaults apply; nothing is currently a stated
   obligation. Worth deciding before Phase 5 rather than retrofitting.
8. ~~**Decrypt-on-select, versus §4.1 principle 1.**~~ **Resolved in Phase 5
   (2026-08-02): the principle now reads "unrequested", and the preference is a
   real setting.** A standing opt-in is a request made once rather than per
   click, which is a genuine distinction for a cached-agent user; the default
   stays off, which is what protects the YubiKey user, and the settings panel
   states the cost where the switch is. `src/lib/prefs.ts` and its `localStorage`
   boolean are gone — the setting lives in `settings.rs` with the other five
   (ADR-11).

---

## 11. Cross-platform notes

- **Windows:** requires **Gpg4win** for `gpg.exe` + a pinentry; locate the binary via
  `which`/known install paths. Watch path separators and CRLF line endings.
- **macOS:** `pinentry-mac` for the passphrase prompt; notarization + hardened runtime for distribution.
- **Linux:** `pinentry-gtk`/`-qt`; package as AppImage/Flatpak/deb as desired.
- `git2` links libgit2 vendored, so reading and writing a store — and its local
  history — need no system git. **Syncing does** (ADR-9): `fetch`/`merge`/`push`
  spawn the user's own `git`, which is what makes their credential helper,
  `ssh-agent` and platform keychain work untouched. On Windows that means Git
  for Windows alongside Gpg4win, but only for a store shared with a remote.

**A working `gpg` binary is a hard prerequisite on every platform** — Gpg4win on
Windows, `pinentry-mac` on macOS, `pinentry-gtk`/`-qt` on Linux. Its absence is a
first-class, explainable failure state (§4.1 principle 5), not a crash, and
detecting it is part of Phase 7.

### Identity & packaging metadata

Fixed by `PRODUCT.md`; packaging (Phase 5) must not drift from it.

| | |
|---|---|
| Name | **Password Store** |
| Window title | `Password Store` |
| Package | `password-store-gui` |
| Bundle identifier | `dev.passwordstoregui.app` |
| License | `GPL-3.0-or-later` (ADR-4 — a consequence of statically linking LGPL `prs-lib`) |

No visual identity exists. The bundled icons and `public/favicon.svg` are
scaffold defaults — **not a reference for anything**, and not to be extended
into a design. No voice or tone has been established either.

---

## 12. References

- `PRODUCT.md` — audience, positioning, product principles, evidence on hand
- pass — https://www.passwordstore.org/ (format, env vars, extensions)
- prs (reference impl, `prs-lib`, `prs-gtk3` example GUI) — https://sr.ht/~timvisee/prs/
- QtPass (UX prior art) — https://qtpass.org/
- Tauri 2 docs — https://tauri.app/
- gpgme Rust bindings (for the optional backend) — https://github.com/gpg-rs/gpgme
