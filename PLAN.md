# PLAN.md — Cross-Platform `pass` GUI Client

> Working plan for Claude Code. This is a living document: update the **Status**
> column as phases land, and record any deviation in **Architecture Decisions**.
> Treat the **Security Invariants** section as hard constraints, not suggestions.

---

## 1. What we're building

A native, fast GUI client for [`pass`](https://www.passwordstore.org/), the
standard Unix password manager, running on **Windows, macOS, and Linux**.

`pass` is not a database — it's a directory tree of GPG-encrypted files
(default `~/.password-store/`), optionally versioned with git. Our client is a
careful GUI over that format: it must stay **byte-compatible** with the on-disk
layout so a store edited by our app still works with the `pass` CLI, QtPass, the
mobile apps, etc.

### Goals
- Interoperate perfectly with existing `pass` stores and GPG setups.
- Feel instant: fast tree browsing, fast decrypt, minimal memory footprint.
- Ship a single small binary per platform.
- Never compromise on secret hygiene (see Security Invariants).

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
| Git | **`git2`** (vendored libgit2) | No system git needed for local ops. |

### Rust crates (initial)
- `tauri` (2.x) + relevant plugins
- `prs-lib` (GPL-3) — store, recipients, GPG backends, git; wrapped, never exposed (ADR-4)
- `git2` — git operations
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

---

## 5. Repository layout

```
password-store-gui/
├── PLAN.md
├── CLAUDE.md                 # conventions + commands for the agent (see §9)
├── package.json              # pnpm workspace root
├── vite.config.ts
├── src/                      # React / TS frontend (no long-lived secrets)
│   ├── main.tsx
│   ├── App.tsx
│   ├── components/           # Tree, EntryDetail, SearchBar, GitStatus, ...
│   ├── hooks/                # useEntries, useEntry, useGit, ...
│   └── lib/                  # typed wrappers over Tauri commands
└── src-tauri/
    ├── Cargo.toml
    ├── tauri.conf.json
    └── src/
        ├── main.rs
        ├── lib.rs
        ├── store/            # our types + Store trait; prs.rs holds the prs-lib impl
        ├── crypto/           # our Gpg trait; prs.rs wraps prs-lib's gnupg-bin backend
        ├── git.rs            # status, commit, pull, push, per-entry history
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

### Phase 1 — Read-only core — Status: ◐
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
- Parse decrypted plaintext into the Entry model.
- Commands: `list_tree`, `show_entry` (returns metadata; password revealed only on demand).
- Frontend: tree browser + entry detail with password **hidden by default** and a reveal toggle.
- **Definition of done:** browse a real store and reveal a password; nothing written to disk; no plaintext in logs.

### Phase 2 — Clipboard & OTP — Status: ☐
- `clipboard`: copy-in-core + auto-clear timer (Invariant 6).
- `otp`: parse `otpauth://`, render TOTP with live countdown.
- Frontend: copy buttons per field; OTP widget.

### Phase 3 — Mutations — Status: ☐
- `insert`, `edit`, `generate`, `rm`, `mv`, `cp` — each re-encrypting to correct recipients.
- Auto-commit to git after each mutation (conventional message like the CLI).
- Frontend: add/edit forms, generate dialog (length + symbol options), delete/rename with confirm.
- **Definition of done:** an entry created here is readable by the `pass` CLI.

### Phase 4 — Git sync — Status: ☐
- `git`: status, pull, push, per-entry history, basic conflict surfacing.
- Decide network-auth path (see Open Decisions).
- Frontend: sync button, ahead/behind indicator, history/diff view (metadata only, never plaintext diffs on screen without reveal).

### Phase 5 — Hardening & packaging — Status: ☐
- Auto-lock / idle-clear / blur-clear (Invariant 7).
- Global search/filter across entry names (and optionally fields, decrypt-on-demand).
- Settings: store path, clip time, generated length, lock timeout.
- Per-OS packaging + code signing (see Cross-Platform Notes).

### Phase 6 — Optional / later — Status: ☐
- `rpgp` pure-Rust backend for a fully bundled build.
- Smartcard / YubiKey verification pass.
- Multi-`.gpg-id` subfolder UX; recipient management + subtree re-encrypt UI.
- Import from other managers.

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
2. **Git network auth.** `git2` credential callbacks (SSH/HTTPS in-process) vs.
   shelling to the user's `git` for remote ops so their credential helpers just work.
   Leaning: shell to `git` for network ops, `git2` for local — simplest and most compatible.
3. **Reveal policy.** Auto-hide on blur? Re-hide after N seconds? Per-field vs whole-entry reveal.
4. **Clipboard mechanism.** Core `arboard` (chosen, for the no-JS-plaintext property)
   vs Tauri clipboard plugin — keep `arboard` unless a platform quirk forces otherwise.

---

## 11. Cross-platform notes

- **Windows:** requires **Gpg4win** for `gpg.exe` + a pinentry; locate the binary via
  `which`/known install paths. Watch path separators and CRLF line endings.
- **macOS:** `pinentry-mac` for the passphrase prompt; notarization + hardened runtime for distribution.
- **Linux:** `pinentry-gtk`/`-qt`; package as AppImage/Flatpak/deb as desired.
- `git2` links libgit2 vendored, so local git needs no system git; network SSH may
  still pull in libssh2 — see Open Decision 2.

---

## 12. References

- pass — https://www.passwordstore.org/ (format, env vars, extensions)
- prs (reference impl, `prs-lib`, `prs-gtk3` example GUI) — https://sr.ht/~timvisee/prs/
- QtPass (UX prior art) — https://qtpass.org/
- Tauri 2 docs — https://tauri.app/
- gpgme Rust bindings (for the optional backend) — https://github.com/gpg-rs/gpgme
