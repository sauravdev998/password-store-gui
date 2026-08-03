# CLAUDE.md

Conventions for working in this repo. `PLAN.md` is the source of truth for
scope, phases, and architecture decisions — read it before starting a phase and
update the **Status** markers as phases land.

## What this is

A Tauri 2 GUI client for [`pass`](https://www.passwordstore.org/). The store is
a tree of GPG-encrypted files on disk, not a database. Anything we write must
stay byte-compatible with the `pass` CLI and other clients.

## Security invariants

`PLAN.md` §4 lists eight hard constraints. They are not guidelines — a change
that violates one is a bug even if the feature works. The short version:

1. Plaintext never touches disk.
2. Plaintext stays in Rust; it crosses IPC only on an explicit user reveal.
   Clipboard copy happens in the core, never in JS.
3. We never handle passphrases — `gpg-agent` + pinentry do. No loopback pinentry.
   This includes **creating** a key (ADR-7): `--batch` is what lets the agent
   prompt, not what stops it, so `--passphrase`, `--pinentry-mode` and
   `%no-protection` stay out of the shipped path — and out of the fixtures used
   to test it.
4. Secret buffers are wrapped in `secrecy`/`zeroize`, never `Debug`/`Display`.
5. Nothing secret reaches logs, errors, traces, or panics.
6. Clipboard auto-clears — on its timer and on exit — and only if it still holds
   what we put there.
7. Auto-lock: leaving the window hides revealed values, going idle closes
   everything to a lock screen. Neither touches the clipboard (ADR-12).
8. Writes encrypt to the recipients from the nearest `.gpg-id`, walking up. On a
   recipient change, the whole affected subtree is re-encrypted — all or
   nothing, and priced before it is agreed to (ADR-13).

When unsure whether something leaks a secret, assume it does.

## Commands

```sh
pnpm install            # once
pnpm tauri dev          # run the app (starts Vite + cargo)
pnpm tauri build        # release bundle for the current OS
pnpm dev                # frontend only, no Rust core
pnpm dev:mock           # frontend against a stubbed core (see below)
pnpm build              # typecheck + bundle the frontend
pnpm lint               # oxlint

cd src-tauri
cargo test
cargo fmt --all
cargo clippy --all-targets -- -D warnings
```

## Rust

- `cargo fmt` and `cargo clippy -- -D warnings` must be clean before a change is
  done. CI enforces both.
- Errors via `thiserror`, typed and secret-free by construction. Never build an
  error message by interpolating decrypted content or a path's file contents.
- `unwrap_used` / `expect_used` are lint-warned crate-wide. No `unwrap()` at all
  on a path that can carry a secret; elsewhere prefer `?` and justify any
  exception in a comment.
- `unsafe_code` is forbidden.
- New modules follow the layout in `PLAN.md` §5.

## Frontend

- The webview holds no long-lived secrets. A revealed field lives in component
  state for as long as it is on screen and no longer — never in a store, never
  in `localStorage`, never in a URL. Nothing writes to `localStorage` at all
  since Phase 5; settings live in the core.
- All IPC goes through typed wrappers in `src/lib/commands.ts`; components do
  not call `invoke` directly.
- A dialog holding plaintext is **mounted only while open** — unmounting is what
  guarantees the string goes with it. Two commands return a whole body rather
  than one field, both recorded rather than left to be discovered: the edit form
  (ADR-8) and reading a past version (ADR-10). Do not add a third without an
  ADR.
- Anything new that puts a decrypted value on screen must answer to `relock` in
  `EntryDetail` or unmount with its dialog, or auto-lock will not reach it
  (ADR-12). Clear values; do not remount the pane, which would decrypt again.
- Tailwind v4 (CSS-first config in `src/index.css`), no heavyweight UI kit.
- Modals use the platform `<dialog>` with `showModal`, including the lock
  screen. A `z-index` overlay is not a substitute: it leaves everything behind
  it on the Tab order.

## Driving the frontend

`pnpm dev:mock` serves the app with `@tauri-apps/api/core` aliased to
`src/lib/mockInvoke.ts`, so every component runs through the real
`commands.ts` wrappers with no Rust behind them. It is how each phase since 3
has been click-tested, and it has found a defect every time. URL flags drive
the awkward states (`?noGit=1`, `?sync=conflicted`, `?env=storeDir`,
`?lockAfter=5`, `?setup=fresh`, …) — see the file.

**It establishes nothing about the core.** No GnuPG runs, nothing is decrypted,
no file is written, and the clipboard is a variable. The stub *mirrors* the
Rust rules rather than sharing them — the entry parser, name validation, the
refusals in `Core`, the strings in `error.rs`, the settings precedence, the
`.gpg-id` walk-up and staleness rules behind the keys panel, and `store_state`
behind the onboarding wizard — so when you change one of those, change the stub
too, or it stops testing the app and starts testing a fiction. When they
disagree, the Rust side is right.

## Settings

`settings.rs` owns the six user settings; `src/lib/settings.ts` is the frontend
half. Three of them duplicate a `pass` environment variable, and **the variable
wins** (ADR-11): the CLI obeys it, and a GUI that quietly disagreed would have
the two looking at different stores. A new setting that shadows a
`PASSWORD_STORE_*` variable follows the same rule, and surfaces its `Source` so
the panel can say what is in charge rather than offering a control that does
nothing.

Read settings at the point of use, not at startup — like the store and the
`gpg` backend, so a change takes effect on the next click.

## Dependencies

`prs-lib` is **wrapped, not exposed** (ADR-4): its types live only in
`store/prs.rs` and `crypto/prs.rs` behind our own traits, and must never appear
in `commands.rs`, in a serialized payload, or in a public signature outside
those modules.

What it actually backs is narrower than ADR-4 first assumed, and the seam is
why that was cheap to change: **decryption and the store walk, and nothing
else.** Encryption is our own `gpg` invocation in `crypto/gnupg.rs` (ADR-6),
recipient walk-up and name validation are ours in `store/` (ADR-4a F-1, F-6),
and git is `git2` plus the user's own binary (ADR-9) — `prs-lib`'s git is not
used at all.

Two dependency rules, both with an ADR behind them:

- Never add a dependency that would move **passphrase** handling into our
  process without updating ADR-3 first.
- Never add one that would move **network credential** handling into it —
  in-process SSH or HTTPS auth — without updating ADR-9. Same reasoning, same
  answer: `git` and `gpg-agent` hold the user's credentials, and we do not.

## Commits

Small, scoped, conventional-commit style (`feat:`, `fix:`, `chore:`). Never
commit a real store, a private key, or `.env`.
