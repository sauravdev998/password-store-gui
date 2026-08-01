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
4. Secret buffers are wrapped in `secrecy`/`zeroize`, never `Debug`/`Display`.
5. Nothing secret reaches logs, errors, traces, or panics.
6. Clipboard auto-clears, and only if it still holds what we put there.
7. Auto-lock clears the in-memory cache on idle and on blur.
8. Writes encrypt to the recipients from the nearest `.gpg-id`, walking up.

When unsure whether something leaks a secret, assume it does.

## Commands

```sh
pnpm install            # once
pnpm tauri dev          # run the app (starts Vite + cargo)
pnpm tauri build        # release bundle for the current OS
pnpm dev                # frontend only, no Rust core
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
  in `localStorage`, never in a URL.
- All IPC goes through typed wrappers in `src/lib/commands.ts`; components do
  not call `invoke` directly.
- Tailwind v4 (CSS-first config in `src/index.css`), no heavyweight UI kit.

## Dependencies

`prs-lib` provides the store, recipients, GPG backends, and git (ADR-4). It is
**wrapped, not exposed**: its types live only in `store/prs.rs` and
`crypto/prs.rs` behind our own traits, and must never appear in `commands.rs`,
in a serialized payload, or in a public signature outside those modules.

Never add a dependency that would move passphrase handling into our process
without updating ADR-3 in `PLAN.md` first.

## Commits

Small, scoped, conventional-commit style (`feat:`, `fix:`, `chore:`). Never
commit a real store, a private key, or `.env`.
