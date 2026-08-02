# Password Store

A native GUI client for [`pass`](https://www.passwordstore.org/), the standard
Unix password manager, for Windows, macOS, and Linux.

`pass` is not a database. It is a directory tree of GPG-encrypted files (by
default `~/.password-store/`), optionally versioned with git. This app is a
careful GUI over that on-disk format: a store it writes stays byte-compatible
with the `pass` CLI, QtPass, and the mobile clients, and a store any of those
wrote opens here.

It is built for people who chose `pass`'s format but do not use a terminal —
and it is meant to leave the store exactly as interoperable as it found it.

## Status

**Pre-release. There is no packaged build yet — building from source is the
only way to run it.** Phases 0–4 are complete, Phases 5 and 6 partly so; see
[`PLAN.md`](PLAN.md) §7 for the current state of each.

Two limits worth knowing before you point this at a store you care about:

- **The GUI has never been driven against a real store.** The Rust core is
  covered by integration tests that run a real `gpg` against a real temporary
  store on all three platforms in CI, and the frontend has been click-tested
  against a stub — but the two have not been exercised together by hand.
- **Sync has never run against a real remote.** The git tests drive two real
  repositories end to end, but every remote in them is a local path.

"Fast" in the description below is engineering intent. Nothing has been
benchmarked.

## What it does

- **Browse and read.** The store as a tree; entry metadata without decrypting.
  Nothing decrypts speculatively — not on hover, not on select, not on a timer.
- **Reveal one field at a time.** Password, a named field, or notes, on an
  explicit click. A revealed value lives on screen and nowhere else.
- **Copy without the value entering the UI.** Copying happens in the Rust core;
  the clipboard clears itself after 45 seconds (configurable) and only if it
  still holds what was put there.
- **TOTP.** Reads `otpauth://` entries and copies the current code.
- **Create, edit, generate, rename, copy, and delete entries**, each written to
  the recipients the store says apply to that path.
- **Git sync.** Status against the upstream, and fetch/merge/push through your
  own `git`, so your credential helper, `ssh-agent`, and keychain keep working.
  Per-entry history, including reading and copying from a past version.
- **Recipient management.** See which keys govern a folder and whether they were
  inherited, change them, and re-encrypt the subtree. The cost is stated before
  the change is agreed to, and a change that would lock you out of your own
  store is refused.
- **Search** over entry names, **auto-lock** on idle and on window blur, and a
  settings panel.

## Requirements

**A working `gpg` on `PATH` is a hard prerequisite on every platform.** This app
drives your GPG rather than reimplementing OpenPGP, and it never handles your
passphrase — `gpg-agent` and pinentry do.

| | |
|---|---|
| Windows | [Gpg4win](https://www.gpg4win.org/) (`gpg.exe` + a pinentry) |
| macOS | GnuPG and `pinentry-mac` |
| Linux | GnuPG and `pinentry-gtk` or `pinentry-qt` |

Reading and writing a store — including its local history — needs no system
`git`; libgit2 is linked in. **Syncing with a remote does**, so a shared store
also wants [Git for Windows](https://gitforwindows.org/) or your platform's
`git`.

## Building from source

You will need [Rust](https://rustup.rs/) 1.88 or newer, Node 22, and
[pnpm](https://pnpm.io/). Tauri's own
[prerequisites](https://tauri.app/start/prerequisites/) apply; on Debian or
Ubuntu that means:

```sh
sudo apt-get install -y libwebkit2gtk-4.1-dev libappindicator3-dev \
  librsvg2-dev patchelf libssl-dev
```

Then:

```sh
pnpm install
pnpm tauri dev      # run it
pnpm tauri build    # release bundle for the current OS
```

The bundle is unsigned and unnotarized.

## Development

```sh
pnpm dev            # frontend only, no Rust core
pnpm dev:mock       # frontend against a stubbed core (below)
pnpm build          # typecheck + bundle the frontend
pnpm lint           # oxlint

cd src-tauri
cargo test
cargo fmt --all
cargo clippy --all-targets -- -D warnings
```

`cargo fmt` and a clippy run clean of warnings are required; CI enforces both,
and runs the Rust tests on Linux, macOS, and Windows.

`pnpm dev:mock` serves the app with `@tauri-apps/api/core` aliased to
`src/lib/mockInvoke.ts`, so every component runs through the real IPC wrappers
with no Rust behind it. URL flags drive the awkward states (`?noGit=1`,
`?sync=conflicted`, `?lockAfter=5`, …). It establishes nothing about the core —
no GnuPG runs, nothing is decrypted, and the clipboard is a variable — but it is
how each phase has been click-tested, and it has found a defect every time.

`scripts/make-fixture-store.sh` builds a throwaway store and `GNUPGHOME` for the
un-stubbed path.

## Security model

Eight hard constraints, listed in full in [`PLAN.md`](PLAN.md) §4. A change that
violates one is a bug even if the feature works.

1. Plaintext never touches disk.
2. Plaintext stays in Rust. It crosses into the webview only on an explicit
   reveal, and clipboard copy happens entirely in the core.
3. Passphrases are never ours to handle — `gpg-agent` and pinentry own them, and
   loopback pinentry is not used.
4. Secret buffers are zeroized and never `Debug`/`Display`.
5. Nothing secret reaches logs, errors, traces, or panics.
6. The clipboard auto-clears, and only if it still holds our value.
7. Auto-lock: blur hides revealed values, idle closes everything.
8. Writes encrypt to the recipients from the nearest `.gpg-id`; a recipient
   change re-encrypts the whole affected subtree, all or nothing.

The Rust↔JS boundary is used as a security seam rather than just an API.

## Configuration

Settings live in a JSON file under the platform's config directory. Three of
them shadow a `pass` environment variable — `PASSWORD_STORE_DIR`,
`PASSWORD_STORE_CLIP_TIME`, `PASSWORD_STORE_GENERATED_LENGTH` — and **the
variable wins**, because the CLI obeys it and a GUI that quietly disagreed would
have the two looking at different stores. Where that happens, the settings panel
shows the control as fixed and names the variable rather than offering a box
that does nothing.

## Project layout

```
src/                 React + TypeScript frontend (Tailwind v4)
  lib/commands.ts    every IPC call, typed
src-tauri/src/
  commands.rs        the command surface
  store/             tree, entry parsing, names, .gpg-id resolution
  crypto/            gpg invocation and decryption
  git/               history and sync
  clipboard.rs       copy with a self-clearing timer
  settings.rs        settings and environment precedence
  tests/             integration tests against a real gpg
```

## Documentation

- [`PLAN.md`](PLAN.md) — scope, architecture decisions, the eight invariants,
  phase status. The source of truth for what is built.
- [`PRODUCT.md`](PRODUCT.md) — audience, positioning, product principles.
- [`CLAUDE.md`](CLAUDE.md) — conventions for working in this repo.

## License

`GPL-3.0-or-later`, a consequence of statically linking the LGPL `prs-lib`
(see [`PLAN.md`](PLAN.md) ADR-4).
