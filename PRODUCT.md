# Product

<!-- impeccable:product-schema 1 -->

## Platform

web

## Users

**Primary: people who want `pass`'s format without a terminal.** They chose
`pass` for what it is — plain GPG-encrypted files on their own disk, no vendor,
no cloud account, readable by a dozen other clients — but they do not use the
CLI and are not going to. They may not know what `gpg-agent`, a recipient, or a
`.gpg-id` file is. Some of them arrive with **no store and no GPG key at all**.

The job: get a password out of the store and into the thing asking for it,
without learning `pass` first, and put new ones in without leaving the app.

Existing `pass` CLI users are a real secondary audience — the store must stay
byte-compatible for them and they will open this alongside their terminal — but
they are not who the interface is designed around. Where the two conflict, the
CLI-averse user wins.

## Product Purpose

A native GUI client for [`pass`](https://www.passwordstore.org/) on Windows,
macOS, and Linux. `pass` is not a database: it is a directory tree of
GPG-encrypted files (default `~/.password-store/`), optionally versioned with
git. This app is a careful GUI over that on-disk format.

Success is that a person who has never opened a terminal can use a real `pass`
store day to day — and that the store they produce is indistinguishable from one
the CLI produced. Both halves are the product; either alone is a different,
lesser thing.

## Positioning

**Native speed and a single small binary.** Rust core plus the OS webview via
Tauri 2: one small signed binary per platform, instant tree browsing, minimal
memory, no runtime to install. The prior art is Qt-heavy, Electron-heavy, or
Linux-only. This is what a neighboring client cannot truthfully copy without
rebuilding on the same foundation.

Underneath that, and not negotiable: the Rust↔JS boundary is used as a security
seam. Plaintext stays in Rust and crosses IPC only on an explicit per-field
reveal; clipboard copy happens entirely in the core so a password never enters
JS. This is architecture, not a marketing claim — see
[`PLAN.md`](PLAN.md) §4.

## Operating Context

Confirmed conditions the interface actually meets:

- **Nested `.gpg-id` recipients.** Folders below the root can carry their own
  `.gpg-id`, so which keys an entry is written to depends on where it lives.
  Recipients resolve by walking up to the nearest file. Which key an entry is
  encrypted to is something the user needs to be able to see, not assume — and
  moving an entry between folders can change it.
- **Smartcard / YubiKey.** Decryption can mean physically touching a hardware
  key. Every decrypt has real cost: it is slow, it can fail, and it interrupts.
  Anything that decrypts speculatively is a design error, not a nicety —
  the app never pops a pinentry the user did not ask for.
- **Git-synced store.** The store is a git repo moved between machines. Sync
  state, divergence, conflicts, and per-entry history are real conditions, not
  edge cases.
- **Passphrase prompts are not ours.** `gpg-agent` and the platform pinentry own
  them and appear as separate OS-level windows outside our control — including
  during onboarding.
- **Platform prerequisites.** A working `gpg` binary is required: Gpg4win on
  Windows, `pinentry-mac` on macOS, `pinentry-gtk`/`-qt` on Linux.

## Capabilities and Constraints

**Confirmed functionality** (status per `PLAN.md` §7):

- Browse the store tree; read entry metadata; reveal a single field at a time.
- Copy password / field / notes / OTP from the core, with auto-clear after
  `PASSWORD_STORE_CLIP_TIME` (default 45s) and only if the clipboard still holds
  what we set.
- TOTP from `otpauth://` URIs, computed in the core — the code is sent, never
  the seed.
- Mutations: insert, edit, generate, rm, mv, cp — each re-encrypting to the
  recipients of the name being written.
- Planned, not built: auto-commit and git sync (Phase 4); auto-lock, global
  search, and settings (Phase 5).

**Hard constraints:**

- **Byte-compatibility with the `pass` CLI is absolute.** Anything written must
  remain readable by `pass`, QtPass, the mobile apps, and other clients. This
  outranks every convenience.
- **The eight security invariants in `PLAN.md` §4 are hard constraints**, not
  guidelines. A change that violates one is a bug even if the feature works.
  Most relevant to interface work: plaintext stays in Rust and crosses IPC only
  on explicit reveal; clipboard copy happens in the core, never in JS; nothing
  secret reaches logs, errors, or panics.
- **We never handle passphrases.** No loopback pinentry, ever.
- Environment variables the store obeys: `PASSWORD_STORE_DIR`,
  `PASSWORD_STORE_CLIP_TIME`, `PASSWORD_STORE_GENERATED_LENGTH`.
- Licensed **GPL-3.0-or-later** (a consequence of statically linking `prs-lib`,
  LGPL-3.0 — see ADR-4).
- The webview runs under a strict CSP (`default-src 'self'`, no `frame-src` /
  `object-src` / `form-action`). No external fonts, scripts, images, or network
  calls of any kind. Every asset ships in the bundle.

**Terminology.** The domain vocabulary is `pass`'s: *store*, *entry*,
*recipients*, `.gpg-id`, *pinentry*, *clip time*. It is accurate and it is what
every other client and every piece of documentation uses — but the primary user
does not know it. How much of it to expose, translate, or teach is a live
design question, not a settled one.

**Undecided / open:**

- **In-app onboarding is committed but unscoped.** The product intent is that a
  user can go from nothing — no GPG key, no store — to a working store without a
  terminal, including key generation and the equivalent of `pass init`. No phase
  in `PLAN.md` covers this yet, and it does not conflict with the
  "no passphrases" invariant only so long as key generation is driven through
  `gpg` with the platform pinentry prompting (never `--passphrase`, never
  loopback). It needs its own ADR before it is built.
- Git network auth: shell out to the user's `git` vs. `git2` credential
  callbacks (`PLAN.md` §10.2).
- Auto-hide on blur and re-hide after N seconds (`PLAN.md` §10.3).
- No product-specific accessibility standard has been committed. Sensible
  defaults apply; nothing here is a stated obligation.

## Brand Commitments

- Name: **Password Store**. Window title `Password Store`; package
  `password-store-gui`; bundle identifier `dev.passwordstoregui.app`.
- No identity exists yet. The bundled icons are Tauri's default scaffold mark
  and `public/favicon.svg` is the Vite default — placeholders, not commitments,
  and not a visual reference for anything.
- No voice or tone has been established.

## Evidence on Hand

- **Real:** `PLAN.md` (architecture, six ADRs, the eight invariants, phase
  status). Integration tests that drive the command surface against a real `gpg`
  and a real temp store, and hand the result to the `pass` binary to prove
  cross-tool compatibility (`src-tauri/tests/`). CI across Linux/macOS/Windows.
- **Absent — do not fabricate:** no users, downloads, stars, or testimonials. No
  benchmarks, despite speed being the positioning; "fast" is an engineering
  intent that has not been measured. No screenshots, README, or project page. No
  released build. No logo. The GUI has never been click-tested against a real
  store.

## Product Principles

1. **A decrypt is expensive and always the user's choice.** Nothing decrypts
   speculatively, on hover, on select, or on a timer. A pinentry prompt or a
   hardware-key tap the user did not ask for is a defect.
2. **Hidden by default, revealed one field at a time.** A revealed value lives
   on screen and nowhere else — not in a store, not in a URL, not across a
   selection change.
3. **The store is the user's, not ours.** Every write stays byte-compatible with
   the CLI; nothing is added to the format for our convenience; a name or file we
   cannot handle is shown as unusable rather than silently hidden.
4. **The user does not have to know `pass` to use it.** Where the format's
   concepts must surface — recipients, sync state, missing keys — the interface
   explains what is happening in plain language and says what to do about it.
5. **Say what is true, especially about failure.** Missing `gpg`, an
   unresolvable recipient, a diverged store: name the actual problem and the
   actual fix. Never a bare "operation failed" — and never a message that
   quotes a secret to be helpful.
