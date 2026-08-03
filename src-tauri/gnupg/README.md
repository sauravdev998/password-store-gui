# The bundled GnuPG (ADR-14)

This directory is staged into the app bundle as a Tauri resource. It is empty in
the repository and populated at build time by `scripts/fetch-gnupg.sh`; the
binaries themselves are never committed.

Expected layout after a fetch, which the resolver in
`src-tauri/src/crypto/gnupg.rs` depends on:

```
gnupg/
  bin/     gpg, gpg-agent, gpgconf, dirmngr, a pinentry
  share/
  COPYING  GnuPG's licence, shipped with the binaries
  SOURCE   the exact upstream version and its source URL
```

`bin/` beside `share/` is load-bearing rather than cosmetic: GnuPG locates its
own helpers relative to the running executable, so flattening the tree gives a
`gpg` that starts and then cannot find `gpg-agent`.

**Linux is not bundled for.** The deb and rpm declare a `gnupg` dependency
instead, and this directory stays empty there — bundling would stand a second
`gpg-agent` version up against a distro-managed `~/.gnupg`. The directory is
still committed (via `.gitkeep`) so `bundle.resources` resolves on every
platform.

The app prefers a system GnuPG and falls back to this one; see ADR-14 in
`PLAN.md` for why that order and not the other.
