# The bundled GnuPG (ADR-14)

This directory is staged into the app bundle as a Tauri resource. It is empty in
the repository and populated at build time by `scripts/fetch-gnupg.sh`; the
binaries themselves are never committed.

The layout differs by platform, because GnuPG does. The resolver in
`src-tauri/src/crypto/gnupg.rs` depends on `bin/<gpg>` either way.

```
gnupg/                     Windows                  macOS
  bin/                     gpg.exe, gpg-agent…      gpg, gpg-agent, gpgconf…
    gpgconf.ctl            —                        where the tree now lives
    pinentry               —                        wrapper → pinentry-mac.app
  libexec/                 —                        scdaemon…, pinentry-mac.app
  share/gnupg/             ✓                        ✓
  COPYING                  GnuPG's licence, shipped with the binaries
  COPYING.pinentry         —                        pinentry's
  SOURCE                   the exact versions, checksums and source URLs
```

`bin/` beside its siblings is load-bearing rather than cosmetic. On Windows,
GnuPG finds its own root relative to the running executable, so flattening the
tree gives a `gpg` that starts and then cannot find `gpg-agent`. On macOS the
paths are compiled in instead, and `bin/gpgconf.ctl` is what overrides them —
its `rootdir` names an environment variable that `crypto::gnupg::gpg` sets on
every child, so the tree works from wherever the `.app` was installed (ADR-14a).

`bin/pinentry` is a two-line wrapper rather than a binary: `gpg-agent` looks for
that exact path first, and `pinentry-mac` has to run from inside its `.app` to
find its interface files.

**Linux is not bundled for.** The deb and rpm declare a `gnupg` dependency
instead, and this directory stays empty there — bundling would stand a second
`gpg-agent` version up against a distro-managed `~/.gnupg`. The directory is
still committed (via `.gitkeep`) so `bundle.resources` resolves on every
platform.

The app prefers a system GnuPG and falls back to this one; see ADR-14 in
`PLAN.md` for why that order and not the other.
