#!/usr/bin/env bash
# Stage a GnuPG into src-tauri/gnupg/ for bundling (ADR-14).
#
# Run before `pnpm tauri build`. Idempotent: an already-staged tree of the
# pinned version is left alone, so it is cheap to call from CI on every job.
#
# **Windows unpacks; macOS builds**, and that asymmetry is the whole shape of
# this script. GnuPG publishes an official Windows build that is *relocatable* —
# it finds its own root relative to the running .exe — so unpacking it is
# genuinely all that is required. There is no such thing for macOS: GnuPG on
# Unix compiles its directories in at build time, and the one supported way to
# move a tree afterwards is a `gpgconf.ctl` file beside `gpgconf`, which
# `common/homedir.c:unix_rootdir` reads relative to the running binary. So the
# macOS half builds GnuPG and its libraries from pinned, checksummed source and
# writes that file; `stage_macos` says the rest.
#
# Linux is not bundled for at all — the deb and rpm depend on `gnupg`.
set -euo pipefail

# ---------------------------------------------------------------------------
# Pinned upstream releases.
#
# Bumping any of these is a deliberate act: a bundled GnuPG does not get the
# user's OS security updates, so these lines are the refresh policy ADR-14 asks
# for. Every checksum below was cross-checked against
# https://gnupg.org/download/integrity_check.html *and* against the detached
# signature made by "Werner Koch (dist signing 2020)".
# ---------------------------------------------------------------------------

# Windows: the official relocatable installer, unpacked rather than run.
readonly WIN_VERSION='2.5.21_20260702'
readonly WIN_URL="https://gnupg.org/ftp/gcrypt/binary/gnupg-w32-${WIN_VERSION}.exe"
readonly WIN_SHA256='6246c925a73167253444afc24a0deb83a3f43b7d636af84d6aaf48a98a62f024'

# macOS: source, built here. The GnuPG version deliberately matches the Windows
# one — two platforms shipping the same app should not ship two GnuPGs.
readonly MAC_GNUPG_VERSION='2.5.21'
readonly MAC_LIBGPG_ERROR_VERSION='1.61'
readonly MAC_LIBGCRYPT_VERSION='1.12.2'
readonly MAC_LIBKSBA_VERSION='1.8.0'
readonly MAC_NPTH_VERSION='1.8'
# Two libassuans is not a mistake: GnuPG 2.5 needs API 3, pinentry still needs
# API 2, and both are linked statically so the two never meet at runtime.
readonly MAC_LIBASSUAN_VERSION='3.0.2'
readonly MAC_LIBASSUAN2_VERSION='2.5.7'

# `name|version|sha256`, in dependency order.
readonly MAC_SOURCES=(
  "libgpg-error|${MAC_LIBGPG_ERROR_VERSION}|7a85413f2bc354f4f8aa832b718af122e48965e9e0eb9012ee659c13c6385c93"
  "libassuan|${MAC_LIBASSUAN_VERSION}|d2931cdad266e633510f9970e1a2f346055e351bb19f9b78912475b8074c36f6"
  "libgcrypt|${MAC_LIBGCRYPT_VERSION}|7ce33c2492221a0436f96a8500215e9f3e3dcb5fd26a757cd415e7a843babd5e"
  "libksba|${MAC_LIBKSBA_VERSION}|296b9db9095749f2aa104202d7ab7fd09ad10710e00780a709c9754b1a1d9292"
  "npth|${MAC_NPTH_VERSION}|8bd24b4f23a3065d6e5b26e98aba9ce783ea4fd781069c1b35d149694e90ca3e"
  "gnupg|${MAC_GNUPG_VERSION}|e3af2c8caa46a66a9329fa7c6880af260451914d819595beabc2c26597b31352"
  "libassuan|${MAC_LIBASSUAN2_VERSION}|0103081ffc27838a2e50479153ca105e873d3d65d8a9593282e9c94c7e6afb76"
)

# The pinentry. Upstream has no native macOS frontend — curses and tty are no
# use to a windowed app, and Qt/GTK would mean bundling a toolkit — so this is
# GPGTools' fork, which adds a Cocoa one and is what a macOS `pass` user already
# runs today. Pinned by commit rather than by tag, because a tag can be moved
# and a commit cannot.
readonly MAC_PINENTRY_REPO='https://github.com/GPGTools/pinentry.git'
readonly MAC_PINENTRY_VERSION='1.3.1.1'
readonly MAC_PINENTRY_COMMIT='bfd451c27c751b8e26ed35ecfb01968c84dc93ca'

# The variable `bin/gpgconf.ctl` expands to find the tree at runtime. It is set
# by the app on every `gpg` it spawns from the bundle; `crypto::gnupg::gpg` is
# the other half of this contract, and a unit test there asserts the two names
# still agree.
readonly MAC_ROOT_VAR='PASSWORD_STORE_GUI_GNUPG_ROOT'

readonly here="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
readonly dest="${here}/../src-tauri/gnupg"

die() { printf 'fetch-gnupg: %s\n' "$1" >&2; exit 1; }
say() { printf 'fetch-gnupg: %s\n' "$1"; }

# What `uname` says, normalized to the three cases we care about.
platform() {
  case "$(uname -s)" in
    MINGW* | MSYS* | CYGWIN* | Windows_NT) echo windows ;;
    Darwin) echo macos ;;
    *) echo linux ;;
  esac
}

# sha256, under whichever name this platform spells it.
sha256() {
  if command -v sha256sum >/dev/null; then
    sha256sum "$1" | cut -d' ' -f1
  else
    shasum -a 256 "$1" | cut -d' ' -f1
  fi
}

# Has this exact tree already been staged?
#
# The version stamp in SOURCE doubles as the idempotence check and as the record
# ADR-14 promises to ship: the exact upstream releases the tree came from.
already_staged() {
  [ -f "${dest}/SOURCE" ] && grep -qF "$1" "${dest}/SOURCE"
}

# Empty the staging directory, keeping the two files that belong to the repo.
#
# Replaced wholesale rather than merged, so a version bump — or a switch between
# the Windows layout and the macOS one — cannot leave the previous tree's files
# behind alongside the new ones.
clear_dest() {
  find "${dest}" -mindepth 1 -maxdepth 1 \
    ! -name '.gitkeep' ! -name 'README.md' -exec rm -rf {} +
}

# ---------------------------------------------------------------------------
# Windows
# ---------------------------------------------------------------------------

stage_windows() {
  local stamp="gnupg-w32 ${WIN_VERSION}"
  if already_staged "${stamp}"; then
    say "${stamp} already staged"
    return
  fi

  command -v 7z >/dev/null || die '7z is required to unpack the GnuPG installer'

  local tmp
  tmp="$(mktemp -d)"
  # shellcheck disable=SC2064  # expand $tmp now, not at trap time
  trap "rm -rf '${tmp}'" EXIT

  say "downloading ${WIN_URL}"
  # --max-time bounds a stalled transfer instead of hanging the build.
  curl -fsSL --retry 3 --max-time 180 -o "${tmp}/gnupg-w32.exe" "${WIN_URL}"

  say 'verifying checksum'
  local got
  got="$(sha256 "${tmp}/gnupg-w32.exe")"
  [ "${got}" = "${WIN_SHA256}" ] || die "checksum mismatch: got ${got}"

  # Unpacked rather than installed. The installer is an NSIS archive, so 7-Zip
  # can extract the tree without executing anything — which is not merely
  # tidier: running it on a hosted runner hangs the step until it times out,
  # whether launched by `choco install gnupg` or directly with NSIS `/S`.
  say 'extracting bin and share'
  rm -rf "${tmp}/tree"
  7z x "${tmp}/gnupg-w32.exe" "-o${tmp}/tree" 'bin/*' 'share/*' -y >/dev/null
  [ -f "${tmp}/tree/bin/gpg.exe" ] || die 'no gpg.exe in the extracted tree'

  clear_dest
  mv "${tmp}/tree/bin" "${tmp}/tree/share" "${dest}/"

  # GnuPG is GPL-3.0-or-later and so is this app, so shipping it is aggregation
  # of compatible works — but the licence and a pointer to the corresponding
  # source have to travel with the binaries.
  if [ -f "${dest}/share/doc/gnupg/COPYING" ]; then
    cp "${dest}/share/doc/gnupg/COPYING" "${dest}/COPYING"
  fi
  cat >"${dest}/SOURCE" <<EOF
${stamp}, bundled under ADR-14.

Binaries unpacked from the official Windows release:
  ${WIN_URL}
  sha256 ${WIN_SHA256}

Corresponding source for this release:
  https://gnupg.org/ftp/gcrypt/gnupg/

GnuPG is free software under the GNU General Public License version 3 or later;
see COPYING beside this file.
EOF

  say "staged ${stamp} in ${dest}"
}

# ---------------------------------------------------------------------------
# macOS
# ---------------------------------------------------------------------------
#
# Three things have to be true of the staged tree, and each one costs something:
#
# 1. **It has to find itself.** `gpg` locates `gpg-agent`, `scdaemon` and the
#    pinentry through paths compiled in at build time, so a copied tree looks
#    for its helpers wherever it happened to be built. The fix is not ours:
#    GnuPG reads `<rootdir>/bin/gpgconf.ctl` relative to the running binary
#    (`common/homedir.c:unix_rootdir`, which uses `proc_pidpath` on macOS), and
#    a `rootdir` line there replaces the compiled-in prefix. The value may
#    contain `${VARIABLE}`, expanded from the environment — which is what lets a
#    file written here name a directory only the running app knows.
#
#    `sysconfdir` is pinned by the same file, and not only for tidiness: left
#    alone it would keep pointing at the build machine's throwaway prefix, and
#    `gpg` reads `gpgconf.conf` and `common.conf` from there.
#
# 2. **It has to carry no dylib references of its own.** Every GnuPG library is
#    built static, so there is nothing to rewrite with `install_name_tool` and
#    nothing to go missing; the only shared libraries left are the system's own,
#    which are where they always are.
#
# 3. **It has to be able to ask for a passphrase**, or the bundle is decoration:
#    `gpg-agent` cannot open a secret key without a pinentry, and Invariant 3
#    says the pinentry — not us — is what sees the passphrase. `gpg-agent` looks
#    for `<rootdir>/bin/pinentry` first, and pinentry-mac is a Cocoa app that
#    has to run from inside its `.app` to find its nib, so `bin/pinentry` is a
#    two-line wrapper that hands over to it.
#
# By default this builds for the machine's own architecture, which is what
# `pnpm tauri build` produces. Set MACOS_ARCHS="arm64 x86_64" for a universal
# tree to go with `--target universal-apple-darwin`; the second architecture is
# cross-compiled and merged with `lipo`.

stage_macos() {
  # shellcheck disable=SC2206  # MACOS_ARCHS is a space-separated list on purpose
  local archs=(${MACOS_ARCHS:-$(uname -m)})
  local stamp="gnupg ${MAC_GNUPG_VERSION} + pinentry-mac ${MAC_PINENTRY_VERSION} (${archs[*]})"

  if already_staged "${stamp}"; then
    say "${stamp} already staged"
    return
  fi

  require_macos_tools "${archs[@]}"

  local tmp
  tmp="$(mktemp -d)"
  # shellcheck disable=SC2064  # expand $tmp now, not at trap time
  trap "rm -rf '${tmp}'" EXIT

  fetch_macos_sources "${tmp}/src"

  local arch
  for arch in "${archs[@]}"; do
    say "building for ${arch} (this takes a few minutes)"
    build_macos_arch "${arch}" "${tmp}/src" "${tmp}/build/${arch}" "${tmp}/out/${arch}"
  done

  # One architecture is already the answer; two get spliced together.
  local merged="${tmp}/out/${archs[0]}"
  if [ "${#archs[@]}" -gt 1 ]; then
    local -a trees=()
    for arch in "${archs[@]}"; do trees+=("${tmp}/out/${arch}"); done
    merged="${tmp}/out/universal"
    lipo_trees "${merged}" "${trees[@]}"
  fi

  assemble_macos_tree "${merged}" "${tmp}/src" "${stamp}" "${archs[*]}"
  say "staged ${stamp} in ${dest}"
}

# Fail early and by name, rather than half way through a ten-minute build.
#
# The autotools are here for pinentry alone — the six GnuPG components are
# release tarballs and ship a `configure`. `autogen.sh` at the pinned commit
# runs `aclocal`, `autoheader`, `automake` and `autoconf` itself rather than
# going through `autoreconf`, and it needs nothing beyond them: pinentry's
# libraries are `noinst_LIBRARIES`, so there is no libtool in it, and it has no
# `po/`, so autogen.sh's gettext branch never runs. Requiring more than this is
# not free caution — a hosted macOS runner has neither `autopoint` nor GNU
# `libtool`, so the extra names turned into a build that refused to start.
require_macos_tools() {
  local archs=("$@") missing=()
  local tool
  for tool in curl shasum tar make cc git aclocal autoheader automake autoconf; do
    command -v "${tool}" >/dev/null || missing+=("${tool}")
  done
  # Interface Builder compiles pinentry-mac's nibs, and it comes with Xcode
  # proper rather than with the Command Line Tools — the one prerequisite a
  # developer machine is likely to be missing.
  command -v ibtool >/dev/null || missing+=("ibtool (install Xcode, not just the Command Line Tools)")
  [ "${#archs[@]}" -lt 2 ] || command -v lipo >/dev/null || missing+=("lipo")

  if [ "${#missing[@]}" -gt 0 ]; then
    die "missing build tools: ${missing[*]}
     The autotools come from: brew install autoconf automake"
  fi
}

# Download and verify every source tarball, and clone the pinned pinentry.
#
# Nothing is unpacked before its checksum matches: this is the only thing
# standing between a build and whatever the network handed back.
fetch_macos_sources() {
  local src="$1"
  mkdir -p "${src}"

  local entry name version want tarball url got
  for entry in "${MAC_SOURCES[@]}"; do
    IFS='|' read -r name version want <<<"${entry}"
    tarball="${name}-${version}.tar.bz2"
    url="https://gnupg.org/ftp/gcrypt/${name}/${tarball}"

    say "downloading ${tarball}"
    curl -fsSL --retry 3 --max-time 300 -o "${src}/${tarball}" "${url}"

    got="$(sha256 "${src}/${tarball}")"
    [ "${got}" = "${want}" ] || die "checksum mismatch for ${tarball}: got ${got}"

    tar xjf "${src}/${tarball}" -C "${src}"
  done

  say "cloning pinentry-mac ${MAC_PINENTRY_COMMIT}"
  git -c advice.detachedHead=false clone --quiet "${MAC_PINENTRY_REPO}" "${src}/pinentry"
  git -C "${src}/pinentry" -c advice.detachedHead=false checkout --quiet "${MAC_PINENTRY_COMMIT}"
  # A clone is not a checksum. This is: git names a commit by its content, so a
  # repository that hands back a different tree cannot hand back this id.
  local head
  head="$(git -C "${src}/pinentry" rev-parse HEAD)"
  [ "${head}" = "${MAC_PINENTRY_COMMIT}" ] || die "pinentry checkout is ${head}, not the pinned commit"
}

# Build every component for one architecture into $out.
build_macos_arch() {
  local arch="$1" src="$2" build="$3" out="$4"
  # Where pinentry's libassuan 2 lives, kept apart from GnuPG's libassuan 3.
  local out2="${out}-pinentry-deps"
  mkdir -p "${build}" "${out}" "${out2}"

  local jobs
  jobs="$(sysctl -n hw.ncpu 2>/dev/null || echo 4)"

  # Cross flags only when actually crossing. A native build is left to
  # `config.guess`, which gets the darwin version right — and pinentry's own
  # configure needs that version to decide it is on a Mac at all
  # (`darwin_version >= 11` in its host case), so a bare `--host=x86_64-apple-darwin`
  # would quietly build a pinentry with no macOS frontend in it.
  # Expanded as `${cross[@]+"${cross[@]}"}` everywhere below rather than plain
  # `"${cross[@]}"`. macOS still ships bash 3.2, where expanding an *empty*
  # array under `set -u` is an unbound-variable error — so the plain form would
  # fail on exactly the common case, a native build with nothing to cross.
  local -a cross=()
  if [ "${arch}" != "$(uname -m)" ]; then
    local release triple
    release="$(uname -r)"
    # config.sub canonicalizes arm64 to aarch64, which is also how
    # libgpg-error's shipped cross-compile lock definitions are named.
    triple="$([ "${arch}" = arm64 ] && echo aarch64 || echo "${arch}")-apple-darwin${release%%.*}"
    cross=(--build="$(uname -m)-apple-darwin${release%%.*}" --host="${triple}")
  fi

  # Everything every component gets, bar the prefix — which is not shared,
  # because pinentry's libassuan goes somewhere else.
  local -a common=(
    "CC=clang -arch ${arch}"
    "CXX=clang++ -arch ${arch}"
    --disable-shared --enable-static
    --disable-doc --disable-nls
    ${cross[@]+"${cross[@]}"}
  )

  configure_make "${src}/libgpg-error-${MAC_LIBGPG_ERROR_VERSION}" \
    "${build}/libgpg-error" "${jobs}" --prefix="${out}" "${common[@]}" \
    --disable-languages --disable-tests --enable-install-gpg-error-config

  configure_make "${src}/libassuan-${MAC_LIBASSUAN_VERSION}" \
    "${build}/libassuan" "${jobs}" --prefix="${out}" "${common[@]}" \
    --with-libgpg-error-prefix="${out}"

  configure_make "${src}/libgcrypt-${MAC_LIBGCRYPT_VERSION}" \
    "${build}/libgcrypt" "${jobs}" --prefix="${out}" "${common[@]}" \
    --with-libgpg-error-prefix="${out}"

  configure_make "${src}/libksba-${MAC_LIBKSBA_VERSION}" \
    "${build}/libksba" "${jobs}" --prefix="${out}" "${common[@]}" \
    --with-libgpg-error-prefix="${out}"

  configure_make "${src}/npth-${MAC_NPTH_VERSION}" \
    "${build}/npth" "${jobs}" --prefix="${out}" "${common[@]}"

  # `--disable-ccid-driver` keeps scdaemon off libusb: on macOS it talks to a
  # smartcard through PC/SC anyway, and the direct driver would add a shared
  # library we would then have to carry. scdaemon itself stays — a bundled GnuPG
  # that could not drive a security key would fail exactly the user §4.1
  # principle 1 has in mind.
  configure_make "${src}/gnupg-${MAC_GNUPG_VERSION}" \
    "${build}/gnupg" "${jobs}" --prefix="${out}" "${common[@]}" \
    --with-libgpg-error-prefix="${out}" \
    --with-libgcrypt-prefix="${out}" \
    --with-libassuan-prefix="${out}" \
    --with-ksba-prefix="${out}" \
    --with-npth-prefix="${out}" \
    --disable-ldap --disable-ccid-driver \
    --disable-g13 --disable-tpm2d --disable-wks-tools

  # pinentry's own libassuan, into its own prefix so GnuPG's stays API 3.
  configure_make "${src}/libassuan-${MAC_LIBASSUAN2_VERSION}" \
    "${build}/libassuan2" "${jobs}" --prefix="${out2}" "${common[@]}" \
    --with-libgpg-error-prefix="${out}"

  build_pinentry_mac "${arch}" "${src}/pinentry" "${build}/pinentry" "${out}" "${out2}" "${jobs}" \
    ${cross[@]+"${cross[@]}"}
}

# ./configure && make && make install, out of tree.
configure_make() {
  local srcdir="$1" builddir="$2" jobs="$3"
  shift 3
  mkdir -p "${builddir}"
  ( cd "${builddir}" && "${srcdir}/configure" "$@" >/dev/null )
  make -C "${builddir}" -j"${jobs}" >/dev/null
  make -C "${builddir}" install >/dev/null
}

# Build pinentry-mac and leave the .app where `assemble_macos_tree` can find it.
#
# The only component not `make install`ed: the fork's `libexec_PROGRAMS` names a
# directory (`pinentry-mac.app`), which `make install` cannot copy, so the app
# bundle is taken out of the build directory by hand. It is also the only one
# that needs `autogen.sh` first, being a git checkout rather than a release.
#
# Every other frontend is switched off explicitly. Left to itself configure
# picks up whatever Qt or GTK Homebrew happens to have installed, and the result
# would be a pinentry with a dependency on the build machine.
build_pinentry_mac() {
  local arch="$1" srcdir="$2" builddir="$3" out="$4" out2="$5" jobs="$6"
  shift 6
  local -a cross=(${1+"$@"})

  # `AM_PATH_GPG_ERROR` and `AM_PATH_LIBASSUAN` come from the libraries we just
  # installed, so autoreconf has to be pointed at them. Exported into the
  # subshell only — the tarball builds have their own copies and must not pick
  # these up.
  local aclocal="${out}/share/aclocal:${out2}/share/aclocal${ACLOCAL_PATH:+:${ACLOCAL_PATH}}"

  ( cd "${srcdir}" && ACLOCAL_PATH="${aclocal}" ./autogen.sh --force >/dev/null )

  mkdir -p "${builddir}"
  ( cd "${builddir}" && "${srcdir}/configure" \
      "CC=clang -arch ${arch}" \
      "CXX=clang++ -arch ${arch}" \
      --prefix="${out}" \
      --disable-nls \
      --with-libgpg-error-prefix="${out}" \
      --with-libassuan-prefix="${out2}" \
      --disable-pinentry-curses --disable-fallback-curses --disable-pinentry-tty \
      --disable-pinentry-emacs --disable-pinentry-efl --disable-pinentry-fltk \
      --disable-pinentry-gtk2 --disable-pinentry-gnome3 \
      --disable-pinentry-qt --disable-pinentry-qt5 --disable-pinentry-tqt \
      ${cross[@]+"${cross[@]}"} >/dev/null )

  make -C "${builddir}" -j"${jobs}" >/dev/null

  local app="${builddir}/macosx/pinentry-mac.app"
  [ -x "${app}/Contents/MacOS/pinentry-mac" ] \
    || die 'pinentry-mac did not build — configure found no macOS frontend'
  rm -rf "${out}/pinentry-mac.app"
  cp -R "${app}" "${out}/pinentry-mac.app"
}

# Splice per-architecture trees into one, with `lipo` for the Mach-O files.
lipo_trees() {
  local merged="$1"; shift
  local -a trees=("$@")
  local first="${trees[0]}"

  say "merging ${#trees[@]} architectures"
  rm -rf "${merged}"
  mkdir -p "${merged}"

  local rel target tree
  local -a inputs
  # `! -type d` rather than `-type f`, so a symlink is carried across as one.
  while IFS= read -r rel; do
    rel="${rel#./}"
    target="${merged}/${rel}"
    mkdir -p "$(dirname "${target}")"
    if file "${first}/${rel}" | grep -q 'Mach-O'; then
      inputs=()
      for tree in "${trees[@]}"; do inputs+=("${tree}/${rel}"); done
      lipo -create "${inputs[@]}" -output "${target}"
    else
      # Headers, scripts, nibs, the licence: identical across architectures, so
      # the first tree's copy is the answer. `-a` keeps a symlink a symlink.
      cp -a "${first}/${rel}" "${target}"
    fi
  done < <(cd "${first}" && find . ! -type d)
}

# Lay the built tree out the way the app and GnuPG both expect, and write the
# two files that make it relocatable and the one that records where it came from.
assemble_macos_tree() {
  local out="$1" src="$2" stamp="$3" arch_list="$4"

  clear_dest
  mkdir -p "${dest}/bin" "${dest}/libexec" "${dest}/share"

  cp -R "${out}/bin/." "${dest}/bin/"
  cp -R "${out}/libexec/." "${dest}/libexec/"
  cp -R "${out}/share/gnupg" "${dest}/share/gnupg"
  cp -R "${out}/pinentry-mac.app" "${dest}/libexec/pinentry-mac.app"

  # The libraries install `libgcrypt-config` and friends beside the binaries.
  # They are build-time helpers that print the throwaway prefix this was
  # compiled against, so shipping them would put a path that never existed on
  # the user's machine inside the app. Nothing GnuPG runs is named `*-config` —
  # `gpgconf` and `gpg-connect-agent` do not match.
  rm -f "${dest}"/bin/*-config

  [ -x "${dest}/bin/gpg" ] || die 'no gpg in the built tree'
  [ -x "${dest}/bin/gpg-agent" ] || die 'no gpg-agent in the built tree'
  [ -x "${dest}/bin/gpgconf" ] || die 'no gpgconf in the built tree'

  # The relocation file. `rootdir` is what makes every compiled-in path a lie
  # the binary is willing to be told about; `sysconfdir` is pinned with it so
  # that `gpgconf.conf` and `common.conf` are read from inside the bundle rather
  # than from the throwaway prefix this was built in.
  cat >"${dest}/bin/gpgconf.ctl" <<EOF
# Written by scripts/fetch-gnupg.sh — see ADR-14 in PLAN.md.
#
# GnuPG on Unix compiles its directories in at build time. This file is how it
# is told otherwise: it is read from the directory of the running binary, and
# \${${MAC_ROOT_VAR}} is expanded from the environment, which
# the app sets to wherever it was installed (src-tauri/src/crypto/gnupg.rs).
#
# Nothing here points at the user's keyring: GNUPGHOME is deliberately untouched
# (ADR-14), so the bundled GnuPG reads the same ~/.gnupg the pass CLI does.
rootdir = \${${MAC_ROOT_VAR}}
sysconfdir = \${${MAC_ROOT_VAR}}/etc/gnupg
EOF

  # gpg-agent looks for <rootdir>/bin/pinentry before anything else
  # (common/homedir.c:get_default_pinentry_name). pinentry-mac is a Cocoa app
  # and needs to be executed from inside its .app to find its nib, so this hands
  # over instead of being the binary itself.
  #
  # It handles no passphrase and reads no input — it replaces itself with the
  # pinentry and is gone (Invariant 3).
  cat >"${dest}/bin/pinentry" <<'EOF'
#!/bin/sh
exec "$(dirname "$0")/../libexec/pinentry-mac.app/Contents/MacOS/pinentry-mac" "$@"
EOF
  chmod +x "${dest}/bin/pinentry"

  # GnuPG is GPL-3.0-or-later and so is this app; pinentry is GPL-2.0-or-later
  # and runs as a separate program. Both licences and a pointer to the
  # corresponding source have to travel with the binaries.
  cp "${src}/gnupg-${MAC_GNUPG_VERSION}/COPYING" "${dest}/COPYING"
  cp "${src}/pinentry/COPYING" "${dest}/COPYING.pinentry"

  {
    echo "${stamp}, bundled under ADR-14."
    echo
    echo "Built from source by scripts/fetch-gnupg.sh for: ${arch_list}"
    echo "Configured --disable-nls, so messages are English only."
    echo
    echo 'Components. The build verifies each tarball against the sha256 here'
    echo 'before unpacking it; those checksums were taken from, and can be'
    echo 'checked against, https://gnupg.org/download/integrity_check.html and'
    echo "the tarballs' own detached GnuPG release signatures."
    echo
    local entry name version want
    for entry in "${MAC_SOURCES[@]}"; do
      IFS='|' read -r name version want <<<"${entry}"
      echo "  https://gnupg.org/ftp/gcrypt/${name}/${name}-${version}.tar.bz2"
      echo "  sha256 ${want}"
      echo
    done
    echo "  ${MAC_PINENTRY_REPO}"
    echo "  commit ${MAC_PINENTRY_COMMIT} (tagged v${MAC_PINENTRY_VERSION})"
    echo
    echo 'GnuPG is free software under the GNU General Public License version 3'
    echo 'or later; pinentry under version 2 or later. See COPYING and'
    echo 'COPYING.pinentry beside this file.'
  } >"${dest}/SOURCE"
}

# ---------------------------------------------------------------------------

main() {
  [ -d "${dest}" ] || die "${dest} does not exist"

  case "$(platform)" in
    windows) stage_windows ;;
    macos) stage_macos ;;
    linux)
      say 'nothing to do on Linux — the deb and rpm depend on gnupg (ADR-14)'
      ;;
  esac
}

main "$@"
