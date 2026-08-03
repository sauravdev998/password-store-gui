#!/usr/bin/env bash
# Stage a GnuPG into src-tauri/gnupg/ for bundling (ADR-14).
#
# Run before `pnpm tauri build`. Idempotent: an already-staged tree of the
# pinned version is left alone, so it is cheap to call from CI on every job.
#
# Windows is the whole of what this script does today. GnuPG publishes an
# official Windows build that is *relocatable* — it finds its own root relative
# to the running .exe — so unpacking it is genuinely all that is required, and
# CI has been running the full Rust suite against a tree extracted exactly this
# way since before any of this was bundled.
#
# macOS is not implemented and deliberately fails loudly rather than silently
# producing a bundle with no GnuPG in it. GnuPG on Unix compiles its paths in,
# so a relocated tree is not self-locating the way the Windows one is; making it
# work means building GnuPG and its five libraries from source for two
# architectures and rewriting the dylib references, which is its own piece of
# work and not a line in a fetch script.
#
# Linux is not bundled for at all — the deb and rpm depend on `gnupg`.
set -euo pipefail

# The pinned upstream release. Bumping this is a deliberate act: a bundled GnuPG
# does not get the user's OS security updates, so this line is the refresh
# policy ADR-14 asks for.
readonly VERSION='2.5.21_20260702'
readonly URL="https://gnupg.org/ftp/gcrypt/binary/gnupg-w32-${VERSION}.exe"
# From gnupg.org/download/integrity_check. Checked before anything is unpacked:
# this is the only thing standing between a build and whatever the network
# handed back.
readonly SHA256='6246c925a73167253444afc24a0deb83a3f43b7d636af84d6aaf48a98a62f024'

readonly here="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
readonly dest="${here}/../src-tauri/gnupg"

die() { printf 'fetch-gnupg: %s\n' "$1" >&2; exit 1; }

# What `uname` says, normalized to the three cases we care about.
platform() {
  case "$(uname -s)" in
    MINGW* | MSYS* | CYGWIN* | Windows_NT) echo windows ;;
    Darwin) echo macos ;;
    *) echo linux ;;
  esac
}

stage_windows() {
  # The version stamp doubles as the idempotence check and as the record ADR-14
  # promises to ship: the exact upstream release this tree came from.
  if [ -f "${dest}/SOURCE" ] && grep -qF "${VERSION}" "${dest}/SOURCE"; then
    echo "fetch-gnupg: gnupg-w32 ${VERSION} already staged"
    return
  fi

  command -v 7z >/dev/null || die '7z is required to unpack the GnuPG installer'

  local tmp
  tmp="$(mktemp -d)"
  # shellcheck disable=SC2064  # expand $tmp now, not at trap time
  trap "rm -rf '${tmp}'" EXIT

  echo "fetch-gnupg: downloading ${URL}"
  # --max-time bounds a stalled transfer instead of hanging the build.
  curl -fsSL --retry 3 --max-time 180 -o "${tmp}/gnupg-w32.exe" "${URL}"

  echo 'fetch-gnupg: verifying checksum'
  local got
  got="$(sha256sum "${tmp}/gnupg-w32.exe" | cut -d' ' -f1)"
  [ "${got}" = "${SHA256}" ] || die "checksum mismatch: got ${got}"

  # Unpacked rather than installed. The installer is an NSIS archive, so 7-Zip
  # can extract the tree without executing anything — which is not merely
  # tidier: running it on a hosted runner hangs the step until it times out,
  # whether launched by `choco install gnupg` or directly with NSIS `/S`.
  echo 'fetch-gnupg: extracting bin and share'
  rm -rf "${tmp}/tree"
  7z x "${tmp}/gnupg-w32.exe" "-o${tmp}/tree" 'bin/*' 'share/*' -y >/dev/null
  [ -f "${tmp}/tree/bin/gpg.exe" ] || die 'no gpg.exe in the extracted tree'

  # Replaced wholesale rather than merged, so a version bump cannot leave the
  # previous release's files behind alongside the new ones.
  rm -rf "${dest}/bin" "${dest}/share" "${dest}/COPYING" "${dest}/SOURCE"
  mv "${tmp}/tree/bin" "${tmp}/tree/share" "${dest}/"

  # GnuPG is GPL-3.0-or-later and so is this app, so shipping it is aggregation
  # of compatible works — but the licence and a pointer to the corresponding
  # source have to travel with the binaries.
  if [ -f "${dest}/share/doc/gnupg/COPYING" ]; then
    cp "${dest}/share/doc/gnupg/COPYING" "${dest}/COPYING"
  fi
  cat >"${dest}/SOURCE" <<EOF
GnuPG ${VERSION}, bundled under ADR-14.

Binaries unpacked from the official Windows release:
  ${URL}
  sha256 ${SHA256}

Corresponding source for this release:
  https://gnupg.org/ftp/gcrypt/gnupg/

GnuPG is free software under the GNU General Public License version 3 or later;
see COPYING beside this file.
EOF

  echo "fetch-gnupg: staged gnupg-w32 ${VERSION} in ${dest}"
}

main() {
  [ -d "${dest}" ] || die "${dest} does not exist"

  case "$(platform)" in
    windows) stage_windows ;;
    macos)
      die 'macOS bundling is not implemented yet — see ADR-14. Build without it
     and the app falls back to a system GnuPG, which is what macOS users have
     today.'
      ;;
    linux)
      echo 'fetch-gnupg: nothing to do on Linux — the deb and rpm depend on gnupg (ADR-14)'
      ;;
  esac
}

main "$@"
