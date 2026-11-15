#!/usr/bin/env bash
#
# Writes THIRD-PARTY-LICENSES.txt for ONE shipped binary: the licence text and
# the exact crates.io release of every crate compiled into it. A binary that
# statically links MIT, BSD, ISC, BlueOak, Unicode or MPL code has to carry
# those texts with it; the repository's own LICENSE covers only HIDE.
#
# The dependency graph differs per target (Windows pulls in crates Linux does
# not), so the file is generated per target instead of once for everything:
# listing a licence for code that is not in the binary would be as wrong as
# omitting one that is.
#
#   usage: scripts/licences/generate.sh <cli|ffi|wasm|desktop> <target-triple|all> <output-file>
#
# `all` is for a package that carries the binaries of every target at once
# (the NuGet package): it lists the union of all their dependency graphs.
#
# Needs cargo-about (the release workflows pin its version) and the committed
# lockfiles; it compiles nothing, and it does not need the Rust target
# installed, so one Linux job can produce the notices for every platform.
set -euo pipefail

usage="usage: generate.sh <cli|ffi|wasm|desktop> <target-triple|all> <output-file>"
kind="${1:?$usage}"
target="${2:?$usage}"
output="${3:?$usage}"
root="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"

case "$kind" in
  cli)
    manifest="apps/hide-cli/Cargo.toml"
    what="the hide command-line tool"
    ;;
  ffi)
    manifest="crates/hide-ffi/Cargo.toml"
    what="the HIDE native library (hide-ffi)"
    ;;
  wasm)
    manifest="crates/hide-wasm/Cargo.toml"
    what="the HIDE WebAssembly module (hide-wasm)"
    ;;
  desktop)
    manifest="apps/hide-desktop/src-tauri/Cargo.toml"
    what="the HIDE desktop application"
    ;;
  *)
    echo "unknown kind '$kind'; $usage" >&2
    exit 2
    ;;
esac

version="$(grep -m1 '^version' "$root/Cargo.toml" | cut -d'"' -f2)"
[ -n "$version" ] || { echo "could not read the version from Cargo.toml" >&2; exit 1; }

work="$(mktemp -d)"
trap 'rm -rf "$work"' EXIT

if [ "$target" = all ]; then
  target_args=()
  target_label="every published target"
else
  target_args=(--target "$target")
  target_label="target $target"
fi

# --locked: the notices must describe the versions in the lockfile, which are
# the versions the release build compiles. --fail: a crate whose licence cannot
# be determined stops the release instead of being left out of the file.
(
  cd "$root"
  cargo about generate --locked --fail \
    -c about.toml -m "$manifest" "${target_args[@]}" \
    -o "$work/body.txt" about.hbs
)

# Some upstream licence files are CRLF; the archive should not mix endings.
tr -d '\r' < "$work/body.txt" > "$work/body.lf"

# An empty or truncated listing would still be a file, and nobody opens it to
# check. Every graph here has dozens of crates and at least Apache-2.0.
crates="$(grep -Ec '^  [^ ]+ [0-9][^ ]*  https://crates\.io/crates/' "$work/body.lf" || true)"
if [ "$crates" -lt 20 ]; then
  echo "only $crates components listed for $kind/$target; refusing to write $output" >&2
  exit 1
fi
grep -q '^Apache License 2.0 (Apache-2.0)$' "$work/body.lf" \
  || { echo "no Apache-2.0 section for $kind/$target" >&2; exit 1; }

if [ "$kind" = desktop ]; then
  # MPL-2.0 section 3.2 requires telling recipients where the source is. The
  # template prints that paragraph inside each MPL section; these four crates
  # are why it exists, so their absence means the template or graph changed.
  for crate in cssparser selectors dtoa-short option-ext; do
    grep -Eq "^  $crate [0-9][^ ]*  https://crates\.io/crates/$crate/" "$work/body.lf" \
      || { echo "MPL-2.0 crate $crate is missing from the desktop notices" >&2; exit 1; }
  done
  grep -q '^Source code (MPL-2.0, section 3.2)' "$work/body.lf" \
    || { echo "the MPL-2.0 source notice is missing from the desktop notices" >&2; exit 1; }
  # The user interface is JavaScript bundled by Vite; cargo-about cannot see
  # it. frontend.mjs reads the installed production packages, so the app's
  # node_modules must be installed (pnpm install --ignore-workspace).
  node "$root/scripts/licences/frontend.mjs" "$root/apps/hide-desktop" > "$work/frontend.txt"
  grep -q '^react [0-9]' "$work/frontend.txt" \
    || { echo "the JavaScript notices do not list react; refusing to write $output" >&2; exit 1; }
fi

{
  echo "Third-party software in $what"
  echo "HIDE $version, $target_label"
  echo
  echo "HIDE itself is licensed under the Apache License 2.0; see the LICENSE file"
  echo "shipped with this one. This file covers the open-source components that are"
  echo "compiled into the binary. Their licences are listed below, each with its full"
  echo "text and the components it applies to."
  echo
  echo "Rust standard library. The binary also contains the Rust standard library"
  echo "($(rustc --version)), which is dual-licensed MIT OR Apache-2.0 and is used"
  echo "here under Apache-2.0, whose text appears below. The notices of the standard"
  echo "library's own dependencies are distributed with every Rust toolchain as"
  echo "share/doc/rust/COPYRIGHT-library.html."
  if [ "$kind" = cli ] && [[ "$target" == *-musl ]]; then
    echo
    echo "musl libc. This build is statically linked against musl libc (MIT licence)."
    echo "The musl copyright notice and licence text are in MUSL-COPYRIGHT.txt, shipped"
    echo "beside this file; it is the copyright file of the Ubuntu musl package on the"
    echo "machine that built this binary."
  fi
  if [ "$kind" = desktop ]; then
    echo
    echo "MPL-2.0 components: cssparser, selectors, dtoa-short and option-ext (and the"
    echo "build-time cssparser-macros) are under the Mozilla Public License 2.0. They are"
    echo "included unmodified; their source code is available from crates.io at the"
    echo "exact versions named in the MPL-2.0 sections below."
    echo
    echo "The user interface bundles JavaScript packages; their licences follow the"
    echo "Rust components, at the end of this file."
    echo
    echo "System libraries. The Windows, macOS and .deb builds use the web view and"
    echo "system libraries already installed on the computer and redistribute none of"
    echo "them. The Linux AppImage does bundle system libraries (WebKitGTK, GTK, GLib,"
    echo "GnuTLS and others, mostly under the GNU LGPL): their copyright and licence"
    echo "files, and where to get their source, are inside the AppImage under"
    echo "usr/share/doc/hide-desktop/third-party/."
  fi
  echo
  cat "$work/body.lf"
  if [ "$kind" = desktop ]; then
    cat "$work/frontend.txt"
  fi
} > "$output"

echo "wrote $output: $crates components for $kind/$target"
