#!/usr/bin/env bash
#
# Collects the copyright and licence files of the Ubuntu packages whose
# libraries are bundled into the Linux AppImage.
#
# The .deb depends on the system's WebKitGTK and GTK and redistributes nothing.
# The AppImage is different: linuxdeploy copies the whole shared-library
# closure (WebKitGTK, GTK, GLib, GnuTLS, GStreamer, libsoup, ICU, about 190
# files) into the image, so the image redistributes them and has to carry
# their licence texts and say where the source is. linuxdeploy's own copyright
# deployment covered only about ten of those packages in 0.9.1.
#
#   usage: appimage-system-libs.sh <AppDir> <main-binary-name> <output-dir>
#
# Run on the machine that built the AppDir: the bundled files were copied from
# this machine's packages, so its dpkg database is the authority on which
# package each one came from. Writes into <output-dir>:
#
#   <package>.copyright   /usr/share/doc/<package>/copyright of every owner
#   common-licenses/      the full GPL/LGPL/MPL/... texts those files refer to
#   BUNDLED-FILES.txt     bundled file -> owning package(s)
#   PACKAGES.txt          package, version, source package, source version
#   README.txt            what this is and where the source code is
#
# It fails, rather than writing an incomplete set, when a bundled binary has
# no owning package or an owning package has no copyright file.
set -euo pipefail

usage="usage: appimage-system-libs.sh <AppDir> <main-binary-name> <output-dir>"
appdir="${1:?$usage}"
main_binary="${2:?$usage}"
out="${3:?$usage}"

die() { echo "appimage-system-libs: $*" >&2; exit 1; }

[ -d "$appdir/usr" ] || die "$appdir does not look like an AppDir (no usr/)"
[ -f "$appdir/usr/bin/$main_binary" ] || die "no usr/bin/$main_binary in $appdir"
command -v dpkg-query >/dev/null || die "dpkg-query not found; this must run on the Debian/Ubuntu build machine"

rm -rf "$out"
mkdir -p "$out"
work="$(mktemp -d)"
trap 'rm -rf "$work"' EXIT

# Every ELF file in the image is third-party code unless it is the application
# itself or the AppRun launcher at the top level (which comes from the AppImage
# tooling, not from an Ubuntu package; README.txt names it). Detecting ELF by
# its magic bytes, not by a .so suffix, also catches the WebKit helper
# processes, which are executables.
is_elf() {
  [ "$(head -c 4 "$1" | od -An -tx1 | tr -d ' \n')" = "7f454c46" ]
}

: > "$work/bundled"
while IFS= read -r -d '' file; do
  rel="${file#"$appdir"/}"
  case "$rel" in
    "usr/bin/$main_binary") continue ;;
    */*) ;;
    *) continue ;;
  esac
  if is_elf "$file"; then
    printf '%s\n' "$rel" >> "$work/bundled"
  fi
done < <(find "$appdir" -type f -print0)
sort -o "$work/bundled" "$work/bundled"

count="$(wc -l < "$work/bundled")"
# The bundler has shipped roughly 160-190 libraries since the AppImage was
# introduced. A handful means its layout changed and this script is looking in
# the wrong place, which must not pass as "nothing to attribute".
[ "$count" -ge 50 ] || die "only $count bundled binaries found in $appdir; expected well over 50"

# One dpkg-query call for every name. Lookup is by file NAME, not by path:
# linuxdeploy flattens libraries into usr/lib under their soname, and on a
# merged-/usr system dpkg may record /lib/... for a file found at /usr/lib/...,
# which is exactly what makes a path lookup miss.
sed 's|.*/||' "$work/bundled" | sort -u > "$work/names"
patterns=()
while IFS= read -r name; do
  patterns+=("*/$name")
done < "$work/names"
# Exits non-zero when any single pattern has no match; coverage is checked
# name by name below, so only the output matters here.
dpkg-query -S "${patterns[@]}" > "$work/owners.raw" 2> "$work/owners.err" || true

# "pkg-a:amd64, pkg-b: /path/to/name"  ->  "name<TAB>pkg-a<TAB>/path/to/name"
awk '
  /^diversion by / { next }
  {
    split_at = index($0, ": /")
    if (split_at == 0) next
    packages = substr($0, 1, split_at - 1)
    path = substr($0, split_at + 2)
    name = path
    sub(/.*\//, "", name)
    count = split(packages, list, /, */)
    for (i = 1; i <= count; i++) {
      package = list[i]
      sub(/:.*/, "", package)
      print name "\t" package "\t" path
    }
  }
' "$work/owners.raw" | sort -u > "$work/owners"

# A name can be owned by more than one package: a cross-compiler's copy under
# /usr/aarch64-linux-gnu/lib, or the same library for another architecture.
# Only the loader's own directories can be where the bundled file came from,
# and when this machine's multiarch directory has the name, that copy is it.
multiarch="$(uname -m)-linux-gnu"
awk -F'\t' -v multiarch="$multiarch" '
  NR == FNR { want[$0] = 1; next }
  !($1 in want) { next }
  $3 !~ /^\/(usr\/)?(lib|lib64|libexec)\// { next }
  {
    key = $1 "\t" $2
    if ($3 ~ ("^/(usr/)?lib/" multiarch "/")) {
      has_native[$1] = 1
      native_rows[key] = 1
    } else {
      other_rows[key] = 1
    }
  }
  END {
    for (key in native_rows) print key
    for (key in other_rows) {
      split(key, parts, "\t")
      if (!(parts[1] in has_native)) print key
    }
  }
' "$work/names" "$work/owners" | sort -u > "$work/owned"
cut -f1 "$work/owned" | sort -u > "$work/owned-names"
comm -23 "$work/names" "$work/owned-names" > "$work/unowned"
if [ -s "$work/unowned" ]; then
  echo "appimage-system-libs: bundled binaries that no installed package owns:" >&2
  sed 's/^/  /' "$work/unowned" >&2
  die "cannot attribute $(wc -l < "$work/unowned") bundled file(s); refusing to write an incomplete notice set"
fi

cut -f2 "$work/owned" | sort -u > "$work/packages"
grep -q '^libwebkit2gtk-4\.1-' "$work/packages" \
  || die "WebKitGTK is not among the owning packages; the lookup is not seeing the real libraries"

while IFS= read -r package; do
  source_file="/usr/share/doc/$package/copyright"
  # -L: several -dev and split packages symlink their doc directory to a
  # sibling's; the text is what has to be in the image.
  [ -e "$source_file" ] || die "package $package has no $source_file"
  cp -L "$source_file" "$out/$package.copyright"
done < "$work/packages"

# Debian copyright files name the GPL, LGPL, MPL and the like by reference to
# /usr/share/common-licenses instead of reproducing them. Outside a Debian
# system that reference points nowhere, so the texts travel with the files.
[ -f /usr/share/common-licenses/LGPL-2.1 ] || die "/usr/share/common-licenses/LGPL-2.1 is missing"
mkdir -p "$out/common-licenses"
cp -L /usr/share/common-licenses/* "$out/common-licenses/"

while IFS= read -r rel; do
  name="${rel##*/}"
  owners="$(awk -F'\t' -v name="$name" '$1 == name { print $2 }' "$work/owned" | paste -sd, -)"
  printf '%s\t%s\n' "$rel" "$owners"
done < "$work/bundled" > "$out/BUNDLED-FILES.txt"

# shellcheck disable=SC2016  # ${...} here is dpkg-query's own format syntax
xargs -a "$work/packages" dpkg-query -W \
  -f '${Package}\t${Version}\t${source:Package}\t${source:Version}\n' \
  | sort -u > "$out/PACKAGES.txt"
[ "$(wc -l < "$out/PACKAGES.txt")" -ge "$(wc -l < "$work/packages")" ] \
  || die "dpkg-query returned fewer packages than were asked for"

# os-release is a list of shell assignments; read the three that are needed
# without sourcing it into this script's own variables.
os_field() {
  sed -n "s/^$1=//p" /etc/os-release | head -n 1 | tr -d '"'
}
codename="$(os_field VERSION_CODENAME)"
[ -n "$codename" ] || die "/etc/os-release has no VERSION_CODENAME"
distribution="$(os_field NAME) $(os_field VERSION_ID) ($codename)"

cat > "$out/README.txt" <<EOF
System libraries bundled in this AppImage
=========================================

This AppImage contains, besides the HIDE desktop application, shared libraries
and helper programs copied unmodified from $distribution
packages on the machine that built it: WebKitGTK, GTK, GLib, GnuTLS, GStreamer,
libsoup, ICU and their dependencies. Many are under the GNU Lesser General
Public License; others are under the GPL with exceptions, the MPL, or MIT- and
BSD-style licences. HIDE's own licence does not apply to them.

In this directory:

  <package>.copyright  The copyright and licence file of each package, exactly
                       as shipped by the distribution.
  common-licenses/     The full texts those files refer to as
                       /usr/share/common-licenses/<name> (LGPL-2.1, GPL-2 ...).
  BUNDLED-FILES.txt    Every bundled binary and the package it came from.
  PACKAGES.txt         Package, version, source package and source version.

Source code. The corresponding source of each library is the Ubuntu source
package named in the third and fourth columns of PACKAGES.txt. It is available
from the Ubuntu archive:

  apt-get source <source-package>=<source-version>
  https://packages.ubuntu.com/$codename/<package>
  https://launchpad.net/ubuntu/+source/<source-package>/<source-version>

Replacing a library. The libraries are dynamically linked and are ordinary
files inside the image. Run the AppImage with --appimage-extract, replace a
file under squashfs-root/usr/lib/ with a compatible build of your own, and
start squashfs-root/AppRun.

Not from a distribution package: the AppRun launcher and the AppImage runtime
that mounts the image come from the AppImage project (MIT licence; the runtime
includes squashfuse, BSD-2-Clause, and libfuse, LGPL-2.1). Their licences are
at https://github.com/AppImage/AppImageKit/blob/master/LICENSE and
https://github.com/AppImage/type2-runtime/blob/main/LICENSE.

The licences of the Rust and JavaScript components compiled into the
application itself are in THIRD-PARTY-LICENSES.txt, which is installed with
the application's resources inside this image.
EOF

echo "appimage-system-libs: $count bundled binaries from $(wc -l < "$work/packages") packages -> $out"
