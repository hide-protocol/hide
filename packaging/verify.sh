#!/usr/bin/env bash
#
# Checks generated package-manager manifests against SHA256SUMS the way each
# package manager will use them: every asset URL must name this release, and
# the hash written beside a URL must be the checksum of the asset that URL
# names. generate.sh runs this on what it just wrote, and the release and
# publish workflows run it again as their own step, so a manifest that pairs
# new hashes with an old release's URLs (the Scoop manifest did, up to 0.9.1)
# cannot be attached to a release or pushed to a tap.
#
#   usage: packaging/verify.sh <version> <dist-dir>
#
# <dist-dir> holds SHA256SUMS and the packaging/ directory generate.sh wrote.
set -euo pipefail

version="${1:?usage: verify.sh <version> <dist-dir>}"
dist="${2:?usage: verify.sh <version> <dist-dir>}"
out="$dist/packaging"
sums="$dist/SHA256SUMS"

[ -f "$sums" ] || { echo "no $sums" >&2; exit 1; }
for manifest in homebrew/hide.rb scoop/hide.json aur/PKGBUILD \
  winget/org.hideprotocol.hide.yaml \
  winget/org.hideprotocol.hide.installer.yaml \
  winget/org.hideprotocol.hide.locale.en-US.yaml; do
  [ -f "$out/$manifest" ] || { echo "missing $out/$manifest" >&2; exit 1; }
done

failures=0
checked=0
fail() { echo "FAIL: $*" >&2; failures=$((failures + 1)); }

# check_pair <manifest> <resolved url> <hash as written>
check_pair() {
  local manifest="$1" url="$2" hash="$3" asset expected
  asset="${url##*/}"
  case "$url" in
    "https://github.com/hide-protocol/hide/releases/download/v$version/"*) ;;
    *) fail "$manifest: $url is not under releases/download/v$version/" ;;
  esac
  case "$asset" in
    *"v$version"*) ;;
    *) fail "$manifest: asset name $asset does not contain v$version" ;;
  esac
  expected="$(awk -v name="$asset" '$2 == name { print $1 }' "$sums")"
  if [ -z "$expected" ]; then
    fail "$manifest: $asset is not in SHA256SUMS"
  elif [ "${hash,,}" != "$expected" ]; then
    fail "$manifest: hash for $asset is $hash, SHA256SUMS says $expected"
  else
    echo "ok   $manifest  $asset"
  fi
  checked=$((checked + 1))
}

# The text between the first pair of double quotes after the key on a line.
quoted() {
  printf '%s' "$1" | sed -e 's/^[^"]*"//' -e 's/".*$//'
}
# The same for a JSON `"key": "value"` line.
json_value() {
  printf '%s' "$1" | sed -e 's/^[^:]*: *"//' -e 's/".*$//'
}

# No placeholder may survive anywhere, and no release other than this one may
# appear in a download URL. Templates name the release through the format's
# own variable, so a literal version in a URL is always a mistake.
for manifest in "$out"/homebrew/hide.rb "$out"/scoop/hide.json "$out"/aur/PKGBUILD "$out"/winget/*.yaml; do
  if grep -q 'PLACEHOLDER_' "$manifest"; then
    fail "$manifest still contains a PLACEHOLDER_"
  fi
  # `|| true`: no match at all is the good case, and grep reports it as 1.
  other="$(grep -Eo 'releases/download/v[0-9]+\.[0-9]+\.[0-9]+' "$manifest" \
    | sort -u | grep -Fvx "releases/download/v$version" || true)"
  if [ -n "$other" ]; then
    fail "$manifest has a download URL for another release: $(printf '%s' "$other" | tr '\n' ' ')"
  fi
done

# Homebrew: `url "..."` followed by `sha256 "..."`; Ruby expands #{version}.
brew_version="$(sed -n 's/^  version "\(.*\)"$/\1/p' "$out/homebrew/hide.rb")"
[ "$brew_version" = "$version" ] || fail "homebrew: version is '$brew_version', expected $version"
brew_count=0
url=""
while IFS= read -r line; do
  case "$line" in
    *'url "'*)
      url="$(quoted "$line")"
      url="${url//'#{version}'/$version}"
      ;;
    *'sha256 "'*)
      if [ -z "$url" ]; then
        fail "homebrew: sha256 with no url before it"
      else
        check_pair homebrew "$url" "$(quoted "$line")"
        brew_count=$((brew_count + 1))
      fi
      url=""
      ;;
  esac
done < "$out/homebrew/hide.rb"
[ "$brew_count" -eq 4 ] || fail "homebrew: expected 4 url/sha256 pairs, found $brew_count"

# Scoop: url/hash pairs under "architecture" (autoupdate has URLs but no
# hashes); Scoop expands $version in url and extract_dir.
scoop_version="$(sed -n 's/^    "version": "\(.*\)",$/\1/p' "$out/scoop/hide.json")"
[ "$scoop_version" = "$version" ] || fail "scoop: version is '$scoop_version', expected $version"
scoop_count=0
url=""
while IFS= read -r line; do
  case "$line" in
    *'"url": "'*)
      url="$(json_value "$line")"
      # \$version is Scoop's literal placeholder; $version is this release.
      url="${url//\$version/$version}"
      ;;
    *'"hash": "'*)
      if [ -z "$url" ]; then
        fail "scoop: hash with no url before it"
      else
        check_pair scoop "$url" "$(json_value "$line")"
        scoop_count=$((scoop_count + 1))
      fi
      url=""
      ;;
    *'"extract_dir": "'*)
      dir="$(json_value "$line")"
      dir="${dir//\$version/$version}"
      case "$dir" in
        "hide-v$version-"*) ;;
        *) fail "scoop: extract_dir $dir does not start with hide-v$version-" ;;
      esac
      ;;
  esac
done < "$out/scoop/hide.json"
[ "$scoop_count" -eq 2 ] || fail "scoop: expected 2 url/hash pairs, found $scoop_count"
# Scoop reads the manifest as JSON; a substitution slip would produce a file
# it rejects. python3 is present on the runners; skipped where it is not.
if command -v python3 >/dev/null 2>&1; then
  python3 -c 'import json, sys; json.load(open(sys.argv[1], encoding="utf-8"))' "$out/scoop/hide.json" \
    || fail "scoop: the generated manifest is not valid JSON"
fi

# WinGet: InstallerUrl / InstallerSha256 pairs, hashes uppercase.
winget_count=0
url=""
while IFS= read -r line; do
  case "$line" in
    *'InstallerUrl: '*) url="${line#*InstallerUrl: }" ;;
    *'InstallerSha256: '*)
      hash="${line#*InstallerSha256: }"
      [ "$hash" = "${hash^^}" ] || fail "winget: hash $hash is not uppercase"
      if [ -z "$url" ]; then
        fail "winget: InstallerSha256 with no InstallerUrl before it"
      else
        check_pair winget "$url" "$hash"
        winget_count=$((winget_count + 1))
      fi
      url=""
      ;;
  esac
done < "$out/winget/org.hideprotocol.hide.installer.yaml"
[ "$winget_count" -eq 2 ] || fail "winget: expected 2 installer entries, found $winget_count"
for manifest in "$out"/winget/*.yaml; do
  grep -q "^PackageVersion: $version\$" "$manifest" || fail "$manifest: PackageVersion is not $version"
done

# AUR: built from the tag's source tarball, which is not a release asset and
# so has no SHA256SUMS entry. What can be checked offline is that the version
# and a real hash were written; generate.sh computes that hash from the
# tarball it downloads with `curl -f`.
grep -q "^pkgver=$version\$" "$out/aur/PKGBUILD" || fail "aur: pkgver is not $version"
grep -Eq "^sha256sums=\('[0-9a-f]{64}'\)\$" "$out/aur/PKGBUILD" || fail "aur: sha256sums is not one 64-digit hash"

if [ "$failures" -gt 0 ]; then
  echo "$failures manifest check(s) failed; nothing under $out is fit to publish" >&2
  exit 1
fi
# Eight asset references exist today (4 Homebrew, 2 Scoop, 2 WinGet). Fewer
# means a loop above stopped matching and passed by checking nothing.
[ "$checked" -eq 8 ] || { echo "expected 8 url/hash pairs, checked $checked" >&2; exit 1; }
echo "verified $checked url/hash pairs for $version against $sums"
