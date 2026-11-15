#!/usr/bin/env bash
#
# Fills the package-manager templates with a version and the checksums of the
# artifacts that were actually built. Generating them rather than editing by
# hand is what stops a manifest quoting a hash from a previous release.
#
#   usage: packaging/generate.sh <version> <dist-dir>
#
# Every template names its download URLs through the version field of its own
# format (Homebrew `#{version}`, Scoop `$version`, the AUR `$pkgver`), so the
# only version this script writes is that field. Until 0.9.1 the Scoop template
# had literal URLs and the script rewrote a literal old version: when the
# template was later updated by hand the rewrite stopped matching, and every
# generated manifest paired the new hashes with the previous release's URLs.
# Nothing may depend on a literal version again, and the checks at the end
# refuse any manifest whose URLs or hashes disagree with SHA256SUMS.
set -euo pipefail

version="${1:?usage: generate.sh <version> <dist-dir>}"
dist="${2:?usage: generate.sh <version> <dist-dir>}"
here="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
out="$dist/packaging"
sums="$dist/SHA256SUMS"
mkdir -p "$out/homebrew" "$out/scoop" "$out/aur" "$out/winget"

case "$version" in
  [0-9]*.[0-9]*.[0-9]*) ;;
  *) echo "version must look like 1.2.3, got '$version'" >&2; exit 1 ;;
esac
[ -f "$sums" ] || { echo "no $sums" >&2; exit 1; }

# Reads a checksum out of SHA256SUMS. A missing entry is fatal: a manifest with
# an empty hash would install anything.
checksum() {
  local file="$1"
  local value
  value="$(awk -v name="$file" '$2 == name { print $1 }' "$sums")"
  if [ -z "$value" ]; then
    echo "no checksum for $file in $sums" >&2
    exit 1
  fi
  printf '%s' "$value"
}

macos_arm="$(checksum "hide-v$version-aarch64-apple-darwin.tar.gz")"
macos_x86="$(checksum "hide-v$version-x86_64-apple-darwin.tar.gz")"
linux_arm="$(checksum "hide-v$version-aarch64-unknown-linux-gnu.tar.gz")"
linux_x86="$(checksum "hide-v$version-x86_64-unknown-linux-gnu.tar.gz")"
windows_x86="$(checksum "hide-v$version-x86_64-pc-windows-msvc.zip")"
windows_arm="$(checksum "hide-v$version-aarch64-pc-windows-msvc.zip")"

# The formula's URLs are built from `version` by Ruby, so this is the only
# place the version goes.
sed \
  -e "s/^  version \".*\"/  version \"$version\"/" \
  -e "s/PLACEHOLDER_MACOS_ARM64/$macos_arm/" \
  -e "s/PLACEHOLDER_MACOS_X86_64/$macos_x86/" \
  -e "s/PLACEHOLDER_LINUX_ARM64/$linux_arm/" \
  -e "s/PLACEHOLDER_LINUX_X86_64/$linux_x86/" \
  "$here/homebrew/hide.rb" > "$out/homebrew/hide.rb"

# Scoop substitutes $version into "url" and "extract_dir" itself (the same
# syntax its autoupdate block uses), so the template holds no literal version
# outside the "version" field.
sed \
  -e "s/^    \"version\": \".*\"/    \"version\": \"$version\"/" \
  -e "s/PLACEHOLDER_WINDOWS_X86_64/$windows_x86/" \
  -e "s/PLACEHOLDER_WINDOWS_ARM64/$windows_arm/" \
  "$here/scoop/hide.json" > "$out/scoop/hide.json"

# The AUR builds from source, so it needs the tarball GitHub generates for the
# tag rather than a release asset. `curl -f` turns a 404 (tag not pushed yet)
# into an error instead of hashing an HTML error page.
source_url="https://github.com/hide-protocol/hide/archive/refs/tags/v$version.tar.gz"
source_sha="$(curl -fsSL "$source_url" | sha256sum | cut -d' ' -f1)"
sed \
  -e "s/^pkgver=.*/pkgver=$version/" \
  -e "s/PLACEHOLDER_SOURCE_TARBALL/$source_sha/" \
  "$here/aur/PKGBUILD" > "$out/aur/PKGBUILD"

warning="Experimental and unaudited. A successful decryption proves the data was not altered; it does not prove who sent it. The wire format is frozen since 0.9.0 and changes before 1.0 only if a security flaw forces it."

# WinGet requires uppercase hashes. Expand before the heredoc: parameter
# transformations do not apply inside one.
windows_x86_upper="${windows_x86^^}"
windows_arm_upper="${windows_arm^^}"

cat > "$out/winget/org.hideprotocol.hide.yaml" <<YAML
# yaml-language-server: \$schema=https://aka.ms/winget-manifest.version.1.6.0.schema.json
PackageIdentifier: org.hideprotocol.hide
PackageVersion: $version
DefaultLocale: en-US
ManifestType: version
ManifestVersion: 1.6.0
YAML

cat > "$out/winget/org.hideprotocol.hide.installer.yaml" <<YAML
# yaml-language-server: \$schema=https://aka.ms/winget-manifest.installer.1.6.0.schema.json
PackageIdentifier: org.hideprotocol.hide
PackageVersion: $version
InstallerType: zip
NestedInstallerType: portable
Commands:
  - hide
Installers:
  - Architecture: x64
    InstallerUrl: https://github.com/hide-protocol/hide/releases/download/v$version/hide-v$version-x86_64-pc-windows-msvc.zip
    InstallerSha256: $windows_x86_upper
    NestedInstallerFiles:
      - RelativeFilePath: hide-v$version-x86_64-pc-windows-msvc\\hide.exe
        PortableCommandAlias: hide
  - Architecture: arm64
    InstallerUrl: https://github.com/hide-protocol/hide/releases/download/v$version/hide-v$version-aarch64-pc-windows-msvc.zip
    InstallerSha256: $windows_arm_upper
    NestedInstallerFiles:
      - RelativeFilePath: hide-v$version-aarch64-pc-windows-msvc\\hide.exe
        PortableCommandAlias: hide
ManifestType: installer
ManifestVersion: 1.6.0
YAML

cat > "$out/winget/org.hideprotocol.hide.locale.en-US.yaml" <<YAML
# yaml-language-server: \$schema=https://aka.ms/winget-manifest.defaultLocale.1.6.0.schema.json
PackageIdentifier: org.hideprotocol.hide
PackageVersion: $version
PackageLocale: en-US
Publisher: HIDE Protocol
PublisherUrl: https://github.com/hide-protocol
PackageName: HIDE
PackageUrl: https://github.com/hide-protocol/hide
License: Apache-2.0
LicenseUrl: https://github.com/hide-protocol/hide/blob/main/LICENSE
ShortDescription: Experimental hybrid post-quantum file and message encryption (unaudited)
Description: |-
  HIDE encrypts files and messages to a recipient's public key using HPKE
  X-Wing (X25519 + ML-KEM-768) with authenticated streaming.

  $warning
Tags:
  - encryption
  - cryptography
  - post-quantum
ReleaseNotesUrl: https://github.com/hide-protocol/hide/releases/tag/v$version
ManifestType: defaultLocale
ManifestVersion: 1.6.0
YAML

# The same check the workflows run as a separate step: every URL names this
# release and every hash is the SHA256SUMS entry of the asset its URL names.
# Run here too so that a manifest that fails it never exists as an output of
# a successful run, wherever the script is called from.
bash "$here/verify.sh" "$version" "$dist"

echo "generated manifests for $version:"
find "$out" -type f | sort
