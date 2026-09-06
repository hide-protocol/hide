#!/usr/bin/env bash
#
# Fills the package-manager templates with a version and the checksums of the
# artifacts that were actually built. Generating them rather than editing by
# hand is what stops a manifest quoting a hash from a previous release.
#
#   usage: packaging/generate.sh <version> <dist-dir>
set -euo pipefail

version="${1:?usage: generate.sh <version> <dist-dir>}"
dist="${2:?usage: generate.sh <version> <dist-dir>}"
here="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
out="$dist/packaging"
mkdir -p "$out/homebrew" "$out/scoop" "$out/aur" "$out/winget"

# Reads a checksum out of SHA256SUMS. A missing entry is fatal: a manifest with
# an empty hash would install anything.
checksum() {
  local file="$1"
  local value
  value="$(awk -v name="$file" '$2 == name { print $1 }' "$dist/SHA256SUMS")"
  if [ -z "$value" ]; then
    echo "no checksum for $file in $dist/SHA256SUMS" >&2
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

sed \
  -e "s/^  version \".*\"/  version \"$version\"/" \
  -e "s/PLACEHOLDER_MACOS_ARM64/$macos_arm/" \
  -e "s/PLACEHOLDER_MACOS_X86_64/$macos_x86/" \
  -e "s/PLACEHOLDER_LINUX_ARM64/$linux_arm/" \
  -e "s/PLACEHOLDER_LINUX_X86_64/$linux_x86/" \
  "$here/homebrew/hide.rb" > "$out/homebrew/hide.rb"

sed \
  -e "s/0\.2\.1/$version/g" \
  -e "s/PLACEHOLDER_WINDOWS_X86_64/$windows_x86/" \
  -e "s/PLACEHOLDER_WINDOWS_ARM64/$windows_arm/" \
  "$here/scoop/hide.json" > "$out/scoop/hide.json"

# The AUR builds from source, so it needs the tarball GitHub generates for the
# tag rather than a release asset.
source_url="https://github.com/hide-protocol/hide/archive/refs/tags/v$version.tar.gz"
source_sha="$(curl -sSL "$source_url" | sha256sum | cut -d' ' -f1)"
sed \
  -e "s/^pkgver=.*/pkgver=$version/" \
  -e "s/PLACEHOLDER_SOURCE_TARBALL/$source_sha/" \
  "$here/aur/PKGBUILD" > "$out/aur/PKGBUILD"

warning="Experimental and unaudited. A successful decryption proves the data was not altered; it does not prove who sent it. The wire format may change while the version is 0.x."

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

echo "generated manifests for $version:"
find "$out" -type f | sort
