<#
.SYNOPSIS
  Sets the release version everywhere it is written down.

.DESCRIPTION
  The version lives in 22 files across seven ecosystems, and every release so
  far has updated them by hand. That is a silent failure waiting to happen: a
  missed manifest publishes a package whose contents claim one version and
  whose metadata claims another, and nothing in CI would notice.

  Run with -Check in CI to assert they all agree without changing anything.

.EXAMPLE
  pwsh -File scripts/set-version.ps1 -Version 0.6.0
  pwsh -File scripts/set-version.ps1 -Check
#>
[CmdletBinding(DefaultParameterSetName = 'Set')]
param(
    [Parameter(ParameterSetName = 'Set', Mandatory)]
    [ValidatePattern('^\d+\.\d+\.\d+$')]
    [string]$Version,

    [Parameter(ParameterSetName = 'Check', Mandatory)]
    [switch]$Check
)

$ErrorActionPreference = 'Stop'
$root = Split-Path -Parent $PSScriptRoot

# Each entry: the file, and the regex whose FIRST capture group is the version.
# Anchored patterns only — a bare version regex would rewrite dependency
# versions and sample output too.
$targets = @(
    @{ Path = 'Cargo.toml'; Pattern = '(?m)^version = "([^"]+)"' }
    @{ Path = 'apps/hide-cli/Cargo.toml'; Pattern = 'version = "([^"]+)" \}' }
    @{ Path = 'crates/hide-epoch/Cargo.toml'; Pattern = 'version = "([^"]+)" \}' }
    @{ Path = 'crates/hide-identity/Cargo.toml'; Pattern = 'version = "([^"]+)" \}' }
    @{ Path = 'crates/hide-mls/Cargo.toml'; Pattern = 'version = "([^"]+)" \}' }
    @{ Path = 'crates/hide-keyring/Cargo.toml'; Pattern = 'version = "([^"]+)" \}' }
    @{ Path = 'crates/hide-object/Cargo.toml'; Pattern = 'version = "([^"]+)" \}' }
    @{ Path = 'crates/hide-ffi/Cargo.toml'; Pattern = 'version = "([^"]+)" \}' }
    @{ Path = 'crates/hide-sign/Cargo.toml'; Pattern = 'version = "([^"]+)" \}' }
    @{ Path = 'crates/hide-wasm/Cargo.toml'; Pattern = 'version = "([^"]+)" \}' }
    @{ Path = 'apps/hide-desktop/package.json'; Pattern = '(?m)^  "version": "([^"]+)"' }
    @{ Path = 'apps/hide-desktop/src-tauri/tauri.conf.json'; Pattern = '(?m)^  "version": "([^"]+)"' }
    @{ Path = 'apps/hide-desktop/src-tauri/Cargo.toml'; Pattern = '(?m)^version = "([^"]+)"' }
    @{ Path = 'sdk/node/package.json'; Pattern = '(?m)^  "version": "([^"]+)"' }
    @{ Path = 'sdk/wasm/package.json'; Pattern = '(?m)^  "version": "([^"]+)"' }
    @{ Path = 'sdk/python/pyproject.toml'; Pattern = '(?m)^version = "([^"]+)"' }
    @{ Path = 'sdk/ruby/hide-protocol.gemspec'; Pattern = 'spec\.version = "([^"]+)"' }
    @{ Path = 'sdk/dotnet/HideProtocol/HideProtocol.csproj'; Pattern = '<Version>([^<]+)</Version>' }
    @{ Path = 'sdk/java/pom.xml'; Pattern = '(?s)<artifactId>hide</artifactId>\s*<version>([^<]+)</version>' }
    @{ Path = 'packaging/aur/PKGBUILD'; Pattern = '(?m)^pkgver=(.+)$' }
    @{ Path = 'packaging/scoop/hide.json'; Pattern = '"version": "([^"]+)"' }
    @{ Path = 'packaging/homebrew/hide.rb'; Pattern = 'version "([^"]+)"' }
)

# The version internal dependencies must point at. In -Check mode this is
# whatever the manifests already agree on, discovered below.
$script:targetVersion = if ($PSCmdlet.ParameterSetName -eq 'Set') { $Version } else { $null }

$found = @{}
$missing = @()

foreach ($target in $targets) {
    $path = Join-Path $root $target.Path
    if (-not (Test-Path $path)) {
        $missing += $target.Path
        continue
    }

    $content = Get-Content $path -Raw
    $match = [regex]::Match($content, $target.Pattern)
    if (-not $match.Success) {
        $missing += "$($target.Path) (pattern did not match)"
        continue
    }

    $current = $match.Groups[1].Value
    if (-not $found.ContainsKey($current)) { $found[$current] = @() }
    $found[$current] += $target.Path

    if ($PSCmdlet.ParameterSetName -eq 'Set' -and $current -ne $Version) {
        $group = $match.Groups[1]
        $updated = $content.Substring(0, $group.Index) + $Version +
                   $content.Substring($group.Index + $group.Length)
        # No trailing newline change: these files are checked byte for byte by
        # other tooling, and a stray newline shows up as a spurious diff.
        [System.IO.File]::WriteAllText($path, $updated)
        Write-Host "  $($target.Path): $current -> $Version"
    }
}

# In -Check mode the expected version is whatever the manifests agree on, which
# is only known now that they have been scanned.
if (-not $script:targetVersion) {
    if ($found.Keys.Count -ne 1) {
        Write-Host 'versions disagree:'
        foreach ($version in $found.Keys) {
            Write-Host "  $version"
            foreach ($file in $found[$version]) { Write-Host "    $file" }
        }
        exit 1
    }
    $script:targetVersion = @($found.Keys)[0]
}

# Internal path dependencies pin a version, which is what crates.io publishes
# against. Leaving these behind would make each crate depend on a release that
# does not contain the code it was built with — and cargo would not complain,
# because the local path wins during a workspace build.
# Path separators differ between the developer machine and CI, so normalise
# before excluding rather than matching a literal backslash.
$internal = Get-ChildItem $root -Recurse -Filter Cargo.toml | Where-Object {
    $normalised = $_.FullName -replace '\\', '/'
    $normalised -notmatch '/target/|/node_modules/'
}

foreach ($manifest in $internal) {
    $content = Get-Content $manifest.FullName -Raw
    $updated = [regex]::Replace(
        $content,
        '(?m)^(hide-[a-z]+ = \{ path = "[^"]+", version = ")[^"]+(" \})',
        {
            param($match)
            "$($match.Groups[1].Value)$script:targetVersion$($match.Groups[2].Value)"
        })
    if ($updated -ne $content) {
        if ($PSCmdlet.ParameterSetName -eq 'Set') {
            [System.IO.File]::WriteAllText($manifest.FullName, $updated)
            $relative = $manifest.FullName.Substring($root.Length + 1) -replace '\\', '/'
            Write-Host "  ${relative}: internal deps"
        } else {
            Write-Host "internal deps disagree in $($manifest.FullName)"
            exit 1
        }
    }
}

# The Node package pins its seven platform packages exactly. A stale pin here
# resolves to the previous release's binary, or to nothing at all if that
# version was never published — and npm reports neither, because an optional
# dependency that fails to resolve is silently skipped.
$nodeManifest = Join-Path $root 'sdk/node/package.json'
$content = Get-Content $nodeManifest -Raw
$updated = [regex]::Replace(
    $content,
    '(?m)^(    "@hide-protocol/[a-z0-9-]+": ")[^"]+(",?)$',
    {
        param($match)
        "$($match.Groups[1].Value)$script:targetVersion$($match.Groups[2].Value)"
    })
if ($updated -ne $content) {
    if ($PSCmdlet.ParameterSetName -eq 'Set') {
        [System.IO.File]::WriteAllText($nodeManifest, $updated)
        Write-Host '  sdk/node/package.json: platform packages'
    } else {
        Write-Host 'the platform packages in sdk/node/package.json disagree'
        exit 1
    }
}

if ($missing.Count -gt 0) {
    Write-Error "these files were not matched, so their version was NOT updated:`n  $($missing -join "`n  ")"
}

if ($PSCmdlet.ParameterSetName -eq 'Check') {
    if ($found.Keys.Count -ne 1) {
        Write-Host 'versions disagree:'
        foreach ($version in $found.Keys) {
            Write-Host "  $version"
            foreach ($file in $found[$version]) { Write-Host "    $file" }
        }
        exit 1
    }
    Write-Host "all $($targets.Count) files agree on $($found.Keys)"
} else {
    Write-Host "`nset to $Version in $($targets.Count) files. Cargo.lock still needs `cargo check`."
}
