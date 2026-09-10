---
name: release
description: Cut a HIDE release end to end — version bump across 23 files, CI green, tag vX.Y.Z (release.yml, 15 assets), publish-sdks dry run then real run via OIDC trusted publishing, live verification against every registry API, clean-directory install, post-release npm lockfile refresh, tracker row. Use when releasing, when a publish job fails, or when a registry does not show the new version.
---

# Release HIDE vX.Y.Z

No secrets exist (`gh secret list` must print nothing); every registry uses OIDC
trusted publishing from `publish-sdks.yml`. Trusted publishing cannot CREATE a
package name: a brand-new crate/package needs one manual publish first, and
crates.io accepts one new crate per 10 minutes.

## 0. Preconditions

```powershell
git status --short                       # only your files
gh secret list                           # must be empty
gh run list --branch main --limit 3      # last main run green
git show v<prev>:.github/workflows/release.yml | rg -n 'uses:' | Select-Object -First 5   # tag runs the workflow AS OF THE TAG
```

## 1. Bump

```powershell
pwsh -File scripts/set-version.ps1 -Version X.Y.Z
pwsh -File scripts/set-version.ps1 -Check           # same check CI `lint` runs
```

Edit `CHANGELOG.md`: rename `## Unreleased` → `## X.Y.Z — YYYY-MM-DD`. Regenerate
`llms-full.txt` if README/docs/SECURITY changed:

```powershell
node scripts/build-llms-full.mjs
node scripts/build-llms-full.mjs --check
```

Commit explicit paths: `chore(release): X.Y.Z`. Push; wait for CI (all 8 jobs).

```powershell
gh run watch $(gh run list --branch main --limit 1 --json databaseId --jq '.[0].databaseId')
```

## 2. Tag

```powershell
git tag -a vX.Y.Z -m "vX.Y.Z"
git push origin vX.Y.Z
gh run list --workflow release.yml --limit 1
gh run watch <id>
gh release view vX.Y.Z --json assets --jq '.assets | length'    # expect 15
```

If it fails: fix on main, delete the tag remotely and locally, re-tag. Do not
re-run the failed tag run — it uses the old workflow file.

## 3. Publish SDKs — dry run first

```powershell
gh workflow run publish-sdks.yml -f version=X.Y.Z -f dry_run=true
gh run watch $(gh run list --workflow publish-sdks.yml --limit 1 --json databaseId --jq '.[0].databaseId')
```

Read every job's log for `dry-run` confirmation lines. Then:

```powershell
gh workflow run publish-sdks.yml -f version=X.Y.Z -f dry_run=false
gh run watch $(gh run list --workflow publish-sdks.yml --limit 1 --json databaseId --jq '.[0].databaseId')
```

Registry-specific inputs `crates pypi npm rubygems nuget` default true; pass
`-f nuget=false` etc. to skip one that already succeeded on a retry.

## 4. Verify LIVE state (script shape — write to `.copilot-tmp/verify-release.ps1`)

```powershell
$v = 'X.Y.Z'
$checks = @(
  @{ n='crates hide-format'; u="https://crates.io/api/v1/crates/hide-format";        p={ param($j) $j.crate.max_version } },
  @{ n='crates hide-object'; u="https://crates.io/api/v1/crates/hide-object";        p={ param($j) $j.crate.max_version } },
  @{ n='pypi';               u="https://pypi.org/pypi/hide-protocol/json";           p={ param($j) $j.info.version } },
  @{ n='npm';                u="https://registry.npmjs.org/hide-protocol/latest";      p={ param($j) $j.version } },
  @{ n='rubygems';           u="https://rubygems.org/api/v1/versions/hide-protocol.json"; p={ param($j) $j[0].number } },
  @{ n='nuget';              u="https://api.nuget.org/v3-flatcontainer/hideprotocol/index.json"; p={ param($j) $j.versions[-1] } }
)
$fail = 0
foreach ($c in $checks) {
  $j = curl.exe -sL -H 'User-Agent: hide-release-check' $c.u | ConvertFrom-Json
  $got = & $c.p $j
  if ("$got" -eq $v) { "OK   $($c.n) $got" } else { "FAIL $($c.n) got '$got' want $v"; $fail++ }
}
"failures: $fail"; exit $fail
```

Names verified 2026-09-10: npm/PyPI/RubyGems `hide-protocol`, NuGet `HideProtocol`
(flatcontainer path is lowercase), crates `hide-*`. Re-check `sdk/*/` manifests if
a registry 404s. crates.io needs a `User-Agent`; PyPI/npm can lag 1–2 min. A count of 0 checks is not a pass — the script
prints one line per registry.

## 5. Clean-directory install

```powershell
$d = New-Item -ItemType Directory "$env:TEMP\hide-rel-$([guid]::NewGuid())"; Set-Location $d
npm init -y | Out-Null; npm install hide-protocol@X.Y.Z; node -e "require('hide-protocol')"
python -m venv .venv; .\.venv\Scripts\pip install hide-protocol==X.Y.Z; .\.venv\Scripts\python -c "import hide"
cargo install hide-cli --version X.Y.Z --root . ; .\bin\hide --version
```

Download one release asset, verify against `SHA256SUMS`, open `conformance/vectors/hello.hide`
with the published binary. Return to the repo afterwards.

## 6. Post-release: npm lockfile

The lockfile records optional platform packages that did not yet exist at
build time with an empty version, so `npm ci` fails after every release (CI
uses `npm install` for this reason). Refresh and commit:

```powershell
Set-Location sdk/node; npm install --package-lock-only; Set-Location ../..
git add sdk/node/package-lock.json
git commit -m "chore(sdk-node): refresh lockfile after X.Y.Z"
```

## 7. Record

- `docs/tracker.csv`: row `type=release`, `status=DONE`, `evidence` = the
  verify script command + `gh release view vX.Y.Z --json assets`.
- `docs/TRACKER.md`: bump "What exists at X.Y.Z"; update test/vector counts.
- `packaging/generate.sh X.Y.Z <dist>` for brew/scoop/winget/AUR from the real
  SHA256SUMS (refuses when a checksum is missing).
- Commit explicit paths; push; confirm `pages.yml` green (`llms-full.txt` diff).

## Failure notes

- "my fix did nothing" on a tag run → the tag built the OLD workflow. `git show vX.Y.Z:<file>`.
- Windows runners have `sha256sum` not `shasum`; Linux AppImage needs `bundle.icon`.
- `workflow_dispatch` publish jobs are guarded by `startsWith(github.ref, 'refs/tags/v')`;
  dispatching from a branch is a no-op by design.
