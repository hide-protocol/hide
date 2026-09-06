# Publishing

Nothing here runs automatically on a tag. A release should be downloadable the
moment it is built; being *installable by name* is a separate decision, because
publishing to a registry claims a name permanently and reaches people who will
not have read [SECURITY.md](../SECURITY.md).

On crates.io and PyPI a published version cannot be deleted, only yanked, and a
PyPI filename can never be reused even after deletion. npm allows `unpublish`
within 72 hours. Treat the first publish of a name as irreversible.

## Credentials to create first

Each goes in **Settings → Secrets and variables → Actions** on
`hide-protocol/hide`. The workflows use GitHub *environments* of the same name,
so approval can be required per registry.

| Registry | Secret | Where to get it | Environment |
| --- | --- | --- | --- |
| crates.io | `CARGO_REGISTRY_TOKEN` | crates.io → Account Settings → API Tokens | `crates-io` |
| PyPI | *(none)* | Prefer Trusted Publishing — see below | `pypi` |
| npm | `NPM_TOKEN` | npmjs.com → Access Tokens → Granular, publish scope | `npm` |
| RubyGems | `RUBYGEMS_API_KEY` | rubygems.org → Settings → API Keys, push scope | `rubygems` |
| NuGet | `NUGET_API_KEY` | nuget.org → API Keys, push scope | `nuget` |
| Homebrew / Scoop taps | `TAP_TOKEN` | A PAT with `contents: write` on the tap repos | `packaging` |

**PyPI needs no token.** Configure Trusted Publishing instead: on PyPI, add a
publisher for owner `hide-protocol`, repository `hide`, workflow
`publish-sdks.yml`, environment `pypi`. OIDC is short-lived and scoped to that
one workflow, so there is no long-lived credential to leak.

Packagist (PHP) needs no secret at all — submit the repository URL once at
<https://packagist.org/packages/submit> and it tracks tags by webhook.

## Names

`hide` on crates.io is taken by an unrelated crate, so the Rust crates publish
under their own names (`hide-format`, `hide-crypto`, …) and the CLI as
`hide-cli`. Elsewhere the name is `hide-protocol`, except NuGet, which is
`HideProtocol` by convention.

## Publishing an SDK release

1. Cut the release first. The SDK workflow verifies the tree, but the packages
   reference a released version.
2. Actions → **Publish SDKs** → Run workflow.
3. Enter the version *without* the leading `v`, tick the registries, and leave
   **dry_run** ticked.
4. Read the output. A dry run builds the wheels, packs the gem and the nupkg,
   and runs `cargo publish --dry-run`, so anything that would fail on the real
   run fails here — except the credential itself.
5. Run it again with **dry_run** unticked.

The `verify` job runs the full suite at the exact commit being published and
refuses to continue when `Cargo.toml` disagrees with the version you typed.

## Making the CLI installable by name

`packaging/generate.sh` fills the Homebrew, Scoop, WinGet and AUR templates from
the checksums of the artifacts that were actually built, so a manifest cannot
quote a hash from a previous release. The release workflow attaches them as an
artifact; **Publish package manifests** pushes them.

Use your own tap and bucket:

```
hide-protocol/homebrew-tap    → brew install hide-protocol/tap/hide
hide-protocol/scoop-bucket    → scoop install hide
```

Create both repositories, then run Actions → **Publish package manifests**.

WinGet and Homebrew-core are submitted by hand, by opening a PR against
`microsoft/winget-pkgs` and `Homebrew/homebrew-core` with the generated
manifest. Expect both to push back while this is 0.x and marked experimental —
Homebrew-core in particular requires a stable, notable project, and the
manifests are ready for the day that is true rather than for today. The AUR
takes `packaging/aur/PKGBUILD` pushed to an `ssh://aur@aur.archlinux.org/hide`
repository; the AUR accepts experimental software without objection.

## After publishing

Verify from outside, not from the build log: install the package on a clean
machine and check `hide --version`, or import the SDK and run one round trip.
A green publish job proves an upload happened, not that the artifact works.
