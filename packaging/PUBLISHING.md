# Publishing

Nothing here runs automatically on a tag. A release should be downloadable the
moment it is built; being *installable by name* is a separate decision, because
publishing to a registry claims a name permanently and reaches people who will
not have read [SECURITY.md](../SECURITY.md).

On crates.io and PyPI a published version cannot be deleted, only yanked, and a
PyPI filename can never be reused even after deletion. npm allows `unpublish`
within 72 hours. Treat the first publish of a name as irreversible.

## No stored credentials

`gh secret list` on `hide-protocol/hide` prints nothing, and that is the
intended state. Every registry publish in `publish-sdks.yml` uses **trusted
publishing**: the job asks GitHub for a short-lived OIDC token
(`permissions: id-token: write`), the registry checks that the token names this
repository, this workflow file and the right environment, and hands back a
credential that lives for minutes. Nothing long-lived exists to leak or rotate.

| Registry | How the job authenticates | Environment |
| --- | --- | --- |
| crates.io | `rust-lang/crates-io-auth-action` exchanges the OIDC token; its output becomes `CARGO_REGISTRY_TOKEN` for that step only | `crates-io` |
| PyPI | `pypa/gh-action-pypi-publish` with no password input | `pypi` |
| npm | `npm publish` detects the OIDC identity itself (npm ≥ 11.5.1, Node 24); provenance is attached automatically | `npm` |
| RubyGems | `rubygems/configure-rubygems-credentials` writes a short-lived key for `gem push` | `rubygems` |
| NuGet | `NuGet/login` exchanges OIDC for a one-hour API key passed to `dotnet nuget push` | `nuget` |

Each registry has to be told once, in its web UI, to trust this repository and
workflow (publisher = `hide-protocol/hide`, workflow `publish-sdks.yml`,
environment as above). That configuration is per package name and is what
makes the next paragraph true.

**Trusted publishing cannot create a NEW package name.** The first publish of
any name (a new crate, a new `@hide-protocol/<platform>` npm package, a new gem
platform) is done once by hand with a personal token on a maintainer's machine,
after which the trusted publisher is configured for it and the workflow takes
over. crates.io also accepts **one new crate per ten minutes**; the `crates` job
waits and retries on `429`, but a release that adds several crates still takes
that long.

**The one exception is `TAP_TOKEN`**, used only by `publish-packages.yml` to
push the Homebrew formula and the Scoop manifest into
`hide-protocol/homebrew-tap` and `hide-protocol/scoop-bucket`. The default
`GITHUB_TOKEN` cannot push to another repository and neither Homebrew nor Scoop
has an OIDC path, so that workflow needs a token with `contents: write` on the
two tap repositories, stored in the `packaging` environment. As of 2026-11-11
that secret does not exist and neither tap repository exists, so the two push
jobs would fail at the clone; the `generate` job runs without it.

Packagist (PHP) needs no secret at all: submit the repository URL once at
<https://packagist.org/packages/submit> and it tracks tags by webhook. Java is
not on Maven Central.

## Names

`hide` on crates.io is taken by an unrelated crate, so the Rust crates publish
under their own names (`hide-format`, `hide-crypto`, …) and the CLI as
`hide-cli`. Elsewhere the name is `hide-protocol`, except NuGet, which is
`HideProtocol` by convention.

## A failed release costs a version number

Tags matching `v*` are **immutable**: a repository ruleset refuses to delete or
move them, and a tag runs `release.yml` as the file was at that tag. There is
no "fix the workflow and re-tag". If the release run fails, or the published
assets turn out wrong, the fix goes on `main` and ships as the next patch
version; the failed tag stays, with no release or a release that must be marked
as superseded in its notes.

Rehearse before tagging: **Actions → Release → Run workflow** on the release
commit runs every job except `publish` (which is guarded on the tag ref), so a
broken build, a missing notice or a wrong asset set fails there first, at the
cost of nothing.

## Publishing an SDK release

1. Cut the release first. The SDK workflow verifies the tree, but the packages
   reference a released version.
2. Actions → **Publish SDKs** → Run workflow.
3. Enter the version *without* the leading `v`, tick **every** registry you
   intend to publish to, and leave **dry_run** ticked. The registry inputs all
   default to off: a dispatch without them runs `verify` alone and reports
   success having published nothing.
4. Read the output. A dry run builds the wheels, packs the gem and the nupkg,
   and runs `cargo publish --dry-run`, so anything that would fail on the real
   run fails here, except the OIDC exchange itself, which only happens when
   publishing.
5. Run it again with **dry_run** unticked.

The `verify` job runs the full suite at the exact commit being published and
refuses to continue when `Cargo.toml` disagrees with the version you typed. It
also checks that `LICENSE` is the complete Apache-2.0 text and that every
`.crate` about to be uploaded contains it, and generates the
`THIRD-PARTY-LICENSES.txt` files that the wheels, gems, npm packages and the
nupkg carry beside the compiled core.

After the run, verify from outside, not from the log: the `release` skill has a
script that asks each registry's API for the latest version.

## Making the CLI installable by name

`packaging/generate.sh` fills the Homebrew, Scoop, WinGet and AUR templates from
the checksums of the artifacts that were actually built, and
`packaging/verify.sh` then checks each manifest the way its package manager
will use it: every download URL names the release being published, and every
hash is the `SHA256SUMS` entry of the asset that URL names. The release
workflow runs both and attaches the result as the `packaging-manifests`
artifact; **Publish package manifests** regenerates them from the published
`SHA256SUMS`, verifies again, downloads the assets to check `SHA256SUMS` against
them, and pushes.

The templates name the release only through their own format's variable
(`#{version}`, `$version`, `$pkgver`). Up to 0.9.1 the Scoop template had
literal URLs and the generator rewrote a literal old version, so when the
template was edited by hand the generated manifest silently paired new hashes
with `v0.5.0` URLs. Do not put a literal version in a template again.

Use your own tap and bucket:

```
hide-protocol/homebrew-tap    → brew install hide-protocol/tap/hide
hide-protocol/scoop-bucket    → scoop install hide
```

Create both repositories and the `TAP_TOKEN` secret, then run Actions →
**Publish package manifests**.

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
