# Licence notices for shipped binaries

Every binary HIDE publishes statically links third-party code, and the AppImage
also bundles system libraries. The licences of that code require their texts
(and, for MPL and LGPL code, a pointer to the source) to travel with the
binary. Nothing here is run by hand for a release: `release.yml` and
`publish-sdks.yml` call these scripts and fail when a notice is missing.

| File | What it does |
| --- | --- |
| `../../about.toml`, `../../about.hbs` | [cargo-about](https://github.com/EmbarkStudios/cargo-about) configuration and plain-text template. The accepted list mirrors `deny.toml`. |
| `generate.sh <cli\|ffi\|wasm\|desktop> <target\|all> <out>` | Writes `THIRD-PARTY-LICENSES.txt` for one binary: every crate compiled into it for that target, with licence text and its exact crates.io release. Compiles nothing. |
| `frontend.mjs <app-dir>` | Prints the licences of the JavaScript packages bundled into the desktop user interface, read from `node_modules`. Appended to the desktop file. |
| `appimage-system-libs.sh <AppDir> <binary> <out>` | On the build machine, maps every bundled ELF file to its Ubuntu package and collects each package's `copyright` file, the common licence texts, and the source-package versions. |
| `tauri-notices.conf.json` | Tauri config overlay: installs `LICENSE` and `THIRD-PARTY-LICENSES.txt` as application resources in every installer. Paths are relative to `apps/hide-desktop/src-tauri`. |
| `tauri-appimage-notices.conf.json` | Tauri config overlay for the second AppImage pass: adds the system-library notices under `usr/share/doc/hide-desktop/third-party/`. |

The overlays are passed with `tauri build --config`, so `tauri.conf.json` and a
plain local `pnpm tauri build` are unaffected.

## Try it locally

```
cargo install cargo-about --locked --version 0.9.3 --features cli
bash scripts/licences/generate.sh cli x86_64-unknown-linux-gnu /tmp/cli.txt
bash scripts/licences/generate.sh desktop x86_64-pc-windows-msvc /tmp/desktop.txt
node scripts/licences/frontend.mjs apps/hide-desktop
```

A dependency under a licence that `about.toml` does not accept makes
`generate.sh` fail; add the licence to `deny.toml` and `about.toml` together,
or drop the dependency.
