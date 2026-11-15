# hide-cli

> **Experimental and unaudited. Do not use it to protect data you cannot afford
> to lose or expose.** No third party has reviewed the protocol or this code.
> Read [SECURITY.md](https://github.com/hide-protocol/hide/blob/main/SECURITY.md)
> before relying on anything here.

`hide-cli` installs `hide`, the command-line tool of the
[HIDE](https://github.com/hide-protocol/hide) encrypted-file protocol. It
encrypts files and short text messages to one or more recipient public keys
(X-Wing: X25519 + ML-KEM-768), signs with a hybrid Ed25519 + ML-DSA-65 key, and
manages the identity logs and epoch keys the protocol defines. It exists to
exercise the format; the cryptography lives in the `hide-*` library crates, and
the tool adds none of its own.

## Install

```
cargo install hide-cli --locked
```

Needs Rust 1.88 or newer. The binary is named `hide`.

Prebuilt binaries for Linux, Windows and macOS are attached to each
[GitHub release](https://github.com/hide-protocol/hide/releases). They are not
code-signed. Check a download against the release's `SHA256SUMS`, and against
its build-provenance attestation:

```
gh attestation verify <file> --repo hide-protocol/hide
```

## `--experimental` is required

Every command refuses to run without `--experimental`. The flag is an
acknowledgement that the protocol and this implementation are unaudited; it
changes nothing else. A warning is also printed on standard error unless
`--quiet` is given.

```
hide --experimental keygen --secret alice.hide-key --public alice.hide-pub
hide --experimental encrypt report.pdf --recipient alice.hide-pub --output report.pdf.hide
hide --experimental open report.pdf.hide --secret alice.hide-key --output report.pdf
hide --experimental info report.pdf.hide
```

`keygen` seals the secret key with a passphrase, which is read only from a
terminal, never from a pipe. `--insecure-plaintext` writes the key unencrypted
and is meant for disposable test keys. `hide --help` lists every command.

## What it does not give you

- A signed container authenticates a key, not a person. There is no directory:
  compare a signer's key with one you already trust.
- An unsigned container proves only that the data was not altered, not who
  created it.
- Forward security exists only if you erase old epoch keys (`epoch-erase`), and
  only as far as the storage underneath really forgets them.
- No hardware-backed key storage.

The full list is in the
[repository README](https://github.com/hide-protocol/hide#what-is-not-implemented-or-guaranteed),
and the threat model, known limitations and how to report a vulnerability are in
[SECURITY.md](https://github.com/hide-protocol/hide/blob/main/SECURITY.md).

## Licence

Apache-2.0. The licence text is in the `LICENSE` file of this package.
