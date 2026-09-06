# Changelog

This project is pre-1.0. The wire format may change while the version is 0.x,
and a format change is always called out here explicitly.

## 0.2.1

### Fixed

- The Windows installer asked for administrator rights and could not complete
  without them. It now installs for the current user, which needs no elevation
  and matches what an unaudited tool should be allowed to do.

## 0.2.0

The container format is **unchanged**: 0.1.0 containers open with 0.2.0 and the
frozen vectors still pass byte for byte.

### Added

- **Passphrase-protected secret keys.** `hide keygen` now seals the secret with
  Argon2id (19 MiB, t=2, OWASP 2024 baseline) and ChaCha20-Poly1305. The Argon2
  parameters are stored in the file and authenticated, so they can be raised
  later without orphaning existing keys. Raw keys still open, so nothing that
  worked before stops working.
- **Text messages.** `hide seal` and `hide unseal` encrypt a message into a
  pasteable block for email or chat.
- **`hide info`** describes a container or key file without decrypting it, and
  without revealing the original filename.
- **`hide share`** prints a public key in a pasteable armored form; armored keys
  are accepted anywhere a public key file is.
- **`hide passwd`** changes the passphrase on an existing key.
- **Desktop application** (Tauri) with keys, files, messages and inspection. It
  calls the same crates as the CLI and contains no separate cryptographic code;
  key material never crosses into the user interface layer.
- **Portable build.** A single executable that requires no installation and
  keeps its keys in a `hide-keys` folder beside itself, writing nothing to the
  user profile.
- An interoperability test asserting the CLI and the desktop application can
  each open what the other produced.

### Changed

- `hide test-keygen` is deprecated in favour of `keygen --insecure-plaintext`.
  It still works and still writes an unencrypted key.
- A passphrase is never read from a pipe, only from a terminal, so it cannot be
  captured from shell history or a CI log.

## 0.1.0

First release. File-format engine only: HPKE X-Wing (X25519 + ML-KEM-768) key
wrapping and authenticated 64 KiB streaming with constant memory, a CLI test
harness, frozen vectors and an independent Node verifier.
