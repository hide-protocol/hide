# HIDE conformance vectors

*HIDE is experimental and has not been audited by a third party.*

Frozen artifacts for [`spec/hide-1.md`](../../spec/hide-1.md). An implementation is conformant only
if every positive vector opens with the recorded plaintext, every file under `rejections/` is
refused, and its results agree with [`manifest.json`](manifest.json) (spec, "Conformance").

These files are protocol artifacts. Changing the bytes of one is a format change; the generators
refuse to overwrite an existing vector with different bytes, and the pre-push hook refuses a dirty
`conformance/vectors`.

## manifest.json

`manifest.json` (`"format": "hide-vectors/1"`) lists all 67 vectors, one entry each:

| field | meaning |
| --- | --- |
| `path` | relative to this directory |
| `kind` | `container`, `key`, `public-key`, `subsystem` or `detached-signature` |
| `expect` | `open` or `reject` |
| `reason` | for rejections, the refusal reason as in `rejections/rejections.txt` |
| `sha256` | lowercase hex SHA-256 of the file |

The top-level `secret` names the key most containers are sealed to (`recipient.test-secret`).
`identity.hide` is sealed to the key derived from `identity.test-seed` (spec §9.1). Check `sha256`
before using a vector, so a corrupted checkout fails loudly. `detached-signature` entries cover an
implementation-defined format (spec §14): verify the hash, and treat the rest as informative.

Current totals: container 10 open / 28 reject; key 3 / 1; public-key 4 / 1; subsystem 13 / 5;
detached-signature 2.

## Families

### HIDE/0.1–0.8 containers (still read)

| file | proves |
| --- | --- |
| `hello.hide`, `empty.hide` | the unsigned container: key schedule, metadata, one and zero records. Minor 1, flags 0 — identical in structure to a HIDE 1 unsigned container |
| `identity.hide` | a container sealed to a recipient key derived from a master seed (`identity.test-seed`) |
| `signed-public.hide`, `signed-confidential.hide` | legacy signed containers (minor 2, HIDE/0.5 transcript), public and confidential placement. Read-only: HIDE 1 never writes minor 2 |

Plaintext is in the matching `.txt`.

### HIDE 1.0 containers (added in 0.9.0)

| file | proves |
| --- | --- |
| `v1-signed.hide`, `v1-signed-confidential.hide` | the SIGNED flag (`0x01`, minor 1) and the HIDE/1.0 transcript, public and confidential placement |
| `grease.hide` | a reader skips an unknown recipient stanza and ignores unknown ignorable header (64–65535) and metadata extensions, and still opens |
| `grease-signed.hide` | the same, signed: the 1.0 transcript binds the unknown stanza and both extensions, and the signature verifies |
| `grease-minor.hide` | minor 7 is a non-breaking revision and opens exactly as minor 1 |

### Keys

| file | proves |
| --- | --- |
| `recipient.test-secret`, `recipient.test-public` | a 0.1.0 recipient key: this file *is* the X-Wing secret, not a master seed. It cannot be converted to a seed |
| `identity.test-seed`, `identity.test-public` | a 32-byte master seed and the recipient public key derived from it (spec §9.1) |
| `signer.test-seed`, `signer.test-public` | a HIDE-Sign seed and its 1984-byte verifying key (spec §8.2) |
| `signed.test-public` | the verifying key of the signed container vectors |

### Detached signatures (implementation-defined)

`hello.sig` and `empty.sig` are raw 3373-byte HIDE-Sign signatures by `signer.test-seed` over
`hello.txt` and the empty message under context `HIDE/0.5 vector`. Signing is deterministic, so they
must also reproduce byte for byte.

### Subsystems (`subsystems/`)

| files | proves |
| --- | --- |
| `identity-log.bin`, `identity-head.bin`, `identity-recovery.bin`, `identity-device-*.bin` | an identity log (spec §10) of four entries — create, enrol phone, enrol laptop, revoke laptop — framed as `array(7)`, replaying to the recorded head |
| `identity-log-legacy.bin` | the same log in the 0.6–0.8 six-item framing, which readers still accept and which re-encodes to `identity-log.bin` |
| `identity-tampered.bin`, `identity-tampered-legacy.bin` | the last byte flipped; refused at entry 3 |
| `epoch-chain.bin`, `epoch-public-key-1.bin` | a chain of three epochs (spec §11) and epoch 1's public key |
| `epoch-broken.bin` | one byte of epoch 1's key flipped; the chain is refused |
| `leaf.bin`, `tree-root.bin`, `inclusion-path.bin` | an RFC 6962 inclusion proof, entry 3 of 8 (spec §12) |
| `root-at-5.bin`, `consistency-path.bin` | a consistency proof from size 5 to size 8 |
| `other-leaf.bin`, `rewritten-root.bin` | a wrong leaf and a rewritten newer root; both refused |

### Rejections (`rejections/`)

Thirty files, each listed with its reason in [`rejections/rejections.txt`](rejections/rejections.txt).
Containers are refused with `recipient.test-secret`; `.test-secret` and `.test-public` files by their
key parser. Every rejection that needs an authentic header MAC is built with everything a recipient
controls recomputed, so it is refused for the stated reason and not by an incidental MAC failure.

| group | files |
| --- | --- |
| Preamble | `bad-magic`, `unsupported-major`, `minor-zero`, `unknown-flag`, `legacy-minor-with-flag`, `header-len-overflow` |
| Stream | `header-bit-flipped`, `final-record-bit-flipped`, `truncated-before-final`, `trailing-bytes-after-final`, `payload-salt-altered` |
| Header extensions and stanzas | `critical-header-key`, `header-key-over-u16`, `ignorable-ext-oversize`, `ignorable-ext-not-bstr`, `too-many-extensions`, `only-unknown-stanzas` |
| Signatures | `stripped-signature`, `unexpected-signature`, `two-signatures`, `unknown-signature-tag`, `signature-extension-rewritten`, `signature-unknown-stanza-removed`, `legacy-minor2-with-extension` |
| Metadata | `critical-metadata-key`, `reserved-metadata-key`, `filename-dotdot`, `non-canonical-metadata` |
| Keys | `small-order.test-public`, `argon2-memory.test-secret` |

## Running

Independent Node implementation (checks the manifest, every hash, every container and key vector,
and the subsystem vectors):

```powershell
cd conformance/node
pnpm install --ignore-workspace
node verify.mjs
```

It prints one `PASS` line per check, including
`manifest.json: 67 vectors, sha256 verified; …`, and exits non-zero on the first failure.

Rust:

```powershell
cargo test -p hide-object --test vectors      # containers, rejections, manifest hashes
cargo test -p hide-sign --test vectors        # signer keys and detached signatures
cargo test -p hide-identity --test vectors    # subsystem vectors
cargo run -p hide-object --features test-vectors --example generate_v1_vectors -- --check
cargo run -p hide-identity --example generate_subsystem_vectors   # check mode; writes nothing
```

The `--check` run exits non-zero if any HIDE 1.0 vector or `manifest.json` no longer matches what the
current code produces. CI runs the three vector tests (`test` job, as part of the workspace suite),
and `generate_v1_vectors -- --check` plus `node verify.mjs` (`interoperability` job).

To implement HIDE elsewhere: read `manifest.json`, verify each `sha256`, then open or refuse each
entry by `kind` and `expect`. Adding a rejection vector: `.github/skills/add-rejection-vector`.
