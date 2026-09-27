# HIDE 1 wire format — specification, release candidate (0.9.0)

## Status

This document specifies the HIDE 1 wire format as released in **0.9.0, the format release
candidate for 1.0**. The format is frozen from 0.9.0: it changes only if a security flaw forces a
change, and any such change is recorded in the change log (Appendix B) with the release that made
it. 1.0 ships once the criteria in [`docs/audit-status.md`](../docs/audit-status.md#road-to-10)
("Road to 1.0") are met. HIDE is experimental and has not been audited by a third party.

[`hide-0.1.md`](hide-0.1.md) is superseded by this document. Every container, key file and log it
describes (versions 0.1–0.8) remains readable under the rules below.

The key words MUST, MUST NOT, REQUIRED, SHALL, SHOULD, SHOULD NOT, MAY and OPTIONAL are to be
interpreted as described in RFC 2119 and RFC 8174 when, and only when, they appear in capitals.

### Conformance

An implementation is conformant only if all of the following hold:

- Every positive vector under `conformance/vectors/` opens, and its plaintext (and metadata, where
  recorded) is byte-identical to the recorded expectation. Signed vectors MUST also verify.
- Every file under `conformance/vectors/rejections/` is refused. An implementation that opens a
  rejection vector is non-conformant even if it opens every positive vector.
- The results agree with `conformance/vectors/manifest.json`, which lists every vector with its
  expected outcome:

```
{
  "format": "hide-vectors/1",
  "vectors": [
    {
      "path":   "<path relative to conformance/vectors/>",
      "kind":   "container" | "key" | "public-key" | "subsystem" | "detached-signature",
      "expect": "open" | "reject",
      "reason": "<short text; for rejections the refusal reason, as in rejections/rejections.txt>",
      "sha256": "<lowercase hex SHA-256 of the file bytes>"
    }
  ]
}
```

The top-level `"secret"` names the recipient key file most container vectors are sealed to;
`identity.hide` is sealed to the key derived from `identity.test-seed` (§9.1). Entries of kind
`detached-signature` cover an implementation-defined format (§14) and are informative: a consumer
verifies their hash and MAY skip them otherwise.

A consumer MUST verify `sha256` before using a vector, so a corrupted checkout fails loudly instead
of passing or failing for the wrong reason. `conformance/node/verify.mjs` is an independent
implementation that exercises both sets.

### Conventions

- Integers are big-endian. `u16be(x)`, `u32be(x)` and `u64be(x)` are 2, 4 and 8 bytes. `||` is
  concatenation. `len(x)` is a byte length.
- `SHA-256` is FIPS 180-4. `HKDF` and `HKDF-Expand` are RFC 5869 with SHA-256. `HMAC-SHA256` is
  RFC 2104. `AEAD` is ChaCha20-Poly1305 (RFC 8439): 32-byte key, 12-byte nonce, 16-byte tag
  appended to the ciphertext.
- **CBOR** means the deterministic subset of RFC 8949 §4.2: shortest-form heads, definite lengths,
  map keys in ascending order without duplicates, no tags, no floats, no simple values other than
  those a structure explicitly allows, no trailing data. Every CBOR decoder in this specification
  MUST re-encode the decoded value and reject the input if the bytes differ.
- Every length or count read from untrusted input MUST be checked against its limit (Appendix A.8)
  before any allocation or loop that depends on it. A decoder MUST NOT pre-allocate from a declared
  count.
- Labels are ASCII strings carried without a terminator. The `0.x` or `1.0` inside a label is part
  of an opaque byte string and is **not** a version field; labels are frozen exactly as spelled.

## Frozen vs implementation-defined

**Frozen.** The following are the HIDE 1 wire format. A change to any of them is a format change.

- The container (§1–§7): preamble, protected header, recipient and signature stanzas, key
  schedule, metadata, payload, both signature transcripts, including the read rules for legacy
  minor 2.
- HIDE-Sign (§8): key derivation, the signed payload framing, verification rules.
- Key files (§9): the unprotected 32-byte master seed, the protected key file (`HIDE-KEY`), the
  recipient public key file and the signing public key file.
- The identity log (§10): signed bytes, link, CBOR encoding and the legacy read rule.
- The epoch chain (§11).
- Transparency hashing and proof verification (§12).
- The MLS credential binding (§13).
- Every domain-separation label (Appendix A.7) and every registry in Appendix A.

**Implementation-defined (informative).** The following are produced by the reference CLI and
SDKs. They are described in §14 so other tools can interoperate with the reference implementation,
but they MAY change in any release without a format version:

- ASCII armor for messages and for public keys.
- The challenge format (`hide_sign::Challenge`).
- The detached-signature file (`<file>.hide-sig`).
- The epoch keystore file (`HIDE-EPK`). It is implementation-defined because it is never exchanged
  between parties: it holds one holder's secrets for that holder's own tool. Interoperability of
  epochs rests entirely on the epoch chain (§11), which is public and frozen; a container encrypted
  to an epoch names only the public key the chain records. No SDK, C ABI function or conformance
  vector consumes the keystore, so nothing outside the reference crate depends on its layout.
- CLI commands and flags, SDK and C ABI functions, and the text of error messages.

## 1. Container

```
container = preamble (16) || header || payload_salt (16) || record...
```

### 1.1 Preamble

All 16 bytes are covered by the header MAC (§3).

| offset | len | field | value | if violated |
|---|---|---|---|---|
| 0 | 8 | magic | `48 49 44 45 0D 0A 1A 0A` | not a HIDE container (InvalidContainer) |
| 8 | 1 | major | `0` | UnsupportedVersion |
| 9 | 1 | minor | `1`, `2` or `>= 3` | `0` → UnsupportedVersion |
| 10 | 1 | kind | `1` | UnsupportedFeature |
| 11 | 1 | flags | bit set, see below | unknown bit → UnsupportedFeature |
| 12 | 4 | header_len | `u32be`, `1 ..= 1048576` | HeaderTooLarge |

A decoder MUST check `header_len` before reading or allocating the header.

**Minor.** The minor is a **non-breaking revision** number:

- `1` — HIDE/1.x. Writers of 1.0 MUST write `1`.
- `>= 3` — HIDE/1.x. A reader MUST accept any minor `>= 3` and process the container exactly as
  minor `1`. The minor byte is still part of the MAC input and of the 1.0 transcript, so it cannot
  be altered undetected.
- `2` — **legacy signed** (HIDE/0.5 through 0.8), read-only (§7.4). Minor `2` is valid only with
  `flags == 0`; minor `2` with any flag bit set MUST be rejected as UnsupportedFeature. Writers MUST
  NOT write minor `2`.
- `0` — MUST be rejected as UnsupportedVersion.

**Flags.** Every bit is **critical**: a reader that does not know a set bit MUST refuse the
container (UnsupportedFeature) rather than ignore it.

| bit | name | meaning |
|---|---|---|
| `0x01` | SIGNED | the container carries exactly one signature under the 1.0 transcript (§7) |
| `0x02`–`0x80` | reserved | MUST be zero; a set bit → UnsupportedFeature |

The container is **signed** iff `minor == 2` or `flags & 0x01`.

An unsigned HIDE 1 container without extensions (minor `1`, flags `0`, no header or metadata
extension keys, only X-Wing stanzas) is byte-identical in structure to HIDE/0.1 and opens in every
0.x reader. Readers of 0.1–0.8 refuse a container with flags `0x01` and refuse extension keys, so a
signed HIDE 1 container does not open in them.

### 1.2 Records and salt

`payload_salt` is 16 random bytes. The records follow (§5). No bytes may follow the FINAL record.

## 2. Protected header

```
header    = [ protected: bstr, header_mac: bstr(32) ]          # CBOR array(2)
protected = CBOR map, encoded as a bstr in header:
            { 1: suite,                # uint, MUST be 1
              2: object_id,            # bstr(32)
              3: [ stanza ... ],       # array, 1 ..= 64 items
              4: encrypted_metadata,   # bstr, 16 ..= 262144 + 16
              5: [ signature ... ],    # array, 0 ..= 1 items
              ? ext_key: ext_value ... }
```

The `header_len` bytes MUST decode as exactly this array. The exact `protected` bytes are
authenticated; a decoder MUST NOT re-serialize them for verification. It MUST still re-encode the
decoded map and reject non-canonical bytes (§Conventions).

Keys `1`–`5` are REQUIRED and appear in that order. An unsigned header, and a header whose
signature is confidential, encodes `5: []`. `suite != 1` → UnsupportedSuite. `object_id` is 32
random bytes, never a hash of the plaintext.

### 2.1 Header extension keys

Further keys follow key 5 in strictly ascending order:

| range | class | rule |
|---|---|---|
| `6 ..= 63` | critical | HIDE 1 assigns none. Present → UnsupportedFeature |
| `64 ..= 65535` | ignorable | value MUST be a bstr of at most 65536 bytes; at most 16 such keys per header |
| `> 65535` | invalid | MalformedHeader |

A non-bstr ignorable value, an oversize value, or more than 16 ignorable keys → MalformedHeader.
A reader that does not understand an ignorable key MUST ignore its meaning but MUST keep its exact
bytes: it is authenticated by the header MAC (it is inside `protected`) and bound into the 1.0
signature transcript. Writers of 1.0 MUST NOT emit extension keys; they exist so a later 1.x can add
optional data that 1.0 readers open.

### 2.2 Recipient stanzas

```
stanza = [ tag: uint, field: bstr ... ]     # CBOR array of 1 ..= 8 items
```

- `tag` MUST be in `1 ..= 65535`; `0` or `> 65535` → MalformedHeader. Every item after the tag
  MUST be a bstr of at most 65536 bytes, else MalformedHeader.
- **Tag 1, X-Wing:** MUST be exactly `[ 1, encapsulation: bstr(1120), wrapped_cek: bstr(48) ]`;
  any other shape → MalformedHeader.
- **Any other tag is unknown:** it is decoded, retained for canonical re-encoding and for the
  signature transcript, and **skipped** when searching for a CEK.
- The limit of 1 to 64 stanzas counts unknown stanzas.
- If no stanza yields a CEK that verifies the header MAC — including when every stanza is unknown —
  the result is NoMatchingRecipient.

Stanzas carry no recipient identifier. A reader trial-decapsulates each X-Wing stanza and accepts a
candidate CEK only after the header MAC verifies (§3).

A sender MUST reject a recipient public key whose X25519 component is one of the seven small-order
encodings listed in §9.5. Such a point yields an all-zero X25519 shared secret, which would leave
the hybrid resting on ML-KEM alone.

### 2.3 Signature stanzas

```
signature = [ 1, verifying_key: bstr(1984), signature: bstr(3373) ]
```

Any other tag or shape MUST be rejected (UnsupportedFeature); signature stanzas are never skipped.
Key 5 holds 0 or 1 of them; a second stanza MUST be rejected rather than skipped, because a
recipient could otherwise append stanzas that nobody checks. Placement and verification are §7.

## 3. Key schedule

Unchanged since HIDE/0.1. The labels keep their `HIDE/0.1` spelling because they are frozen opaque
strings.

```
info = "HIDE/0.1 object-key" || object_id || u16be(suite)
aad  = object_id || u16be(suite)
wrapped_cek = HPKE-Seal(recipient_public, info, aad, CEK)
              # RFC 9180 base mode; KEM X-Wing (0x647A), KDF HKDF-SHA256, AEAD ChaCha20-Poly1305

K(label, salt) = HKDF-SHA256(IKM = CEK, salt, info = label, L = 32)
metadata_key   = K("HIDE/0.1 metadata",   object_id)
header_mac_key = K("HIDE/0.1 header-mac", object_id)
payload_key    = HKDF-SHA256(IKM = CEK, salt = payload_salt,
                             info = "HIDE/0.1 payload" || object_id, L = 32)
header_mac     = HMAC-SHA256(header_mac_key, preamble || protected)
```

`CEK` is 32 random bytes. Each derived key has exactly one purpose, so the fixed all-zero metadata
nonce is safe. The header MAC MUST be compared in constant time.

## 4. Metadata

```
encrypted_metadata = AEAD-Seal(metadata_key, nonce = 0^12,
                               aad = "HIDE/0.1 metadata" || object_id || u16be(suite),
                               plaintext = metadata)
metadata = CBOR map, at most 262144 bytes:
           { ? 1: filename,     # tstr, 1 ..= 255 bytes
             ? 2: media_type,   # tstr, <= 255 bytes
             ? 3: signature,    # §2.3 shape, confidential placement (§7)
             ? ext_key: ext_value ... }
```

Key rules, in ascending key order:

| key | rule |
|---|---|
| `1`, `2`, `3` | as above; any other value type or an oversize string → InvalidMetadata |
| `4`, `5` | reserved core keys → UnsupportedFeature |
| `6 ..= 63` | critical, none assigned → UnsupportedFeature |
| `64 ..= 65535` | ignorable: value MUST be a bstr of at most 65536 bytes, at most 16 such keys |
| `> 65535` | invalid |

Ignorable metadata keys are part of `metadata_base` (§7.2) and therefore signed. The 262144-byte
metadata limit applies to the whole map, extensions included. Writers of 1.0 MUST NOT emit
extension keys.

**Filename.** A filename MUST be a single portable path component. It MUST be rejected if it:

- is empty or longer than 255 bytes;
- is exactly `.` or `..`;
- ends with `.` or ` ` (space);
- contains a control character or any of `<` `>` `:` `"` `/` `\` `|` `?` `*`;
- has, before its first `.`, a Windows reserved stem (case-insensitive): `CON`, `PRN`, `AUX`,
  `NUL`, `COM1`–`COM9`, `LPT1`–`LPT9`.

Dots are otherwise allowed anywhere, so `hello.txt` and `.profile` are valid.

**A decrypting application MUST treat the filename as untrusted** and MUST NOT use it to choose an
output path.

## 5. Payload

```
record = kind(1) || ciphertext_len(u32be) || ciphertext
kind:  1 = DATA   plaintext exactly 65536 bytes
       2 = FINAL  plaintext 1 ..= 65536 bytes, or 0 bytes only when it is the sole record
ciphertext_len  in 16 ..= 65552   (plaintext + 16-byte tag)

nonce = 0x000000 || u64be(counter) || (kind == FINAL ? 0x01 : 0x00)
aad   = "HIDE/0.1 chunk" || object_id || SHA-256(protected)
        || u64be(counter) || kind || u32be(plaintext_len)
ciphertext = AEAD-Seal(payload_key, nonce, aad, plaintext)
```

`counter` starts at 0 and increases by 1 per record; at most 2^32 records. Exactly one FINAL
record ends the object and no bytes may follow it. An unknown `kind`, an out-of-range length, a
missing FINAL (TruncatedPayload) or trailing bytes (TrailingData) MUST be rejected.

A decryptor MUST NOT publish plaintext until FINAL authenticates — and, for a signed container,
until the signature verifies (§7.3). Plaintext goes to private staging and is committed atomically.

## 6. Security notes and error handling

Authenticated against non-recipients: the whole preamble (including minor and flags), suite,
object id, every recipient stanza including unknown ones, header extensions, metadata including its
extensions, chunk order and count, and end-of-stream.

The header MAC key is derived from the CEK, which every recipient holds, so any recipient can
rewrite the stanza list of an **unsigned** container and recompute a valid MAC. A signature (§7)
binds the stanzas, extensions, metadata and plaintext and closes this.

The 16-byte `payload_salt` is outside every authenticator; altering it changes the payload key so
every record fails to open — a denial of service and nothing more.

Not provided: identity binding, forward secrecy (except by epoch erasure, §11), recipient anonymity
against traffic analysis, hiding of file size or recipient count. A signature attests to a key, not
to a person.

### 6.1 Error handling

Implementations MUST distinguish:

- **malformed** input — a limit exceeded, non-canonical CBOR, a wrong length or shape
  (MalformedHeader, NonCanonical, InvalidMetadata, HeaderTooLarge, InvalidContainer);
- **unsupported** input — a version, kind, suite, flag or critical key this reader does not
  implement (UnsupportedVersion, UnsupportedFeature, UnsupportedSuite);
- **authentication failure** — a header MAC, AEAD tag or signature that does not verify.

The first is a producer bug, the second a version mismatch, the third possibly an attack.
Implementations MUST NOT report *which* recipient stanza failed to decapsulate, nor whether a
stanza decapsulated but the header MAC then failed: every non-recipient outcome is the single
result NoMatchingRecipient.

## 7. Signatures

A signature is HIDE-Sign (§8): hybrid Ed25519 + ML-DSA-65, 1984-byte verifying key, 3373-byte
signature. Both halves MUST verify.

### 7.1 Placement

A signed container carries exactly one signature, in exactly one place:

- **Public** — in `protected` key 5. Readable by anyone holding the file; it discloses the signer
  to storage providers and network observers.
- **Confidential** — in metadata key 3. Readable only by those who can already decrypt.

### 7.2 HIDE 1.0 transcript (flags & SIGNED)

```
context = "HIDE/1.0 container"

message = "HIDE/1.0 transcript"
       || preamble[0 .. 12]                           # magic(8) major minor kind flags
       || u16be(suite)
       || object_id(32)
       || u64be(stanza_count)
       || for each stanza, in wire order:
              u64be(tag)
           || u64be(field_count)                      # number of bstr items after the tag
           || for each field: u64be(len(field)) || field
       || u64be(header_ext_count)
       || for each header extension, ascending key:
              u16be(key) || u64be(len(value)) || value
       || u64be(len(metadata_base)) || metadata_base
       || SHA-256(plaintext)
       || u64be(plaintext_len)

signature = HIDE-Sign(identity, context, message)    # §8.3
```

- `header_len` (preamble bytes 12–16) is excluded: it depends on whether the signature is in the
  header.
- Key 5's contents are excluded: a signature cannot cover itself.
- `metadata_base` is the metadata map encoded canonically **without** key 3 and **with** every
  metadata extension key. For a publicly signed container it is the metadata as transmitted.
- The X-Wing stanza is `u64be(1) || u64be(2) || u64be(1120) || encapsulation || u64be(48) ||
  wrapped_cek`.

The plaintext hash is mandatory. Every recipient holds the CEK and the payload salt is in the
clear, so a recipient can re-encrypt arbitrary content under an unchanged header with every AEAD
tag valid. Binding `SHA-256(plaintext)` is what makes a signature mean "this signer produced this
content" rather than "this signer addressed these recipients".

The metadata is bound as plaintext rather than as ciphertext because sealing is randomised and the
confidential placement reseals after signing, so the ciphertext a verifier holds is not the one
that existed at signing time.

### 7.3 Verifier obligations

A verifier MUST reject the object — not merely report an unverified signature — when any of the
following holds:

| condition | result |
|---|---|
| the signature does not verify (either half) | InvalidSignature |
| signed (minor 2, or flags 0x01) but no signature in key 5 or metadata key 3 — **stripped** | reject |
| a signature in key 5 or metadata key 3 but not signed (minor 1 or `>= 3`, flags 0) — **unexpected** | reject |
| a signature in both key 5 and metadata key 3 | InvalidSignature |
| more than one stanza in key 5 | reject (§2.3) |
| minor 2 with any header extension, metadata extension or unknown recipient stanza | MalformedHeader |

Verification needs the plaintext hash and so completes only after FINAL. Plaintext MUST NOT be
published until both FINAL and the signature have verified.

### 7.4 Legacy transcript (minor 2, read-only)

A minor-2 container is signed with the HIDE/0.5 transcript. It MUST have `flags == 0`, MUST carry
exactly one signature (key 5 or metadata key 3), and MUST NOT carry header extensions, metadata
extensions or unknown recipient stanzas, because this transcript does not bind them
(MalformedHeader).

```
context = "HIDE/0.5 container"

message = "HIDE/0.5 transcript"
       || 0x0001                                       # suite, u16be
       || object_id(32)
       || u64be(recipient_count)
       || for each stanza, in wire order: encapsulation(1120) || wrapped_cek(48)
       || u64be(len(metadata_base)) || metadata_base   # metadata without key 3
       || SHA-256(plaintext)
       || u64be(plaintext_len)

signature = HIDE-Sign(identity, context, message)
```

The legacy transcript does not bind the preamble; minor 2 itself is the signal that a signature is
required. Writers MUST NOT produce it.

## 8. HIDE-Sign

HIDE-Sign is a hybrid signature: Ed25519 (RFC 8032, pure, no prehash) and ML-DSA-65 (FIPS 204). A
signature is valid only if both component signatures are valid.

### 8.1 Sizes

```
SEED_LENGTH          = 32
verifying_key (1984) = ed25519_public(32)    || ml_dsa65_public(1952)
signature     (3373) = ed25519_signature(64) || ml_dsa65_signature(3309)
```

### 8.2 Key derivation

A signing identity is a 32-byte signing seed `s`, used directly as the HKDF PRK (no Extract):

```
ed_seed = HKDF-Expand(PRK = s, info = "HIDE/0.5 identity ed25519",   L = 32)
ml_seed = HKDF-Expand(PRK = s, info = "HIDE/0.5 identity ml-dsa-65", L = 32)
          # for L = 32 each equals HMAC-SHA256(s, info || 0x01)

ed25519 key pair   = RFC 8032 §5.1.5 with secret key ed_seed
ml-dsa-65 key pair = FIPS 204 ML-DSA.KeyGen_internal(xi = ml_seed)
```

The signing seed of a HIDE identity is derived from the master seed (§9.1). A signing seed MUST NOT
be used as a master seed or vice versa.

### 8.3 Signing

```
payload   = u64be(len(context)) || context || message
ed_sig    = Ed25519.Sign(ed_key, payload)
ml_sig    = ML-DSA-65.Sign(ml_key, payload, ctx = "")   # FIPS 204 Alg. 2, deterministic (rnd = 0^32)
signature = ed_sig || ml_sig
```

- The HIDE context is bound only through `payload`. The FIPS 204 `ctx` MUST be empty;
  implementations MUST NOT pass the HIDE context as `ctx`. The HIDE context has no length limit of
  its own.
- Signing is deterministic. A signer MAY use the hedged FIPS 204 variant; the result verifies, but
  frozen signature vectors use the deterministic variant and a test that reproduces them MUST too.

### 8.4 Verification

Given `(verifying_key, context, message, signature)`, a verifier:

1. MUST reject unless `len(verifying_key) == 1984` and `len(signature) == 3373`.
2. Splits both at the Ed25519 boundary and computes `payload` as in §8.3.
3. Verifies the Ed25519 half **strictly**: it MUST reject a small-order or non-canonical `A`, a
   small-order or non-canonical `R`, and `S >= L`, and MUST use the cofactorless equation
   `[S]B = R + [k]A`.
4. Decodes the ML-DSA signature per FIPS 204 `sigDecode`; a decoding failure counts as a failed
   half, not as malformed input. Verifies with `ctx = ""`.
5. MUST evaluate both halves before deciding, and MUST report one failure that does not say which
   half failed.

Every 1952-byte string parses as an ML-DSA-65 public key, and an Ed25519 point that fails
decompression may be refused at parse time or at verification; either way no signature under such a
key may be accepted. Tests MUST assert "validates nothing", not "fails to parse".

### 8.5 Contexts

Every context this specification uses is listed in Appendix A.7. Because `payload` length-prefixes
the context, distinct contexts never produce the same `payload`. Context strings beginning with the
ASCII bytes `HIDE/` are reserved for this specification. An implementation that exposes a
general-purpose sign-with-context API SHOULD refuse a caller-supplied context in that prefix
(§15.2).

## 9. Key files

### 9.1 Master seed and derived keys

A HIDE identity is a 32-byte master seed `m` from the OS CSPRNG:

```
recipient_seed = HKDF-Expand(PRK = m, info = "HIDE/0.5 identity encryption", L = 32)
signing_seed   = HKDF-Expand(PRK = m, info = "HIDE/0.5 identity signing",    L = 32)
```

`recipient_seed` is the 32-byte X-Wing private key in seed form (draft-connolly-cfrg-xwing-kem),
expanded by X-Wing itself. `signing_seed` is `s` of §8.2. Neither is computable from the other
without `m`.

### 9.2 Unprotected key file

Exactly 32 bytes, equal to `m`. A reader MUST interpret a 32-byte key file that does not begin with
the protected-file magic as a master seed and MUST derive per §9.1.

*Legacy (0.1.0–0.4.x):* a 32-byte file was the X-Wing `recipient_seed` itself. Such files are
indistinguishable from a master seed; a reader MUST NOT try to detect them. Reading one as a master
seed yields a different key, which is the specified behaviour. The frozen vector
`conformance/vectors/recipient.test-secret` is such a legacy key and is consumed only through the
X-Wing seed path.

### 9.3 Protected key file

```
offset len  field
0      8    magic        "HIDE-KEY"  (48 49 44 45 2D 4B 45 59)
8      1    version      0x02        (0x01 legacy)
9      1    parallelism  u8
10     4    memory_kib   u32be
14     4    iterations   u32be
18     16   salt
34     12   nonce
46     1    purpose      (version 2 only)
47     32   ciphertext
79     16   tag
            total 95 bytes; version 1 has no purpose byte: 94 bytes, ciphertext at offset 46

header = every byte before the ciphertext      # 47 bytes (v2), 46 bytes (v1)
kek    = Argon2id(password = UTF-8(passphrase), salt, t = iterations, m = memory_kib,
                  p = parallelism, version = 0x13, tag length = 32)    # RFC 9106, no secret, no AD
ciphertext || tag = AEAD-Seal(kek, nonce, aad = header, plaintext = seed(32))
```

| purpose | meaning | plaintext |
|---|---|---|
| `0x01` | Identity | master seed `m` (§9.1) |
| `0x02` | Encryption-only | X-Wing `recipient_seed` |
| other | malformed | |

Version 1 is always Encryption-only.

**Writers** MUST emit version 2 with `parallelism = 1`, `memory_kib = 19456`, `iterations = 2`, a
fresh random salt and nonce, SHOULD emit purpose `0x01`, MUST refuse a passphrase shorter than 8
Unicode scalar values, and MUST NOT emit version 1.

**Readers**, in this order and before any Argon2 work:

1. magic mismatch → not a key file;
2. version not in {1, 2} → unsupported version;
3. length ≠ 95 (v2) or 94 (v1) → malformed;
4. parameters outside §9.4 → unreasonable parameters;
5. v2 purpose not in {1, 2} → malformed;
6. derive `kek`, AEAD-Open with `aad = header`; failure → the single error "wrong passphrase or
   modified file".

Asked for an encryption key, a reader derives `recipient_seed` from an Identity file. Asked for a
signing key from an Encryption-only file, it MUST refuse. An API that demands an Encryption-only
file MUST refuse an Identity file by purpose rather than silently derive.

### 9.4 Argon2 parameter bounds

```
MIN_MEMORY_KIB = 8192      MAX_MEMORY_KIB = 262144
MIN_ITERATIONS = 1         MAX_ITERATIONS = 64
parallelism in 1 ..= 4     memory_kib / 8 >= parallelism
```

A reader MUST reject anything outside these bounds before allocating. The header is authenticated,
so the bounds do not protect an honest file; they bound the cost of a hostile one.

### 9.5 Recipient public key file

Exactly 1216 bytes: `ML-KEM-768 public(1184) || X25519 public(32)`. A reader MUST reject any other
length and MUST reject a key whose X25519 component (bytes 1184..1216) equals one of these seven
32-byte encodings:

```
0000000000000000000000000000000000000000000000000000000000000000
0100000000000000000000000000000000000000000000000000000000000000
e0eb7a7c3b41b8ae1656e3faf19fc46ada098deb9c32b1fd866205165f49b800
5f9c95bca3508c24b1d0b1559c83ef5b04445cc4581c8e86d8224eddd09f1157
ecffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f
edffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f
eeffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f
```

The comparison is on the raw bytes (§15.7).

### 9.6 Signing public key file

Exactly 1984 bytes, the §8.1 verifying key.

## 10. Identity logs

An identity is an ordered, hash-linked, public log of events.

### 10.1 Events

| tag | event | payload | label |
|---|---|---|---|
| 1 | Create | device verifying key (1984) | UTF-8, <= 256 bytes |
| 2 | Enrol | device verifying key (1984) | UTF-8, <= 256 bytes |
| 3 | Revoke | device id (32) | MUST be empty |
| 4 | Recover | device verifying key (1984) | UTF-8, <= 256 bytes |

```
device_id(key) = SHA-256("HIDE/0.6 device id" || key(1984))
```

### 10.2 Signed bytes, signature and link

For entry *n* with predecessor link `previous` (32 zero bytes for *n* = 0):

```
signed = previous(32) || u64be(sequence) || tag(1) || signer(32) || fields
fields = u64be(len(payload)) || payload || u64be(len(label)) || label   # tags 1, 2, 4
       | u64be(32) || device_id(32)                                     # tag 3, no label field

signature = HIDE-Sign(author_key, context = "HIDE/0.6 identity entry", message = signed)

link = SHA-256("HIDE/0.6 identity link"
               || u64be(len(signed))    || signed
               || u64be(len(signature)) || signature)
```

`signer` is the device id of the signing key; for Recover it is `device_id(recovery_key)`. The head
of a log is the link of its last entry. `previous` is inside the signed bytes, so an entry cannot be
transplanted into another log or reordered.

### 10.3 Wire encoding

```
log   = [ entry ... ]                  # CBOR array, 0 ..= 100000 entries
entry = [ sequence:  uint,
          tag:       uint (1 ..= 4),
          payload:   bstr,
          label:     tstr,             # "" for Revoke
          signer:    bstr(32),
          link:      bstr(32),
          signature: bstr(3373) ]      # array head MUST declare 7
```

**Legacy framing (read-only).** Versions 0.6–0.8 wrote each entry with an array head declaring 6
items (`0x86`) followed by the same 7 items. Neither signatures nor links cover the framing, so a
reader MUST accept such a log, subject to:

- The first entry's head selects the framing for the whole log. A head that is neither 7 nor 6, or
  a log mixing both, MUST be rejected as malformed.
- The canonical re-encoding check is performed in the input's own framing.
- Writers MUST emit the 7-item head. Re-serialising a legacy log yields 7-item heads; the bytes
  differ, the head link does not.

Decoder rejections (malformed unless stated): declared count > 100000 (too many entries); label
declared longer than 256 bytes (label too long, checked before copying); unknown tag; Revoke payload
≠ 32 bytes; `signer` or `link` ≠ 32 bytes; `signature` ≠ 3373 bytes; trailing bytes; non-canonical
encoding, including a non-empty Revoke label. A decoder MUST NOT pre-allocate beyond
`len(input) / 8` entries.

### 10.4 Verification (replay)

A verifier holds the log and the identity's recovery verifying key, obtained out of band. It MUST:

1. Reject an empty log and a log of more than 100000 entries.
2. Reject unless entry 0 is Create.
3. For each entry *i*, in order, with `previous` = link of entry *i−1* (zero for *i* = 0):
   1. `sequence == i`, else out of order.
   2. label <= 256 bytes.
   3. Recompute `signed` and `link`; `link` MUST equal the encoded link, else broken link.
   4. Determine the permitted author from the membership **as it stands before this entry**:
      - Create: `sequence == 0` (else bad root); payload 1984 bytes; `signer == device_id(payload)`,
        else unauthorised. Author = payload key.
      - Recover: `signer == device_id(recovery_key)`, else unauthorised. Author = recovery key.
      - Enrol, Revoke: `signer` MUST be currently trusted, else unauthorised. Author = that
        device's recorded key.
   5. Verify `signature` under the author key (§8.4), else bad signature.
   6. Apply:
      - Create: trust `device_id(payload)`.
      - Enrol: payload 1984 bytes; reject if its id is already trusted; trust it. A previously
        revoked device MAY be re-enrolled; its revocation record is cleared.
      - Revoke: reject if the id is not trusted, or if it is the only trusted device; untrust it
        and record the revoking sequence. A device MAY revoke itself.
      - Recover: mark every trusted device revoked at this sequence, clear the set, trust
        `device_id(payload)`.
4. The trusted set after the last entry is the identity's **membership**.

A payload key of the right length that fails to parse is reported as a bad signature. Authority is
evaluated at the entry's position, never against the final state: a revoked device cannot re-enrol
itself, revoke the device that removed it, or author anything after its removal. Revocation is not
retroactive; entries signed before it remain valid.

## 11. Epoch chains

An epoch chain publishes one X-Wing public key per epoch, hash-linked in order. Each epoch secret
MUST be independent CSPRNG output, never derived from a master seed; otherwise anyone who later
obtained the seed could reconstruct erased epochs.

```
link_n = SHA-256("HIDE/0.6 epoch chain" || previous(32) || u64be(n)
                 || u64be(len(public_key)) || public_key)        # previous = 0^32 for n = 0

chain  = [ [ number: uint, public_key: bstr, link: bstr(32) ] ... ]   # CBOR
```

Decoding MUST reject: declared count > 1000000; an item head other than `array(3)`; `link` ≠ 32
bytes; trailing bytes; non-canonical encoding. It MUST NOT pre-allocate beyond `len(input) / 4`
records.

Verification is separate from decoding and a consumer MUST run both. It MUST reject: more than
1000000 records; record *i* with `number != i`; `public_key` ≠ 1216 bytes; a recomputed link that
differs. A sender encrypting to epoch *n* MUST also apply §9.5 to `public_key`.

The head of a chain is its last link (zero for an empty chain). Destroying an epoch's secret makes
every container written to that epoch permanently unreadable by everyone; the chain still proves the
epoch existed and where it sat, which distinguishes "erased" from "never existed".

## 12. Transparency

Merkle tree hashing is RFC 6962 §2.1 with SHA-256:

```
MTH({})        = SHA-256("")
leaf_hash(d)   = SHA-256(0x00 || d)
node_hash(l,r) = SHA-256(0x01 || l || r)
MTH(D[n])      = node_hash(MTH(D[0:k]), MTH(D[k:n])),  k = 2^floor(log2(n - 1)),  n > 1
```

`k` MUST be computed from the bit length of `n − 1`, never by a loop over values.

**Checkpoint** (40 bytes): `u64be(size) || root(32)`. Any other length is malformed.

**Inclusion proof** `(index, size, path)` and **consistency proof** `(old_size, new_size, path)`:
`path` is a sequence of 32-byte hashes in RFC 6962 §2.1.1 / §2.1.2 order; the integers are u64.

Inclusion verification MUST: reject `len(path) > 64` before any work; reject `index >= size`; derive
the left/right turns by descending from `(index, size)` with the split rule; reject unless
`len(path)` equals the number of turns; fold the path from the leaf using the turns in reverse; and
compare with the root.

Consistency verification MUST: reject `len(path) > 64`; reject `old_size == 0` or
`old_size > new_size`; if `old_size == new_size`, accept iff `path` is empty and the roots are equal;
otherwise descend while `old != new` (if `old <= k` go left and set `new := k`; else go right, set
`old -= k`, `new -= k` and mark the old tree incomplete), require
`len(path) == turns + (incomplete ? 1 : 0)`, seed both accumulators with `old_root` (complete) or
the first path element (incomplete), fold the remaining path so left turns extend only the new
accumulator and right turns extend both, and accept iff both accumulators equal their roots.

Every loop is bounded by the bit width of its u64 inputs (at most 65 iterations). Neither proof
detects a split view; no witnessing is specified (§15.3).

## 13. MLS credential binding

Group messaging uses MLS (RFC 9420) unchanged with cipher suite
`MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519` (0x0001), which is classical. HIDE specifies only
the credential.

```
credential_type = 0xF01D                                 # RFC 9420 §17.5 private use
credential.data = device_id(32) || verifying_key(1984) || signature(3373)   # 5389 bytes, no framing

message   = device_id(32) || signature_key     # LeafNode.signature_key, raw, no length prefix
signature = HIDE-Sign(device_key, context = "HIDE/0.7 mls binding", message)
```

A validator MUST reject a roster entry or external sender unless all hold:

1. The credential type is `0xF01D` and `len(data) == 5389`.
2. `verifying_key` parses (§8.4).
3. `device_id == SHA-256("HIDE/0.6 device id" || verifying_key)`.
4. `signature` verifies over `message` built from **this** LeafNode's `signature_key`.
5. `device_id` is in the membership (§10.4) the validator holds.
6. The verifying key that membership records for the device equals `verifying_key`.

A successor credential is acceptable only if predecessor and successor both satisfy 1–3 and name the
same `device_id`; the successor leaf MUST additionally pass 4–6. The MLS identity of a member is its
`device_id`. A wire message larger than 1048576 bytes MUST be refused before it reaches the MLS
parser. Revoking a device in the identity log does not remove it from a group; a client MUST check
senders and the roster against the current membership.

## 14. Implementation-defined formats (informative)

Not frozen. Described as the reference implementation produces them in 0.9.0.

### 14.1 Detached file signature

`<file>.hide-sig`, 5357 bytes:

```
file      = verifying_key(1984) || signature(3373)
message   = "HIDE/0.5 detached-file" || SHA-256(file_bytes) || u64be(len(file_bytes))
signature = HIDE-Sign(context = "HIDE/0.5 detached", message)
```

The embedded key is informational; the CLI compares it with the key the user supplies and refuses
on mismatch before verifying.

### 14.2 Challenge

```
challenge = nonce(32) || u64be(len(audience)) || audience(UTF-8) || u64be(issued_at) || u64be(valid_for)
answer    = HIDE-Sign(context = "HIDE/0.5 challenge", challenge)
```

Decoding rejects truncation, trailing bytes and a non-UTF-8 audience. `expires_at = issued_at +
valid_for` (saturating). A verifier rejects when `now > expires_at`, then verifies, then rejects a
nonce it has already accepted.

### 14.3 ASCII armor

Message: `----- BEGIN HIDE MESSAGE -----` LF, padded standard base64 (RFC 4648 §4) of a container in
76-column lines, `----- END HIDE MESSAGE -----` LF. Readers skip text before the header line, trim
whitespace, and accept at most 1 MiB.

Public key: `hide-public-key:` then LF-separated 64-column standard base64 lines and a final LF.
The reader drops empty lines and lines starting with `hide-public-key:` and concatenates the rest.

### 14.4 Epoch keystore

One passphrase-sealed file holding the epoch secrets (§11) its holder still has.

```
offset len       field
0      8         magic        "HIDE-EPK"  (48 49 44 45 2D 45 50 4B)
8      1         version      0x01
9      1         parallelism  u8
10     4         memory_kib   u32be
14     4         iterations   u32be
18     16        salt
34     32        chain_head   §11 head of the chain the secrets belong to
66     4         body_len     u32be
70     body_len  body         CBOR, below
70+b   12        trailer_nonce
82+b   16        trailer_tag

header = bytes[0 .. 70]
body   = [ [ number: uint, nonce: bstr(12), sealed: bstr(48) ] ... ]   # strictly ascending number

kek         = Argon2id(passphrase, salt, params)                         # as §9.3
sealed_i    = AEAD-Seal(kek, nonce_i, aad = header || u64be(number_i), recipient_seed_i(32))
trailer_tag = AEAD-Seal(kek, trailer_nonce, aad = header || body, plaintext = "")
```

Limits: 65536 entries; body <= 4784133 bytes; file <= 4784231 bytes. Writers use a fresh salt per
seal, fresh nonces per entry and for the trailer, the §9.3 writer parameters and the 8-character
passphrase minimum. Readers check, before any Argon2 work: magic, file length, version, minimum
length 98, §9.4 bounds, `body_len`, total length `70 + body_len + 28`, and the body (count, shapes,
ascending numbers, canonical encoding). Then they verify the trailer before opening any entry. On
restore, `chain_head` MUST equal the supplied chain's head and every opened seed MUST produce the
public key the chain records for its epoch number. Erasing an epoch means resealing without it.

## 15. Known limitations of the 1.0 freeze

Each item is a property of the frozen format as specified above.

### 15.1 The recovery key is not committed in the log

Create names only the founding device; nothing in the log commits to the recovery key. Anyone can
take an identity log, append a Recover signed by a key they control, and present the result with
that key as the "recovery key"; it replays cleanly (§10.4). Only a recovery key pinned out of band
prevents this. Because the Create layout is frozen, the log alone can never establish which recovery
key is genuine.

### 15.2 Generic signing APIs accept reserved contexts

The reference C ABI (`hide_sign_message`) and the SDK sign-with-context functions accept any
context, including `HIDE/0.6 identity entry`, `HIDE/0.7 mls binding` and `HIDE/1.0 container`. A
party that can make a key holder sign a chosen context and message through such an API obtains an
identity-log entry, an MLS binding or a container signature under that key. The context reservation
of §8.5 is a SHOULD and is not enforced by the reference implementation in 0.9.0.

### 15.3 Transparency is algorithms only

§12 freezes hashing and proof verification. It does not define which bytes form a leaf (no leaf
encoding for identity logs or epoch chains), gives no byte encoding for a proof (the C ABI and WASM
take `path` as concatenated hashes and the integers as separate arguments), and checkpoints are
unsigned. Two implementations can therefore agree on every proof and still log different leaves for
the same identity, and a checkpoint says nothing about who published it. Split views are not
detected.

### 15.4 Epoch chains are not bound to an identity

Nothing signs a chain or its head, and nothing ties a chain to an identity log. Anyone can publish a
well-formed chain for any recipient; a sender that obtains a chain from an untrusted source may
encrypt to keys the recipient never held.

### 15.5 Passphrases are not normalised

The Argon2 password is the raw UTF-8 of the passphrase with no Unicode normalisation. The same
passphrase entered in NFC on one platform and NFD on another derives different keys, and the key
file does not open.

### 15.6 Label spellings are frozen as opaque strings

Every label keeps the spelling of the release that introduced it (`HIDE/0.1 …`, `HIDE/0.5 …`,
`HIDE/0.6 …`, `HIDE/0.7 …`, `HIDE/1.0 …`). They are byte strings, not version indicators. Renaming
any of them is a wire change.

### 15.7 Small-order rejection is by encoding

§9.5 compares the X25519 component against seven specific byte strings. Non-canonical encodings of
the same points (top bit set, or values `>= p`) are not rejected by that rule.

### 15.8 MLS membership is a snapshot

The reference MLS validator checks the membership it was constructed with. "Current membership" in
§13 is that snapshot; a long-lived client does not observe later revocations until it is rebuilt.
The reference successor check compares device ids only and relies on the MLS library invoking
member validation on the successor leaf for items 4–6.

### 15.9 Re-serialised legacy logs change bytes

A legacy (6-item head) identity log re-serialised by a 1.0 writer yields different bytes with the
same head link. Anything that hashes an encoded log rather than its head link sees two values for
one log.

## Appendix A. Registries

### A.1 Protected header keys

| key | name | status |
|---|---|---|
| 1 | suite | required |
| 2 | object_id | required |
| 3 | recipient stanzas | required |
| 4 | encrypted_metadata | required |
| 5 | public signatures | required (may be empty) |
| 6–63 | — | critical, reserved; present → UnsupportedFeature |
| 64–65535 | — | ignorable, bstr <= 65536, <= 16 per header |
| `0xFAFA` | GREASE | used in vectors `grease.hide`, `grease-signed.hide`; never written |
| > 65535 | — | invalid → MalformedHeader |

### A.2 Metadata keys

| key | name | status |
|---|---|---|
| 1 | filename | optional tstr, §4 rules |
| 2 | media_type | optional tstr, <= 255 bytes |
| 3 | confidential signature | optional, §2.3 shape |
| 4–5 | — | reserved core → UnsupportedFeature |
| 6–63 | — | critical, reserved → UnsupportedFeature |
| 64–65535 | — | ignorable, bstr <= 65536, <= 16 per map |
| `0x4A4A` | GREASE | used in vectors; never written |
| > 65535 | — | invalid |

### A.3 Preamble flags

| bit | name | status |
|---|---|---|
| `0x01` | SIGNED | assigned, §7.2 |
| `0x02`–`0x80` | — | reserved, critical → UnsupportedFeature |

Preamble minor: `0` invalid; `1` HIDE 1; `2` legacy signed (read-only, flags 0); `>= 3` non-breaking
HIDE 1 revision, processed as `1` (`7` used in vector `grease-minor.hide`).

### A.4 Recipient stanza tags

| tag | name | shape |
|---|---|---|
| 0 | — | invalid |
| 1 | X-Wing | `[1, encapsulation(1120), wrapped_cek(48)]` |
| `0x7A7A` | GREASE | used in vectors; never written |
| other, <= 65535 | unknown | skipped, retained, transcript-bound |

### A.5 Signature stanza tags

| tag | name | shape |
|---|---|---|
| 1 | hybrid Ed25519 + ML-DSA-65 | `[1, verifying_key(1984), signature(3373)]` |
| other | — | UnsupportedFeature |

### A.6 Suites

| id | KEM | KDF | AEAD |
|---|---|---|---|
| 1 | X-Wing (ML-KEM-768 + X25519, HPKE KEM `0x647A`) | HKDF-SHA256 | ChaCha20-Poly1305 |

The MLS cipher suite number `0x0001` (§13) is a separate registry.

### A.7 Domain-separation labels

| label | role | § |
|---|---|---|
| `HIDE/0.1 object-key` | HPKE info prefix | 3 |
| `HIDE/0.1 metadata` | HKDF info; metadata AAD prefix | 3, 4 |
| `HIDE/0.1 header-mac` | HKDF info | 3 |
| `HIDE/0.1 payload` | HKDF info prefix | 3 |
| `HIDE/0.1 chunk` | chunk AAD prefix | 5 |
| `HIDE/0.5 transcript` | legacy signed-message prefix | 7.4 |
| `HIDE/0.5 container` | legacy HIDE-Sign context | 7.4 |
| `HIDE/1.0 transcript` | signed-message prefix | 7.2 |
| `HIDE/1.0 container` | HIDE-Sign context | 7.2 |
| `HIDE/0.5 identity ed25519` | HKDF-Expand info (signing seed) | 8.2 |
| `HIDE/0.5 identity ml-dsa-65` | HKDF-Expand info (signing seed) | 8.2 |
| `HIDE/0.5 identity encryption` | HKDF-Expand info (master seed) | 9.1 |
| `HIDE/0.5 identity signing` | HKDF-Expand info (master seed) | 9.1 |
| `HIDE/0.6 identity entry` | HIDE-Sign context | 10.2 |
| `HIDE/0.6 identity link` | SHA-256 prefix | 10.2 |
| `HIDE/0.6 device id` | SHA-256 prefix | 10.1, 13 |
| `HIDE/0.6 epoch chain` | SHA-256 prefix | 11 |
| `HIDE/0.7 mls binding` | HIDE-Sign context | 13 |
| `HIDE/0.5 challenge` | HIDE-Sign context (implementation-defined) | 14.2 |
| `HIDE/0.5 detached` | HIDE-Sign context (implementation-defined) | 14.1 |
| `HIDE/0.5 detached-file` | signed-message prefix (implementation-defined) | 14.1 |

HIDE-Sign contexts are length-prefixed and cannot collide with one another or with a message. The
SHA-256 prefixes are not prefixes of one another. The HKDF infos under each PRK are pairwise
distinct. `HIDE/0.5 detached` is a byte prefix of `HIDE/0.5 detached-file`, but one is a context and
the other the start of a message, so they never occupy the same position.

Test-only labels (`HIDE/0.5 test`, `HIDE/0.5 other`, `HIDE/0.5 vector`, `HIDE/0.5 ffi test`,
`HIDE/0.5 something else`, `HIDE/0.5 node test`, `HIDE/0.5 cross-surface`) MUST NOT appear in
production code paths. New test labels SHOULD use the prefix `HIDE/test/`.

Other fixed values: container magic `48 49 44 45 0D 0A 1A 0A`; `HIDE-KEY` (versions 1, 2; purposes
1, 2); `HIDE-EPK` (version 1, implementation-defined); Merkle prefixes `0x00` / `0x01`; identity
tags 1–4; MLS credential type `0xF01D`.

### A.8 Limits

| constant | value | § |
|---|---|---|
| `MAX_HEADER_LEN` (`header_len`) | 1048576 | 1.1 |
| `MAX_RECIPIENTS` (stanzas, unknown included) | 64, minimum 1 | 2.2 |
| items per recipient stanza | 1 ..= 8 | 2.2 |
| stanza tag | 1 ..= 65535 | 2.2 |
| stanza field | <= 65536 bytes | 2.2 |
| `MAX_SIGNATURES` (key 5) | 1 | 2.3 |
| ignorable extension keys | <= 16 per header, <= 16 per metadata map | 2.1, 4 |
| ignorable extension value | <= 65536 bytes | 2.1, 4 |
| `MAX_METADATA_LEN` (plaintext) | 262144; ciphertext <= 262160 | 4 |
| filename, media_type | <= 255 bytes | 4 |
| `CHUNK_LEN` | 65536 | 5 |
| records (`MAX_CHUNKS`) | 2^32 | 5 |
| Argon2 memory | 8192 ..= 262144 KiB | 9.4 |
| Argon2 iterations | 1 ..= 64 | 9.4 |
| Argon2 parallelism | 1 ..= 4 | 9.4 |
| writer Argon2 | m = 19456, t = 2, p = 1 | 9.3 |
| `MIN_PASSPHRASE_LEN` (writers) | 8 | 9.3 |
| identity `MAX_ENTRIES` | 100000 | 10.3 |
| identity `MAX_LABEL_BYTES` | 256 | 10.1 |
| `MAX_CHAIN_ENTRIES` | 1000000 | 11 |
| `MAX_PROOF_LEN` | 64 hashes | 12 |
| `MAX_MLS_MESSAGE` | 1048576 | 13 |
| implementation limits (not frozen): `MAX_SIGNED_INPUT` 2^30 bytes (signed encrypt holds the plaintext), keystore 65536 entries / 4784231 bytes, CLI key file 4096, signing key file 8192, log file 16 MiB, armored message 1 MiB | | 14 |

## Appendix B. Change log

- 0.1 — container: preamble, header, key schedule, metadata, payload.
- 0.5 — hybrid signatures, public and confidential placement, preamble minor 2.
- 0.6 — identity logs, epoch chains, transparency proofs.
- 0.7 — `MAX_SIGNATURES` reduced from 8 to 1; MLS credential binding `0xF01D`; error handling
  stated normatively.
- 0.9.0 — format release candidate for 1.0:
  - Preamble flag `0x01` SIGNED and the HIDE 1.0 signature transcript (`HIDE/1.0 container`,
    `HIDE/1.0 transcript`), which binds the preamble, every stanza, header extensions and metadata
    extensions. Minor 2 becomes legacy and read-only.
  - The preamble minor becomes a non-breaking revision: readers accept minor `>= 3` as minor 1.
    Every flag bit is critical.
  - Extension key ranges in the protected header and the metadata: 6–63 critical, 64–65535
    ignorable bstr.
  - Unknown recipient stanza tags are decoded, bound and skipped instead of rejected.
  - Identity log entries are framed as `array(7)`; the 0.6–0.8 6-item head is read-only.
  - GREASE vectors (`grease.hide`, `grease-signed.hide`, `grease-minor.hide`) and new rejection
    vectors for every refusal rule above.
  - `conformance/vectors/manifest.json` (`hide-vectors/1`) lists every vector with its expected
    outcome and SHA-256.
  - Specification: HIDE-Sign, key files, identity log encoding and transparency proof rules are
    specified in full; the §4 filename rule is corrected (dots are allowed).
