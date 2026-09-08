# HIDE/0.1 wire format (experimental)

Draft, unaudited, and expected to change. Integers are big-endian. All structural encoding is
deterministic CBOR (RFC 8949 §4.2); a decoder MUST re-encode and compare bytes, and MUST reject
indefinite lengths, non-shortest integers, duplicate or out-of-order map keys, tags, floats and
trailing data.

## 1. Container

```
preamble (16 bytes) || header || payload_salt (16 bytes) || records...
```

Preamble: magic `48 49 44 45 0D 0A 1A 0A`, major `0`, minor `1` or `2`, kind `1`, flags `0`,
then `header_len` as `u32`. A decoder MUST validate limits before allocating.

Minor `2` means the container is signed (§7). A signed container advertises `2` so that a reader
which does not implement signatures refuses it, rather than opening it and silently ignoring the
signature. Unsigned containers keep minor `1` and are byte-identical to HIDE/0.1.

Limits: header ≤ 1 MiB, recipients 1..=64, encrypted metadata ≤ 256 KiB + 16, chunk plaintext ≤ 64 KiB.

## 2. Header

`[ protected: bstr, header_mac: bstr(32) ]`. The exact `protected` bytes are authenticated; a decoder
MUST NOT re-serialize them for verification.

```
protected = { 1: 1, 2: object_id(32), 3: [ stanza... ], 4: encrypted_metadata, 5: [ signature... ] }
stanza    = [ 1, encapsulation(1120), wrapped_cek(48) ]
signature = [ 1, verifying_key(1984), signature(3373) ]
```

Key 5 held an empty array in HIDE/0.1 and now carries public signatures, 0 or 1 of them. Exactly one
signer is verified, so a decoder MUST reject a second stanza rather than skip it: a recipient could
otherwise append stanzas that nobody checks. (HIDE/0.6 and earlier admitted up to 8 on the wire; no
known container carries more than one.) An unsigned header still encodes `5: []`, byte-for-byte as
before.

`object_id` is random, never a hash of the plaintext. Stanzas carry no recipient identifier; a client
trial-decapsulates and accepts a candidate CEK only after the header MAC verifies.

A sender MUST reject a recipient public key whose X25519 component (the trailing 32 bytes) is one of
the seven Curve25519 points of order below 8. Such a point yields an all-zero X25519 shared secret,
which would leave the hybrid resting on ML-KEM alone.

## 3. Key schedule

```
info = "HIDE/0.1 object-key" || object_id || 0x0001
aad  = object_id || 0x0001
wrapped_cek = HPKE-Seal(recipient_public, info, aad, CEK)   # X-Wing, HKDF-SHA256, ChaCha20-Poly1305

K(label, salt) = HKDF-SHA256(IKM = CEK, salt, info = label, L = 32)
metadata_key   = K("HIDE/0.1 metadata",   object_id)
header_mac_key = K("HIDE/0.1 header-mac", object_id)
payload_key    = HKDF-SHA256(CEK, payload_salt, "HIDE/0.1 payload" || object_id, 32)
header_mac     = HMAC-SHA256(header_mac_key, preamble || protected)
```

Each derived key is used for exactly one purpose, so the fixed all-zero metadata nonce is safe.

## 4. Metadata

`{ 1: filename, 2: media_type, 3: signature }`, all optional, the strings each ≤ 255 bytes, encrypted with
`AAD = "HIDE/0.1 metadata" || object_id || 0x0001`. A filename MUST be a single portable component:
no `/`, `\`, `:`, `.`, `..`, control characters, trailing dot or space, or Windows reserved name.
**A decrypting application MUST treat the filename as untrusted** and MUST NOT use it to choose an
output path.

Key 3 carries a confidential signature, in the same `[ 1, verifying_key, signature ]` shape as §2.
Because it lives inside the encrypted metadata, it identifies the signer only to those who can
already decrypt.

## 5. Payload

```
record = kind(1) || ciphertext_len(u32) || ciphertext
kind: 1 = DATA (plaintext exactly 65536), 2 = FINAL (0 only when it is the sole record)
nonce = 0x000000 || counter(u64) || (kind == FINAL)
aad   = "HIDE/0.1 chunk" || object_id || SHA-256(protected) || counter || kind || plaintext_len
```

Exactly one FINAL record ends the object, and no bytes may follow it. A decryptor MUST NOT publish
plaintext until FINAL verifies; write to private staging and commit atomically.

## 6. Security notes

Authenticated against non-recipients: container structure, suite, object id, recipient set, metadata,
chunk order and count, and end-of-stream. The header MAC key is derived from the CEK, which every
recipient holds, so any recipient can rewrite the recipient set of an UNSIGNED container and
recompute a valid MAC. A signature (§7) binds the stanza list into the transcript and closes this. Not
provided: identity binding, forward secrecy, recipient anonymity against traffic analysis, and hiding
of file size or recipient count. The 16-byte `payload_salt` is outside every authenticator; altering
it changes the payload key so every record fails to open, a denial of service and nothing more. Sender authentication is available only
when the container is signed (§7), and even then a signature attests to a key, not to a person.

## 7. Signatures (HIDE/0.5, minor 2)

A signature is hybrid Ed25519 + ML-DSA-65: the 1984-byte verifying key is `ed25519(32) || ml_dsa(1952)`
and the 3373-byte signature is `ed25519(64) || ml_dsa(3309)`. A verifier MUST require **both** halves
to verify, and MUST evaluate both before deciding, so the time taken does not reveal which failed.

A signature may appear in exactly one of two places, never both:

- **Public** — in `protected` key 5. Readable by anyone holding the file, so it discloses the signer
	to storage providers and network observers.
- **Confidential** — in metadata key 3. Readable only by those who can already decrypt.

A container carrying signatures in both places MUST be rejected.

### 7.1 What is signed

```
message = "HIDE/0.5 transcript" || 0x0001 || object_id
			 || u64(recipient_count) || (encapsulation || wrapped_cek)...
			 || u64(len(metadata_base)) || metadata_base
			 || SHA-256(plaintext) || u64(plaintext_len)

signature = HIDE-Sign(identity, context = "HIDE/0.5 container", message)
```

`metadata_base` is the metadata encoded **without** key 3, and the public form omits key 5's
contents, because a signature cannot cover itself.

The plaintext hash is not optional. Every recipient holds the CEK and the payload salt is in the
clear, so a recipient can re-encrypt arbitrary content under an unchanged header, producing a
container whose every AEAD tag is valid. A signature over the header alone would still verify over
that content. **Binding `SHA-256(plaintext)` is what makes a signature mean "this signer produced
this content" rather than merely "this signer addressed these recipients."**

The metadata is bound as plaintext rather than as the header's ciphertext because sealing is
randomised and the confidential placement reseals after signing, so the ciphertext a verifier holds
is not the one that existed when the signature was made.

### 7.2 Verifier obligations

A verifier MUST reject the object, not merely report an unverified signature, when the signature
fails, when the preamble says minor `2` but no signature is present (a stripped signature), or when a
signature is present but the preamble says minor `1`. Signature verification requires the plaintext
hash and therefore completes only after FINAL; the §5 rule stands, and plaintext MUST NOT be
published until verification succeeds as well.

A signature attests to a key. Binding that key to a person needs a directory or transparency log,
which HIDE does not yet provide.

## 8. Identity logs (HIDE/0.6)

An identity is not a key but an ordered log of events. Entry *n* is:

```
signed  = previous(32) || sequence(u64be) || tag(1) || signer(32)
          || len(field, u64be) || field ...
link    = SHA-256("HIDE/0.6 identity link"
                  || len(signed, u64be)    || signed
                  || len(signature, u64be) || signature)
```

The signature itself is over `signed` with the context label `"HIDE/0.6 identity entry"`.

`previous` is the predecessor's `link`, and zero for entry 0. It is inside the signed bytes, so an
entry cannot be transplanted into another log or reordered within its own: doing either changes the
message that was signed.

A device id is the full 32-byte `SHA-256("HIDE/0.6 device id" || verifying_key)`.

Events are `Create`, `Enrol`, `Revoke` and `Recover`. Every field of variable length is preceded by its
length, so no two distinct event sequences can serialise identically.

**Authority is evaluated at the entry's position in the log, never against the final state.** A
verifier replays from entry 0 and asks whether the signer was trusted *at that point*. This is what
gives revocation meaning: a revoked device cannot re-enrol itself, cannot revoke the device that
removed it, and cannot author anything that appears after its removal.

Revocation is **not retroactive**. Entries signed before it remain valid, because invalidating them
would invalidate every message the device ever sent. Only the offline recovery key may sign `Recover`,
which replaces the entire device set.

The log is public: verifying it requires no secret.

## 9. Epoch chains (HIDE/0.6)

Keys are grouped into epochs. Each record is:

```
link = SHA-256("HIDE/0.6 epoch chain" || previous(32) || number(u64be)
               || len(public_key, u64be) || public_key)
```

`previous` is the preceding epoch's `link`, and zero for epoch 0.

An epoch's secret is an **independent random key**, not derived from any master seed. This is the
whole point: if epoch keys were derived, anyone who later obtained the seed could reconstruct the
epochs that were supposedly erased, and there would be no forward security at all.

Destroying an epoch's secret makes every container written to that epoch permanently unreadable — by
everyone, including the intended recipient. The published chain still proves the epoch existed and
where it sat in the order, which is what lets a reader distinguish "erased" from "never existed".

## 10. Transparency (HIDE/0.6)

Merkle hashing follows RFC 6962 exactly: leaves are prefixed `0x00` and interior nodes `0x01`, so a
leaf can never be reinterpreted as a node. A subtree of *n* leaves splits at the largest power of two
strictly below *n*, which makes a tree's shape a function of its size alone.

A checkpoint is `size(u64be) || root(32)`. A root without its size commits to nothing checkable.

Two proofs are defined. **Inclusion** shows an entry is in the log at a given size. **Consistency**
shows the log of size *m* is a prefix of the log of size *n* — this is the one that matters, because
it is what makes a rewritten history detectable rather than merely impolite.

Neither proof detects a **split view**: two divergent logs are each internally consistent. Catching
that requires independent witnesses who gossip roots and refuse to sign two roots for one size. No
witnessing is specified here, and a log without it is a promise, not a proof.
