# HIDE/0.1 wire format (experimental)

Draft, unaudited, and expected to change. Integers are big-endian. All structural encoding is
deterministic CBOR (RFC 8949 §4.2); a decoder MUST re-encode and compare bytes, and MUST reject
indefinite lengths, non-shortest integers, duplicate or out-of-order map keys, tags, floats and
trailing data.

## 1. Container

```
preamble (16 bytes) || header || payload_salt (16 bytes) || records...
```

Preamble: magic `48 49 44 45 0D 0A 1A 0A`, major `0`, minor `1`, kind `1`, flags `0`,
then `header_len` as `u32`. A decoder MUST validate limits before allocating.

Limits: header ≤ 1 MiB, recipients 1..=64, encrypted metadata ≤ 256 KiB + 16, chunk plaintext ≤ 64 KiB.

## 2. Header

`[ protected: bstr, header_mac: bstr(32) ]`. The exact `protected` bytes are authenticated; a decoder
MUST NOT re-serialize them for verification.

```
protected = { 1: 1, 2: object_id(32), 3: [ stanza... ], 4: encrypted_metadata, 5: [] }
stanza    = [ 1, encapsulation(1120), wrapped_cek(48) ]
```

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

`{ 1: filename, 2: media_type }`, both optional, each ≤ 255 bytes, encrypted with
`AAD = "HIDE/0.1 metadata" || object_id || 0x0001`. A filename MUST be a single portable component:
no `/`, `\`, `:`, `.`, `..`, control characters, trailing dot or space, or Windows reserved name.
**A decrypting application MUST treat the filename as untrusted** and MUST NOT use it to choose an
output path.

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

Authenticated: container structure, suite, object id, recipient set, metadata, chunk order and count,
and end-of-stream. Not provided: sender authentication, identity binding, forward secrecy, recipient
anonymity against traffic analysis, and hiding of file size or recipient count.
