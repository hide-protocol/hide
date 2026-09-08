# hide-format

Wire format for the [HIDE](https://github.com/hide-protocol/hide) protocol:
the 16-byte preamble, the bounded canonical CBOR header (recipient and
signature stanzas, metadata) and the constants every other crate agrees on
(`CHUNK_LEN`, `MAX_RECIPIENTS`, `MAX_HEADER_LEN`).

Every length field in untrusted input is checked against a fixed limit before
anything is allocated. Parsing and encoding here; no cryptography.

```rust
use hide_format::{Metadata, Preamble, PREAMBLE_LEN};

let preamble = Preamble::new(512)?;
let bytes: [u8; PREAMBLE_LEN] = preamble.encode();
let decoded = Preamble::decode(&bytes)?;
assert_eq!(decoded.header_len(), 512);
assert!(!decoded.is_signed());

let metadata = Metadata {
    filename: Some("notes.txt".into()),
    media_type: Some("text/plain".into()),
    ..Metadata::default()
};
let encoded = metadata.encode()?;
assert!(!encoded.is_empty());
# Ok::<(), hide_format::FormatError>(())
```

The normative description lives in
[`spec/hide-0.1.md`](https://github.com/hide-protocol/hide/blob/main/spec/hide-0.1.md);
the frozen vectors under `conformance/vectors/` are what this crate is tested
against.

**Experimental and unaudited.** The format may still change before 1.0.
Licensed Apache-2.0.
