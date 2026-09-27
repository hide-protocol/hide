# Differential fuzzer: Rust reader vs independent Node reader

`run.mjs` generates mutated HIDE containers and feeds the **same bytes** to two
readers that share no code:

- **Rust**: `crates/hide-object/examples/differential_oracle.rs`, which calls
  `hide_object::decrypt_to_staging` — the path the CLI, desktop app, FFI and
  WASM all use.
- **Node**: `conformance/node/verify.mjs` `decrypt()`, written from
  `spec/hide-1.md` without calling the crates.

It fails (exit 1) when they disagree.

## Run

```powershell
cargo build -p hide-object --features test-vectors --example differential_oracle
cd conformance/node; pnpm install --ignore-workspace; cd ../..   # once
node conformance/differential/run.mjs --iterations 3000 --seed 1
```

Options: `--iterations N` (default 2000), `--seed S` (default 1),
`--oracle <path>` (another oracle binary), `--keep` (keep the mutants even on a
clean run). The Rust oracle runs **once** over the whole mutant directory and
prints one JSON line per file, so thousands of files cost one process.

Mutants are written to `.copilot-tmp/differential/<seed>/` and deleted after a
clean run. A disagreement is saved to `findings/<sha256>.hide` plus
`findings/<sha256>.json` (mutation description, both verdicts).

## What it compares

| Both readers... | Result |
|---|---|
| accept, and agree on plaintext SHA-256, plaintext length, filename, media type, metadata-extension count and signer (SHA-256 of the 1984-byte verifying key) | pass |
| reject | pass; the (Rust error, Node code) pair is counted in the mapping table |
| one accepts, one rejects | **finding** |
| accept but differ on any field above | **finding** |

Error **classes** are not compared: the two readers check rules in different
orders and name them differently (e.g. Rust `UnexpectedSignature` /
`MissingSignature` vs Node `InvalidSignature`; Rust `TrailingData` vs Node
`InvalidSignature`, because Node settles signature placement before reading
records and Rust after). The
mapping table is printed so an inconsistent pairing is visible; a Rust class
mapping to several Node codes is flagged as a warning, never a failure.

## Mutation families

- **seed** — every `.hide` in `conformance/vectors/` and
  `conformance/vectors/rejections/`, unmutated. A baseline: the positive vectors
  must be accepted by both, the rejections refused by both.
- **sweep** — ~300 containers, independent of `--seed`: every edge value from
  the lists below applied ALONE to a valid base (each filename, media type,
  header/metadata key × value type, 15/16/17 extensions, minor × flags,
  unknown-stanza tag × item count, 64/65 stanzas, each signing placement ×
  transcript × post-signing tamper). Random stacking rarely leaves one edge
  case alone on an otherwise valid container, and a rule is only compared when
  nothing earlier refuses the file; the sweep is what guarantees each rule is
  reached on every run.
- **raw** — 1–3 byte edits of a seed: bit flips, byte sets, insert/delete,
  truncation, appended bytes, `header_len` rewrites, preamble version/kind/flag
  bytes. Almost all die at the header MAC; they test the checks that run
  before authentication (preamble, `header_len` bound, CBOR envelope).
- **structured** — a container assembled from parts with a known CEK
  (`verify.mjs` `rebuild()`), so the header MAC, metadata AEAD and every record
  are valid for the mutated content and the mutation reaches the semantic
  checks behind them. 1–3 mutations per container from: preamble minor/flags/
  kind/major; header extension keys (0, 6..63, 64.., 65535, 65536, 2^32, 2^63)
  with non-bstr and 65536/65537-byte values; 15–18 extensions; removed,
  reordered and duplicated keys (raw, non-canonical order); suite and object_id;
  unknown recipient stanzas (tags 0, 2..65535, 65536, 2^32, non-uint; 0..9
  items; fields up to 65537 bytes; tag-1 stanzas of the wrong shape; the real
  X-Wing stanza disguised under another tag; 63–65 stanzas); key 5 signature
  arrays (0/1/2 stanzas, wrong tag, wrong key/signature lengths, wrong type);
  metadata filenames (`..`, `.`, trailing dot/space, `CON`, `con.txt`, `COM1`,
  `LPT9`, `/`, `\`, C0/C1 controls incl. U+0085, 255/256 bytes, multi-byte
  UTF-8, U+017F), media types, metadata keys 0..7, 63, 64.., 65536, wrong value
  types, 15–18 metadata extensions, raw metadata bytes (non-map, trailing
  byte, non-minimal integers, oversize); plaintext sizes around the 64 KiB
  record boundary; and signatures (public or confidential, 1.0 or legacy
  transcript, flag set or not) with post-signing tampering: stripped, placed
  in both locations, corrupted signature or key, small-order Ed25519 key,
  extension edited/added, stanzas reordered or added, filename or plaintext
  changed, flag cleared, minor bumped.

The PRNG (splitmix32) makes every mutation choice a function of `--seed`. The
X-Wing wraps for the four base objects are cached in
`.copilot-tmp/differential/bases.json`, so unsigned mutants are byte-identical
across runs; signed mutants are identical in structure only, because ML-DSA
signing uses fresh randomness. Findings are saved verbatim, so that does not
affect reproducing one.

## What this proves

- For the containers generated, the Rust reader and a reader written only from
  the spec make the same accept/reject decision and, on accept, return the same
  plaintext, metadata and signer.
- A rule one side enforces and the other does not shows up as a finding the
  first time a mutant exercises it — including rules behind the MAC, which a
  byte-level fuzzer cannot reach.

## What it does not prove

- **Not correctness against the spec.** Two readers agreeing can both be wrong;
  a finding still has to be adjudicated against `spec/hide-1.md`.
- **Not coverage of rules nobody thought to mutate.** Structured mutations are
  hand-picked; the raw family is too shallow to get past the MAC.
- **Not error-class equivalence.** Only accept/reject and the accepted output
  are compared.
- **Only the recipient in `recipient.test-secret`**, only the X-Wing suite, and
  only containers up to two records. Multi-recipient HPKE behaviour, key files
  and the §8–§10 subsystems are out of scope (see `conformance/node/subsystems.mjs`).
- **Not the streaming property.** The Node reader holds the whole container;
  "no plaintext released before FINAL" is tested in the Rust crates, not here.
