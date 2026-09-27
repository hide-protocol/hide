# Independent Node verifier

*HIDE is experimental and has not been audited by a third party.*

A second implementation of [`spec/hide-1.md`](../../spec/hide-1.md) in JavaScript. It does not call
the Rust crates: the preamble, protected header, stanza grammar, metadata rules, key schedule,
record stream, both signature transcripts, identity logs, epoch chains and transparency proofs are
re-derived from the specification, so a disagreement with Rust shows up as a failing vector rather
than as two copies of the same bug.

It is maintained in this repository by the same maintainers as the Rust code. That makes it a check
on the specification and on the Rust implementation, not an independent review.

| file | covers |
| --- | --- |
| `verify.mjs` | the container (spec §1–§7): reader and writer, the HIDE/1.0 and legacy HIDE/0.5 transcripts, key-file and public-key structure, `manifest.json` |
| `subsystems.mjs` | identity logs (§10), epoch chains (§11), RFC 6962 proofs (§12) |

Primitives come from `@hpke/core` + `@hpke/hybridkem-x-wing` (X-Wing), `@noble/post-quantum`
(ML-DSA-65) and `node:crypto` (Ed25519, ChaCha20-Poly1305, HKDF, HMAC, SHA-256). CBOR is encoded by
the verifier's own deterministic encoder: `cbor@10` does not sort wide map keys, which would make
GREASE vectors look non-canonical. Strict Ed25519 (small-order A and R, non-canonical S) is enforced
here because `node:crypto` alone accepts small-order points.

## Run

Node 22 or later.

```powershell
cd conformance/node
pnpm install --ignore-workspace
node verify.mjs
```

What it checks, in order:

1. Known-answer probes for its CBOR encoder.
2. Every frozen container vector opens with the recorded plaintext; signed ones verify.
3. Its own writer emits minor 1, flags 0, and it reopens its own output. The container is saved
   to `.copilot-tmp/node-interop.hide` (plaintext alongside) so it can be opened with the Rust CLI
   by hand; no automated job consumes it.
4. Self-tests: containers it builds and mutates (minor, flags, extensions, unknown stanzas,
   stripped or rewritten signatures, legacy minor 2 misuse, malleated Ed25519) are opened or
   refused as the spec requires.
5. `../vectors/manifest.json`: every entry's SHA-256, then open or refuse by `kind` and `expect`.
   Without a manifest it falls back to `rejections/rejections.txt`.
6. Subsystem vectors, including refusal of each tampered file for the stated reason.

Each check prints a `PASS` line; the run ends with `verify.mjs: all checks passed` or exits
non-zero at the first failure. CI runs it in the `interoperability` job.

## As a library

`verify.mjs` exports `decrypt`, `encrypt` and `rebuild` (re-MAC and re-encrypt a mutated container
so it reaches the checks behind the header MAC), the transcript builders `transcript10` and
`transcriptLegacy`, `encodeCbor`, `keyFileProblem`, `publicKeyProblem` and `checkManifest`.
`subsystems.mjs` exports `decodeIdentity`, `replayIdentity`, `decodeEpochs`, `verifyEpochs`,
`verifyInclusion`, `verifyConsistency` and `verifySubsystems`. Running either file directly only
runs its checks when it is the entry point.
