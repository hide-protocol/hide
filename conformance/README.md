# Conformance

Two things live here: the frozen vector set a HIDE implementation must agree with, and a harness
that lets **an implementation maintained outside this repository** say, in a form anyone can
re-run, which of those vectors it passes.

The harness exists because of criterion 3 in [`docs/stability.md`](../docs/stability.md): 1.0 wants
*two independent implementations passing the full vector set*. The Rust crates are one. The Node
verifier under [`node/`](node) is written here, by the same maintainers, so it is a second
implementation of the format but not an independent one, and the project has always said so rather
than counting it.

## Running it

Build or install your own implementation, then point the harness at it:

```
node conformance/harness/run.mjs \
  --command "my-hide {verb} --input {input} --key {key} --out {out}" \
  --require-complete
```

`--command` is a template. The harness substitutes the placeholders and runs it once per vector:

| placeholder | what it is |
|---|---|
| `{verb}` | the operation (`open-container`, `load-key`, `load-public-key`, `verify-subsystem`) |
| `{input}` | the vector file to read |
| `{key}` | the key file that vector needs (`--key` may be unused by your command) |
| `{out}` | a path your command may write a decrypted result to |
| `{message}` | for a detached signature, the message file the signature covers |
| `{vectors}` | the vector directory, for an implementation that wants to read the manifest itself |

Other options: `--vectors <dir>` (default `conformance/vectors`), `--compliance <file>` (default
[`compliance.json`](compliance.json)), `--timeout <ms>` per vector. A vector your command cannot
check is reported `NOT CHECKED`; with `--require-complete` it is a failure instead, which is what
the `full` level asks for.

A working example is in [`harness/adapters/hide-cli.mjs`](harness/adapters/hide-cli.mjs), which
drives the Rust `hide` CLI. **It is an example, not the independent implementation**: it was
written in this repository, and it recovers the refusal class by matching the CLI's error text,
which the project does not promise to keep stable. Your adapter should report the class from its
own error type.

## The verdict channel

Your command reports its verdict through its **exit status**, so no output format has to be parsed
and no output text is part of the interface:

| exit | meaning |
|---|---|
| `0` | accepted |
| `2` | refused: malformed (§6.1) |
| `3` | refused: unsupported (§6.1) |
| `4` | refused: authentication (§6.1) |
| `5` | refused: no matching recipient (§6.1, the single non-recipient outcome) |
| `10` | this command does not implement `{verb}` — the vector is `NOT CHECKED`, never a pass |
| anything else | the command did not run; the harness reports a failure |

The classes are not decoration. A harness that accepted any non-zero status as "it refused" could
not tell a right refusal from a wrong one — which is exactly the defect the frozen rejection
vectors were created to catch, and why each one names the error it must produce.

## Reading the vectors, and the one that needs the legacy key form

Every container vector except `identity.hide` is sealed to the recipient whose **32 raw bytes are
`recipient.test-secret`** — the 0.1.0–0.4.x meaning of a key file, which spec §9.2 records as legacy.
`identity.hide` is sealed to the key *derived* from the 32-byte master seed in `identity.test-seed`,
which is the meaning §9.2 gives a raw file today.

This matters for an implementation that only accepts the current meaning as a **file**: it has no
key file to open `hello.hide` with, and it will refuse the container for the wrong reason — no
matching recipient — before it ever reaches the damage a rejection vector carries. Reporting that
as "refused" would be a false pass, so an implementation in that position must report exit `10`
(not implemented) for those vectors instead. The Rust crates can check them because their vector
tests read the legacy form directly through the library
(`RecipientSecret::from_bytes` in `crates/hide-object/tests/vectors.rs`); this repository's CLI
deliberately cannot, because it refuses to treat a raw 32-byte file as anything but a master seed.

The reference adapter passes `identity.test-seed` and reports the rest as not checked for that
reason. **It does not do that yet**, and its current run is not a conformance claim for containers:
run against the Rust CLI on 2026-11-15 it passed 28 vectors (the public-key and key vectors, the
signature vectors and 16 refusals whose class it could reach) and failed 22, every one of them with
the signature of this mismatch — `refused as no-matching-recipient, expected …` for a rejection
vector, and `expected open, observed refused` for an accept vector. That is the adapter reporting a
wrong-key refusal as if it were the vector's verdict, which is exactly the false pass the exit-`10`
rule exists to prevent; making it report `10` for those is the next change to it. A third-party
implementation that supports the legacy reading — which the frozen vectors require if `full` is the
target — can check them all.

## Levels

`compliance.json` states what each level requires, in machine-readable form:

- **`container`** — reads and refuses containers with the §6.1 class. The minimum for an
  interoperable reader.
- **`container+credentials`** — also opens key files and accepts or refuses recipient public keys.
- **`full`** — every vector in the manifest, run with `--require-complete`. This is what criterion
  3 asks of an implementation maintained outside this repository.

`compliance.json` pins the SHA-256 of `conformance/vectors/manifest.json`, so a claim made against
one vector set cannot be read as a claim about another.

## What passing proves, and what it does not

It proves that an implementation agrees with the frozen vectors on what the format is, including
the *class* of every refusal. That is a real property: it is the one the Rust crates and the Node
verifier both hold, and the cross-surface check exists because a self-consistent surface can still
disagree with its neighbour.

It does **not** prove that the implementation is safe, that its cryptography is correct, that it
handles input outside the vector set, or that it does anything about the operational half of a
transparency log. Nothing here is an audit: see [`docs/audit-status.md`](../docs/audit-status.md).

## Invitation

If you have implemented the format — in Go, Python, Rust, C or anything else — run the harness and
open an issue with the command line you used and the output. A run that passes `full` would close
criterion 3, and the first thing the project would do is say so in the README instead of describing
the gap.

The vectors are frozen: changing one is a protocol change, so a disagreement is much more likely to
be a defect in an implementation than in the vector set. If you believe a vector is wrong, say which
and why — that is a far more interesting report than a passing run.
