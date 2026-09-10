---
name: fuzz-triage
description: Triage a libFuzzer finding in HIDE — locate the failing CI/nightly run, download the reproducer artifact, hex-dump it with python, classify crash/timeout/oom, reproduce in WSL with cargo +nightly fuzz, fix with an explicit bound, pin the bytes as a unit regression test AND a frozen rejection vector, seed the corpus, close the issue. Use when the `fuzz` CI job fails, when fuzz-nightly opens an issue labelled fuzz+security, or when a fuzz target times out.
---

# Fuzz triage

Fuzz targets: `format_header object_open keyring_open identity_log epoch_chain
transparency_proofs challenge_decode mls_message` (`fuzz/fuzz_targets/*.rs`).
Findings so far were all bound/canonicality bugs code review missed. Assume the same.

## 1. Find the run

```powershell
gh run list --workflow fuzz-nightly.yml --status failure --limit 5
gh run list --workflow ci.yml --status failure --limit 5
gh issue list --label fuzz --state open
```

Which target failed (job name = target in nightly; one job in CI):

```powershell
gh run view <id> --json jobs --jq '.jobs[] | {name, conclusion}'
```

## 2. Download the reproducer

```powershell
New-Item -ItemType Directory .copilot-tmp/fuzz -Force | Out-Null
gh run download <id> --pattern 'fuzz-artifacts-<target>' --dir .copilot-tmp/fuzz
Get-ChildItem -Recurse .copilot-tmp/fuzz | Select-Object FullName, Length
```

Artifact names: `fuzz-artifacts-<target>` (nightly), `fuzz-artifacts` (CI). Files
are `crash-<sha1>`, `timeout-<sha1>`, `oom-<sha1>`, `leak-<sha1>`.

For the log line that names the failure, save the log to a file first — never pipe
`gh run view --log` straight into `Select-String` in a long session:

```powershell
$j = ((gh run view <id> --json jobs | ConvertFrom-Json).jobs | Where-Object name -eq '<job>').databaseId
gh run view <id> --log-failed --job=$j 2>&1 | Out-File -Encoding utf8 .copilot-tmp/fuzz/log.txt
rg -n 'panicked|SUMMARY|Test unit written|timeout after|out-of-memory|MS: ' .copilot-tmp/fuzz/log.txt
```

## 3. Hex-dump with python (never PowerShell)

PowerShell types a `[byte[]]` variable as XmlDocument in long sessions and
`Format-Hex` truncates. Use python:

```powershell
python -c "import sys,pathlib; b=pathlib.Path(sys.argv[1]).read_bytes(); print(len(b)); print(b.hex(' '))" .copilot-tmp/fuzz/<file>
```

Read the bytes against the wire layout in `spec/hide-0.1.md`. Known shapes:

- `9a 00 00 00 00` — CBOR array(0) with a 4-byte length prefix: non-canonical.
- Key file offset 10 = Argon2 `m_cost` u32 BE; offset 14 = `t_cost`; 18 = `p`.
- `1a`/`1b` after a field tag: an oversized integer that a loop or `with_capacity`
  will trust.

## 4. Classify

| Prefix | Meaning | Usual root cause |
|---|---|---|
| `crash-` | panic/UB (ASAN) | `unwrap`, slice index, `as usize`, arithmetic overflow |
| `timeout-` | >60 s on one input | loop bounded by input VALUE (probe shift wrapped) |
| `oom-` | >2048 MiB RSS | allocation from an unchecked length/cost |
| `leak-` | ASAN leak | usually a false positive from a `LazyLock`; confirm before acting |

Each maps to a rule in `.github/instructions/rust-crates.instructions.md`.

## 5. Reproduce locally (WSL, nightly, gnu target)

`rust-toolchain.toml` pins stable; ASAN cannot link musl. From WSL:

```powershell
wsl -d Ubuntu-24.04 -- bash -c 'export PATH=$HOME/.cargo/bin:/usr/local/bin:/usr/bin:/bin; cd /mnt/e/gh/HIDE/fuzz && cargo +nightly fuzz run --target x86_64-unknown-linux-gnu <target> ../.copilot-tmp/fuzz/<file> -- -timeout=60 -rss_limit_mb=2048'
```

Export a clean PATH: the inherited Windows PATH contains parentheses that break
`bash -lc`. If nightly is absent: `rustup toolchain install nightly` and
`cargo install cargo-fuzz` inside WSL.

Confirm it fails the same way BEFORE editing anything. Then form ONE hypothesis.

## 6. Fix with a bound

- Missing ceiling → add `const MAX_*` next to the existing ones and check it before
  the allocation/loop (pattern: `hide-keyring/src/lib.rs` `MAX_MEMORY_KIB`).
- Non-canonical accepted → `if encode(&decoded)? != bytes { return Err(Malformed) }`.
- Value-bounded loop → rewrite in terms of bit width (`ilog2`, `leading_zeros`).
- `as usize` → `usize::try_from(..)`.

Re-run step 5 on the fix. Then `cargo test --workspace --all-features`.

## 7. Pin the bytes twice

**Unit regression test** in the owning crate's `tests/` or `#[cfg(test)]` module,
named for the finding, asserting the exact `Err` variant:

```rust
#[test]
fn refuses_five_byte_length_prefix_on_small_array() {
    // Fuzzer reproducer (fuzz-nightly run <id>): a 4-byte length prefix on
    // array(0). Re-encoding must not reproduce these bytes.
    let bytes = [0x9a, 0x00, 0x00, 0x00, 0x00];
    assert_eq!(decode(&bytes), Err(IdentityError::Malformed));
}
```

**Frozen rejection vector** when the input is a container, key file or public key:
follow skill `add-rejection-vector` (file + `rejections.txt` row + both verifiers +
`listed >= N` + `.gitignore` exception if the extension is new).

## 8. Seed the corpus

Copy the reproducer where CI seeds from, so every future run starts on it:

- Container → `conformance/vectors/rejections/<name>.hide` (already copied to
  `format_header`/`object_open` corpora by the CI seed step only if under
  `conformance/vectors/*.hide` — add a `cp` line in both `ci.yml` and
  `fuzz-nightly.yml` "Seed the corpus" steps if the location is new).
- Key file → `conformance/vectors/rejections/<name>.test-secret`.
- Subsystem bytes → `conformance/vectors/subsystems/<sub>-<name>.bin`.

`fuzz/corpus/` itself is gitignored; the nightly cache carries it forward.

## 9. Verify and close

```powershell
cargo test --workspace --all-features
cargo test -p hide-object --test vectors
cd conformance/node; node verify.mjs; cd ../..
cargo test --manifest-path apps/hide-desktop/src-tauri/Cargo.toml
```

Add a `docs/tracker.csv` row (type `fuzz-finding`, `evidence` = the test command)
and the one-line `docs/TRACKER.md` mention; `CHANGELOG.md` under `## Unreleased`.

Commit with explicit paths (shared clone): `fix(<crate>): <bound> — fuzz reproducer
<sha1> (closes #N)`. Then:

```powershell
gh issue close <N> --comment "Fixed in <sha>: <rule>. Regression test <name>; rejection vector <file>."
```

Record symptom → root cause → fix in `/memories/repo/hide-protocol.md` in the same turn.
