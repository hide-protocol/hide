<!-- HIDE is experimental and unaudited. Every claim in README/spec must be backed by a test. -->

## What and why

<!-- One paragraph. Link the tracker item or issue. -->

## Checklist

- [ ] Tests added or changed; the new test fails on the previous code.
- [ ] `conformance/vectors` are unchanged, **or** intentionally regenerated
      (`cargo run -p hide-object --features test-vectors --example generate_vectors`)
      and the format change is explained below.
- [ ] `spec/hide-0.1.md` updated if any byte on the wire changed.
- [ ] `CHANGELOG.md` entry under the unreleased version; a format change is called out explicitly.
- [ ] `./scripts/set-version.ps1 -Check` passes.
- [ ] No new cryptographic primitives and no hand-rolled KEM combiner (`AGENTS.md` invariants);
      secret types still do not derive `Debug`, `Clone` or `Serialize`.
- [ ] `cargo test --workspace --all-features` passes locally.
- [ ] Documentation touched where the behaviour is described (README, docs/, SDK READMEs).

## Format or API change

<!-- "None", or: what changed on the wire, why the old vectors no longer apply, migration impact. -->
