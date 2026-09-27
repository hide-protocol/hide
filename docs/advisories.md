# HIDE security advisories

*HIDE is experimental and has not been audited by a third party. See [audit-status.md](audit-status.md).*

Defects found by internal review before a release are listed in [../SECURITY.md](../SECURITY.md) and [../CHANGELOG.md](../CHANGELOG.md), not here. An advisory is published only for a defect that affected a *released* version and was reported or discovered after that release shipped. The seven 0.7.0 findings described in `SECURITY.md` were found internally before release, so they are recorded there and in the changelog; none has an advisory ID.

## HIDE-2026-001 — a 95-byte key file could make `open` allocate up to 4 GiB

| Field | Value |
| --- | --- |
| ID | HIDE-2026-001 |
| Published | 2026-09-27 |
| Affected | `>=0.2.0, <0.8.0` — `hide-keyring`, and every surface that opens a protected key file through it: `hide-cli`, the desktop app, `hide-ffi` and all SDKs |
| Fixed in | 0.8.0 |
| Severity | Medium — denial of service on a parser; no key or plaintext exposure |
| Component | `hide-keyring` |
| CVE | none requested |
| Credit | found internally by the nightly fuzzer (`keyring_open`), issue #6 |

### Description
A protected key file stores its Argon2id parameters in its header so they can
be raised later without orphaning keys. The memory cost was accepted up to
4 GiB and the parallelism had no upper bound. The parameters are read before
anything is authenticated — they are the input to the derivation that would
authenticate them — so anyone who can hand a victim a key file (an attachment,
a shared folder, a "backup" to restore) could make `hide`, the desktop app or an
SDK call allocate gigabytes and spend minutes deriving before the wrong
passphrase was reported. A 95-byte file requested 2.4 GiB.

### Impact
Availability of the process that opens the file. `docs/threat-model.md` puts
parser denial of service in scope. No confidentiality or integrity guarantee
was affected: the derivation still had to succeed against a passphrase the
attacker does not know.

### Fix
Commit `7298790`: memory is capped at 256 MiB (thirteen times the 19 MiB every
writer emits) and parallelism at 4, both checked before any allocation. The
reproducer is frozen as `conformance/vectors/rejections/argon2-memory.test-secret`
and refused by the Rust and the independent Node verifier; the unit test that
pins it fails on 0.7.0.

### Workaround
Do not open key files from untrusted sources with versions before 0.8.0.

### Timeline
2026-09-09 found by nightly fuzzing (issue #6) · 2026-09-10 fixed on `main` · 2026-09-27 fix released in 0.8.0 · 2026-09-27 published

## How to report

Use GitHub's **Report a vulnerability** button on the repository's Security tab, which opens a private advisory. Details, response times and safe-harbour terms are in [../SECURITY.md](../SECURITY.md). There is no bug bounty; reporters are credited here and in the changelog.

## Advisory format

Every advisory will use the structure below, so a reader or a tool can parse the list without reading prose.

```
## HIDE-YYYY-NNN — one-line title

| Field | Value |
| --- | --- |
| ID | HIDE-YYYY-NNN (year of publication, then a three-digit sequence starting at 001) |
| Published | YYYY-MM-DD |
| Affected | exact version range, e.g. `>=0.5.0, <0.7.1`; per-surface if it differs (crate, CLI, SDK, desktop) |
| Fixed in | the first version that contains the fix |
| Severity | Critical / High / Medium / Low, with one sentence of justification |
| Component | crate or surface: `hide-object`, `hide-ffi`, `hide-cli`, `sdk/python`, … |
| CVE | if one was assigned; otherwise "none requested" or "requested" |
| Credit | reporter name or handle, or "found internally" |

### Description
What the defect is, what an attacker needs, and what they gain. Precise enough
to assess exposure; a reproduction is linked, not inlined, if it is dangerous.

### Impact
Which guarantee from docs/threat-model.md was violated, for whom.

### Fix
The commit or PR, and the test that fails on the previous code.

### Workaround
What a user who cannot upgrade can do, or "none".

### Timeline
YYYY-MM-DD reported · YYYY-MM-DD acknowledged · YYYY-MM-DD fix released · YYYY-MM-DD published
```

Severity follows the intent of CVSS but is stated in words: **Critical** = plaintext or key recovery by a non-recipient; **High** = forgery, authentication bypass, or plaintext recovery by a recipient beyond what they are entitled to; **Medium** = denial of service on a parser, information leak about the recipient set, or a weakened but not broken guarantee; **Low** = hardening defects with no known attack.

Advisories are appended to this file in reverse chronological order and never edited after publication except to add a CVE number or a correction marked as such.
