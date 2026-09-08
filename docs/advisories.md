# HIDE security advisories

*HIDE is experimental and has not been audited by a third party. See [audit-status.md](audit-status.md).*

## No advisories have been published.

Defects found by internal review before a release are listed in [../SECURITY.md](../SECURITY.md) and [../CHANGELOG.md](../CHANGELOG.md), not here. An advisory is published only for a defect that affected a *released* version and was reported or discovered after that release shipped. The seven 0.7.0 findings described in `SECURITY.md` were found internally, so they are recorded there and in the changelog; none has an advisory ID.

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
