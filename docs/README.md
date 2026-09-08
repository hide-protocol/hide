# HIDE documentation index

*HIDE is experimental and has not been audited by a third party. See [audit-status.md](audit-status.md).*

HIDE is hybrid post-quantum file encryption (X25519 + ML-KEM-768 via X-Wing, NIST FIPS 203) with hybrid signatures (Ed25519 + ML-DSA-65, FIPS 204). These documents are for people deciding whether to adopt it, whether to audit it, or what to answer when asked about it.

| Document | Question it answers |
| --- | --- |
| [threat-model.md](threat-model.md) | Who is the adversary, and what is and is not defended |
| [comparison.md](comparison.md) | How HIDE differs from age, GPG, libsodium, minisign, Signal, MLS, Tink, AWS KMS, Kryptor |
| [use-cases.md](use-cases.md) | Where HIDE fits, where it does not, and what to use instead |
| [faq.md](faq.md) | Short factual answers to the questions people actually ask |
| [stability.md](stability.md) | What may change before 1.0 and how a change is announced |
| [migrating-from-age.md](migrating-from-age.md) | Command mapping and what you give up |
| [architecture.md](architecture.md) | Crate boundaries, the C ABI, how SDKs load the core, how CI enforces invariants |
| [audit-status.md](audit-status.md) | What has been reviewed, by whom, and what an audit should cover |
| [advisories.md](advisories.md) | Published security advisories (none yet) and their format |
| [TRACKER.md](TRACKER.md) | Work tracker |

Elsewhere in the repository: the wire format in [../spec/hide-0.1.md](../spec/hide-0.1.md), the security policy and reporting channel in [../SECURITY.md](../SECURITY.md), release history in [../CHANGELOG.md](../CHANGELOG.md), and the engineering invariants in [../AGENTS.md](../AGENTS.md).
