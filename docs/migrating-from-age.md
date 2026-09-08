# Migrating from age to HIDE

*HIDE is experimental and has not been audited by a third party. See [audit-status.md](audit-status.md).*

Read the "What you lose" section before the command table. age is audited, packaged in every major distribution, and since v1.3.0 offers hybrid post-quantum recipients of its own. Moving from age to HIDE trades those for hybrid signatures, encrypted metadata, a multi-device identity log and epoch erasure — and for an unaudited 0.x format. There is no interoperability: a HIDE container is not an age file and never will be; you re-encrypt.

Every `hide` flag below was checked against `hide --help` and each subcommand's `--help` on 0.6.2. Every `hide` invocation needs `--experimental`; `--quiet` additionally suppresses the warning banner for scripts.

## Command mapping

| Task | age | HIDE |
| --- | --- | --- |
| Generate a key | `age-keygen -o key.txt` | `hide --experimental keygen --secret alice.hide-key --public alice.hide-pub` — also writes `alice.hide-pub.sign`; secret is passphrase-sealed by default |
| Generate an unprotected key (tests only) | `age-keygen -o key.txt` (always plaintext) | `hide --experimental keygen --secret k.hide-key --public k.hide-pub --insecure-plaintext` |
| Generate a post-quantum key | `age-keygen -pq -o key.txt` | not needed; every HIDE key is X-Wing (X25519 + ML-KEM-768) |
| Print the public key | `age-keygen -y key.txt` | `hide --experimental share alice.hide-pub` (pasteable text); or `keygen --armor` at creation |
| Encrypt to a recipient | `age -r age1… -o f.age f` | `hide --experimental encrypt f --recipient alice.hide-pub --output f.hide` |
| Encrypt to several recipients | `age -r A -r B -o f.age f` | `hide --experimental encrypt f --recipient a.hide-pub --recipient b.hide-pub --output f.hide` (max 64) |
| Recipients from a file | `age -R recipients.txt …` | no equivalent; repeat `--recipient` (see script below) |
| Encrypt with a passphrase | `age -p -o f.age f` | no equivalent; HIDE encrypts to keys only. Seal the *key* with a passphrase instead |
| Decrypt | `age -d -i key.txt -o f f.age` | `hide --experimental open f.hide --secret alice.hide-key --output f` — refuses to overwrite `f` |
| Decrypt to stdout | `age -d -i key.txt f.age` | no equivalent for files; `open` requires `--output`. `unseal` prints text messages |
| ASCII-armored output | `age -a -r … -o f.age f` | `hide --experimental seal "text" --recipient alice.hide-pub` for short messages, printed as pasteable text; `--output` to write a file. No armor for file containers |
| Decrypt armored text | `age -d -i key.txt f.age` | `hide --experimental unseal message.txt --secret alice.hide-key` (omit the path to read stdin) |
| Sign | — (age has no signatures) | `hide --experimental sign f --secret alice.hide-key` → `f.hide-sig`; or `encrypt … --sign alice.hide-key` to sign inside the container |
| Verify | — | `hide --experimental verify f --signer alice.hide-pub.sign [--signature f.hide-sig]` |
| Inspect a file | `age-inspect f.age` | `hide --experimental info f.hide` — also describes key files and detached signatures |
| Change key passphrase | re-encrypt the identity file with `age -p` | `hide --experimental passwd --secret alice.hide-key` |
| Encrypt to an SSH key | `age -R ~/.ssh/id_ed25519.pub …` | **not supported.** `hide ssh-key` and `hide agent` are for SSH *login* with a HIDE identity, not for encrypting to SSH keys |
| Encrypt to a GitHub user's keys | `curl https://github.com/user.keys \| age -R - …` | not supported |
| Hardware token | `age-plugin-yubikey` | not supported |
| Multi-device identity | — | `identity-create`, `identity-enrol`, `identity-revoke`, `identity-show` |
| Key rotation with erasure | — | `epoch-init`, `epoch-show` (public history; the CLI does not yet persist the secret) |

## Format differences

| | age | HIDE |
| --- | --- | --- |
| Header | Text stanzas, one per recipient, `-> X25519 …`; MAC over header | Deterministic CBOR, one stanza per recipient with no recipient identifier; HMAC-SHA256 over `preamble ‖ protected` |
| KEM | X25519 (default) or ML-KEM-768 + X25519 (`age1pq1…` recipients) | X-Wing (X25519 + ML-KEM-768) via HPKE, always |
| Payload | STREAM with ChaCha20-Poly1305, 64 KiB chunks | ChaCha20-Poly1305, 64 KiB chunks, counter + kind in the nonce, 91-byte AAD binding object id, header hash, counter, kind, length; explicit FINAL record |
| Metadata | None | Encrypted filename and media type; optional confidential signature |
| Signatures | None (integrity only) | Ed25519 + ML-DSA-65 hybrid, public or confidential placement; transcript binds recipient set and `SHA-256(plaintext)` |
| Recipient set integrity against a co-recipient | Not provided | Provided only when signed |
| Passphrase mode | scrypt recipient type | None; passphrases seal keys (Argon2id), not files |
| Identity | One key; files list identities | Master seed → encryption key + signing key; optional hash-linked device log with revocation and recovery key |
| Public key size | 62 characters (`age1…`); ~2000 for PQ | 1216 bytes binary (encryption); 1984 bytes (signing) |
| Per-recipient overhead | ~100 bytes; ~1.6 KB for PQ | 1168 bytes (1120-byte encapsulation + 48-byte wrapped CEK) |
| Interoperable implementations | Go, Rust, TypeScript | Rust; an independent Node verifier for the container only |
| Specification | C2SP `age-encryption.org/v1`, stable | [../spec/hide-0.1.md](../spec/hide-0.1.md), draft; may change before 1.0 ([stability.md](stability.md)) |

## What you lose

- **The audit.** age has been audited by a third party; HIDE has not ([audit-status.md](audit-status.md)).
- **Packaging.** age is in apt, dnf, brew, winget, pacman and more. HIDE's package-manager manifests exist in `packaging/` and are deliberately unpublished.
- **The plugin ecosystem.** YubiKey/PIV, TPM, and other `age-plugin-*` recipients have no HIDE equivalent.
- **SSH-key recipients.** Encrypting to `ssh-ed25519`/`ssh-rsa` public keys, and to a GitHub user's published keys, is an age convenience HIDE does not have. HIDE's SSH integration goes the other way: a HIDE identity can act as an ssh-agent for login (Ed25519 half only, not post-quantum).
- **Passphrase-encrypted files.** HIDE has no scrypt-style passphrase recipient.
- **Three implementations.** age has Go, Rust and TypeScript; HIDE has one Rust core behind nine bindings plus a Node container verifier.
- **Small keys.** A HIDE public key is 1216 bytes; an age key is 62 characters.
- **stdout decryption and overwrite.** `hide open` requires `--output` and refuses to overwrite, by design.

## What you gain

Hybrid signatures inside or beside the container; a recipient set that a co-recipient cannot rewrite when signed; encrypted filename and media type; an identity that spans devices with public, replayable revocation and an offline recovery key; epoch chains for forward security by erasure; RFC 6962 proofs; PQ-hybrid as the only mode. Details in [comparison.md](comparison.md).

## Interoperability

None. age cannot read a HIDE container and HIDE cannot read an age file. Migration means decrypting with age and encrypting with HIDE; keep the age files until every recipient has confirmed they can open the HIDE ones.

## Script sketch

Re-encrypts every `*.age` under a directory to a set of HIDE recipients. Plaintext is written to a private temporary directory and removed afterwards; the age original is kept. Requires `age` and `hide` on `PATH`.

```powershell
# migrate-age-to-hide.ps1
param(
    [Parameter(Mandatory)] [string] $Root,
    [Parameter(Mandatory)] [string] $AgeIdentity,          # age -i file
    [Parameter(Mandatory)] [string[]] $HideRecipients,     # *.hide-pub files
    [string] $SignWith                                     # optional *.hide-key
)
$ErrorActionPreference = 'Stop'
$staging = Join-Path ([IO.Path]::GetTempPath()) ("hide-migrate-" + [Guid]::NewGuid())
New-Item -ItemType Directory -Path $staging | Out-Null
try {
    $recipientArgs = foreach ($r in $HideRecipients) { '--recipient'; $r }
    $signArgs = if ($SignWith) { @('--sign', $SignWith) } else { @() }
    Get-ChildItem -Path $Root -Recurse -Filter '*.age' | ForEach-Object {
        $plain = Join-Path $staging $_.BaseName
        $out = Join-Path $_.DirectoryName ($_.BaseName + '.hide')
        if (Test-Path $out) { Write-Warning "exists, skipping: $out"; return }
        & age -d -i $AgeIdentity -o $plain $_.FullName
        if ($LASTEXITCODE -ne 0) { throw "age failed on $($_.FullName)" }
        & hide --experimental --quiet encrypt $plain @recipientArgs --output $out @signArgs
        if ($LASTEXITCODE -ne 0) { throw "hide failed on $($_.FullName)" }
        Remove-Item $plain
        Write-Host "ok  $($_.FullName) -> $out"
    }
} finally {
    Remove-Item -Recurse -Force $staging
}
```

Verify before deleting anything: `hide --experimental open f.hide --secret you.hide-key --output f.check` and compare with the age plaintext. Then decide, per file, whether the age original stays.
