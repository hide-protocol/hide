# HideProtocol — .NET SDK

A .NET binding to the HIDE encrypted-file protocol.

**EXPERIMENTAL AND UNAUDITED.** Do not use this to protect data you cannot
afford to lose or expose.

**A successful decryption proves the data was not altered. It does NOT prove
who created it.** There are no signatures: anyone holding a recipient's public
key can produce a container that decrypts cleanly for them. A decrypted
filename is likewise attacker-controlled — never use it to choose an output
path.

This SDK contains no cryptography. It binds to the same C ABI
(`crates/hide-ffi`) as every other HIDE SDK.

## Usage

```csharp
using HideProtocol;

using SecretKey secret = SecretKey.Generate();
byte[] publicKey = secret.PublicKey();

byte[] box = Hide.Encrypt("hello"u8, [publicKey], filename: "note.txt", mediaType: "text/plain");

Decrypted opened = Hide.Decrypt(box, secret);
// opened.Plaintext, opened.FileName, opened.MediaType
```

Storing a key on disk:

```csharp
byte[] sealedKey = secret.Protect("correct horse battery");   // >= 8 characters
File.WriteAllBytes("key.hide", sealedKey);

Hide.InspectKey(sealedKey);                                   // KeyKind.Protected
using SecretKey reopened = SecretKey.Open(sealedKey, "correct horse battery");
```

Sharing a public key as text:

```csharp
string text = Hide.ArmorPublicKey(publicKey);                 // "hide-public-key:..."
byte[] back = Hide.DearmorPublicKey(text);
```

## The native library

The managed assembly needs `hide_ffi` at runtime. It is located, in order:

1. the path in the `HIDE_LIBRARY` environment variable, if it names a file;
2. `hide_ffi.dll` / `libhide_ffi.dylib` / `libhide_ffi.so` beside the assembly;
3. the platform's default probing paths.

To run against a local build:

```powershell
cargo build -p hide-ffi
$env:HIDE_LIBRARY = 'E:\gh\HIDE\target\debug\hide_ffi.dll'
dotnet test
```

```bash
cargo build -p hide-ffi
export HIDE_LIBRARY="$PWD/target/debug/libhide_ffi.so"
dotnet test
```

## Notes

- `SecretKey` is `IDisposable`. Key material never crosses into managed memory,
  and `ToString()` never renders anything derived from it.
- `Encrypt` takes 1..64 recipients, each exactly 1216 bytes.
- Metadata returned by `Decrypt` is decoded from a length-prefixed buffer, so a
  value containing a NUL byte is returned whole rather than truncated.
- Metadata passed *into* `Encrypt` may not contain a NUL: the C ABI takes those
  arguments NUL-terminated, so such a value is rejected rather than silently cut.

Licensed under Apache-2.0.
