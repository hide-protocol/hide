# hide-ffi

The C ABI of the [HIDE](https://github.com/hide-protocol/hide) protocol, and
the single core every language binding (Python, Node, Go, Java, Ruby, PHP,
.NET) calls. No binding reimplements any cryptography: they all load this
library. Builds as `cdylib`, `staticlib` and `rlib`; the header is
`include/hide.h`.

Rules every caller must follow:

- Everything returned is a length-prefixed `HideBuffer`, freed with
  `hide_buffer_free` — never `free()`. Text is bytes with a length, so nothing
  scans attacker-controlled data for a terminator.
- `HideSecretKey` and `HideSigningIdentity` are opaque; there is deliberately
  no function that exports key material.
- Every function returns `HIDE_OK` (0) or an error code; outputs are untouched
  on error. A panic inside the library is reported as `HIDE_ERR_PANIC`, never
  allowed to unwind into the host process.

```c
#include "hide.h"

HideSecretKey *secret = NULL;
HideBuffer public_key = hide_buffer_empty();
if (hide_keypair_generate(&secret, &public_key) != HIDE_OK) { /* handle */ }

HideBuffer container = hide_buffer_empty();
int32_t rc = hide_encrypt((const uint8_t *)"hello", 5,
                          public_key.data, 1, "hello.txt", "text/plain", &container);

HideBuffer plaintext = hide_buffer_empty();
if (rc == HIDE_OK)
    rc = hide_decrypt(container.data, container.len, secret, &plaintext, NULL, NULL);

hide_buffer_free(&plaintext);
hide_buffer_free(&container);
hide_buffer_free(&public_key);
hide_secret_key_free(secret);
```

Nothing is written to the plaintext buffer unless the whole payload
authenticates, and a decrypted filename must never be used to choose an output
path. This is the only crate in the workspace that allows `unsafe`.

**Experimental and unaudited.** Licensed Apache-2.0.
