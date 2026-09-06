/*
 * HIDE — C API.
 *
 * EXPERIMENTAL AND UNAUDITED. Do not use this to protect data you cannot
 * afford to lose or expose. A successful decryption proves the data was not
 * altered; it does NOT prove who created it.
 *
 * Ownership rules, which every binding must follow:
 *
 *   - Buffers returned by this library are freed with hide_buffer_free.
 *     Never libc free() them. Everything the library returns is a
 *     length-prefixed buffer, including text: nothing relies on a caller
 *     scanning attacker-controlled bytes for a terminator.
 *   - Initialise a HideBuffer with hide_buffer_empty() before passing its
 *     address; free() reads the pointer it is given.
 *   - A HideSecretKey is opaque. There is deliberately no function that
 *     exports key material.
 *   - Every function returns HIDE_OK (0) or an error code. On error, output
 *     parameters are left untouched.
 */

#ifndef HIDE_H
#define HIDE_H

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

#define HIDE_OK                        0
#define HIDE_ERR_INVALID_ARGUMENT      1
#define HIDE_ERR_WRONG_PASSPHRASE      2
#define HIDE_ERR_NOT_A_KEY             3
#define HIDE_ERR_AUTHENTICATION        4
#define HIDE_ERR_NO_MATCHING_RECIPIENT 5
#define HIDE_ERR_MALFORMED             6
#define HIDE_ERR_TOO_LARGE             7
#define HIDE_ERR_PANIC                98
#define HIDE_ERR_INTERNAL             99

#define HIDE_KEY_RAW       0
#define HIDE_KEY_PROTECTED 1

#define HIDE_PUBLIC_KEY_LEN     1216
#define HIDE_MIN_PASSPHRASE_LEN 8

/* An owned byte buffer. Free with hide_buffer_free. */
typedef struct {
  uint8_t *data;
  size_t len;
  size_t capacity; /* internal; do not rely on this field */
} HideBuffer;

/* An opaque secret key. Free with hide_secret_key_free. */
typedef struct HideSecretKey HideSecretKey;

/* Static, must not be freed. */
const char *hide_error_message(int32_t code);
const char *hide_version(void);

HideBuffer hide_buffer_empty(void);
void hide_buffer_free(HideBuffer *buffer);

/* Keys. */
int32_t hide_keypair_generate(HideSecretKey **out_secret, HideBuffer *out_public);
int32_t hide_inspect_key(const uint8_t *data, size_t len, int32_t *out_kind);
int32_t hide_secret_key_open(const uint8_t *data, size_t len,
                             const char *passphrase /* NULL if raw */,
                             HideSecretKey **out_secret);
int32_t hide_secret_key_protect(const HideSecretKey *secret, const char *passphrase,
                                HideBuffer *out);
int32_t hide_secret_key_public(const HideSecretKey *secret, HideBuffer *out);
void hide_secret_key_free(HideSecretKey *secret);

/*
 * Public-key armor, for pasting into email or chat. The armored form is
 * returned as UTF-8 bytes in a buffer, not as a C string.
 */
int32_t hide_public_key_armor(const uint8_t *data, size_t len, HideBuffer *out);
int32_t hide_public_key_dearmor(const char *text, HideBuffer *out);

/*
 * Encrypt for 1..64 recipients. `recipients` is a flat array of
 * recipient_count keys, each exactly HIDE_PUBLIC_KEY_LEN bytes.
 * `filename` and `media_type` may be NULL.
 */
int32_t hide_encrypt(const uint8_t *plaintext, size_t plaintext_len,
                     const uint8_t *recipients, size_t recipient_count,
                     const char *filename, const char *media_type,
                     HideBuffer *out);

/*
 * Decrypt. Nothing is written to `out` unless the entire payload
 * authenticates, so a caller cannot act on unverified data.
 *
 * out_filename / out_media_type may be NULL. When set they receive UTF-8
 * bytes with an explicit length (empty when absent), freed like any buffer.
 * Metadata is length-prefixed rather than NUL-terminated because it is
 * attacker-controlled, and a length cannot be got wrong by scanning.
 *
 * A decrypted filename is attacker-controlled: never use it to choose an
 * output path.
 */
int32_t hide_decrypt(const uint8_t *container, size_t container_len,
                     const HideSecretKey *secret, HideBuffer *out,
                     HideBuffer *out_filename, HideBuffer *out_media_type);

#ifdef __cplusplus
} /* extern "C" */
#endif

#endif /* HIDE_H */
