<?php

declare(strict_types=1);

namespace HideProtocol;

/**
 * FFI binding to the HIDE C core.
 *
 * ext-ffi rather than a compiled extension: the package then works on any PHP
 * 8.1+ with no build step, and there is no second place where the ABI lives.
 *
 * @internal Not part of the public API.
 */
final class Binding
{
    public const OK = 0;
    public const ERR_INVALID_ARGUMENT = 1;
    public const ERR_WRONG_PASSPHRASE = 2;
    public const ERR_NOT_A_KEY = 3;
    public const ERR_AUTHENTICATION = 4;
    public const ERR_NO_MATCHING_RECIPIENT = 5;
    public const ERR_MALFORMED = 6;
    public const ERR_TOO_LARGE = 7;

    public const KEY_RAW = 0;
    public const KEY_PROTECTED = 1;

    /**
     * A hand-written subset of crates/hide-ffi/include/hide.h.
     *
     * The real header cannot be handed to FFI::load(): it contains
     * preprocessor directives and comments that ext-ffi does not parse. THIS
     * MUST BE KEPT IN SYNC WITH include/hide.h — a silent mismatch here is
     * memory corruption, not a compile error.
     *
     * HideSecretKey is opaque in the header, so it is declared as void* here;
     * the ABI is identical and PHP never needs its shape.
     */
    private const CDEF = <<<'C'
        typedef struct {
            uint8_t *data;
            size_t len;
            size_t capacity;
        } HideBuffer;

        const char *hide_error_message(int32_t code);
        const char *hide_version(void);

        HideBuffer hide_buffer_empty(void);
        void hide_buffer_free(HideBuffer *buffer);

        int32_t hide_keypair_generate(void **out_secret, HideBuffer *out_public);
        int32_t hide_inspect_key(const uint8_t *data, size_t len, int32_t *out_kind);
        int32_t hide_secret_key_open(const uint8_t *data, size_t len,
                                     const char *passphrase, void **out_secret);
        int32_t hide_secret_key_protect(const void *secret, const char *passphrase,
                                        HideBuffer *out);
        int32_t hide_secret_key_public(const void *secret, HideBuffer *out);
        void hide_secret_key_free(void *secret);

        int32_t hide_public_key_armor(const uint8_t *data, size_t len, HideBuffer *out);
        int32_t hide_public_key_dearmor(const char *text, HideBuffer *out);

        int32_t hide_encrypt(const uint8_t *plaintext, size_t plaintext_len,
                             const uint8_t *recipients, size_t recipient_count,
                             const char *filename, const char *media_type,
                             HideBuffer *out);

        int32_t hide_decrypt(const uint8_t *container, size_t container_len,
                             const void *secret, HideBuffer *out,
                             HideBuffer *out_filename, HideBuffer *out_media_type);
        C;

    private static ?\FFI $ffi = null;

    public static function ffi(): \FFI
    {
        return self::$ffi ??= \FFI::cdef(self::CDEF, self::locateLibrary());
    }

    /** @return list<string> */
    public static function libraryNames(): array
    {
        if (PHP_OS_FAMILY === 'Windows') {
            return ['hide_ffi.dll'];
        }
        if (PHP_OS_FAMILY === 'Darwin') {
            return ['libhide_ffi.dylib'];
        }

        return ['libhide_ffi.so'];
    }

    /**
     * HIDE_LIBRARY first, then beside the package, then the system loader.
     */
    private static function locateLibrary(): string
    {
        $names = self::libraryNames();

        $override = getenv('HIDE_LIBRARY');
        if (is_string($override) && $override !== '') {
            if (!is_file($override)) {
                throw new HideException(
                    "HIDE_LIBRARY points at {$override}, which does not exist."
                );
            }

            return $override;
        }

        foreach ([__DIR__, dirname(__DIR__) . '/lib'] as $directory) {
            foreach ($names as $name) {
                $candidate = $directory . DIRECTORY_SEPARATOR . $name;
                if (is_file($candidate)) {
                    return $candidate;
                }
            }
        }

        // Left to the system loader; a failure here surfaces as an FFI error.
        return $names[0];
    }

    /**
     * A HideBuffer owned by PHP, initialised as the header requires before its
     * address is handed to the library.
     */
    public static function emptyBuffer(): \FFI\CData
    {
        $ffi = self::ffi();
        $buffer = $ffi->new('HideBuffer');
        // Held in a variable first: taking the address of a call result is not sound.
        $empty = $ffi->hide_buffer_empty();
        \FFI::memcpy(\FFI::addr($buffer), \FFI::addr($empty), \FFI::sizeof($buffer));

        return $buffer;
    }

    /**
     * Copies a native buffer into a PHP string and frees the original.
     *
     * The explicit length is the whole point: everything the library returns
     * is length-prefixed, and metadata is attacker-controlled and may contain
     * a NUL. Decoding it as a C string would silently truncate.
     */
    public static function take(\FFI\CData $buffer): string
    {
        try {
            if ($buffer->data === null || $buffer->len === 0) {
                return '';
            }

            return \FFI::string(self::ffi()->cast('char *', $buffer->data), $buffer->len);
        } finally {
            self::ffi()->hide_buffer_free(\FFI::addr($buffer));
        }
    }

    /** Metadata arrives as length-prefixed UTF-8; empty means absent. */
    public static function takeOptionalText(\FFI\CData $buffer): ?string
    {
        $raw = self::take($buffer);

        return $raw === '' ? null : $raw;
    }

    /**
     * An owned copy of a PHP string as uint8_t[], binary-safe.
     *
     * A zero-length allocation is not valid C, so one byte is reserved and the
     * length passed to the library is still zero.
     */
    public static function bytes(string $value): \FFI\CData
    {
        $length = strlen($value);
        $data = self::ffi()->new('uint8_t[' . max(1, $length) . ']', false);
        if ($length > 0) {
            \FFI::memcpy($data, $value, $length);
        }

        return $data;
    }

    /**
     * A NUL-terminated copy for the few `const char *` parameters.
     *
     * These are caller-supplied text, never attacker-controlled output; an
     * embedded NUL would truncate, so it is refused rather than silently cut.
     */
    public static function cString(?string $value, string $what): ?\FFI\CData
    {
        if ($value === null) {
            return null;
        }
        if (str_contains($value, "\0")) {
            throw new \InvalidArgumentException("the {$what} must not contain a NUL byte");
        }

        $length = strlen($value);
        $data = self::ffi()->new('char[' . ($length + 1) . ']', false);
        if ($length > 0) {
            \FFI::memcpy($data, $value, $length);
        }
        $data[$length] = "\0";

        return $data;
    }

    /** Frees a buffer allocated with bytes()/cString(), which are unmanaged. */
    public static function release(?\FFI\CData $data): void
    {
        if ($data !== null) {
            \FFI::free($data);
        }
    }

    /** Raises the mapped exception unless the call succeeded. */
    public static function check(int $code): void
    {
        if ($code === self::OK) {
            return;
        }

        // Static and library-owned, not attacker data. ext-ffi materialises a
        // `const char *` return as a PHP string already.
        $message = (string) self::ffi()->hide_error_message($code);

        throw match ($code) {
            self::ERR_INVALID_ARGUMENT, self::ERR_TOO_LARGE => new \InvalidArgumentException($message),
            self::ERR_WRONG_PASSPHRASE => new WrongPassphraseException($message),
            self::ERR_NOT_A_KEY => new NotAKeyException($message),
            self::ERR_AUTHENTICATION, self::ERR_MALFORMED => new AuthenticationException($message),
            self::ERR_NO_MATCHING_RECIPIENT => new NoMatchingRecipientException($message),
            default => new HideException($message),
        };
    }
}
