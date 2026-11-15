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
    /**
     * The HIDE release this binding was written against. A core of any other
     * major.minor.patch is refused at load: it would still load, and would
     * silently lack whatever the newer release enforces.
     */
    public const VERSION = '0.9.1';

    public const OK = 0;
    public const ERR_INVALID_ARGUMENT = 1;
    public const ERR_WRONG_PASSPHRASE = 2;
    public const ERR_NOT_A_KEY = 3;
    public const ERR_AUTHENTICATION = 4;
    public const ERR_NO_MATCHING_RECIPIENT = 5;
    public const ERR_MALFORMED = 6;
    public const ERR_TOO_LARGE = 7;
    public const ERR_CHALLENGE_EXPIRED = 8;
    public const ERR_CHALLENGE_REPLAYED = 9;

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

        int32_t hide_identity_generate(const char *passphrase, HideBuffer *out_key_file);
        int32_t hide_signing_identity_open(const uint8_t *data, size_t len,
                                          const char *passphrase, void **out_identity);
        int32_t hide_signing_identity_public(const void *identity, HideBuffer *out);
        void hide_signing_identity_free(void *identity);

        int32_t hide_sign_message(const void *identity,
                                  const uint8_t *context, size_t context_len,
                                  const uint8_t *message, size_t message_len,
                                  HideBuffer *out);
        int32_t hide_verify_message(const uint8_t *public_key, size_t public_key_len,
                                    const uint8_t *context, size_t context_len,
                                    const uint8_t *message, size_t message_len,
                                    const uint8_t *signature, size_t signature_len);

        int32_t hide_challenge_new(const char *audience, uint64_t now,
                                   uint64_t valid_for, HideBuffer *out);
        int32_t hide_challenge_answer(const void *identity,
                                      const uint8_t *challenge, size_t challenge_len,
                                      HideBuffer *out);

        void *hide_spent_nonces_new(void);
        void hide_spent_nonces_free(void *spent);
        int32_t hide_challenge_accept(void *spent,
                                      const uint8_t *challenge, size_t challenge_len,
                                      const uint8_t *signature, size_t signature_len,
                                      const uint8_t *public_key, size_t public_key_len,
                                      uint64_t now);

        int32_t hide_identity_verify(const uint8_t *log, size_t log_len,
                         const uint8_t *recovery, size_t recovery_len,
                         size_t *out_devices);
        int32_t hide_identity_trusts_device(const uint8_t *log, size_t log_len,
                            const uint8_t *recovery, size_t recovery_len,
                            const uint8_t *device_public,
                            size_t device_public_len,
                            int32_t *out_trusted);
        int32_t hide_identity_head(const uint8_t *log, size_t log_len,
                       const uint8_t *recovery, size_t recovery_len,
                       HideBuffer *out);

        int32_t hide_epoch_verify(const uint8_t *chain, size_t chain_len,
                      size_t *out_epochs);
        int32_t hide_epoch_public_key(const uint8_t *chain, size_t chain_len,
                          uint64_t epoch, HideBuffer *out);

        int32_t hide_transparency_verify_inclusion(const uint8_t *leaf, size_t leaf_len,
                               uint64_t index, uint64_t size,
                               const uint8_t *path, size_t path_len,
                               const uint8_t *root, size_t root_len);
        int32_t hide_transparency_verify_consistency(uint64_t old_size, uint64_t new_size,
                                 const uint8_t *path, size_t path_len,
                                 const uint8_t *old_root,
                                 size_t old_root_len,
                                 const uint8_t *new_root,
                                 size_t new_root_len);

                    int32_t hide_identity_verify_pinned(const uint8_t *log, size_t log_len,
                            const uint8_t *recovery_binding,
                            size_t recovery_binding_len,
                            const uint8_t *pinned_root,
                            size_t pinned_root_len,
                            size_t *out_devices);
                    int32_t hide_epoch_verify_bound(const uint8_t *log, size_t log_len,
                            const uint8_t *recovery_binding,
                            size_t recovery_binding_len,
                            const uint8_t *pinned_root, size_t pinned_root_len,
                            const uint8_t *chain, size_t chain_len,
                            const uint8_t *epoch_binding,
                            size_t epoch_binding_len, size_t *out_epochs);
                    int32_t hide_checkpoint_verify(const uint8_t *note, size_t note_len,
                               const char *origin,
                               const uint8_t *log_public, size_t log_public_len,
                               uint64_t *out_size, HideBuffer *out_root);
        C;

    private static ?\FFI $ffi = null;

    private static ?string $path = null;

    public static function ffi(): \FFI
    {
        if (self::$ffi === null) {
            $path = self::locateLibrary();
            // Asked through a declaration of its own, BEFORE the full one:
            // ext-ffi resolves every declared function when it loads, so a
            // stale core would otherwise be reported as whichever newer
            // function it lacks rather than as the wrong version.
            // Static and library-owned; ext-ffi returns `const char *` as a string.
            $version = (string) \FFI::cdef('const char *hide_version(void);', $path)->hide_version();
            $problem = self::versionMismatch(self::VERSION, $version);
            if ($problem !== null) {
                throw new HideException("{$problem} (loaded from {$path})");
            }
            $ffi = \FFI::cdef(self::CDEF, $path);
            self::$path = $path;
            self::$ffi = $ffi;
        }

        return self::$ffi;
    }

    /** The absolute path the core was loaded from. */
    public static function libraryPath(): string
    {
        self::ffi();

        return (string) self::$path;
    }

    /**
     * Null when the core is the release this binding was written for,
     * otherwise the reason it is refused. Only major.minor.patch is compared;
     * a pre-release or build suffix is ignored.
     */
    public static function versionMismatch(string $binding, ?string $core): ?string
    {
        $want = self::parseVersion($binding);
        $got = $core === null ? null : self::parseVersion($core);
        if ($want !== null && $want === $got) {
            return null;
        }

        return sprintf(
            'this binding is version %s but the HIDE native library reports "%s"; '
                . 'use the library built from the same release',
            $binding,
            $core ?? '',
        );
    }

    /** @return array{0: int, 1: int, 2: int}|null */
    private static function parseVersion(string $text): ?array
    {
        if (preg_match('/\A(\d{1,9})\.(\d{1,9})\.(\d{1,9})(?:[-+].*)?\z/s', $text, $parts) !== 1) {
            return null;
        }

        return [(int) $parts[1], (int) $parts[2], (int) $parts[3]];
    }

    /** @return list<string> */
    public static function libraryNames(): array
    {
        return self::libraryNamesFor(PHP_OS_FAMILY);
    }

    /**
     * @return list<string>
     */
    public static function libraryNamesFor(string $family): array
    {
        if ($family === 'Windows') {
            return ['hide_ffi.dll'];
        }
        if ($family === 'Darwin') {
            return ['libhide_ffi.dylib'];
        }
        if ($family === 'Unknown') {
            throw new HideException(
                'HIDE does not know the native library name for this platform (PHP_OS_FAMILY is '
                . "Unknown, PHP_OS is " . PHP_OS . '). Build the core with '
                . '`cargo build --release -p hide-ffi` and set HIDE_LIBRARY to it together with '
                . 'HIDE_ALLOW_LIBRARY_OVERRIDE=1.'
            );
        }

        return ['libhide_ffi.so'];
    }

    /**
     * HIDE_LIBRARY first (development only, requires HIDE_ALLOW_LIBRARY_OVERRIDE=1),
     * then beside the package. Always an absolute path, or an exception.
     */
    private static function locateLibrary(): string
    {
        $override = getenv('HIDE_LIBRARY');
        // HIDE_LIBRARY replaces the whole cryptographic core, so one settable env
        // var must not be enough: it is honoured only with an explicit second opt-in.
        $allowed = getenv('HIDE_ALLOW_LIBRARY_OVERRIDE') === '1';
        $override = is_string($override) ? $override : null;

        // With the opt-in the override decides, even on a platform whose
        // library name is unknown.
        $names = $allowed && $override !== null && $override !== '' ? [] : self::libraryNames();

        return self::locate($override, $allowed, [__DIR__, dirname(__DIR__) . '/lib'], $names);
    }

    /**
     * The search itself, free of process state so it can be tested directly.
     *
     * The library is never left to the system loader to find by name: that
     * search covers LD_LIBRARY_PATH / DYLD_LIBRARY_PATH, and on Windows the
     * working directory and PATH, so whoever controls any of those would
     * choose the cryptographic core.
     *
     * @param list<string> $directories
     * @param list<string> $names
     */
    public static function locate(?string $override, bool $allowed, array $directories, array $names): string
    {
        $note = '';
        if ($override !== null && $override !== '') {
            if ($allowed) {
                $resolved = is_file($override) ? realpath($override) : false;
                if ($resolved === false) {
                    throw new HideException(
                        "HIDE_LIBRARY points at {$override}, which does not exist."
                    );
                }

                return $resolved;
            }
            $note = ' HIDE_LIBRARY is set but was ignored, because HIDE_ALLOW_LIBRARY_OVERRIDE=1 is not.';
        }

        foreach ($directories as $directory) {
            foreach ($names as $name) {
                $candidate = $directory . DIRECTORY_SEPARATOR . $name;
                $resolved = is_file($candidate) ? realpath($candidate) : false;
                if ($resolved !== false) {
                    return $resolved;
                }
            }
        }

        throw new HideException(
            'the HIDE native library (' . implode(' / ', $names) . ') was not found for '
            . PHP_OS_FAMILY . ' (' . PHP_OS . ', ' . (PHP_INT_SIZE * 8) . '-bit) in '
            . implode(' or ', $directories)
            . '. This package does not bundle it, and never leaves it to the system loader to'
            . ' find by name: LD_LIBRARY_PATH, PATH and the working directory are not searched.'
            . ' Copy the library into one of those directories, or set HIDE_LIBRARY to the file'
            . ' produced by `cargo build --release -p hide-ffi` AND HIDE_ALLOW_LIBRARY_OVERRIDE=1.'
            . $note
        );
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
            self::ERR_AUTHENTICATION => new AuthenticationException($message),
            self::ERR_MALFORMED => new MalformedException($message),
            self::ERR_NO_MATCHING_RECIPIENT => new NoMatchingRecipientException($message),
            self::ERR_CHALLENGE_EXPIRED => new ChallengeExpiredException($message),
            self::ERR_CHALLENGE_REPLAYED => new ChallengeReplayedException($message),
            default => new HideException($message),
        };
    }
}
