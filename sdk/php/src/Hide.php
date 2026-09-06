<?php

declare(strict_types=1);

namespace HideProtocol;

/**
 * HIDE — encrypt to a person, not to a key.
 *
 * EXPERIMENTAL AND UNAUDITED. Do not protect data you cannot afford to lose or
 * expose. A successful decryption proves the data was not altered; it does NOT
 * prove who created it.
 */
final class Hide
{
    public const PUBLIC_KEY_LEN = 1216;
    public const MIN_PASSPHRASE_LEN = 8;

    private function __construct()
    {
    }

    public static function version(): string
    {
        // Static and library-owned; ext-ffi returns `const char *` as a string.
        return (string) Binding::ffi()->hide_version();
    }

    /**
     * Encrypts for 1..64 recipient public keys, each exactly PUBLIC_KEY_LEN
     * bytes, passed to the library as one flat concatenated buffer.
     *
     * @param list<string> $recipients
     */
    public static function encrypt(
        string $plaintext,
        array $recipients,
        ?string $filename = null,
        ?string $mediaType = null,
    ): string {
        $count = count($recipients);
        if ($count < 1 || $count > 64) {
            throw new \InvalidArgumentException('there must be between 1 and 64 recipients');
        }

        $joined = '';
        foreach ($recipients as $key) {
            if (strlen($key) !== self::PUBLIC_KEY_LEN) {
                throw new \InvalidArgumentException(
                    'a public key is ' . self::PUBLIC_KEY_LEN . ' bytes, got ' . strlen($key)
                );
            }
            $joined .= $key;
        }

        $ffi = Binding::ffi();
        $plain = Binding::bytes($plaintext);
        $keys = Binding::bytes($joined);
        $name = Binding::cString($filename, 'filename');
        $media = Binding::cString($mediaType, 'media type');
        $out = Binding::emptyBuffer();

        try {
            Binding::check($ffi->hide_encrypt(
                $ffi->cast('uint8_t *', $plain),
                strlen($plaintext),
                $ffi->cast('uint8_t *', $keys),
                $count,
                $name,
                $media,
                \FFI::addr($out),
            ));
        } finally {
            Binding::release($plain);
            Binding::release($keys);
            Binding::release($name);
            Binding::release($media);
        }

        return Binding::take($out);
    }

    /**
     * Decrypts and verifies.
     *
     * Nothing is returned unless the whole payload authenticates. The filename
     * is attacker-controlled: never use it to choose an output path.
     */
    public static function decrypt(string $container, SecretKey $secret): Decrypted
    {
        $ffi = Binding::ffi();
        $handle = $secret->alive();
        $data = Binding::bytes($container);
        $out = Binding::emptyBuffer();
        $filename = Binding::emptyBuffer();
        $mediaType = Binding::emptyBuffer();

        try {
            Binding::check($ffi->hide_decrypt(
                $ffi->cast('uint8_t *', $data),
                strlen($container),
                $handle,
                \FFI::addr($out),
                \FFI::addr($filename),
                \FFI::addr($mediaType),
            ));
        } finally {
            Binding::release($data);
        }

        return new Decrypted(
            Binding::take($out),
            Binding::takeOptionalText($filename),
            Binding::takeOptionalText($mediaType),
        );
    }

    /** Renders a public key as pasteable text. */
    public static function armorPublicKey(string $publicKey): string
    {
        $ffi = Binding::ffi();
        $data = Binding::bytes($publicKey);
        $out = Binding::emptyBuffer();
        try {
            Binding::check($ffi->hide_public_key_armor(
                $ffi->cast('uint8_t *', $data),
                strlen($publicKey),
                \FFI::addr($out),
            ));
        } finally {
            Binding::release($data);
        }

        return Binding::take($out);
    }

    public static function dearmorPublicKey(string $text): string
    {
        $ffi = Binding::ffi();
        $arg = Binding::cString($text, 'armored key');
        $out = Binding::emptyBuffer();
        try {
            Binding::check($ffi->hide_public_key_dearmor($arg, \FFI::addr($out)));
        } finally {
            Binding::release($arg);
        }

        return Binding::take($out);
    }

    /** Returns "raw" or "protected" without needing the passphrase. */
    public static function inspectKey(string $data): string
    {
        $ffi = Binding::ffi();
        $bytes = Binding::bytes($data);
        $kind = $ffi->new('int32_t');
        $kind->cdata = -1;
        try {
            Binding::check($ffi->hide_inspect_key(
                $ffi->cast('uint8_t *', $bytes),
                strlen($data),
                \FFI::addr($kind),
            ));
        } finally {
            Binding::release($bytes);
        }

        return $kind->cdata === Binding::KEY_PROTECTED ? 'protected' : 'raw';
    }
}
