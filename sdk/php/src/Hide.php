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

    public const SIGNATURE_LEN = 3373;
    public const VERIFYING_KEY_LEN = 1984;
    public const NONCE_LEN = 32;

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

    /**
     * Verifies a signature, throwing unless BOTH halves verify.
     *
     * Returns void rather than a bool: a caller who forgets to check a return
     * value would treat every failure as a pass.
     */
    public static function verify(
        string $publicKey,
        string $context,
        string $message,
        string $signature,
    ): void {
        $ffi = Binding::ffi();
        // All four are binary and length-prefixed; none may be a C string.
        $key = Binding::bytes($publicKey);
        $contextBytes = Binding::bytes($context);
        $messageBytes = Binding::bytes($message);
        $signatureBytes = Binding::bytes($signature);

        try {
            Binding::check($ffi->hide_verify_message(
                $ffi->cast('uint8_t *', $key),
                strlen($publicKey),
                $ffi->cast('uint8_t *', $contextBytes),
                strlen($context),
                $ffi->cast('uint8_t *', $messageBytes),
                strlen($message),
                $ffi->cast('uint8_t *', $signatureBytes),
                strlen($signature),
            ));
        } finally {
            Binding::release($key);
            Binding::release($contextBytes);
            Binding::release($messageBytes);
            Binding::release($signatureBytes);
        }
    }

    /**
     * Creates a challenge for a prover to answer.
     *
     * A detached signature proves possession at some point, to nobody in
     * particular, and can be replayed. A challenge binds a random nonce, an
     * audience and an expiry, so an answer is good once, here, now.
     */
    public static function newChallenge(string $audience, int $now, int $validFor): string
    {
        $ffi = Binding::ffi();
        $arg = Binding::cString($audience, 'audience');
        $out = Binding::emptyBuffer();
        try {
            Binding::check($ffi->hide_challenge_new($arg, $now, $validFor, \FFI::addr($out)));
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

    /**
     * Replays an identity log and returns how many devices it trusts now.
     *
     * Throws MalformedException for a log that does not decode and
     * AuthenticationException for one that decodes but does not verify — the
     * distinction that tells corruption from forgery. A count is returned
     * rather than a bool: a caller who forgot to check one would read every
     * failure as a pass.
     */
    public static function verifyIdentity(string $log, string $recoveryKey): int
    {
        $ffi = Binding::ffi();
        $bytes = Binding::bytes($log);
        $recovery = Binding::bytes($recoveryKey);
        $devices = $ffi->new('size_t');

        try {
            Binding::check($ffi->hide_identity_verify(
                $ffi->cast('uint8_t *', $bytes),
                strlen($log),
                $ffi->cast('uint8_t *', $recovery),
                strlen($recoveryKey),
                \FFI::addr($devices),
            ));
        } finally {
            Binding::release($bytes);
            Binding::release($recovery);
        }

        return (int) $devices->cdata;
    }

    /**
     * Whether the log trusts this device right now.
     *
     * A bool is right here — this is a membership query, not a cryptographic
     * check. The log is still verified first, so false means "not a member",
     * never "did not verify": that throws.
     */
    public static function identityTrustsDevice(
        string $log,
        string $recoveryKey,
        string $devicePublicKey,
    ): bool {
        $ffi = Binding::ffi();
        $bytes = Binding::bytes($log);
        $recovery = Binding::bytes($recoveryKey);
        $device = Binding::bytes($devicePublicKey);
        $trusted = $ffi->new('int32_t');
        $trusted->cdata = 0;

        try {
            Binding::check($ffi->hide_identity_trusts_device(
                $ffi->cast('uint8_t *', $bytes),
                strlen($log),
                $ffi->cast('uint8_t *', $recovery),
                strlen($recoveryKey),
                $ffi->cast('uint8_t *', $device),
                strlen($devicePublicKey),
                \FFI::addr($trusted),
            ));
        } finally {
            Binding::release($bytes);
            Binding::release($recovery);
            Binding::release($device);
        }

        return $trusted->cdata !== 0;
    }

    /** The head link: 32 bytes naming this exact history. */
    public static function identityHead(string $log, string $recoveryKey): string
    {
        $ffi = Binding::ffi();
        $bytes = Binding::bytes($log);
        $recovery = Binding::bytes($recoveryKey);
        $out = Binding::emptyBuffer();

        try {
            Binding::check($ffi->hide_identity_head(
                $ffi->cast('uint8_t *', $bytes),
                strlen($log),
                $ffi->cast('uint8_t *', $recovery),
                strlen($recoveryKey),
                \FFI::addr($out),
            ));
        } finally {
            Binding::release($bytes);
            Binding::release($recovery);
        }

        return Binding::take($out);
    }

    /** Verifies a published epoch history and returns how many epochs it holds. */
    public static function verifyEpochChain(string $chain): int
    {
        $ffi = Binding::ffi();
        $bytes = Binding::bytes($chain);
        $epochs = $ffi->new('size_t');

        try {
            Binding::check($ffi->hide_epoch_verify(
                $ffi->cast('uint8_t *', $bytes),
                strlen($chain),
                \FFI::addr($epochs),
            ));
        } finally {
            Binding::release($bytes);
        }

        return (int) $epochs->cdata;
    }

    /**
     * The public key a sender should encrypt to for this epoch.
     *
     * The chain is verified first, so a key is never returned from a history
     * that does not hold together. An epoch beyond the chain throws
     * InvalidArgumentException.
     */
    public static function epochPublicKey(string $chain, int $epoch): string
    {
        $ffi = Binding::ffi();
        $bytes = Binding::bytes($chain);
        $out = Binding::emptyBuffer();

        try {
            Binding::check($ffi->hide_epoch_public_key(
                $ffi->cast('uint8_t *', $bytes),
                strlen($chain),
                $epoch,
                \FFI::addr($out),
            ));
        } finally {
            Binding::release($bytes);
        }

        return Binding::take($out);
    }

    /**
     * Checks that $leaf is entry $index of a log of $size entries under $root.
     *
     * $path is the concatenated 32-byte hashes; any other length throws
     * InvalidArgumentException. Returns void, for the same reason verify()
     * does.
     */
    public static function verifyInclusion(
        string $leaf,
        int $index,
        int $size,
        string $path,
        string $root,
    ): void {
        $ffi = Binding::ffi();
        $leafBytes = Binding::bytes($leaf);
        $pathBytes = Binding::bytes($path);
        $rootBytes = Binding::bytes($root);

        try {
            Binding::check($ffi->hide_transparency_verify_inclusion(
                $ffi->cast('uint8_t *', $leafBytes),
                strlen($leaf),
                $index,
                $size,
                $ffi->cast('uint8_t *', $pathBytes),
                strlen($path),
                $ffi->cast('uint8_t *', $rootBytes),
                strlen($root),
            ));
        } finally {
            Binding::release($leafBytes);
            Binding::release($pathBytes);
            Binding::release($rootBytes);
        }
    }

    /**
     * Checks that $oldRoot really is the root the log had before it grew to
     * $newRoot. This is the check that catches a rewritten history.
     */
    public static function verifyConsistency(
        int $oldSize,
        int $newSize,
        string $path,
        string $oldRoot,
        string $newRoot,
    ): void {
        $ffi = Binding::ffi();
        $pathBytes = Binding::bytes($path);
        $oldBytes = Binding::bytes($oldRoot);
        $newBytes = Binding::bytes($newRoot);

        try {
            Binding::check($ffi->hide_transparency_verify_consistency(
                $oldSize,
                $newSize,
                $ffi->cast('uint8_t *', $pathBytes),
                strlen($path),
                $ffi->cast('uint8_t *', $oldBytes),
                strlen($oldRoot),
                $ffi->cast('uint8_t *', $newBytes),
                strlen($newRoot),
            ));
        } finally {
            Binding::release($pathBytes);
            Binding::release($oldBytes);
            Binding::release($newBytes);
        }
    }
}
