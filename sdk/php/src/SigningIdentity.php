<?php

declare(strict_types=1);

namespace HideProtocol;

/**
 * A signing key. The seed stays inside the native library and is never exposed
 * to PHP — there is deliberately no accessor for it.
 *
 * Release it with close(); it is also released when the object is collected.
 */
final class SigningIdentity
{
    private ?\FFI\CData $handle;

    private function __construct(\FFI\CData $handle)
    {
        $this->handle = $handle;
    }

    /**
     * Creates an identity and returns the sealed key file to store.
     *
     * One seed backs both encryption and signing, so there is a single thing
     * to back up. A forgotten passphrase cannot be recovered: there is no escrow.
     */
    public static function generate(string $passphrase): string
    {
        if (strlen($passphrase) < Hide::MIN_PASSPHRASE_LEN) {
            throw new \InvalidArgumentException(
                'the passphrase must be at least ' . Hide::MIN_PASSPHRASE_LEN . ' characters'
            );
        }

        $out = Binding::emptyBuffer();
        $secret = Binding::cString($passphrase, 'passphrase');
        try {
            Binding::check(Binding::ffi()->hide_identity_generate($secret, \FFI::addr($out)));
        } finally {
            Binding::release($secret);
        }

        return Binding::take($out);
    }

    /**
     * Loads a signing identity from a key file.
     *
     * A key file written before signatures existed carries no signing seed and
     * is refused rather than being silently downgraded.
     */
    public static function load(string $bytes, ?string $passphrase = null): self
    {
        $ffi = Binding::ffi();
        $handle = $ffi->new('void *');
        $data = Binding::bytes($bytes);
        $secret = Binding::cString($passphrase, 'passphrase');

        try {
            Binding::check($ffi->hide_signing_identity_open(
                $ffi->cast('uint8_t *', $data),
                strlen($bytes),
                $secret,
                \FFI::addr($handle),
            ));
        } finally {
            Binding::release($data);
            Binding::release($secret);
        }

        return new self($handle);
    }

    /** The shareable verifying key, for others to check signatures with. */
    public function publicKey(): string
    {
        $handle = $this->alive();
        $out = Binding::emptyBuffer();
        Binding::check(Binding::ffi()->hide_signing_identity_public($handle, \FFI::addr($out)));

        return Binding::take($out);
    }

    /**
     * Signs $message under $context.
     *
     * The context separates uses of one identity, so a signature made for one
     * purpose cannot be presented as another. Never let a remote party choose it.
     */
    public function sign(string $context, string $message): string
    {
        $ffi = Binding::ffi();
        $handle = $this->alive();
        // Binary and length-prefixed: a context or message may contain a NUL.
        $contextBytes = Binding::bytes($context);
        $messageBytes = Binding::bytes($message);
        $out = Binding::emptyBuffer();

        try {
            Binding::check($ffi->hide_sign_message(
                $handle,
                $ffi->cast('uint8_t *', $contextBytes),
                strlen($context),
                $ffi->cast('uint8_t *', $messageBytes),
                strlen($message),
                \FFI::addr($out),
            ));
        } finally {
            Binding::release($contextBytes);
            Binding::release($messageBytes);
        }

        return Binding::take($out);
    }

    /** Answers a challenge, proving possession to whoever issued it. */
    public function answer(string $challenge): string
    {
        $ffi = Binding::ffi();
        $handle = $this->alive();
        $data = Binding::bytes($challenge);
        $out = Binding::emptyBuffer();

        try {
            Binding::check($ffi->hide_challenge_answer(
                $handle,
                $ffi->cast('uint8_t *', $data),
                strlen($challenge),
                \FFI::addr($out),
            ));
        } finally {
            Binding::release($data);
        }

        return Binding::take($out);
    }

    public function close(): void
    {
        if ($this->handle !== null) {
            Binding::ffi()->hide_signing_identity_free($this->handle);
            $this->handle = null;
        }
    }

    public function isClosed(): bool
    {
        return $this->handle === null;
    }

    /** @internal */
    public function alive(): \FFI\CData
    {
        if ($this->handle === null) {
            throw new \InvalidArgumentException('this identity has been closed');
        }

        return $this->handle;
    }

    public function __destruct()
    {
        $this->close();
    }

    /**
     * var_dump() and print_r() go through this, so it must never render key
     * material — not even a fingerprint derived from it.
     *
     * @return array{state: string}
     */
    public function __debugInfo(): array
    {
        return ['state' => $this->handle === null ? 'closed' : 'open'];
    }

    public function __toString(): string
    {
        return 'HideProtocol\SigningIdentity(' . ($this->handle === null ? 'closed' : 'open') . ')';
    }
}
