<?php

declare(strict_types=1);

namespace HideProtocol;

/**
 * A secret key. The bytes stay inside the native library and are never exposed
 * to PHP — there is deliberately no accessor for them.
 *
 * Release it with close(); it is also released when the object is collected.
 */
final class SecretKey
{
    private ?\FFI\CData $handle;

    private function __construct(\FFI\CData $handle)
    {
        $this->handle = $handle;
    }

    public static function generate(): self
    {
        $ffi = Binding::ffi();
        $handle = $ffi->new('void *');
        $public = Binding::emptyBuffer();

        try {
            Binding::check($ffi->hide_keypair_generate(\FFI::addr($handle), \FFI::addr($public)));
        } finally {
            $ffi->hide_buffer_free(\FFI::addr($public));
        }

        return new self($handle);
    }

    /** Opens a key file. A protected key without its passphrase fails. */
    public static function open(string $bytes, ?string $passphrase = null): self
    {
        $ffi = Binding::ffi();
        $handle = $ffi->new('void *');
        $data = Binding::bytes($bytes);
        $secret = Binding::cString($passphrase, 'passphrase');

        try {
            Binding::check($ffi->hide_secret_key_open(
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

    public function publicKey(): string
    {
        $handle = $this->alive();
        $out = Binding::emptyBuffer();
        Binding::check(Binding::ffi()->hide_secret_key_public($handle, \FFI::addr($out)));

        return Binding::take($out);
    }

    /**
     * Seals this key with a passphrase, for writing to disk.
     *
     * A forgotten passphrase cannot be recovered: there is no escrow.
     */
    public function protect(string $passphrase): string
    {
        $handle = $this->alive();
        if (strlen($passphrase) < Hide::MIN_PASSPHRASE_LEN) {
            throw new \InvalidArgumentException(
                'the passphrase must be at least ' . Hide::MIN_PASSPHRASE_LEN . ' characters'
            );
        }

        $out = Binding::emptyBuffer();
        $secret = Binding::cString($passphrase, 'passphrase');
        try {
            Binding::check(Binding::ffi()->hide_secret_key_protect($handle, $secret, \FFI::addr($out)));
        } finally {
            Binding::release($secret);
        }

        return Binding::take($out);
    }

    public function close(): void
    {
        if ($this->handle !== null) {
            Binding::ffi()->hide_secret_key_free($this->handle);
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
            throw new \InvalidArgumentException('this key has been closed');
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
        return 'HideProtocol\SecretKey(' . ($this->handle === null ? 'closed' : 'open') . ')';
    }
}
