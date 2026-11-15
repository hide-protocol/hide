<?php

declare(strict_types=1);

namespace HideProtocol;

/**
 * A secret key. The bytes stay inside the native library and are never exposed
 * to PHP — there is deliberately no accessor for them.
 *
 * Release it with close(); it is also released when the object is collected.
 *
 * It cannot be cloned or serialized: a copy would share the one native handle
 * and free it a second time.
 */
final class SecretKey
{
    // Null by default, so an instance made without the constructor
    // (unserialize, reflection) is simply closed rather than uninitialised.
    private ?\FFI\CData $handle = null;

    private function __construct(\FFI\CData $handle)
    {
        $this->handle = $handle;
    }

    /**
     * Private, so `clone $key` is refused by the engine before any copy
     * exists. If it is reached from inside the class scope anyway, $this is
     * the copy: it must forget the handle before failing, or its destructor
     * would free the key the original still owns.
     */
    private function __clone()
    {
        $this->handle = null;

        throw new HideException('a SecretKey cannot be cloned: the copy would share one native key');
    }

    /** @return array<string, mixed> */
    public function __serialize(): array
    {
        throw new HideException('a SecretKey cannot be serialized: use protect() to store a key');
    }

    /** @param array<string, mixed> $data */
    public function __unserialize(array $data): void
    {
        throw new HideException('a SecretKey cannot be unserialized: use SecretKey::open()');
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
        // Text first: a refused passphrase must not strand the unmanaged copy
        // of the key file made below.
        $secret = Binding::cString($passphrase, 'passphrase');
        $data = Binding::bytes($bytes);

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
