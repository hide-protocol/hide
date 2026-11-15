<?php

declare(strict_types=1);

namespace HideProtocol;

/**
 * The verifier's record of answered challenges.
 *
 * Replay can only be detected by the verifier: a replayed answer is a genuine
 * signature and nothing about it is invalid on its own. This must therefore
 * outlive a single request.
 *
 * The record lives in this PHP process's memory and cannot be cloned,
 * serialized or shared. Under PHP-FPM or mod_php every request starts with an
 * empty record, so on its own it does NOT stop an answer being replayed in a
 * later request: there, also keep the nonce of every accepted challenge in
 * shared storage (a database row or a cache entry with a unique key, kept
 * until the challenge expires) and refuse a challenge already recorded.
 */
final class SpentNonces
{
    // Null by default, so an instance made without the constructor
    // (unserialize, reflection) is simply closed rather than uninitialised.
    private ?\FFI\CData $handle = null;

    public function __construct()
    {
        $handle = Binding::ffi()->hide_spent_nonces_new();
        if ($handle === null) {
            throw new HideException('could not allocate the nonce record');
        }
        $this->handle = $handle;
    }

    /**
     * Private, so `clone $spent` is refused by the engine before any copy
     * exists. If it is reached from inside the class scope anyway, $this is
     * the copy: it must forget the handle before failing, or its destructor
     * would free the record the original still owns.
     */
    private function __clone()
    {
        $this->handle = null;

        throw new HideException('a SpentNonces record cannot be cloned: the copy would share one native record');
    }

    /** @return array<string, mixed> */
    public function __serialize(): array
    {
        throw new HideException(
            'a SpentNonces record cannot be serialized: it exists only in this process'
        );
    }

    /** @param array<string, mixed> $data */
    public function __unserialize(array $data): void
    {
        throw new HideException(
            'a SpentNonces record cannot be unserialized: it exists only in this process'
        );
    }

    /**
     * Accepts an answer exactly once.
     *
     * Throws ChallengeReplayedException the second time,
     * ChallengeExpiredException after the window, and AuthenticationException
     * if it does not verify.
     */
    public function accept(string $challenge, string $signature, string $publicKey, int $now): void
    {
        $ffi = Binding::ffi();
        $handle = $this->alive();
        $challengeBytes = Binding::bytes($challenge);
        $signatureBytes = Binding::bytes($signature);
        $keyBytes = Binding::bytes($publicKey);

        try {
            Binding::check($ffi->hide_challenge_accept(
                $handle,
                $ffi->cast('uint8_t *', $challengeBytes),
                strlen($challenge),
                $ffi->cast('uint8_t *', $signatureBytes),
                strlen($signature),
                $ffi->cast('uint8_t *', $keyBytes),
                strlen($publicKey),
                $now,
            ));
        } finally {
            Binding::release($challengeBytes);
            Binding::release($signatureBytes);
            Binding::release($keyBytes);
        }
    }

    public function close(): void
    {
        if ($this->handle !== null) {
            Binding::ffi()->hide_spent_nonces_free($this->handle);
            $this->handle = null;
        }
    }

    public function isClosed(): bool
    {
        return $this->handle === null;
    }

    private function alive(): \FFI\CData
    {
        if ($this->handle === null) {
            throw new \InvalidArgumentException('this record has been closed');
        }

        return $this->handle;
    }

    public function __destruct()
    {
        $this->close();
    }
}
