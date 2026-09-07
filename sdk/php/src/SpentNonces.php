<?php

declare(strict_types=1);

namespace HideProtocol;

/**
 * The verifier's record of answered challenges.
 *
 * Replay can only be detected by the verifier: a replayed answer is a genuine
 * signature and nothing about it is invalid on its own. This must therefore
 * outlive a single request.
 */
final class SpentNonces
{
    private ?\FFI\CData $handle;

    public function __construct()
    {
        $handle = Binding::ffi()->hide_spent_nonces_new();
        if ($handle === null) {
            throw new HideException('could not allocate the nonce record');
        }
        $this->handle = $handle;
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
