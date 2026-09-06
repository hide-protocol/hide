<?php

declare(strict_types=1);

namespace HideProtocol;

/** A verified payload. Holding this object means it authenticated. */
final class Decrypted
{
    public function __construct(
        public readonly string $plaintext,
        public readonly ?string $filename = null,
        public readonly ?string $mediaType = null,
    ) {
    }
}
