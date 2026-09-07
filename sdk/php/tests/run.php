<?php

/**
 * Exercises the PHP SDK against the real native library.
 *
 * A plain runner rather than PHPUnit: this repository is developed offline and
 * composer cannot fetch a test framework. Run it with
 *
 *     HIDE_LIBRARY=/path/to/libhide_ffi.so php -d ffi.enable=1 tests/run.php
 *
 * It prints one line per test and exits non-zero if any of them failed.
 */

declare(strict_types=1);

require __DIR__ . '/../autoload.php';
require __DIR__ . '/fixtures.php';

use HideProtocol\AuthenticationException;
use HideProtocol\ChallengeExpiredException;
use HideProtocol\ChallengeReplayedException;
use HideProtocol\Hide;
use HideProtocol\HideException;
use HideProtocol\MalformedException;
use HideProtocol\NoMatchingRecipientException;
use HideProtocol\NotAKeyException;
use HideProtocol\SecretKey;
use HideProtocol\SigningIdentity;
use HideProtocol\SpentNonces;
use HideProtocol\WrongPassphraseException;

/** @var list<array{0: string, 1: callable}> */
$tests = [];
$failures = 0;

function test(string $name, callable $body): void
{
    global $tests;
    $tests[] = [$name, $body];
}

function assertTrue(bool $condition, string $message): void
{
    if (!$condition) {
        throw new AssertionError($message);
    }
}

function assertSame(mixed $expected, mixed $actual, string $message): void
{
    if ($expected !== $actual) {
        throw new AssertionError(sprintf(
            '%s (expected %s, got %s)',
            $message,
            var_export(is_string($expected) ? substr($expected, 0, 40) : $expected, true),
            var_export(is_string($actual) ? substr($actual, 0, 40) : $actual, true),
        ));
    }
}

/** Asserts the callable throws $class (or a subclass). */
function assertThrows(string $class, callable $body, string $message): void
{
    try {
        $body();
    } catch (Throwable $error) {
        if ($error instanceof $class) {
            return;
        }
        throw new AssertionError($message . ' — got ' . $error::class . ': ' . $error->getMessage());
    }

    throw new AssertionError($message . ' — nothing was thrown');
}

test('the version is reported', function (): void {
    assertTrue(Hide::version() !== '', 'version must not be empty');
    assertTrue((bool) preg_match('/^\d+\.\d+/', Hide::version()), 'version looks like a version');
});

test('a round trip carries metadata', function (): void {
    $secret = SecretKey::generate();
    try {
        $public = $secret->publicKey();
        assertSame(Hide::PUBLIC_KEY_LEN, strlen($public), 'public key length');

        $payload = "nume,suma\nAna,9000\n";
        $box = Hide::encrypt($payload, [$public], 'salarii.csv', 'text/csv');
        assertTrue(!str_contains($box, 'Ana'), 'plaintext leaked into the container');

        $opened = Hide::decrypt($box, $secret);
        assertSame($payload, $opened->plaintext, 'plaintext round trips');
        assertSame('salarii.csv', $opened->filename, 'filename round trips');
        assertSame('text/csv', $opened->mediaType, 'media type round trips');
    } finally {
        $secret->close();
    }
});

test('metadata is read back by length, not as a C string', function (): void {
    $secret = SecretKey::generate();
    try {
        // Returned metadata is length-prefixed, so nothing here depends on a
        // terminator: a binding scanning for one would mangle the UTF-8.
        // No separators or a colon: the format restricts what a filename may be.
        $name = "raport-2026-șțăîâ.csv";
        $box = Hide::encrypt('x', [$secret->publicKey()], $name, 'text/csv');
        assertSame($name, Hide::decrypt($box, $secret)->filename, 'UTF-8 filename round trips');

        // A NUL cannot cross the `const char *` parameter, so it is refused
        // outright rather than silently truncating the caller's filename.
        assertThrows(
            InvalidArgumentException::class,
            static fn () => Hide::encrypt('x', [$secret->publicKey()], "a\0b"),
            'a NUL-bearing filename was accepted',
        );
    } finally {
        $secret->close();
    }
});

test('every single-byte mutation of a container is refused', function (): void {
    $secret = SecretKey::generate();
    try {
        $box = Hide::encrypt('confidential', [$secret->publicKey()]);
        $length = strlen($box);
        // Sampling the regions that matter rather than all ~1.3 kB, to keep the
        // suite fast; the Rust side tests every byte exhaustively.
        $offsets = [0, 8, 15, 40, intdiv($length, 2), $length - 20, $length - 1];
        foreach ($offsets as $offset) {
            $damaged = $box;
            $damaged[$offset] = chr(ord($damaged[$offset]) ^ 0x40);
            assertThrows(
                HideException::class,
                static fn () => Hide::decrypt($damaged, $secret),
                "a mutation at offset {$offset} was accepted",
            );
        }
    } finally {
        $secret->close();
    }
});

test('truncation and extension fail', function (): void {
    $secret = SecretKey::generate();
    try {
        $box = Hide::encrypt('payload', [$secret->publicKey()]);
        assertThrows(
            HideException::class,
            static fn () => Hide::decrypt(substr($box, 0, -1), $secret),
            'a truncated container was accepted',
        );
        assertThrows(
            HideException::class,
            static fn () => Hide::decrypt($box . "\0", $secret),
            'an extended container was accepted',
        );
    } finally {
        $secret->close();
    }
});

test('the wrong key cannot decrypt', function (): void {
    $alice = SecretKey::generate();
    $bob = SecretKey::generate();
    try {
        $box = Hide::encrypt('for alice', [$alice->publicKey()]);
        assertThrows(
            NoMatchingRecipientException::class,
            static fn () => Hide::decrypt($box, $bob),
            'bob decrypted a container addressed to alice',
        );
    } finally {
        $alice->close();
        $bob->close();
    }
});

test('many recipients share one payload', function (): void {
    $keys = [SecretKey::generate(), SecretKey::generate(), SecretKey::generate()];
    try {
        $box = Hide::encrypt('shared', array_map(
            static fn (SecretKey $key): string => $key->publicKey(),
            $keys,
        ));
        foreach ($keys as $index => $key) {
            assertSame('shared', Hide::decrypt($box, $key)->plaintext, "recipient {$index}");
        }
    } finally {
        foreach ($keys as $key) {
            $key->close();
        }
    }
});

test('protected keys round trip and reject a wrong passphrase', function (): void {
    $secret = SecretKey::generate();
    $public = $secret->publicKey();
    $sealed = $secret->protect('correct horse battery');
    $secret->close();

    assertSame('protected', Hide::inspectKey($sealed), 'a sealed key inspects as protected');

    assertThrows(
        WrongPassphraseException::class,
        static fn () => SecretKey::open($sealed, 'wrong passphrase'),
        'a wrong passphrase opened the key',
    );
    assertThrows(
        WrongPassphraseException::class,
        static fn () => SecretKey::open($sealed),
        'a missing passphrase opened the key',
    );

    $reopened = SecretKey::open($sealed, 'correct horse battery');
    try {
        assertSame($public, $reopened->publicKey(), 'the reopened key is the same key');
    } finally {
        $reopened->close();
    }
});

test('a short passphrase is refused', function (): void {
    $secret = SecretKey::generate();
    try {
        assertThrows(
            InvalidArgumentException::class,
            static fn () => $secret->protect('short'),
            'a short passphrase was accepted',
        );
    } finally {
        $secret->close();
    }
});

test('armor round trips', function (): void {
    $secret = SecretKey::generate();
    try {
        $public = $secret->publicKey();
        $text = Hide::armorPublicKey($public);
        assertTrue(str_starts_with($text, 'hide-public-key:'), 'armor is labelled');
        assertSame($public, Hide::dearmorPublicKey($text), 'armor round trips');
        assertThrows(
            HideException::class,
            static fn () => Hide::dearmorPublicKey('not a key'),
            'garbage was dearmored',
        );
    } finally {
        $secret->close();
    }
});

test('the recipient count and key length are bounded', function (): void {
    $secret = SecretKey::generate();
    try {
        $public = $secret->publicKey();
        assertThrows(
            InvalidArgumentException::class,
            static fn () => Hide::encrypt('x', []),
            'zero recipients were accepted',
        );
        assertThrows(
            InvalidArgumentException::class,
            static fn () => Hide::encrypt('x', array_fill(0, 65, $public)),
            '65 recipients were accepted',
        );
        assertThrows(
            InvalidArgumentException::class,
            static fn () => Hide::encrypt('x', ['too short']),
            'an undersized public key was accepted',
        );
        assertThrows(
            InvalidArgumentException::class,
            static fn () => Hide::encrypt('x', [$public . 'x']),
            'an oversized public key was accepted',
        );
        // The upper bound itself must still work.
        assertSame(
            'x',
            Hide::decrypt(Hide::encrypt('x', array_fill(0, 64, $public)), $secret)->plaintext,
            '64 recipients',
        );
    } finally {
        $secret->close();
    }
});

test('a closed key is unusable and never prints key material', function (): void {
    $secret = SecretKey::generate();
    $public = $secret->publicKey();
    $fingerprint = substr(bin2hex($public), 0, 16);

    $rendered = print_r($secret, true) . var_export($secret, true) . (string) $secret;
    assertTrue(str_contains($rendered, 'SecretKey'), 'the class is named');
    assertTrue(!str_contains($rendered, $fingerprint), 'key material leaked into output');

    ob_start();
    var_dump($secret);
    $dumped = (string) ob_get_clean();
    assertTrue(!str_contains($dumped, $fingerprint), 'key material leaked into var_dump');
    // Without __debugInfo, var_dump renders the raw native handle. That is not
    // key material, but it is internal state a dump has no business showing,
    // and its absence is what proves __debugInfo is in force.
    assertTrue(!str_contains($dumped, 'handle'), 'the native handle leaked into var_dump');
    assertTrue(!str_contains($dumped, 'CData'), 'a native pointer leaked into var_dump');
    assertTrue(str_contains($dumped, 'state'), 'var_dump shows only the safe state');

    $secret->close();
    $secret->close(); // idempotent
    assertTrue($secret->isClosed(), 'the key reports itself closed');
    assertThrows(
        InvalidArgumentException::class,
        static fn () => $secret->publicKey(),
        'a closed key was still usable',
    );
});

test('empty payloads are valid', function (): void {
    $secret = SecretKey::generate();
    try {
        $box = Hide::encrypt('', [$secret->publicKey()]);
        assertSame('', Hide::decrypt($box, $secret)->plaintext, 'an empty payload round trips');
        assertSame(null, Hide::decrypt($box, $secret)->filename, 'absent metadata is null');
    } finally {
        $secret->close();
    }
});

test('garbage is rejected rather than crashing', function (): void {
    $secret = SecretKey::generate();
    try {
        $inputs = ['', 'not a container', str_repeat("\0", 64), random_bytes(2048)];
        foreach ($inputs as $index => $input) {
            assertThrows(
                Throwable::class,
                static fn () => Hide::decrypt($input, $secret),
                "garbage input {$index} was accepted",
            );
        }
        foreach (['', 'x', str_repeat("\xff", 100)] as $index => $input) {
            assertThrows(
                Throwable::class,
                static fn () => SecretKey::open($input),
                "garbage key {$index} was accepted",
            );
        }
    } finally {
        $secret->close();
    }
});

/** An identity ready to sign, plus the sealed key file it came from. */
function newIdentity(string $passphrase = 'correct horse battery'): array
{
    $sealed = SigningIdentity::generate($passphrase);

    return [SigningIdentity::load($sealed, $passphrase), $sealed];
}

test('an identity signs and the signature verifies', function (): void {
    [$identity] = newIdentity();
    try {
        $public = $identity->publicKey();
        assertSame(Hide::VERIFYING_KEY_LEN, strlen($public), 'verifying key length');

        $signature = $identity->sign('invoice', 'total: 9000 RON');
        assertSame(Hide::SIGNATURE_LEN, strlen($signature), 'signature length');

        Hide::verify($public, 'invoice', 'total: 9000 RON', $signature);
    } finally {
        $identity->close();
    }
});

test('a changed message does not verify', function (): void {
    [$identity] = newIdentity();
    try {
        $public = $identity->publicKey();
        $signature = $identity->sign('invoice', 'total: 9000 RON');
        assertThrows(
            AuthenticationException::class,
            static fn () => Hide::verify($public, 'invoice', 'total: 9001 RON', $signature),
            'a tampered message verified',
        );
    } finally {
        $identity->close();
    }
});

test('a different context does not verify', function (): void {
    [$identity] = newIdentity();
    try {
        $public = $identity->publicKey();
        $signature = $identity->sign('invoice', 'total: 9000 RON');
        assertThrows(
            AuthenticationException::class,
            static fn () => Hide::verify($public, 'receipt', 'total: 9000 RON', $signature),
            'a signature verified under another context',
        );
    } finally {
        $identity->close();
    }
});

test('one identity cannot be impersonated by another', function (): void {
    [$alice] = newIdentity();
    [$mallory] = newIdentity('another passphrase entirely');
    try {
        $forged = $mallory->sign('invoice', 'total: 9000 RON');
        assertThrows(
            AuthenticationException::class,
            static fn () => Hide::verify($alice->publicKey(), 'invoice', 'total: 9000 RON', $forged),
            'mallory signed as alice',
        );
    } finally {
        $alice->close();
        $mallory->close();
    }
});

test('an encryption-only key file cannot sign', function (): void {
    $secret = SecretKey::generate();
    $sealed = $secret->protect('correct horse battery');
    $secret->close();

    // Predates signatures, so it carries no signing seed: refused rather than
    // silently downgraded to an invented one.
    assertThrows(
        NotAKeyException::class,
        static fn () => SigningIdentity::load($sealed, 'correct horse battery'),
        'an encryption-only key produced a signing identity',
    );
});

test('a challenge is accepted once and refused when replayed', function (): void {
    [$identity] = newIdentity();
    $spent = new SpentNonces();
    try {
        $public = $identity->publicKey();
        $challenge = Hide::newChallenge('https://example.test', 1000, 60);
        $answer = $identity->answer($challenge);
        assertSame(Hide::SIGNATURE_LEN, strlen($answer), 'an answer is a signature');

        $spent->accept($challenge, $answer, $public, 1010);
        assertThrows(
            ChallengeReplayedException::class,
            static fn () => $spent->accept($challenge, $answer, $public, 1020),
            'a replayed answer was accepted',
        );
    } finally {
        $spent->close();
        $identity->close();
    }
});

test('an answer after the window has expired', function (): void {
    [$identity] = newIdentity();
    $spent = new SpentNonces();
    try {
        $challenge = Hide::newChallenge('https://example.test', 1000, 60);
        $answer = $identity->answer($challenge);
        assertThrows(
            ChallengeExpiredException::class,
            static fn () => $spent->accept($challenge, $answer, $identity->publicKey(), 2000),
            'an expired answer was accepted',
        );
    } finally {
        $spent->close();
        $identity->close();
    }
});

test('an identity log reports the devices it trusts', function (): void {
    // Four events: create, enrol phone, enrol laptop, revoke laptop.
    assertSame(
        2,
        Hide::verifyIdentity(Fixtures::get('IDENTITY_LOG'), Fixtures::get('IDENTITY_RECOVERY')),
        'the log trusts two devices',
    );
});

test('a revoked device is no longer trusted', function (): void {
    assertTrue(
        Hide::identityTrustsDevice(
            Fixtures::get('IDENTITY_LOG'),
            Fixtures::get('IDENTITY_RECOVERY'),
            Fixtures::get('IDENTITY_DEVICE_PHONE'),
        ),
        'the enrolled phone is not trusted',
    );
    assertTrue(
        !Hide::identityTrustsDevice(
            Fixtures::get('IDENTITY_LOG'),
            Fixtures::get('IDENTITY_RECOVERY'),
            Fixtures::get('IDENTITY_DEVICE_LAPTOP'),
        ),
        'a revoked laptop is still trusted',
    );
});

test('a tampered log is refused', function (): void {
    assertThrows(
        AuthenticationException::class,
        static fn () => Hide::verifyIdentity(
            Fixtures::get('IDENTITY_TAMPERED'),
            Fixtures::get('IDENTITY_RECOVERY'),
        ),
        'a tampered log verified',
    );
    // Bytes that do not decode at all are a different failure from bytes that
    // decode and do not verify.
    assertThrows(
        MalformedException::class,
        static fn () => Hide::verifyIdentity('not a log', Fixtures::get('IDENTITY_RECOVERY')),
        'undecodable bytes were not reported as malformed',
    );
});

test('the head names this exact history', function (): void {
    $head = Hide::identityHead(Fixtures::get('IDENTITY_LOG'), Fixtures::get('IDENTITY_RECOVERY'));
    assertSame(32, strlen($head), 'the head is 32 bytes');
    assertSame(Fixtures::get('IDENTITY_HEAD'), $head, 'the head names this history');
});

test('an epoch chain verifies and yields keys', function (): void {
    assertSame(3, Hide::verifyEpochChain(Fixtures::get('EPOCH_CHAIN')), 'the chain holds 3 epochs');
    assertSame(
        Fixtures::get('EPOCH_PUBLIC_KEY_1'),
        Hide::epochPublicKey(Fixtures::get('EPOCH_CHAIN'), 1),
        'epoch 1 public key',
    );
});

test('an epoch beyond the chain is refused', function (): void {
    assertThrows(
        InvalidArgumentException::class,
        static fn () => Hide::epochPublicKey(Fixtures::get('EPOCH_CHAIN'), 3),
        'an out-of-range epoch yielded a key',
    );
});

test('a spliced epoch chain does not verify', function (): void {
    assertThrows(
        AuthenticationException::class,
        static fn () => Hide::verifyEpochChain(Fixtures::get('EPOCH_BROKEN')),
        'a spliced chain verified',
    );
});

test('an inclusion proof verifies only for its own leaf', function (): void {
    Hide::verifyInclusion(
        Fixtures::get('LEAF'),
        3,
        8,
        Fixtures::get('INCLUSION_PATH'),
        Fixtures::get('TREE_ROOT'),
    );
    assertThrows(
        AuthenticationException::class,
        static fn () => Hide::verifyInclusion(
            Fixtures::get('OTHER_LEAF'),
            3,
            8,
            Fixtures::get('INCLUSION_PATH'),
            Fixtures::get('TREE_ROOT'),
        ),
        'a foreign leaf was included',
    );
});

test('a path that is not whole hashes is refused', function (): void {
    $truncated = substr(Fixtures::get('INCLUSION_PATH'), 0, -1);
    assertThrows(
        InvalidArgumentException::class,
        static fn () => Hide::verifyInclusion(
            Fixtures::get('LEAF'),
            3,
            8,
            $truncated,
            Fixtures::get('TREE_ROOT'),
        ),
        'a partial hash was accepted',
    );
});

test('a consistency proof catches a rewritten history', function (): void {
    Hide::verifyConsistency(
        5,
        8,
        Fixtures::get('CONSISTENCY_PATH'),
        Fixtures::get('ROOT_AT_5'),
        Fixtures::get('TREE_ROOT'),
    );
    // Same size, one entry silently replaced.
    assertThrows(
        AuthenticationException::class,
        static fn () => Hide::verifyConsistency(
            5,
            8,
            Fixtures::get('CONSISTENCY_PATH'),
            Fixtures::get('ROOT_AT_5'),
            Fixtures::get('REWRITTEN_ROOT'),
        ),
        'a rewritten history was consistent',
    );
});

foreach ($tests as [$name, $body]) {
    try {
        $body();
        echo "ok   {$name}\n";
    } catch (Throwable $error) {
        $failures++;
        echo "FAIL {$name}\n     " . $error::class . ': ' . $error->getMessage() . "\n";
    }
}

$total = count($tests);
echo "\n{$total} tests, {$failures} failed\n";
exit($failures === 0 ? 0 : 1);
