<?php

/**
 * Exercises the PHP SDK against the real native library.
 *
 * A plain runner rather than PHPUnit: this repository is developed offline and
 * composer cannot fetch a test framework. Run it with
 *
 *     HIDE_LIBRARY=/path/to/libhide_ffi.so HIDE_ALLOW_LIBRARY_OVERRIDE=1 \
 *       php -d ffi.enable=1 tests/run.php
 *
 * It prints one line per test and exits non-zero if any of them failed.
 *
 * Called as `run.php --probe <autoload.php>` it only loads the native library
 * through that copy of the package and prints where it came from; the loading
 * tests run it as a child process.
 */

declare(strict_types=1);

$arguments = $_SERVER['argv'] ?? [];
if (($arguments[1] ?? null) === '--probe') {
    require $arguments[2];
    try {
        echo 'LIBRARY=' . \HideProtocol\Binding::libraryPath() . "\n";
        echo 'VERSION=' . \HideProtocol\Hide::version() . "\n";
        exit(0);
    } catch (\Throwable $error) {
        echo 'FAILED=' . $error::class . ': ' . $error->getMessage() . "\n";
        exit(3);
    }
}

require __DIR__ . '/../autoload.php';
require __DIR__ . '/fixtures.php';

use HideProtocol\AuthenticationException;
use HideProtocol\Binding;
use HideProtocol\ChallengeAudienceException;
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
/** @var array<string, string>|null The scratch layout the loading tests share; see stage(). */
$stage = null;

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

test('reserved protocol contexts are refused', function (): void {
    // Spec §15.2: the generic API must not mint protocol signatures.
    [$identity] = newIdentity();
    try {
        foreach (['HIDE/0.6 identity entry', 'HIDE/1.0 container', 'HIDE/'] as $context) {
            assertThrows(
                InvalidArgumentException::class,
                static fn () => $identity->sign($context, 'm'),
                "signed under reserved context {$context}",
            );
        }
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
    $spent = new SpentNonces('https://example.test');
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
    $spent = new SpentNonces('https://example.test');
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

test('an answer for another audience is refused', function (): void {
    // The record knows which service it answers for, so a challenge relayed
    // from elsewhere is refused even though the answer is a genuine signature
    // and would verify on its own.
    [$identity] = newIdentity();
    $spent = new SpentNonces('https://example.test');
    try {
        $public = $identity->publicKey();

        $relayed = Hide::newChallenge('https://elsewhere.test', 1000, 60);
        $answer = $identity->answer($relayed);
        // The same answer would be accepted by a record that answered to
        // https://elsewhere.test, so the refusal is about the audience alone.
        assertThrows(
            ChallengeAudienceException::class,
            static fn () => $spent->accept($relayed, $answer, $public, 1010),
            'an answer minted for another audience was accepted',
        );

        // The audience this record does answer to is unaffected.
        $ours = Hide::newChallenge('https://example.test', 1000, 60);
        $spent->accept($ours, $identity->answer($ours), $public, 1010);
    } finally {
        $spent->close();
        $identity->close();
    }
});

test('a record built with an empty audience accepts nothing', function (): void {
    // Failing closed: a verifier that forgot to name its audience refuses
    // every answer rather than accepting one minted for anyone.
    [$identity] = newIdentity();
    $spent = new SpentNonces('');
    try {
        $public = $identity->publicKey();
        $challenge = Hide::newChallenge('https://example.test', 1000, 60);
        assertThrows(
            ChallengeAudienceException::class,
            static fn () => $spent->accept($challenge, $identity->answer($challenge), $public, 1010),
            'an empty-audience record accepted an answer',
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

/**
 * Exactly AuthenticationException: a MalformedException here would mean the
 * check never got as far as verifying, and the test would pass for the wrong reason.
 */
function assertForgery(callable $body, string $message): void
{
    try {
        $body();
    } catch (Throwable $error) {
        if ($error::class === AuthenticationException::class) {
            return;
        }
        throw new AssertionError($message . ' — got ' . $error::class . ': ' . $error->getMessage());
    }

    throw new AssertionError($message . ' — nothing was thrown');
}

test('a pinned identity verifies against its root', function (): void {
    assertSame(
        2,
        Hide::verifyIdentityPinned(
            Fixtures::get('BINDING_IDENTITY_LOG'),
            Fixtures::get('BINDING_RECOVERY'),
            Fixtures::get('BINDING_ROOT'),
        ),
        'the pinned log trusts two devices',
    );
});

test('a hijacked log is refused even with a forged recovery binding', function (): void {
    assertForgery(
        static fn () => Hide::verifyIdentityPinned(
            Fixtures::get('BINDING_HIJACKED_LOG'),
            Fixtures::get('BINDING_RECOVERY'),
            Fixtures::get('BINDING_ROOT'),
        ),
        'a hijacked log verified under the real binding',
    );
    assertForgery(
        static fn () => Hide::verifyIdentityPinned(
            Fixtures::get('BINDING_HIJACKED_LOG'),
            Fixtures::get('BINDING_RECOVERY_FORGED'),
            Fixtures::get('BINDING_ROOT'),
        ),
        'a hijacked log verified under a forged binding',
    );
});

test('a log under another root is refused', function (): void {
    assertForgery(
        static fn () => Hide::verifyIdentityPinned(
            Fixtures::get('BINDING_IDENTITY_LOG'),
            Fixtures::get('BINDING_RECOVERY'),
            str_repeat("\0", 32),
        ),
        'a log verified against a root that is not its own',
    );
});

test('a truncated recovery binding is malformed', function (): void {
    assertThrows(
        MalformedException::class,
        static fn () => Hide::verifyIdentityPinned(
            Fixtures::get('BINDING_IDENTITY_LOG'),
            substr(Fixtures::get('BINDING_RECOVERY'), 0, 100),
            Fixtures::get('BINDING_ROOT'),
        ),
        'a truncated binding was not reported as malformed',
    );
});

test('an epoch chain bound to the identity verifies', function (): void {
    assertSame(
        3,
        Hide::verifyEpochChainBound(
            Fixtures::get('BINDING_IDENTITY_LOG'),
            Fixtures::get('BINDING_RECOVERY'),
            Fixtures::get('BINDING_ROOT'),
            Fixtures::get('EPOCH_CHAIN'),
            Fixtures::get('BINDING_EPOCH'),
        ),
        'the bound chain holds 3 epochs',
    );
});

test('an epoch chain bound by a stranger is refused', function (): void {
    assertForgery(
        static fn () => Hide::verifyEpochChainBound(
            Fixtures::get('BINDING_IDENTITY_LOG'),
            Fixtures::get('BINDING_RECOVERY'),
            Fixtures::get('BINDING_ROOT'),
            Fixtures::get('EPOCH_CHAIN'),
            Fixtures::get('BINDING_EPOCH_STRANGER'),
        ),
        'a stranger bound the chain',
    );
});

test('a checkpoint verifies and yields size and root', function (): void {
    $checkpoint = Hide::verifyCheckpoint(
        Fixtures::get('CHECKPOINT_3'),
        'log.example/hide',
        Fixtures::get('CHECKPOINT_LOG_KEY'),
    );
    assertSame(3, $checkpoint['size'], 'the checkpoint names a tree of size 3');
    assertSame(32, strlen($checkpoint['root']), 'the root is 32 bytes');
});

test('a checkpoint is refused when altered, misattributed or mis-keyed', function (): void {
    assertForgery(
        static fn () => Hide::verifyCheckpoint(
            Fixtures::get('CHECKPOINT_TAMPERED'),
            'log.example/hide',
            Fixtures::get('CHECKPOINT_LOG_KEY'),
        ),
        'a tampered note verified',
    );
    assertForgery(
        static fn () => Hide::verifyCheckpoint(
            Fixtures::get('CHECKPOINT_3'),
            'other.example',
            Fixtures::get('CHECKPOINT_LOG_KEY'),
        ),
        'a note verified under another origin',
    );
    assertForgery(
        static fn () => Hide::verifyCheckpoint(
            Fixtures::get('CHECKPOINT_3'),
            'log.example/hide',
            Fixtures::get('CHECKPOINT_WITNESS_KEY'),
        ),
        'a note verified under the witness key',
    );
});

test('an embedded NUL is refused in every C string', function (): void {
    // The core reads a `const char *` up to the first NUL, so a binding that
    // passed these through would seal a key under "longenough".
    $cut = 'longenough';
    $withNul = $cut . "\0rest";
    $secret = SecretKey::generate();
    try {
        $public = $secret->publicKey();
        $sealed = $secret->protect($cut);
        $identityFile = SigningIdentity::generate($cut);
        $armored = Hide::armorPublicKey($public);

        $cases = [
            'passphrase given to protect()' => static fn () => $secret->protect($withNul),
            'passphrase given to SecretKey::open()' => static fn () => SecretKey::open($sealed, $withNul),
            'passphrase given to SigningIdentity::generate()' =>
                static fn () => SigningIdentity::generate($withNul),
            'passphrase given to SigningIdentity::load()' =>
                static fn () => SigningIdentity::load($identityFile, $withNul),
            'filename' => static fn () => Hide::encrypt('x', [$public], "safe.txt\0evil"),
            'media type' => static fn () => Hide::encrypt('x', [$public], null, "text/pl\0ain"),
            'audience' => static fn () => Hide::newChallenge("app.example\0.evil.example", 1000, 60),
            'nonce record audience' => static fn () => new SpentNonces($withNul),
            'armored key' => static fn () => Hide::dearmorPublicKey($armored . "\0trailing"),
            'origin' => static fn () => Hide::verifyCheckpoint(
                Fixtures::get('CHECKPOINT_3'),
                "log.example/hide\0",
                Fixtures::get('CHECKPOINT_LOG_KEY'),
            ),
        ];
        foreach ($cases as $what => $call) {
            assertThrows(InvalidArgumentException::class, $call, "a NUL in the {$what} was accepted");
        }

        // The untruncated passphrase still opens the key, so the refusals
        // above are about the NUL and nothing else.
        $reopened = SecretKey::open($sealed, $cut);
        try {
            assertSame($public, $reopened->publicKey(), 'the key sealed under the real passphrase');
        } finally {
            $reopened->close();
        }
    } finally {
        $secret->close();
    }
});

test('a handle cannot be cloned', function (): void {
    // A copy would share the one native pointer, and both destructors would
    // free it.
    $secret = SecretKey::generate();
    [$identity] = newIdentity();
    $spent = new SpentNonces('https://example.test');
    try {
        $public = $secret->publicKey();
        $handles = ['SecretKey' => $secret, 'SigningIdentity' => $identity, 'SpentNonces' => $spent];
        foreach ($handles as $name => $handle) {
            assertThrows(Error::class, static fn () => clone $handle, "a {$name} was cloned");

            // From inside the class scope the engine does make the copy before
            // it calls __clone. The copy must fail AND must not take the
            // native handle with it when it is destroyed.
            $inside = Closure::bind(static fn (object $original) => clone $original, null, $handle::class);
            assertThrows(
                HideException::class,
                static fn () => $inside($handle),
                "a {$name} was cloned from inside its own class",
            );
            gc_collect_cycles();
        }

        // Every original still owns a live native object.
        assertSame($public, $secret->publicKey(), 'the key survives a refused clone');
        $signature = $identity->sign('clone', 'message');
        Hide::verify($identity->publicKey(), 'clone', 'message', $signature);
        $challenge = Hide::newChallenge('https://example.test', 1000, 60);
        $spent->accept($challenge, $identity->answer($challenge), $identity->publicKey(), 1010);
    } finally {
        $spent->close();
        $identity->close();
        $secret->close();
    }
});

test('a handle cannot be serialized or unserialized', function (): void {
    $secret = SecretKey::generate();
    [$identity] = newIdentity();
    $spent = new SpentNonces('https://example.test');
    try {
        $handles = ['SecretKey' => $secret, 'SigningIdentity' => $identity, 'SpentNonces' => $spent];
        foreach ($handles as $name => $handle) {
            assertThrows(HideException::class, static fn () => serialize($handle), "a {$name} was serialized");
            assertThrows(
                HideException::class,
                static fn () => unserialize(sprintf('O:%d:"%s":0:{}', strlen($handle::class), $handle::class)),
                "a {$name} was unserialized",
            );
            // The legacy payload shape, which would otherwise bypass the constructor.
            assertThrows(
                HideException::class,
                static fn () => unserialize(
                    sprintf('O:%d:"%s":1:{s:6:"handle";N;}', strlen($handle::class), $handle::class)
                ),
                "a {$name} was unserialized from a property list",
            );
        }
        gc_collect_cycles();

        assertSame(Hide::PUBLIC_KEY_LEN, strlen($secret->publicKey()), 'the key is still usable');
        assertSame(Hide::VERIFYING_KEY_LEN, strlen($identity->publicKey()), 'the identity is still usable');
    } finally {
        $spent->close();
        $identity->close();
        $secret->close();
    }
});

test('the core is the version this binding was written for', function (): void {
    assertSame(Binding::VERSION, Hide::version(), 'the core and the binding are the same release');

    $same = [['0.9.1', '0.9.1'], ['1.2.3', '1.2.3'], ['0.10.0', '0.10.0-rc.1'], ['0.10.0', '0.10.0+build.5']];
    foreach ($same as [$binding, $core]) {
        assertSame(null, Binding::versionMismatch($binding, $core), "binding {$binding} refused core {$core}");
    }
    $different = [
        '0.9.0', '0.10.1', '1.9.1', '0.9.10', '0.9', '0.9.1.0', '', 'v0.9.1', '0.+9.1', "0.9.1\n", 'garbage', null,
    ];
    foreach ($different as $core) {
        assertTrue(
            Binding::versionMismatch('0.9.1', $core) !== null,
            'binding 0.9.1 accepted core ' . var_export($core, true),
        );
    }
});

/**
 * Copies of this package and of the core in a scratch directory, so child
 * processes can be given a layout the test controls: one copy of the package
 * with the core in its lib/, one without, a spare core to point an override
 * at, and one planted where a lookup by bare name would find it.
 *
 * @return array{root: string, name: string, with: string, without: string, beside: string, spare: string, planted: string}
 */
function stage(): array
{
    global $stage;
    if ($stage !== null) {
        return $stage;
    }

    $library = Binding::libraryPath();
    $name = Binding::libraryNames()[0];
    $root = sys_get_temp_dir() . DIRECTORY_SEPARATOR . 'hide-php-test-' . bin2hex(random_bytes(6));
    $package = dirname(__DIR__);

    foreach (['with', 'without'] as $copy) {
        $target = $root . DIRECTORY_SEPARATOR . $copy;
        makeDirectory($target . DIRECTORY_SEPARATOR . 'src');
        copyFile($package . DIRECTORY_SEPARATOR . 'autoload.php', $target . DIRECTORY_SEPARATOR . 'autoload.php');
        foreach (glob($package . DIRECTORY_SEPARATOR . 'src' . DIRECTORY_SEPARATOR . '*.php') ?: [] as $source) {
            copyFile($source, $target . DIRECTORY_SEPARATOR . 'src' . DIRECTORY_SEPARATOR . basename($source));
        }
    }

    $copies = [
        'beside' => $root . DIRECTORY_SEPARATOR . 'with' . DIRECTORY_SEPARATOR . 'lib',
        'spare' => $root . DIRECTORY_SEPARATOR . 'spare',
        'planted' => $root . DIRECTORY_SEPARATOR . 'planted',
    ];
    foreach ($copies as $directory) {
        makeDirectory($directory);
        copyFile($library, $directory . DIRECTORY_SEPARATOR . $name);
    }

    $root = (string) realpath($root);
    $stage = [
        'root' => $root,
        'name' => $name,
        'with' => $root . DIRECTORY_SEPARATOR . 'with' . DIRECTORY_SEPARATOR . 'autoload.php',
        'without' => $root . DIRECTORY_SEPARATOR . 'without' . DIRECTORY_SEPARATOR . 'autoload.php',
        'beside' => (string) realpath($copies['beside'] . DIRECTORY_SEPARATOR . $name),
        'spare' => (string) realpath($copies['spare'] . DIRECTORY_SEPARATOR . $name),
        'planted' => (string) realpath($copies['planted']),
    ];

    return $stage;
}

function makeDirectory(string $path): void
{
    if (!is_dir($path) && !mkdir($path, 0700, true) && !is_dir($path)) {
        throw new RuntimeException("could not create {$path}");
    }
}

function copyFile(string $from, string $to): void
{
    if (!copy($from, $to)) {
        throw new RuntimeException("could not copy {$from} to {$to}");
    }
}

function removeTree(string $path): void
{
    if (is_dir($path) && !is_link($path)) {
        foreach (scandir($path) ?: [] as $entry) {
            if ($entry !== '.' && $entry !== '..') {
                removeTree($path . DIRECTORY_SEPARATOR . $entry);
            }
        }
        @rmdir($path);

        return;
    }
    @unlink($path);
}

/**
 * Runs the probe in a fresh PHP process and returns [exit code, output].
 *
 * Both override variables are removed from the child's environment first, so
 * it sees only what $set gives it.
 *
 * @param array<string, string> $set
 * @return array{0: int, 1: string}
 */
function probe(string $autoload, string $directory, array $set): array
{
    // Environment names are case-insensitive on Windows, where a second
    // "PATH" beside "Path" would make the child's value ambiguous.
    $same = PHP_OS_FAMILY === 'Windows' ? 'strcasecmp' : 'strcmp';
    $environment = getenv();
    $changes = ['HIDE_LIBRARY' => null, 'HIDE_ALLOW_LIBRARY_OVERRIDE' => null] + $set;
    foreach (array_keys($changes) as $name) {
        foreach (array_keys($environment) as $existing) {
            if ($same((string) $existing, $name) === 0) {
                unset($environment[$existing]);
            }
        }
    }
    foreach ($set as $name => $value) {
        $environment[$name] = $value;
    }

    $command = [PHP_BINARY, '-d', 'ffi.enable=1', __FILE__, '--probe', $autoload];
    $process = proc_open($command, [1 => ['pipe', 'w'], 2 => ['redirect', 1]], $pipes, $directory, $environment);
    if (!is_resource($process)) {
        throw new RuntimeException('the probe process did not start');
    }
    $output = (string) stream_get_contents($pipes[1]);
    fclose($pipes[1]);

    return [proc_close($process), $output];
}

/** @param array{0: int, 1: string} $child */
function assertLoadedFrom(string $expected, array $child, string $what): void
{
    [$exit, $output] = $child;
    $lines = array_map('trim', explode("\n", $output));
    assertTrue(
        $exit === 0 && in_array('LIBRARY=' . $expected, $lines, true),
        "{$what}: wanted LIBRARY={$expected}, got exit {$exit}, output: {$output}",
    );
}

test('the library search returns an absolute path or fails', function (): void {
    // The search in isolation: no process state, and nothing is loaded.
    $root = stage()['root'] . DIRECTORY_SEPARATOR . 'locate';
    $name = 'placeholder-core.bin';
    foreach (['beside', 'second', 'empty', 'elsewhere'] as $directory) {
        makeDirectory($root . DIRECTORY_SEPARATOR . $directory);
    }
    $beside = $root . DIRECTORY_SEPARATOR . 'beside';
    $second = $root . DIRECTORY_SEPARATOR . 'second';
    $empty = $root . DIRECTORY_SEPARATOR . 'empty';
    $elsewhere = $root . DIRECTORY_SEPARATOR . 'elsewhere';
    file_put_contents($beside . DIRECTORY_SEPARATOR . $name, 'x');
    file_put_contents($second . DIRECTORY_SEPARATOR . $name, 'x');
    file_put_contents($elsewhere . DIRECTORY_SEPARATOR . 'spare.bin', 'x');
    $besideFile = (string) realpath($beside . DIRECTORY_SEPARATOR . $name);
    $secondFile = (string) realpath($second . DIRECTORY_SEPARATOR . $name);
    $spare = (string) realpath($elsewhere . DIRECTORY_SEPARATOR . 'spare.bin');
    $missing = $elsewhere . DIRECTORY_SEPARATOR . 'missing.bin';

    assertSame($besideFile, Binding::locate(null, false, [$beside], [$name]), 'the copy beside the package');
    assertSame($secondFile, Binding::locate(null, false, [$empty, $second], [$name]), 'the second directory');
    assertSame($besideFile, Binding::locate(null, false, [$beside, $second], [$name]), 'the first directory wins');

    // The gate: without the opt-in an override is ignored, whatever it names.
    assertSame($besideFile, Binding::locate($spare, false, [$beside], [$name]), 'an override without the opt-in');
    assertSame($besideFile, Binding::locate($missing, false, [$beside], [$name]), 'a missing override without the opt-in');
    assertSame($spare, Binding::locate($spare, true, [$beside], [$name]), 'an override with the opt-in');
    assertSame($spare, Binding::locate($spare, true, [], []), 'an override needs no library name');

    // Nothing found is an exception that says so; a bare name is never left
    // for the system loader to resolve.
    $refusals = [
        'was not found' => static fn () => Binding::locate(null, false, [$empty], [$name]),
        'was ignored' => static fn () => Binding::locate($spare, false, [$empty], [$name]),
        'does not exist' => static fn () => Binding::locate($missing, true, [$beside], [$name]),
        // A directory is not a library.
        'which does not exist' => static fn () => Binding::locate($elsewhere, true, [$beside], [$name]),
    ];
    foreach ($refusals as $fragment => $call) {
        try {
            $found = $call();
        } catch (HideException $error) {
            assertTrue(
                str_contains($error->getMessage(), $fragment),
                "the failure does not say \"{$fragment}\": " . $error->getMessage(),
            );
            continue;
        }
        throw new AssertionError("a library was found where there is none: {$found}");
    }

    assertSame(['hide_ffi.dll'], Binding::libraryNamesFor('Windows'), 'the Windows name');
    assertSame(['libhide_ffi.dylib'], Binding::libraryNamesFor('Darwin'), 'the macOS name');
    assertSame(['libhide_ffi.so'], Binding::libraryNamesFor('Linux'), 'the Linux name');
    assertSame(['libhide_ffi.so'], Binding::libraryNamesFor('BSD'), 'the BSD name');
    assertThrows(
        HideException::class,
        static fn () => Binding::libraryNamesFor('Unknown'),
        'an unknown platform was given a library name',
    );
});

test('a library override without the opt-in is ignored', function (): void {
    // HIDE_LIBRARY replaces the whole cryptographic core. On its own it must
    // change nothing, whether it names a real library or not.
    $stage = stage();
    $missing = $stage['root'] . DIRECTORY_SEPARATOR . 'no-such-directory' . DIRECTORY_SEPARATOR . $stage['name'];

    assertLoadedFrom(
        $stage['beside'],
        probe($stage['with'], $stage['root'], ['HIDE_LIBRARY' => $missing]),
        'an override naming a missing file',
    );
    assertLoadedFrom(
        $stage['beside'],
        probe($stage['with'], $stage['root'], ['HIDE_LIBRARY' => $stage['spare']]),
        'an override naming a real file',
    );

    // With nothing beside the package the override is still not used, and
    // the failure is not about the path it names.
    [$exit, $output] = probe($stage['without'], $stage['root'], ['HIDE_LIBRARY' => $missing]);
    assertTrue(
        $exit === 3 && str_contains($output, 'was ignored') && !str_contains($output, 'does not exist'),
        "an override without the opt-in was consulted: exit {$exit}, output: {$output}",
    );
});

test('a library override with the opt-in is used', function (): void {
    $stage = stage();
    assertLoadedFrom(
        $stage['spare'],
        probe($stage['with'], $stage['root'], [
            'HIDE_LIBRARY' => $stage['spare'],
            'HIDE_ALLOW_LIBRARY_OVERRIDE' => '1',
        ]),
        'the override with the opt-in',
    );

    // Anything but exactly "1" is not an opt-in.
    assertLoadedFrom(
        $stage['beside'],
        probe($stage['with'], $stage['root'], [
            'HIDE_LIBRARY' => $stage['spare'],
            'HIDE_ALLOW_LIBRARY_OVERRIDE' => 'true',
        ]),
        'HIDE_ALLOW_LIBRARY_OVERRIDE=true',
    );
});

test('the library is never taken from the working directory or a search path', function (): void {
    // A copy of the core in the working directory and on every path the
    // system loader searches must not be picked up: whoever controls one of
    // those would otherwise choose the cryptographic core.
    $stage = stage();
    [$exit, $output] = probe($stage['without'], $stage['planted'], [
        'PATH' => $stage['planted'] . PATH_SEPARATOR . (string) getenv('PATH'),
        'LD_LIBRARY_PATH' => $stage['planted'],
        'DYLD_LIBRARY_PATH' => $stage['planted'],
    ]);
    assertTrue(
        $exit === 3 && str_contains($output, 'was not found') && !str_contains($output, 'LIBRARY='),
        "a planted library was loaded, or the failure was not the expected one: exit {$exit}, output: {$output}",
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

// Scratch copies in the temporary directory; nothing depends on them.
if ($stage !== null) {
    removeTree($stage['root']);
}

$total = count($tests);
echo "\n{$total} tests, {$failures} failed\n";
exit($failures === 0 ? 0 : 1);
