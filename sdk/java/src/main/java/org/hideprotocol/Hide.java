package org.hideprotocol;

import java.lang.foreign.Arena;
import java.lang.foreign.MemorySegment;
import java.lang.foreign.ValueLayout;
import java.nio.charset.StandardCharsets;

/**
 * HIDE — encrypt to a person, not to a key.
 *
 * <p><strong>EXPERIMENTAL AND UNAUDITED.</strong> Do not protect data you
 * cannot afford to lose or expose. A successful decryption proves the data was
 * not altered; it does <em>not</em> prove who created it.
 *
 * <pre>{@code
 * try (SecretKey secret = SecretKey.generate()) {
 *     byte[] box = Hide.encrypt("hello".getBytes(UTF_8),
 *                               List.of(secret.publicKey()), null, null);
 *     Hide.Decrypted opened = Hide.decrypt(box, secret);
 * }
 * }</pre>
 *
 * <p>Requires {@code --enable-native-access=ALL-UNNAMED} on Java 22+.
 */
public final class Hide {

    private Hide() {
    }

    /** The exact size of a HIDE public key. */
    public static final int PUBLIC_KEY_LEN = Native.PUBLIC_KEY_LEN;

    /** The exact size of a HIDE signature. */
    public static final int SIGNATURE_LEN = Native.SIGNATURE_LEN;

    /** The exact size of a shareable verifying key. */
    public static final int VERIFYING_KEY_LEN = Native.VERIFYING_KEY_LEN;

    /** The size of the random nonce inside a challenge. */
    public static final int NONCE_LEN = Native.NONCE_LEN;

    /** The shortest passphrase that will be accepted. */
    public static final int MIN_PASSPHRASE_LEN = Native.MIN_PASSPHRASE_LEN;

    /** A verified payload. Receiving one means it authenticated. */
    public record Decrypted(byte[] data, String filename, String mediaType) {
    }

    /** The version of the underlying native library. */
    public static String version() {
        try {
            return Native.readCString((MemorySegment) Native.VERSION.invokeExact());
        } catch (Throwable error) {
            throw wrap(error);
        }
    }

    /** Encrypts for 1..64 recipient public keys. */
    public static byte[] encrypt(byte[] plaintext, java.util.List<byte[]> recipients,
                                 String filename, String mediaType) {
        if (recipients.isEmpty() || recipients.size() > 64) {
            throw new IllegalArgumentException("there must be between 1 and 64 recipients");
        }
        byte[] joined = new byte[recipients.size() * PUBLIC_KEY_LEN];
        int offset = 0;
        for (byte[] key : recipients) {
            if (key.length != PUBLIC_KEY_LEN) {
                throw new IllegalArgumentException(
                        "a public key is " + PUBLIC_KEY_LEN + " bytes, got " + key.length);
            }
            System.arraycopy(key, 0, joined, offset, PUBLIC_KEY_LEN);
            offset += PUBLIC_KEY_LEN;
        }

        try (Arena arena = Arena.ofConfined()) {
            MemorySegment out = Native.emptyBuffer(arena);
            // invokeExact matches on static types, so a ternary that widens to
            // Object silently fails to link. Bind each argument first.
            MemorySegment name = filename == null
                ? MemorySegment.NULL
                : arena.allocateFrom(filename);
            MemorySegment type = mediaType == null
                ? MemorySegment.NULL
                : arena.allocateFrom(mediaType);
            int code = (int) Native.ENCRYPT.invokeExact(
                    arena.allocateFrom(ValueLayout.JAVA_BYTE, plaintext),
                    (long) plaintext.length,
                    arena.allocateFrom(ValueLayout.JAVA_BYTE, joined),
                    (long) recipients.size(),
                name, type, out);
            check(code);
            return Native.take(out);
        } catch (Throwable error) {
            throw wrap(error);
        }
    }

    /**
     * Decrypts and verifies. Nothing is returned unless the entire payload
     * authenticates.
     *
     * <p>The filename is attacker-controlled: never use it to build an output
     * path.
     */
    public static Decrypted decrypt(byte[] container, SecretKey secret) {
        MemorySegment key = secret.alive();
        try (Arena arena = Arena.ofConfined()) {
            MemorySegment out = Native.emptyBuffer(arena);
            MemorySegment filename = Native.emptyBuffer(arena);
            MemorySegment mediaType = Native.emptyBuffer(arena);

            int code = (int) Native.DECRYPT.invokeExact(
                    arena.allocateFrom(ValueLayout.JAVA_BYTE, container),
                    (long) container.length, key, out, filename, mediaType);
            check(code);

            return new Decrypted(
                    Native.take(out),
                    text(Native.take(filename)),
                    text(Native.take(mediaType)));
        } catch (Throwable error) {
            throw wrap(error);
        }
    }

    /** Renders a public key as pasteable text. */
    public static String armorPublicKey(byte[] publicKey) {
        try (Arena arena = Arena.ofConfined()) {
            MemorySegment out = Native.emptyBuffer(arena);
            check((int) Native.PUBLIC_KEY_ARMOR.invokeExact(
                    arena.allocateFrom(ValueLayout.JAVA_BYTE, publicKey),
                    (long) publicKey.length, out));
            return new String(Native.take(out), StandardCharsets.UTF_8);
        } catch (Throwable error) {
            throw wrap(error);
        }
    }

    /** Parses armored public-key text back into bytes. */
    public static byte[] dearmorPublicKey(String text) {
        try (Arena arena = Arena.ofConfined()) {
            MemorySegment out = Native.emptyBuffer(arena);
            check((int) Native.PUBLIC_KEY_DEARMOR.invokeExact(arena.allocateFrom(text), out));
            return Native.take(out);
        } catch (Throwable error) {
            throw wrap(error);
        }
    }

    /** Reports {@code "raw"} or {@code "protected"} without the passphrase. */
    public static String inspectKey(byte[] data) {
        try (Arena arena = Arena.ofConfined()) {
            MemorySegment kind = arena.allocate(ValueLayout.JAVA_INT);
            check((int) Native.INSPECT_KEY.invokeExact(
                    arena.allocateFrom(ValueLayout.JAVA_BYTE, data), (long) data.length, kind));
            return kind.get(ValueLayout.JAVA_INT, 0) == Native.KEY_PROTECTED ? "protected" : "raw";
        } catch (Throwable error) {
            throw wrap(error);
        }
    }

    /** Signs {@code message} under {@code context}. */
    public static byte[] sign(SigningIdentity identity, byte[] context, byte[] message) {
        return identity.sign(context, message);
    }

    /**
     * Throws unless both signature halves verify.
     *
     * <p>Returns nothing rather than a boolean: a caller who forgets to check
     * a return value would treat every failure as a pass.
     */
    public static void verify(byte[] publicKey, byte[] context, byte[] message,
                              byte[] signature) {
        try (Arena arena = Arena.ofConfined()) {
            MemorySegment key = arena.allocateFrom(ValueLayout.JAVA_BYTE, publicKey);
            MemorySegment ctx = arena.allocateFrom(ValueLayout.JAVA_BYTE, context);
            MemorySegment body = arena.allocateFrom(ValueLayout.JAVA_BYTE, message);
            MemorySegment sig = arena.allocateFrom(ValueLayout.JAVA_BYTE, signature);
            check((int) Native.VERIFY_MESSAGE.invokeExact(
                    key, (long) publicKey.length,
                    ctx, (long) context.length,
                    body, (long) message.length,
                    sig, (long) signature.length));
        } catch (Throwable error) {
            throw wrap(error);
        }
    }

    /**
     * Creates a challenge for a prover to answer.
     *
     * <p>A detached signature proves possession at some point, to nobody in
     * particular, and can be replayed. A challenge binds a nonce, an audience
     * and an expiry, so an answer is good once, here, now.
     */
    public static byte[] newChallenge(String audience, long now, long validFor) {
        try (Arena arena = Arena.ofConfined()) {
            MemorySegment out = Native.emptyBuffer(arena);
            MemorySegment name = arena.allocateFrom(audience);
            check((int) Native.CHALLENGE_NEW.invokeExact(name, now, validFor, out));
            return Native.take(out);
        } catch (Throwable error) {
            throw wrap(error);
        }
    }

    /** Metadata is empty rather than absent at the ABI; normalise it here. */
    private static String text(byte[] bytes) {
        return bytes.length == 0 ? null : new String(bytes, StandardCharsets.UTF_8);
    }

    /**
     * Replays an identity log and reports how many devices it trusts now.
     *
     * <p>Throws {@link HideException.Malformed} for a log that does not decode
     * and {@link HideException.Authentication} for one that decodes but does
     * not verify — the distinction that tells corruption from forgery. A count
     * is returned rather than a boolean: a caller who forgot to check one
     * would read every failure as a pass.
     */
    public static int verifyIdentity(byte[] log, byte[] recoveryKey) {
        try (Arena arena = Arena.ofConfined()) {
            MemorySegment devices = arena.allocate(ValueLayout.JAVA_LONG);
            check((int) Native.IDENTITY_VERIFY.invokeExact(
                    arena.allocateFrom(ValueLayout.JAVA_BYTE, log), (long) log.length,
                    arena.allocateFrom(ValueLayout.JAVA_BYTE, recoveryKey),
                    (long) recoveryKey.length, devices));
            return (int) devices.get(ValueLayout.JAVA_LONG, 0);
        } catch (Throwable error) {
            throw wrap(error);
        }
    }

    /**
     * Whether the log trusts this device right now.
     *
     * <p>A boolean is right here — this is a membership query, not a
     * cryptographic check. The log is still verified first, so {@code false}
     * means "not a member", never "did not verify": that throws.
     */
    public static boolean identityTrustsDevice(byte[] log, byte[] recoveryKey,
                                               byte[] devicePublicKey) {
        try (Arena arena = Arena.ofConfined()) {
            MemorySegment trusted = arena.allocate(ValueLayout.JAVA_INT);
            check((int) Native.IDENTITY_TRUSTS_DEVICE.invokeExact(
                    arena.allocateFrom(ValueLayout.JAVA_BYTE, log), (long) log.length,
                    arena.allocateFrom(ValueLayout.JAVA_BYTE, recoveryKey),
                    (long) recoveryKey.length,
                    arena.allocateFrom(ValueLayout.JAVA_BYTE, devicePublicKey),
                    (long) devicePublicKey.length, trusted));
            return trusted.get(ValueLayout.JAVA_INT, 0) != 0;
        } catch (Throwable error) {
            throw wrap(error);
        }
    }

    /** The head link: 32 bytes naming this exact history. */
    public static byte[] identityHead(byte[] log, byte[] recoveryKey) {
        try (Arena arena = Arena.ofConfined()) {
            MemorySegment out = Native.emptyBuffer(arena);
            check((int) Native.IDENTITY_HEAD.invokeExact(
                    arena.allocateFrom(ValueLayout.JAVA_BYTE, log), (long) log.length,
                    arena.allocateFrom(ValueLayout.JAVA_BYTE, recoveryKey),
                    (long) recoveryKey.length, out));
            return Native.take(out);
        } catch (Throwable error) {
            throw wrap(error);
        }
    }

    /** Verifies a published epoch history and reports how many epochs it holds. */
    public static int verifyEpochChain(byte[] chain) {
        try (Arena arena = Arena.ofConfined()) {
            MemorySegment epochs = arena.allocate(ValueLayout.JAVA_LONG);
            check((int) Native.EPOCH_VERIFY.invokeExact(
                    arena.allocateFrom(ValueLayout.JAVA_BYTE, chain), (long) chain.length,
                    epochs));
            return (int) epochs.get(ValueLayout.JAVA_LONG, 0);
        } catch (Throwable error) {
            throw wrap(error);
        }
    }

    /**
     * The public key a sender should encrypt to for {@code epoch}.
     *
     * <p>The chain is verified first, so a key is never returned from a
     * history that does not hold together. An epoch beyond the chain throws
     * {@link IllegalArgumentException}.
     */
    public static byte[] epochPublicKey(byte[] chain, long epoch) {
        try (Arena arena = Arena.ofConfined()) {
            MemorySegment out = Native.emptyBuffer(arena);
            check((int) Native.EPOCH_PUBLIC_KEY.invokeExact(
                    arena.allocateFrom(ValueLayout.JAVA_BYTE, chain), (long) chain.length,
                    epoch, out));
            return Native.take(out);
        } catch (Throwable error) {
            throw wrap(error);
        }
    }

    /**
     * Checks that {@code leaf} is entry {@code index} of a log of {@code size}
     * entries under {@code root}.
     *
     * <p>{@code path} is the concatenated 32-byte hashes; any other length
     * throws {@link IllegalArgumentException}. Nothing is returned, for the
     * same reason {@link #verify} returns nothing.
     */
    public static void verifyInclusion(byte[] leaf, long index, long size, byte[] path,
                                       byte[] root) {
        try (Arena arena = Arena.ofConfined()) {
            MemorySegment leafBytes = arena.allocateFrom(ValueLayout.JAVA_BYTE, leaf);
            MemorySegment pathBytes = arena.allocateFrom(ValueLayout.JAVA_BYTE, path);
            MemorySegment rootBytes = arena.allocateFrom(ValueLayout.JAVA_BYTE, root);
            check((int) Native.TRANSPARENCY_VERIFY_INCLUSION.invokeExact(
                    leafBytes, (long) leaf.length, index, size,
                    pathBytes, (long) path.length,
                    rootBytes, (long) root.length));
        } catch (Throwable error) {
            throw wrap(error);
        }
    }

    /**
     * Checks that {@code oldRoot} really is the root the log had before it grew
     * to {@code newRoot}. This is the check that catches a rewritten history.
     */
    public static void verifyConsistency(long oldSize, long newSize, byte[] path,
                                         byte[] oldRoot, byte[] newRoot) {
        try (Arena arena = Arena.ofConfined()) {
            MemorySegment pathBytes = arena.allocateFrom(ValueLayout.JAVA_BYTE, path);
            MemorySegment oldBytes = arena.allocateFrom(ValueLayout.JAVA_BYTE, oldRoot);
            MemorySegment newBytes = arena.allocateFrom(ValueLayout.JAVA_BYTE, newRoot);
            check((int) Native.TRANSPARENCY_VERIFY_CONSISTENCY.invokeExact(
                    oldSize, newSize,
                    pathBytes, (long) path.length,
                    oldBytes, (long) oldRoot.length,
                    newBytes, (long) newRoot.length));
        } catch (Throwable error) {
            throw wrap(error);
        }
    }

    static void check(int code) {
        if (code == Native.OK) {
            return;
        }
        String message;
        try {
            message = Native.readCString(
                    (MemorySegment) Native.ERROR_MESSAGE.invokeExact(code));
        } catch (Throwable error) {
            message = "error " + code;
        }
        throw switch (code) {
            case Native.ERR_WRONG_PASSPHRASE -> new HideException.WrongPassphrase(message);
            case Native.ERR_NOT_A_KEY -> new HideException.NotAKey(message);
            case Native.ERR_NO_MATCHING_RECIPIENT ->
                    new HideException.NoMatchingRecipient(message);
                case Native.ERR_AUTHENTICATION -> new HideException.Authentication(message);
                case Native.ERR_MALFORMED -> new HideException.Malformed(message);
                case Native.ERR_CHALLENGE_EXPIRED -> new HideException.ChallengeExpired(message);
                case Native.ERR_CHALLENGE_REPLAYED -> new HideException.ChallengeReplayed(message);
            case Native.ERR_INVALID_ARGUMENT, Native.ERR_TOO_LARGE ->
                    new IllegalArgumentException(message);
            default -> new HideException(message);
        };
    }

    /** Keeps unchecked exceptions intact rather than double-wrapping them. */
    static RuntimeException wrap(Throwable error) {
        if (error instanceof RuntimeException runtime) {
            return runtime;
        }
        return new HideException("hide: " + error);
    }
}
