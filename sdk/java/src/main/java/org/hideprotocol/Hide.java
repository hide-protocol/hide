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

    /** Metadata is empty rather than absent at the ABI; normalise it here. */
    private static String text(byte[] bytes) {
        return bytes.length == 0 ? null : new String(bytes, StandardCharsets.UTF_8);
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
            case Native.ERR_AUTHENTICATION, Native.ERR_MALFORMED ->
                    new HideException.Authentication(message);
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
