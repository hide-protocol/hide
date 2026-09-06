package org.hideprotocol;

import java.lang.foreign.Arena;
import java.lang.foreign.MemorySegment;
import java.lang.foreign.ValueLayout;

/**
 * A secret key. The bytes stay inside the native library and are never exposed
 * to Java; there is deliberately no accessor for them.
 *
 * <p>Implements {@link AutoCloseable}, so use it in try-with-resources. Holding
 * one open keeps key material in memory.
 */
public final class SecretKey implements AutoCloseable {

    private MemorySegment handle;

    SecretKey(MemorySegment handle) {
        this.handle = handle;
    }

    /** Creates a new key pair. */
    public static SecretKey generate() {
        try (Arena arena = Arena.ofConfined()) {
            MemorySegment secret = arena.allocate(ValueLayout.ADDRESS);
            MemorySegment publicKey = Native.emptyBuffer(arena);
            Hide.check((int) Native.KEYPAIR_GENERATE.invokeExact(secret, publicKey));
            Native.take(publicKey);
            return new SecretKey(secret.get(ValueLayout.ADDRESS, 0));
        } catch (Throwable error) {
            throw Hide.wrap(error);
        }
    }

    /**
     * Loads a key file. Pass {@code null} for a raw key; a protected key
     * without its passphrase fails rather than guessing.
     */
    public static SecretKey load(byte[] data, String passphrase) {
        try (Arena arena = Arena.ofConfined()) {
            MemorySegment bytes = arena.allocateFrom(ValueLayout.JAVA_BYTE, data);
            MemorySegment secret = arena.allocate(ValueLayout.ADDRESS);
                // Bound to a MemorySegment local: invokeExact matches static types,
                // and a ternary widening to Object would fail to link at runtime.
            MemorySegment phrase = passphrase == null
                    ? MemorySegment.NULL
                    : arena.allocateFrom(passphrase);
            Hide.check((int) Native.SECRET_KEY_OPEN.invokeExact(
                    bytes, (long) data.length, phrase, secret));
            return new SecretKey(secret.get(ValueLayout.ADDRESS, 0));
        } catch (Throwable error) {
            throw Hide.wrap(error);
        }
    }

    /** Derives the shareable public key. */
    public byte[] publicKey() {
        MemorySegment live = alive();
        try (Arena arena = Arena.ofConfined()) {
            MemorySegment out = Native.emptyBuffer(arena);
            Hide.check((int) Native.SECRET_KEY_PUBLIC.invokeExact(live, out));
            return Native.take(out);
        } catch (Throwable error) {
            throw Hide.wrap(error);
        }
    }

    /**
     * Seals this key with a passphrase, for writing to disk.
     *
     * <p>A forgotten passphrase cannot be recovered: there is no escrow.
     */
    public byte[] protect(String passphrase) {
        MemorySegment live = alive();
        if (passphrase.length() < Native.MIN_PASSPHRASE_LEN) {
            throw new IllegalArgumentException(
                    "the passphrase must be at least " + Native.MIN_PASSPHRASE_LEN + " characters");
        }
        try (Arena arena = Arena.ofConfined()) {
            MemorySegment out = Native.emptyBuffer(arena);
            Hide.check((int) Native.SECRET_KEY_PROTECT.invokeExact(
                    live, arena.allocateFrom(passphrase), out));
            return Native.take(out);
        } catch (Throwable error) {
            throw Hide.wrap(error);
        }
    }

    /** Releases the key and zeroizes its material. Safe to call twice. */
    @Override
    public void close() {
        if (handle != null) {
            try {
                Native.SECRET_KEY_FREE.invokeExact(handle);
            } catch (Throwable error) {
                throw Hide.wrap(error);
            } finally {
                handle = null;
            }
        }
    }

    /** Never renders key material, not even a fingerprint of it. */
    @Override
    public String toString() {
        return handle == null ? "SecretKey[closed]" : "SecretKey";
    }

    MemorySegment alive() {
        if (handle == null) {
            throw new IllegalStateException("this key has been closed");
        }
        return handle;
    }
}
