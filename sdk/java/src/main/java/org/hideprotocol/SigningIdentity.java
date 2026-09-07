package org.hideprotocol;

import java.lang.foreign.Arena;
import java.lang.foreign.MemorySegment;
import java.lang.foreign.ValueLayout;

/**
 * A signing key. The seed stays inside the native library and is never exposed
 * to Java; there is deliberately no accessor for it.
 *
 * <p>Implements {@link AutoCloseable}, so use it in try-with-resources. Holding
 * one open keeps key material in memory.
 */
public final class SigningIdentity implements AutoCloseable {

    private MemorySegment handle;

    SigningIdentity(MemorySegment handle) {
        this.handle = handle;
    }

    /**
     * Creates an identity, returning the sealed key file to store.
     *
     * <p>One seed backs both encryption and signing, so there is a single thing
     * to back up. A forgotten passphrase cannot be recovered: there is no
     * escrow.
     */
    public static byte[] generate(String passphrase) {
        if (passphrase.length() < Native.MIN_PASSPHRASE_LEN) {
            throw new IllegalArgumentException(
                    "the passphrase must be at least " + Native.MIN_PASSPHRASE_LEN + " characters");
        }
        try (Arena arena = Arena.ofConfined()) {
            MemorySegment out = Native.emptyBuffer(arena);
            MemorySegment phrase = arena.allocateFrom(passphrase);
            Hide.check((int) Native.IDENTITY_GENERATE.invokeExact(phrase, out));
            return Native.take(out);
        } catch (Throwable error) {
            throw Hide.wrap(error);
        }
    }

    /**
     * Loads a signing identity. Pass {@code null} for a raw key file.
     *
     * <p>A key file written before signatures existed carries no signing seed
     * and fails with {@link HideException.NotAKey} rather than being silently
     * downgraded.
     */
    public static SigningIdentity load(byte[] data, String passphrase) {
        try (Arena arena = Arena.ofConfined()) {
            MemorySegment bytes = arena.allocateFrom(ValueLayout.JAVA_BYTE, data);
            MemorySegment identity = arena.allocate(ValueLayout.ADDRESS);
            // Bound to a MemorySegment local: invokeExact matches static types,
            // and a ternary widening to Object would fail to link at runtime.
            MemorySegment phrase = passphrase == null
                    ? MemorySegment.NULL
                    : arena.allocateFrom(passphrase);
            Hide.check((int) Native.SIGNING_IDENTITY_OPEN.invokeExact(
                    bytes, (long) data.length, phrase, identity));
            return new SigningIdentity(identity.get(ValueLayout.ADDRESS, 0));
        } catch (Throwable error) {
            throw Hide.wrap(error);
        }
    }

    /** The shareable verifying key, for others to check signatures with. */
    public byte[] publicKey() {
        MemorySegment live = alive();
        try (Arena arena = Arena.ofConfined()) {
            MemorySegment out = Native.emptyBuffer(arena);
            Hide.check((int) Native.SIGNING_IDENTITY_PUBLIC.invokeExact(live, out));
            return Native.take(out);
        } catch (Throwable error) {
            throw Hide.wrap(error);
        }
    }

    /**
     * Signs {@code message} under {@code context}.
     *
     * <p>The context separates uses of one identity, so a signature made for
     * one purpose cannot be replayed as another. Never let a remote party
     * choose it.
     */
    public byte[] sign(byte[] context, byte[] message) {
        MemorySegment live = alive();
        try (Arena arena = Arena.ofConfined()) {
            MemorySegment out = Native.emptyBuffer(arena);
            MemorySegment ctx = arena.allocateFrom(ValueLayout.JAVA_BYTE, context);
            MemorySegment body = arena.allocateFrom(ValueLayout.JAVA_BYTE, message);
            Hide.check((int) Native.SIGN_MESSAGE.invokeExact(
                    live, ctx, (long) context.length, body, (long) message.length, out));
            return Native.take(out);
        } catch (Throwable error) {
            throw Hide.wrap(error);
        }
    }

    /** Answers a challenge, proving possession to whoever issued it. */
    public byte[] answer(byte[] challenge) {
        MemorySegment live = alive();
        try (Arena arena = Arena.ofConfined()) {
            MemorySegment out = Native.emptyBuffer(arena);
            MemorySegment bytes = arena.allocateFrom(ValueLayout.JAVA_BYTE, challenge);
            Hide.check((int) Native.CHALLENGE_ANSWER.invokeExact(
                    live, bytes, (long) challenge.length, out));
            return Native.take(out);
        } catch (Throwable error) {
            throw Hide.wrap(error);
        }
    }

    /** Releases the identity and zeroizes its seed. Safe to call twice. */
    @Override
    public void close() {
        if (handle != null) {
            try {
                Native.SIGNING_IDENTITY_FREE.invokeExact(handle);
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
        return handle == null ? "SigningIdentity[closed]" : "SigningIdentity";
    }

    MemorySegment alive() {
        if (handle == null) {
            throw new IllegalStateException("this identity has been closed");
        }
        return handle;
    }
}
