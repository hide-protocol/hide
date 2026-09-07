package org.hideprotocol;

import java.lang.foreign.Arena;
import java.lang.foreign.MemorySegment;
import java.lang.foreign.ValueLayout;

/**
 * The verifier's record of answered challenges.
 *
 * <p>Replay can only be detected by the verifier: a replayed answer is a
 * genuine signature and nothing about it is invalid on its own. This must
 * therefore outlive a single request.
 */
public final class SpentNonces implements AutoCloseable {

    private MemorySegment handle;

    public SpentNonces() {
        try {
            MemorySegment allocated = (MemorySegment) Native.SPENT_NONCES_NEW.invokeExact();
            if (allocated.equals(MemorySegment.NULL)) {
                throw new HideException("could not allocate the nonce record");
            }
            this.handle = allocated;
        } catch (Throwable error) {
            throw Hide.wrap(error);
        }
    }

    /**
     * Accepts an answer exactly once.
     *
     * <p>Throws {@link HideException.ChallengeReplayed} the second time,
     * {@link HideException.ChallengeExpired} after the window, and
     * {@link HideException.Authentication} if it does not verify.
     */
    public void accept(byte[] challenge, byte[] signature, byte[] publicKey, long now) {
        MemorySegment live = alive();
        try (Arena arena = Arena.ofConfined()) {
            MemorySegment bytes = arena.allocateFrom(ValueLayout.JAVA_BYTE, challenge);
            MemorySegment sig = arena.allocateFrom(ValueLayout.JAVA_BYTE, signature);
            MemorySegment key = arena.allocateFrom(ValueLayout.JAVA_BYTE, publicKey);
            Hide.check((int) Native.CHALLENGE_ACCEPT.invokeExact(
                    live, bytes, (long) challenge.length,
                    sig, (long) signature.length,
                    key, (long) publicKey.length, now));
        } catch (Throwable error) {
            throw Hide.wrap(error);
        }
    }

    /** Releases the record. Safe to call twice. */
    @Override
    public void close() {
        if (handle != null) {
            try {
                Native.SPENT_NONCES_FREE.invokeExact(handle);
            } catch (Throwable error) {
                throw Hide.wrap(error);
            } finally {
                handle = null;
            }
        }
    }

    private MemorySegment alive() {
        if (handle == null) {
            throw new IllegalStateException("this record has been closed");
        }
        return handle;
    }
}
