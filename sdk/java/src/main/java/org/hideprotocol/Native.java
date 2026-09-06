package org.hideprotocol;

import java.lang.foreign.Arena;
import java.lang.foreign.FunctionDescriptor;
import java.lang.foreign.Linker;
import java.lang.foreign.MemoryLayout;
import java.lang.foreign.MemorySegment;
import java.lang.foreign.StructLayout;
import java.lang.foreign.SymbolLookup;
import java.lang.foreign.ValueLayout;
import java.lang.invoke.MethodHandle;
import java.lang.invoke.VarHandle;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.List;

/**
 * Binds the HIDE C core through the Foreign Function and Memory API, so there
 * is no JNI shim to compile and no second implementation of the cryptography.
 *
 * <p>Package-private on purpose: callers use {@link Hide} and {@link SecretKey}.
 */
final class Native {

    private Native() {
    }

    static final int OK = 0;
    static final int ERR_INVALID_ARGUMENT = 1;
    static final int ERR_WRONG_PASSPHRASE = 2;
    static final int ERR_NOT_A_KEY = 3;
    static final int ERR_AUTHENTICATION = 4;
    static final int ERR_NO_MATCHING_RECIPIENT = 5;
    static final int ERR_MALFORMED = 6;
    static final int ERR_TOO_LARGE = 7;

    static final int KEY_PROTECTED = 1;

    static final int PUBLIC_KEY_LEN = 1216;
    static final int MIN_PASSPHRASE_LEN = 8;

    /** Mirrors HideBuffer in hide.h. */
    static final StructLayout BUFFER = MemoryLayout.structLayout(
            ValueLayout.ADDRESS.withName("data"),
            ValueLayout.JAVA_LONG.withName("len"),
            ValueLayout.JAVA_LONG.withName("capacity")
    ).withName("HideBuffer");

    static final VarHandle BUFFER_DATA =
            BUFFER.varHandle(MemoryLayout.PathElement.groupElement("data"));
    static final VarHandle BUFFER_LEN =
            BUFFER.varHandle(MemoryLayout.PathElement.groupElement("len"));

    private static final Linker LINKER = Linker.nativeLinker();
    private static final SymbolLookup LOOKUP = load();

    static final MethodHandle VERSION = bind("hide_version",
            FunctionDescriptor.of(ValueLayout.ADDRESS));
    static final MethodHandle ERROR_MESSAGE = bind("hide_error_message",
            FunctionDescriptor.of(ValueLayout.ADDRESS, ValueLayout.JAVA_INT));
    static final MethodHandle BUFFER_FREE = bind("hide_buffer_free",
            FunctionDescriptor.ofVoid(ValueLayout.ADDRESS));

    static final MethodHandle KEYPAIR_GENERATE = bind("hide_keypair_generate",
            FunctionDescriptor.of(ValueLayout.JAVA_INT, ValueLayout.ADDRESS, ValueLayout.ADDRESS));
    static final MethodHandle INSPECT_KEY = bind("hide_inspect_key",
            FunctionDescriptor.of(ValueLayout.JAVA_INT, ValueLayout.ADDRESS,
                    ValueLayout.JAVA_LONG, ValueLayout.ADDRESS));
    static final MethodHandle SECRET_KEY_OPEN = bind("hide_secret_key_open",
            FunctionDescriptor.of(ValueLayout.JAVA_INT, ValueLayout.ADDRESS,
                    ValueLayout.JAVA_LONG, ValueLayout.ADDRESS, ValueLayout.ADDRESS));
    static final MethodHandle SECRET_KEY_PROTECT = bind("hide_secret_key_protect",
            FunctionDescriptor.of(ValueLayout.JAVA_INT, ValueLayout.ADDRESS,
                    ValueLayout.ADDRESS, ValueLayout.ADDRESS));
    static final MethodHandle SECRET_KEY_PUBLIC = bind("hide_secret_key_public",
            FunctionDescriptor.of(ValueLayout.JAVA_INT, ValueLayout.ADDRESS, ValueLayout.ADDRESS));
    static final MethodHandle SECRET_KEY_FREE = bind("hide_secret_key_free",
            FunctionDescriptor.ofVoid(ValueLayout.ADDRESS));

    static final MethodHandle PUBLIC_KEY_ARMOR = bind("hide_public_key_armor",
            FunctionDescriptor.of(ValueLayout.JAVA_INT, ValueLayout.ADDRESS,
                    ValueLayout.JAVA_LONG, ValueLayout.ADDRESS));
    static final MethodHandle PUBLIC_KEY_DEARMOR = bind("hide_public_key_dearmor",
            FunctionDescriptor.of(ValueLayout.JAVA_INT, ValueLayout.ADDRESS, ValueLayout.ADDRESS));

    static final MethodHandle ENCRYPT = bind("hide_encrypt",
            FunctionDescriptor.of(ValueLayout.JAVA_INT, ValueLayout.ADDRESS,
                    ValueLayout.JAVA_LONG, ValueLayout.ADDRESS, ValueLayout.JAVA_LONG,
                    ValueLayout.ADDRESS, ValueLayout.ADDRESS, ValueLayout.ADDRESS));
    static final MethodHandle DECRYPT = bind("hide_decrypt",
            FunctionDescriptor.of(ValueLayout.JAVA_INT, ValueLayout.ADDRESS,
                    ValueLayout.JAVA_LONG, ValueLayout.ADDRESS, ValueLayout.ADDRESS,
                    ValueLayout.ADDRESS, ValueLayout.ADDRESS));

    private static MethodHandle bind(String name, FunctionDescriptor descriptor) {
        return LINKER.downcallHandle(
                LOOKUP.find(name).orElseThrow(() ->
                        new UnsatisfiedLinkError("the HIDE library has no symbol " + name)),
                descriptor);
    }

    private static SymbolLookup load() {
        String property = System.getProperty("hide.library");
        String environment = System.getenv("HIDE_LIBRARY");
        for (String candidate : new String[] { property, environment }) {
            if (candidate != null && Files.exists(Path.of(candidate))) {
                return SymbolLookup.libraryLookup(Path.of(candidate), Arena.global());
            }
        }
        for (String name : libraryNames()) {
            try {
                return SymbolLookup.libraryLookup(name, Arena.global());
            } catch (IllegalArgumentException ignored) {
                // Try the next candidate.
            }
        }
        throw new UnsatisfiedLinkError(
                "the HIDE native library was not found. Set -Dhide.library=<path> or "
                        + "HIDE_LIBRARY to the file produced by `cargo build -p hide-ffi`.");
    }

    private static List<String> libraryNames() {
        String os = System.getProperty("os.name", "").toLowerCase();
        if (os.contains("win")) {
            return List.of("hide_ffi.dll");
        }
        if (os.contains("mac")) {
            return List.of("libhide_ffi.dylib");
        }
        return List.of("libhide_ffi.so");
    }

    /** Reads a C string of unknown length without over-reading it. */
    static String readCString(MemorySegment address) {
        return address.reinterpret(Long.MAX_VALUE).getString(0);
    }

    /** Copies a native buffer into a Java array, then frees the original. */
    static byte[] take(MemorySegment buffer) throws Throwable {
        try {
            MemorySegment data = (MemorySegment) BUFFER_DATA.get(buffer, 0L);
            long length = (long) BUFFER_LEN.get(buffer, 0L);
            if (data.equals(MemorySegment.NULL) || length == 0) {
                return new byte[0];
            }
            return data.reinterpret(length).toArray(ValueLayout.JAVA_BYTE);
        } finally {
            BUFFER_FREE.invokeExact(buffer);
        }
    }

    /** An empty buffer, so free() never reads uninitialised memory. */
    static MemorySegment emptyBuffer(Arena arena) {
        MemorySegment buffer = arena.allocate(BUFFER);
        buffer.fill((byte) 0);
        return buffer;
    }
}
