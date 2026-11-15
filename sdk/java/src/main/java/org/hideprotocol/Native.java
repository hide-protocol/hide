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
import java.net.URISyntaxException;
import java.net.URL;
import java.nio.file.Files;
import java.nio.file.InvalidPathException;
import java.nio.file.Path;
import java.security.CodeSource;
import java.util.Objects;

/**
 * Binds the HIDE C core through the Foreign Function and Memory API, so there
 * is no JNI shim to compile and no second implementation of the cryptography.
 *
 * <p>Package-private on purpose: callers use {@link Hide} and {@link SecretKey}.
 */
final class Native {

    private Native() {
    }

    /**
     * The HIDE release this binding was written against. A core of any other
     * major.minor.patch is refused at load: it would still link, and would
     * silently lack whatever the newer release enforces.
     */
    static final String BINDING_VERSION = "0.9.1";

    static final int OK = 0;
    static final int ERR_INVALID_ARGUMENT = 1;
    static final int ERR_WRONG_PASSPHRASE = 2;
    static final int ERR_NOT_A_KEY = 3;
    static final int ERR_AUTHENTICATION = 4;
    static final int ERR_NO_MATCHING_RECIPIENT = 5;
    static final int ERR_MALFORMED = 6;
    static final int ERR_TOO_LARGE = 7;
        static final int ERR_CHALLENGE_EXPIRED = 8;
        static final int ERR_CHALLENGE_REPLAYED = 9;
        static final int ERR_CHALLENGE_AUDIENCE = 11;

    static final int KEY_PROTECTED = 1;

    static final int PUBLIC_KEY_LEN = 1216;
        static final int SIGNATURE_LEN = 3373;
        static final int VERIFYING_KEY_LEN = 1984;
        static final int NONCE_LEN = 32;
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
    private static final Path LIBRARY = locate();
    private static final SymbolLookup LOOKUP = open(LIBRARY);

    static final MethodHandle VERSION = bind("hide_version",
            FunctionDescriptor.of(ValueLayout.ADDRESS));

    // Before any other symbol is bound: a stale core is better reported as
    // "wrong version" than as whichever newer symbol it happens to lack.
    static {
        String core;
        try {
            core = readCString((MemorySegment) VERSION.invokeExact());
        } catch (Throwable error) {
            throw new UnsatisfiedLinkError(
                    "the HIDE library at " + LIBRARY + " did not report a version: " + error);
        }
        String problem = versionMismatch(BINDING_VERSION, core);
        if (problem != null) {
            throw new UnsatisfiedLinkError(problem + " (loaded from " + LIBRARY + ")");
        }
    }

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

    static final MethodHandle IDENTITY_GENERATE = bind("hide_identity_generate",
            FunctionDescriptor.of(ValueLayout.JAVA_INT, ValueLayout.ADDRESS, ValueLayout.ADDRESS));
    static final MethodHandle SIGNING_IDENTITY_OPEN = bind("hide_signing_identity_open",
            FunctionDescriptor.of(ValueLayout.JAVA_INT, ValueLayout.ADDRESS,
                    ValueLayout.JAVA_LONG, ValueLayout.ADDRESS, ValueLayout.ADDRESS));
    static final MethodHandle SIGNING_IDENTITY_PUBLIC = bind("hide_signing_identity_public",
            FunctionDescriptor.of(ValueLayout.JAVA_INT, ValueLayout.ADDRESS, ValueLayout.ADDRESS));
    static final MethodHandle SIGNING_IDENTITY_FREE = bind("hide_signing_identity_free",
            FunctionDescriptor.ofVoid(ValueLayout.ADDRESS));

    static final MethodHandle SIGN_MESSAGE = bind("hide_sign_message",
            FunctionDescriptor.of(ValueLayout.JAVA_INT, ValueLayout.ADDRESS,
                    ValueLayout.ADDRESS, ValueLayout.JAVA_LONG,
                    ValueLayout.ADDRESS, ValueLayout.JAVA_LONG, ValueLayout.ADDRESS));
    static final MethodHandle VERIFY_MESSAGE = bind("hide_verify_message",
            FunctionDescriptor.of(ValueLayout.JAVA_INT, ValueLayout.ADDRESS,
                    ValueLayout.JAVA_LONG, ValueLayout.ADDRESS, ValueLayout.JAVA_LONG,
                    ValueLayout.ADDRESS, ValueLayout.JAVA_LONG,
                    ValueLayout.ADDRESS, ValueLayout.JAVA_LONG));

    static final MethodHandle CHALLENGE_NEW = bind("hide_challenge_new",
            FunctionDescriptor.of(ValueLayout.JAVA_INT, ValueLayout.ADDRESS,
                    ValueLayout.JAVA_LONG, ValueLayout.JAVA_LONG, ValueLayout.ADDRESS));
    static final MethodHandle CHALLENGE_ANSWER = bind("hide_challenge_answer",
            FunctionDescriptor.of(ValueLayout.JAVA_INT, ValueLayout.ADDRESS,
                    ValueLayout.ADDRESS, ValueLayout.JAVA_LONG, ValueLayout.ADDRESS));
    static final MethodHandle SPENT_NONCES_NEW = bind("hide_spent_nonces_new",
            FunctionDescriptor.of(ValueLayout.ADDRESS, ValueLayout.ADDRESS));
    static final MethodHandle SPENT_NONCES_FREE = bind("hide_spent_nonces_free",
            FunctionDescriptor.ofVoid(ValueLayout.ADDRESS));
    static final MethodHandle CHALLENGE_ACCEPT = bind("hide_challenge_accept",
            FunctionDescriptor.of(ValueLayout.JAVA_INT, ValueLayout.ADDRESS,
                    ValueLayout.ADDRESS, ValueLayout.JAVA_LONG,
                    ValueLayout.ADDRESS, ValueLayout.JAVA_LONG,
                    ValueLayout.ADDRESS, ValueLayout.JAVA_LONG, ValueLayout.JAVA_LONG));

    static final MethodHandle IDENTITY_VERIFY = bind("hide_identity_verify",
            FunctionDescriptor.of(ValueLayout.JAVA_INT, ValueLayout.ADDRESS,
                    ValueLayout.JAVA_LONG, ValueLayout.ADDRESS, ValueLayout.JAVA_LONG,
                    ValueLayout.ADDRESS));
    static final MethodHandle IDENTITY_TRUSTS_DEVICE = bind("hide_identity_trusts_device",
            FunctionDescriptor.of(ValueLayout.JAVA_INT, ValueLayout.ADDRESS,
                    ValueLayout.JAVA_LONG, ValueLayout.ADDRESS, ValueLayout.JAVA_LONG,
                    ValueLayout.ADDRESS, ValueLayout.JAVA_LONG, ValueLayout.ADDRESS));
    static final MethodHandle IDENTITY_HEAD = bind("hide_identity_head",
            FunctionDescriptor.of(ValueLayout.JAVA_INT, ValueLayout.ADDRESS,
                    ValueLayout.JAVA_LONG, ValueLayout.ADDRESS, ValueLayout.JAVA_LONG,
                    ValueLayout.ADDRESS));

    static final MethodHandle EPOCH_VERIFY = bind("hide_epoch_verify",
            FunctionDescriptor.of(ValueLayout.JAVA_INT, ValueLayout.ADDRESS,
                    ValueLayout.JAVA_LONG, ValueLayout.ADDRESS));
    static final MethodHandle EPOCH_PUBLIC_KEY = bind("hide_epoch_public_key",
            FunctionDescriptor.of(ValueLayout.JAVA_INT, ValueLayout.ADDRESS,
                    ValueLayout.JAVA_LONG, ValueLayout.JAVA_LONG, ValueLayout.ADDRESS));

    static final MethodHandle IDENTITY_VERIFY_PINNED = bind("hide_identity_verify_pinned",
            FunctionDescriptor.of(ValueLayout.JAVA_INT, ValueLayout.ADDRESS,
                    ValueLayout.JAVA_LONG, ValueLayout.ADDRESS, ValueLayout.JAVA_LONG,
                    ValueLayout.ADDRESS, ValueLayout.JAVA_LONG, ValueLayout.ADDRESS));
    static final MethodHandle EPOCH_VERIFY_BOUND = bind("hide_epoch_verify_bound",
            FunctionDescriptor.of(ValueLayout.JAVA_INT, ValueLayout.ADDRESS,
                    ValueLayout.JAVA_LONG, ValueLayout.ADDRESS, ValueLayout.JAVA_LONG,
                    ValueLayout.ADDRESS, ValueLayout.JAVA_LONG,
                    ValueLayout.ADDRESS, ValueLayout.JAVA_LONG,
                    ValueLayout.ADDRESS, ValueLayout.JAVA_LONG, ValueLayout.ADDRESS));
    static final MethodHandle CHECKPOINT_VERIFY = bind("hide_checkpoint_verify",
            FunctionDescriptor.of(ValueLayout.JAVA_INT, ValueLayout.ADDRESS,
                    ValueLayout.JAVA_LONG, ValueLayout.ADDRESS,
                    ValueLayout.ADDRESS, ValueLayout.JAVA_LONG,
                    ValueLayout.ADDRESS, ValueLayout.ADDRESS));

    static final MethodHandle TRANSPARENCY_VERIFY_INCLUSION =
            bind("hide_transparency_verify_inclusion",
                    FunctionDescriptor.of(ValueLayout.JAVA_INT, ValueLayout.ADDRESS,
                            ValueLayout.JAVA_LONG, ValueLayout.JAVA_LONG, ValueLayout.JAVA_LONG,
                            ValueLayout.ADDRESS, ValueLayout.JAVA_LONG,
                            ValueLayout.ADDRESS, ValueLayout.JAVA_LONG));
    static final MethodHandle TRANSPARENCY_VERIFY_CONSISTENCY =
            bind("hide_transparency_verify_consistency",
                    FunctionDescriptor.of(ValueLayout.JAVA_INT, ValueLayout.JAVA_LONG,
                            ValueLayout.JAVA_LONG, ValueLayout.ADDRESS, ValueLayout.JAVA_LONG,
                            ValueLayout.ADDRESS, ValueLayout.JAVA_LONG,
                            ValueLayout.ADDRESS, ValueLayout.JAVA_LONG));

    private static MethodHandle bind(String name, FunctionDescriptor descriptor) {
        return LINKER.downcallHandle(
                LOOKUP.find(name).orElseThrow(() ->
                        new UnsatisfiedLinkError("the HIDE library has no symbol " + name)),
                descriptor);
    }

    /** The absolute path the core was loaded from. */
    static Path libraryPath() {
        return LIBRARY;
    }

    /**
     * Finds the core as an absolute path, or fails.
     *
     * <p>The library is never handed to the operating system loader by bare
     * name: that search covers the working directory and {@code PATH} on
     * Windows and {@code LD_LIBRARY_PATH} / {@code DYLD_LIBRARY_PATH}
     * elsewhere, so whoever controls any of those would choose the
     * cryptographic core.
     */
    private static Path locate() {
        return locate(
                System.getProperty("hide.library"),
                System.getenv("HIDE_LIBRARY"),
                "1".equals(System.getenv("HIDE_ALLOW_LIBRARY_OVERRIDE"))
                        || Boolean.getBoolean("hide.allowLibraryOverride"),
                codeSourceDirectory(),
                libraryName(System.getProperty("os.name", "")));
    }

    /**
     * The search itself, free of process state so it can be tested directly.
     *
     * <p>Either override replaces the whole cryptographic core, so one
     * settable property or environment variable must not be enough: without
     * the explicit second opt-in both are ignored, whatever they name.
     */
    static Path locate(String property, String environment, boolean allowOverride,
                       Path beside, String fileName) {
        StringBuilder tried = new StringBuilder();
        if (allowOverride) {
            for (String candidate : new String[] { property, environment }) {
                if (candidate == null || candidate.isEmpty()) {
                    continue;
                }
                Path path = absolute(candidate);
                if (path != null && Files.isRegularFile(path)) {
                    return path;
                }
                tried.append(" The override ").append(candidate).append(" is not a file.");
            }
        } else if (isSet(property) || isSet(environment)) {
            tried.append(" -Dhide.library / HIDE_LIBRARY is set but was ignored, because"
                    + " the opt-in below is not.");
        }
        if (beside != null) {
            Path path = beside.resolve(fileName).toAbsolutePath().normalize();
            if (Files.isRegularFile(path)) {
                return path;
            }
            tried.append(" There is no ").append(fileName).append(" in ").append(beside)
                    .append('.');
        }
        throw new UnsatisfiedLinkError(
                "the HIDE native library was not found. The jar does not bundle it, and it is"
                        + " never looked up by name through the system loader (PATH,"
                        + " java.library.path and LD_LIBRARY_PATH are not searched). Either put "
                        + fileName + " in the directory that holds this jar, or set"
                        + " -Dhide.library=<path> or HIDE_LIBRARY to the file produced by"
                        + " `cargo build --release -p hide-ffi` AND opt in with"
                        + " -Dhide.allowLibraryOverride=true or HIDE_ALLOW_LIBRARY_OVERRIDE=1."
                        + tried);
    }

    private static boolean isSet(String value) {
        return value != null && !value.isEmpty();
    }

    private static Path absolute(String candidate) {
        try {
            return Path.of(candidate).toAbsolutePath().normalize();
        } catch (InvalidPathException error) {
            return null;
        }
    }

    /**
     * The directory holding this jar, or the class directory itself when the
     * binding runs unpacked. Whoever can write there can already replace the
     * binding, so trusting a core found there grants nothing new.
     */
    private static Path codeSourceDirectory() {
        try {
            CodeSource source = Native.class.getProtectionDomain().getCodeSource();
            URL location = source == null ? null : source.getLocation();
            if (location == null || !"file".equals(location.getProtocol())) {
                return null;
            }
            Path path = Path.of(location.toURI()).toAbsolutePath().normalize();
            return Files.isDirectory(path) ? path : path.getParent();
        } catch (URISyntaxException | RuntimeException error) {
            return null;
        }
    }

    static String libraryName(String osName) {
        String os = osName.toLowerCase(java.util.Locale.ROOT);
        if (os.contains("win")) {
            return "hide_ffi.dll";
        }
        if (os.contains("mac") || os.contains("darwin")) {
            return "libhide_ffi.dylib";
        }
        return "libhide_ffi.so";
    }

    private static SymbolLookup open(Path library) {
        try {
            return SymbolLookup.libraryLookup(library, Arena.global());
        } catch (IllegalArgumentException error) {
            throw new UnsatisfiedLinkError(
                    "the HIDE native library at " + library + " could not be loaded: "
                            + error.getMessage());
        }
    }

    /**
     * {@code null} when the core is the release this binding was written for,
     * otherwise the reason it is refused. Only major.minor.patch is compared;
     * a pre-release or build suffix is ignored.
     */
    static String versionMismatch(String binding, String core) {
        long[] want = parseVersion(binding);
        long[] got = parseVersion(core);
        if (want != null && got != null && java.util.Arrays.equals(want, got)) {
            return null;
        }
        return "this binding is version " + binding + " but the HIDE native library reports \""
                + core + "\"; use the library built from the same release";
    }

    private static long[] parseVersion(String text) {
        if (text == null) {
            return null;
        }
        int cut = indexOfSuffix(text);
        String[] parts = (cut < 0 ? text : text.substring(0, cut)).split("\\.", -1);
        if (parts.length != 3) {
            return null;
        }
        long[] version = new long[3];
        for (int index = 0; index < 3; index++) {
            String part = parts[index];
            if (part.isEmpty() || part.length() > 9 || !part.chars().allMatch(c -> c >= '0' && c <= '9')) {
                return null;
            }
            version[index] = Long.parseLong(part);
        }
        return version;
    }

    private static int indexOfSuffix(String text) {
        int dash = text.indexOf('-');
        int plus = text.indexOf('+');
        if (dash < 0) {
            return plus;
        }
        return plus < 0 ? dash : Math.min(dash, plus);
    }

    /**
     * A NUL-terminated copy for a {@code const char *} parameter.
     *
     * <p>The core reads such a parameter up to the first NUL, so a string
     * carrying one would be silently cut: {@code "longenough\0rest"} would
     * seal under {@code "longenough"}. It is refused instead. Every
     * {@code const char *} argument in this binding goes through here.
     */
    static MemorySegment cString(Arena arena, String value, String what) {
        Objects.requireNonNull(value, what);
        if (value.indexOf('\0') >= 0) {
            throw new IllegalArgumentException("the " + what + " must not contain a NUL character");
        }
        return arena.allocateFrom(value);
    }

    /** As {@link #cString}, with {@code null} meaning an absent (NULL) argument. */
    static MemorySegment optionalCString(Arena arena, String value, String what) {
        return value == null ? MemorySegment.NULL : cString(arena, value, what);
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
