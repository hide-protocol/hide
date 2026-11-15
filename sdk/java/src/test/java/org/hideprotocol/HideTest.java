package org.hideprotocol;

import static java.nio.charset.StandardCharsets.UTF_8;

import java.io.IOException;
import java.io.UncheckedIOException;
import java.net.URISyntaxException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardCopyOption;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Comparator;
import java.util.List;
import java.util.Map;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.stream.Stream;

/**
 * A dependency-free test runner, so the SDK can be verified without pulling a
 * build tool into the repository. Run with:
 *
 * <pre>
 * java --enable-native-access=ALL-UNNAMED -Dhide.library=&lt;path&gt; \
 *      -Dhide.allowLibraryOverride=true -cp &lt;classes&gt; org.hideprotocol.HideTest
 * </pre>
 *
 * <p>With the single argument {@code --probe} it only loads the native library
 * and prints where it came from; the loading tests run it as a child process.
 */
public final class HideTest {

    private static int failures;

    public static void main(String[] args) {
        if (args.length == 1 && args[0].equals("--probe")) {
            probe();
            return;
        }
        System.out.println("native library version: " + Hide.version());

        run("round trip carries metadata", HideTest::roundTrip);
        run("single-byte mutations are rejected", HideTest::mutations);
        run("truncation and extension fail", HideTest::truncation);
        run("the wrong key cannot decrypt", HideTest::wrongKey);
        run("many recipients share one payload", HideTest::manyRecipients);
        run("protected keys round trip", HideTest::protectedKeys);
        run("a short passphrase is refused", HideTest::shortPassphrase);
        run("armor round trips", HideTest::armor);
        run("recipient count is bounded", HideTest::bounds);
        run("a closed key is unusable", HideTest::closedKey);
        run("empty payloads are valid", HideTest::emptyPayload);
        run("garbage is rejected, not crashed", HideTest::garbage);
        run("signatures round trip", HideTest::signatures);
        run("a changed message does not verify", HideTest::changedMessage);
        run("a different context does not verify", HideTest::differentContext);
        run("reserved protocol contexts are refused", HideTest::reservedContext);
        run("an identity cannot be impersonated", HideTest::impersonation);
        run("an encryption-only key cannot sign", HideTest::encryptionOnlyKey);
        run("a challenge is answered once", HideTest::challengeOnce);
        run("a late answer is expired", HideTest::challengeExpiry);
        run("an identity log reports the devices it trusts", HideTest::identityDevices);
        run("a revoked device is no longer trusted", HideTest::revokedDevice);
        run("a tampered log is refused", HideTest::tamperedLog);
        run("the head names this exact history", HideTest::identityHead);
        run("an epoch chain verifies and yields keys", HideTest::epochChain);
        run("an epoch beyond the chain is refused", HideTest::epochOutOfRange);
        run("a spliced epoch chain does not verify", HideTest::splicedEpochChain);
        run("an inclusion proof verifies only for its own leaf", HideTest::inclusion);
        run("a path that is not whole hashes is refused", HideTest::partialHashPath);
        run("a consistency proof catches a rewritten history", HideTest::consistency);
        run("a pinned identity verifies against its root", HideTest::pinnedIdentity);
        run("a hijacked identity is refused", HideTest::hijackedIdentity);
        run("another root is refused", HideTest::anotherRoot);
        run("a truncated recovery binding is malformed", HideTest::truncatedBinding);
        run("an epoch chain bound to the pinned identity verifies", HideTest::boundEpochChain);
        run("an epoch chain signed by a stranger is refused", HideTest::strangerEpochChain);
        run("a checkpoint yields its size and root", HideTest::checkpoint);
        run("a checkpoint is refused unless everything matches", HideTest::checkpointRefused);
        run("an embedded NUL is refused in every C string", HideTest::embeddedNul);
        run("one answer is accepted once across threads", HideTest::concurrentAccept);
        run("the core is the version this binding was written for", HideTest::versionHandshake);
        run("the library search returns an absolute path or fails", HideTest::locateRules);
        run("the library is never taken from the working directory or a search path",
                HideTest::noBareNameLoading);
        run("a library override without the opt-in is ignored", HideTest::overrideAloneIgnored);
        run("a library override with the opt-in is used", HideTest::overrideWithOptIn);

        deleteStage();
        if (failures > 0) {
            System.err.println(failures + " test(s) failed");
            System.exit(1);
        }
        System.out.println("all tests passed");
    }

    /**
     * The core reads every {@code const char *} up to the first NUL, so a
     * binding that passes a string straight through opens a key sealed under
     * "longenough" when the caller typed "longenough\0rest".
     */
    private static void embeddedNul() {
        String cut = "longenough";
        String withNul = cut + "\0rest";
        byte[] one = { 1 };
        try (SecretKey secret = SecretKey.generate()) {
            byte[] publicKey = secret.publicKey();
            byte[] sealed = secret.protect(cut);
            byte[] identityFile = SigningIdentity.generate(cut);
            String armored = Hide.armorPublicKey(publicKey);

            assertThrows(IllegalArgumentException.class, () -> secret.protect(withNul),
                    "protect with a NUL in the passphrase");
            assertThrows(IllegalArgumentException.class,
                    () -> SecretKey.load(sealed, withNul).close(),
                    "SecretKey.load with a NUL in the passphrase");
            assertThrows(IllegalArgumentException.class, () -> SigningIdentity.generate(withNul),
                    "SigningIdentity.generate with a NUL in the passphrase");
            assertThrows(IllegalArgumentException.class,
                    () -> SigningIdentity.load(identityFile, withNul).close(),
                    "SigningIdentity.load with a NUL in the passphrase");
            assertThrows(IllegalArgumentException.class,
                    () -> Hide.encrypt(one, List.of(publicKey), "safe.txt\0evil", null),
                    "a NUL in the filename");
            assertThrows(IllegalArgumentException.class,
                    () -> Hide.encrypt(one, List.of(publicKey), null, "text/pl\0ain"),
                    "a NUL in the media type");
            assertThrows(IllegalArgumentException.class,
                    () -> Hide.newChallenge("app.example\0.evil.example", 1_000, 60),
                    "a NUL in the audience");
            assertThrows(IllegalArgumentException.class,
                    () -> Hide.dearmorPublicKey(armored + "\0trailing"),
                    "a NUL in the armored key");
            assertThrows(IllegalArgumentException.class,
                    () -> Hide.verifyCheckpoint(Fixtures.CHECKPOINT_3, "log.example/hide\0",
                            Fixtures.CHECKPOINT_LOG_KEY),
                    "a NUL in the origin");
        }
    }

    /**
     * Servers share one record between request threads. However many of them
     * present the same valid answer at once, exactly one may be told it is
     * fresh, and the record must survive it.
     */
    private static void concurrentAccept() {
        final int threads = 16;
        // Without the lock roughly one round in ten goes wrong, so a handful
        // of rounds would pass by luck.
        final int rounds = 120;
        try (SigningIdentity identity = newIdentity(); SpentNonces spent = new SpentNonces()) {
            byte[] publicKey = identity.publicKey();
            for (int round = 0; round < rounds; round++) {
                byte[] challenge = Hide.newChallenge("api.example", 1_000, 60);
                byte[] answer = identity.answer(challenge);

                AtomicInteger accepted = new AtomicInteger();
                AtomicInteger replayed = new AtomicInteger();
                AtomicInteger other = new AtomicInteger();
                CountDownLatch ready = new CountDownLatch(threads);
                CountDownLatch start = new CountDownLatch(1);
                Thread[] workers = new Thread[threads];
                for (int index = 0; index < threads; index++) {
                    workers[index] = new Thread(() -> {
                        ready.countDown();
                        try {
                            start.await();
                            spent.accept(challenge, answer, publicKey, 1_010);
                            accepted.incrementAndGet();
                        } catch (HideException.ChallengeReplayed expected) {
                            replayed.incrementAndGet();
                        } catch (Throwable unexpected) {
                            other.incrementAndGet();
                        }
                    });
                    workers[index].start();
                }
                try {
                    ready.await();
                    start.countDown();
                    for (Thread worker : workers) {
                        worker.join();
                    }
                } catch (InterruptedException interrupted) {
                    Thread.currentThread().interrupt();
                    throw new AssertionError("interrupted");
                }
                assertTrue(accepted.get() == 1 && replayed.get() == threads - 1 && other.get() == 0,
                        "round " + round + ": " + accepted.get() + " accepted, " + replayed.get()
                                + " replayed, " + other.get() + " other; wanted 1, "
                                + (threads - 1) + ", 0");
            }
        }
    }

    private static void versionHandshake() {
        assertTrue(Native.BINDING_VERSION.equals(Hide.version()),
                "the core is " + Hide.version() + ", the binding is " + Native.BINDING_VERSION);

        String[][] same = {
            { "0.9.1", "0.9.1" }, { "1.2.3", "1.2.3" },
            { "0.10.0", "0.10.0-rc.1" }, { "0.10.0", "0.10.0+build.5" },
        };
        for (String[] pair : same) {
            assertTrue(Native.versionMismatch(pair[0], pair[1]) == null,
                    "binding " + pair[0] + " refused core " + pair[1]);
        }
        String[] different = {
            "0.9.0", "0.10.1", "1.9.1", "0.9.10", "0.9", "0.9.1.0", "", "v0.9.1", "0.+9.1",
            "garbage", null,
        };
        for (String core : different) {
            assertTrue(Native.versionMismatch("0.9.1", core) != null,
                    "binding 0.9.1 accepted core " + core);
        }
    }

    /** The search in isolation: no process state, and no library is loaded. */
    private static void locateRules() {
        Path root = stage().root;
        String name = "placeholder-core.bin";
        try {
            Path beside = Files.createDirectories(root.resolve("locate-beside"));
            Path elsewhere = Files.createDirectories(root.resolve("locate-elsewhere"));
            Path empty = Files.createDirectories(root.resolve("locate-empty"));
            Path besideFile = Files.write(beside.resolve(name), new byte[] { 1 });
            Path first = Files.write(elsewhere.resolve("first.bin"), new byte[] { 1 });
            Path second = Files.write(elsewhere.resolve("second.bin"), new byte[] { 1 });
            String missing = elsewhere.resolve("missing.bin").toString();

            assertSamePath(besideFile, Native.locate(null, null, false, beside, name),
                    "no override: the copy beside the code");
            // The gate: without the opt-in an override is ignored, whether it
            // names a real file or not.
            assertSamePath(besideFile,
                    Native.locate(first.toString(), second.toString(), false, beside, name),
                    "an override without the opt-in");
            assertSamePath(besideFile, Native.locate(missing, missing, false, beside, name),
                    "a missing override without the opt-in");
            assertSamePath(first,
                    Native.locate(first.toString(), second.toString(), true, beside, name),
                    "the property comes before the environment");
            assertSamePath(second, Native.locate(null, second.toString(), true, beside, name),
                    "the environment override with the opt-in");
            assertSamePath(second, Native.locate(missing, second.toString(), true, beside, name),
                    "a missing property falls through to the environment");
            assertSamePath(besideFile, Native.locate(missing, null, true, beside, name),
                    "a missing override falls through to the copy beside the code");
            assertTrue(Native.locate(null, null, false, beside, name).isAbsolute(),
                    "the result is absolute");

            // Nothing found is an error that says what was tried, never a bare
            // name left for the system loader to resolve.
            assertNotFound(() -> Native.locate(null, null, false, empty, name), "was not found");
            assertNotFound(() -> Native.locate(null, null, false, null, name), "was not found");
            assertNotFound(() -> Native.locate(first.toString(), null, false, empty, name),
                    "was ignored");
            assertNotFound(() -> Native.locate(missing, null, true, empty, name), "is not a file");
            // A directory is not a library.
            assertNotFound(() -> Native.locate(elsewhere.toString(), null, true, null, name),
                    "is not a file");
        } catch (IOException error) {
            throw new UncheckedIOException(error);
        }

        assertTrue("hide_ffi.dll".equals(Native.libraryName("Windows 11")), "windows name");
        assertTrue("libhide_ffi.dylib".equals(Native.libraryName("Mac OS X")), "macos name");
        assertTrue("libhide_ffi.so".equals(Native.libraryName("Linux")), "linux name");
    }

    /**
     * A copy of the core in the working directory and on every search path the
     * system loader honours must not be picked up: whoever controls one of
     * those would otherwise choose the cryptographic core.
     */
    private static void noBareNameLoading() {
        Stage stage = stage();
        String planted = stage.planted.toString();
        String path = planted + java.io.File.pathSeparator
                + System.getenv().getOrDefault("PATH", "");
        Child child = probe(stage.withoutLibrary, stage.planted,
                Map.of("PATH", path, "LD_LIBRARY_PATH", planted, "DYLD_LIBRARY_PATH", planted),
                List.of("-Djava.library.path=" + planted));
        assertTrue(child.exit == 3 && child.output.contains("was not found")
                        && !child.output.contains("LIBRARY="),
                "a planted library was loaded, or the failure was not the expected one: exit "
                        + child.exit + ", output: " + child.output);
    }

    /** HIDE_LIBRARY / -Dhide.library alone must change nothing. */
    private static void overrideAloneIgnored() {
        Stage stage = stage();
        String missing = stage.root.resolve("no-such-directory").resolve(stage.name).toString();

        // Pointing at nothing: the load must not fail on that path.
        Child nothing = probe(stage.withLibrary, stage.root, Map.of("HIDE_LIBRARY", missing),
                List.of("-Dhide.library=" + missing));
        assertLoadedFrom(stage.beside, nothing, "an override naming a missing file");

        // Pointing at a real, different copy: it must not be the one loaded.
        Child real = probe(stage.withLibrary, stage.root,
                Map.of("HIDE_LIBRARY", stage.spare.toString()),
                List.of("-Dhide.library=" + stage.spare));
        assertLoadedFrom(stage.beside, real, "an override naming a real file");

        // And with nothing beside the code, the override is still not used.
        Child alone = probe(stage.withoutLibrary, stage.root,
                Map.of("HIDE_LIBRARY", stage.spare.toString()), List.of());
        assertTrue(alone.exit == 3 && alone.output.contains("was ignored"),
                "an override without the opt-in was honoured: exit " + alone.exit + ", output: "
                        + alone.output);
    }

    private static void overrideWithOptIn() {
        Stage stage = stage();
        Child environment = probe(stage.withLibrary, stage.root,
                Map.of("HIDE_LIBRARY", stage.spare.toString(), "HIDE_ALLOW_LIBRARY_OVERRIDE", "1"),
                List.of());
        assertLoadedFrom(stage.spare, environment, "the environment pair");

        Child properties = probe(stage.withLibrary, stage.root, Map.of(),
                List.of("-Dhide.library=" + stage.spare, "-Dhide.allowLibraryOverride=true"));
        assertLoadedFrom(stage.spare, properties, "the system-property pair");

        // Anything but exactly "1" is not an opt-in.
        Child almost = probe(stage.withLibrary, stage.root,
                Map.of("HIDE_LIBRARY", stage.spare.toString(),
                        "HIDE_ALLOW_LIBRARY_OVERRIDE", "true"),
                List.of());
        assertLoadedFrom(stage.beside, almost, "HIDE_ALLOW_LIBRARY_OVERRIDE=true");
    }

    /** Child-process entry point: load the core and say where it came from. */
    private static void probe() {
        try {
            System.out.println("LIBRARY=" + Native.libraryPath().toRealPath());
            System.out.println("VERSION=" + Hide.version());
        } catch (Throwable error) {
            System.out.println("FAILED=" + error);
            System.exit(3);
        }
    }

    /**
     * Copies of this binding and of the core in a scratch directory, so the
     * child processes can be given a layout the test controls: one copy of the
     * classes with the core beside them, one without, a spare core to point an
     * override at, and one planted where a bare-name lookup would find it.
     */
    private static final class Stage {
        Path root;
        String name;
        String withLibrary;
        String withoutLibrary;
        Path beside;
        Path spare;
        Path planted;
    }

    private static Stage staged;

    private static Stage stage() {
        if (staged != null) {
            return staged;
        }
        try {
            Stage stage = new Stage();
            Path library = Native.libraryPath();
            stage.name = Native.libraryName(System.getProperty("os.name", ""));
            stage.root = Files.createTempDirectory("hide-java-test").toRealPath();

            Path main = codeSource(Native.class);
            Path tests = codeSource(HideTest.class);
            String extra = main.equals(tests) ? "" : java.io.File.pathSeparator + tests;

            Path with = Files.createDirectories(stage.root.resolve("with"));
            Path without = Files.createDirectories(stage.root.resolve("without"));
            stage.withLibrary = copyCode(main, with) + extra;
            stage.withoutLibrary = copyCode(main, without) + extra;
            stage.beside = Files.copy(library, with.resolve(stage.name));

            stage.spare = Files.copy(library,
                    Files.createDirectories(stage.root.resolve("spare")).resolve(stage.name));
            stage.planted = Files.createDirectories(stage.root.resolve("planted"));
            Files.copy(library, stage.planted.resolve(stage.name));
            staged = stage;
            return stage;
        } catch (IOException error) {
            throw new UncheckedIOException(error);
        }
    }

    private static Path codeSource(Class<?> type) {
        try {
            return Path.of(type.getProtectionDomain().getCodeSource().getLocation().toURI())
                    .toRealPath();
        } catch (URISyntaxException | IOException error) {
            throw new AssertionError("cannot locate the code of " + type.getName() + ": " + error);
        }
    }

    /** Copies a class directory or a jar into {@code target}; returns the classpath entry. */
    private static String copyCode(Path source, Path target) throws IOException {
        if (!Files.isDirectory(source)) {
            return Files.copy(source, target.resolve(source.getFileName())).toString();
        }
        try (Stream<Path> walk = Files.walk(source)) {
            for (Path path : (Iterable<Path>) walk::iterator) {
                Path copy = target.resolve(source.relativize(path).toString());
                if (Files.isDirectory(path)) {
                    Files.createDirectories(copy);
                } else if (path.toString().endsWith(".class")) {
                    Files.copy(path, copy, StandardCopyOption.REPLACE_EXISTING);
                }
            }
        }
        return target.toString();
    }

    private static void deleteStage() {
        if (staged == null) {
            return;
        }
        try (Stream<Path> walk = Files.walk(staged.root)) {
            walk.sorted(Comparator.reverseOrder()).forEach(path -> path.toFile().delete());
        } catch (IOException ignored) {
            // Scratch files in the temporary directory; nothing depends on them.
        }
    }

    private record Child(int exit, String output) {
    }

    /**
     * Runs the probe in a fresh JVM. Both override variables are removed from
     * its environment first, so it sees only what {@code environment} sets.
     */
    private static Child probe(String classpath, Path directory, Map<String, String> environment,
                               List<String> options) {
        List<String> command = new ArrayList<>();
        command.add(Path.of(System.getProperty("java.home"), "bin", "java").toString());
        command.add("--enable-native-access=ALL-UNNAMED");
        command.addAll(options);
        command.add("-cp");
        command.add(classpath);
        command.add(HideTest.class.getName());
        command.add("--probe");

        ProcessBuilder builder = new ProcessBuilder(command);
        builder.directory(directory.toFile());
        builder.redirectErrorStream(true);
        builder.environment().remove("HIDE_LIBRARY");
        builder.environment().remove("HIDE_ALLOW_LIBRARY_OVERRIDE");
        builder.environment().remove("JAVA_TOOL_OPTIONS");
        builder.environment().putAll(environment);
        try {
            Process process = builder.start();
            String output = new String(process.getInputStream().readAllBytes(), UTF_8);
            if (!process.waitFor(120, TimeUnit.SECONDS)) {
                process.destroyForcibly();
                throw new AssertionError("the probe did not finish: " + output);
            }
            return new Child(process.exitValue(), output);
        } catch (IOException error) {
            throw new UncheckedIOException(error);
        } catch (InterruptedException interrupted) {
            Thread.currentThread().interrupt();
            throw new AssertionError("interrupted");
        }
    }

    private static void assertLoadedFrom(Path expected, Child child, String what) {
        String wanted;
        try {
            wanted = "LIBRARY=" + expected.toRealPath();
        } catch (IOException error) {
            throw new UncheckedIOException(error);
        }
        assertTrue(child.exit == 0 && child.output.lines().anyMatch(wanted::equals),
                what + ": wanted " + wanted + ", got exit " + child.exit + ", output: "
                        + child.output);
    }

    private static void assertSamePath(Path expected, Path actual, String what) {
        try {
            assertTrue(actual.isAbsolute() && Files.isSameFile(expected, actual),
                    what + ": wanted " + expected + ", got " + actual);
        } catch (IOException error) {
            throw new UncheckedIOException(error);
        }
    }

    private static void assertNotFound(Runnable body, String fragment) {
        try {
            body.run();
        } catch (UnsatisfiedLinkError expected) {
            assertTrue(expected.getMessage().contains(fragment),
                    "the failure does not say \"" + fragment + "\": " + expected.getMessage());
            return;
        }
        throw new AssertionError("a library was found where there is none");
    }

        private static void identityDevices() {
        // Four events: create, enrol phone, enrol laptop, revoke laptop.
        assertTrue(Hide.verifyIdentity(Fixtures.IDENTITY_LOG, Fixtures.IDENTITY_RECOVERY) == 2,
            "the log must trust two devices");
        }

        private static void revokedDevice() {
        assertTrue(Hide.identityTrustsDevice(Fixtures.IDENTITY_LOG, Fixtures.IDENTITY_RECOVERY,
            Fixtures.IDENTITY_DEVICE_PHONE), "the enrolled phone is trusted");
        assertTrue(!Hide.identityTrustsDevice(Fixtures.IDENTITY_LOG, Fixtures.IDENTITY_RECOVERY,
            Fixtures.IDENTITY_DEVICE_LAPTOP), "a revoked laptop is still trusted");
        }

        private static void tamperedLog() {
        assertThrows(HideException.Authentication.class,
            () -> Hide.verifyIdentity(Fixtures.IDENTITY_TAMPERED, Fixtures.IDENTITY_RECOVERY),
            "a tampered log");
        // Bytes that do not decode at all are a different failure from bytes
        // that decode and do not verify.
        assertThrows(HideException.Malformed.class,
            () -> Hide.verifyIdentity("not a log".getBytes(UTF_8), Fixtures.IDENTITY_RECOVERY),
            "undecodable bytes");
        }

        private static void identityHead() {
        byte[] head = Hide.identityHead(Fixtures.IDENTITY_LOG, Fixtures.IDENTITY_RECOVERY);
        assertTrue(head.length == 32, "the head is 32 bytes");
        assertTrue(Arrays.equals(head, Fixtures.IDENTITY_HEAD), "the head names this history");
        }

        private static void epochChain() {
        assertTrue(Hide.verifyEpochChain(Fixtures.EPOCH_CHAIN) == 3, "the chain holds 3 epochs");
        assertTrue(Arrays.equals(Hide.epochPublicKey(Fixtures.EPOCH_CHAIN, 1),
            Fixtures.EPOCH_PUBLIC_KEY_1), "epoch 1 public key");
        }

        private static void epochOutOfRange() {
        assertThrows(IllegalArgumentException.class,
            () -> Hide.epochPublicKey(Fixtures.EPOCH_CHAIN, 3), "an out-of-range epoch");
        }

        private static void splicedEpochChain() {
        assertThrows(HideException.Authentication.class,
            () -> Hide.verifyEpochChain(Fixtures.EPOCH_BROKEN), "a spliced chain");
        }

        private static void inclusion() {
        Hide.verifyInclusion(Fixtures.LEAF, 3, 8, Fixtures.INCLUSION_PATH, Fixtures.TREE_ROOT);
        assertThrows(HideException.Authentication.class,
            () -> Hide.verifyInclusion(Fixtures.OTHER_LEAF, 3, 8, Fixtures.INCLUSION_PATH,
                Fixtures.TREE_ROOT),
            "a foreign leaf");
        }

        private static void partialHashPath() {
        byte[] truncated =
            Arrays.copyOf(Fixtures.INCLUSION_PATH, Fixtures.INCLUSION_PATH.length - 1);
        assertThrows(IllegalArgumentException.class,
            () -> Hide.verifyInclusion(Fixtures.LEAF, 3, 8, truncated, Fixtures.TREE_ROOT),
            "a partial hash");
        }

        private static void consistency() {
        Hide.verifyConsistency(5, 8, Fixtures.CONSISTENCY_PATH, Fixtures.ROOT_AT_5,
            Fixtures.TREE_ROOT);
        // Same size, one entry silently replaced.
        assertThrows(HideException.Authentication.class,
            () -> Hide.verifyConsistency(5, 8, Fixtures.CONSISTENCY_PATH, Fixtures.ROOT_AT_5,
                Fixtures.REWRITTEN_ROOT),
            "a rewritten history");
        }

            private static void pinnedIdentity() {
            assertTrue(Hide.verifyIdentityPinned(Fixtures.BINDING_IDENTITY_LOG,
                Fixtures.BINDING_RECOVERY, Fixtures.BINDING_ROOT) == 2,
                "the pinned log must trust two devices");
            }

            private static void hijackedIdentity() {
            // A Recover appended under a stranger's key, with the genuine binding
            // and with one forged for the stranger.
            assertThrows(HideException.Authentication.class,
                () -> Hide.verifyIdentityPinned(Fixtures.BINDING_HIJACKED_LOG,
                    Fixtures.BINDING_RECOVERY, Fixtures.BINDING_ROOT),
                "a hijacked log with the genuine binding");
            assertThrows(HideException.Authentication.class,
                () -> Hide.verifyIdentityPinned(Fixtures.BINDING_HIJACKED_LOG,
                    Fixtures.BINDING_RECOVERY_FORGED, Fixtures.BINDING_ROOT),
                "a hijacked log with a forged binding");
            }

            private static void anotherRoot() {
            assertThrows(HideException.Authentication.class,
                () -> Hide.verifyIdentityPinned(Fixtures.BINDING_IDENTITY_LOG,
                    Fixtures.BINDING_RECOVERY, new byte[32]),
                "a different pinned root");
            }

            private static void truncatedBinding() {
            byte[] truncated = Arrays.copyOf(Fixtures.BINDING_RECOVERY, 100);
            assertThrows(HideException.Malformed.class,
                () -> Hide.verifyIdentityPinned(Fixtures.BINDING_IDENTITY_LOG, truncated,
                    Fixtures.BINDING_ROOT),
                "a truncated binding");
            }

            private static void boundEpochChain() {
            assertTrue(Hide.verifyEpochChainBound(Fixtures.BINDING_IDENTITY_LOG,
                Fixtures.BINDING_RECOVERY, Fixtures.BINDING_ROOT, Fixtures.EPOCH_CHAIN,
                Fixtures.BINDING_EPOCH) == 3, "the bound chain holds 3 epochs");
            }

            private static void strangerEpochChain() {
            assertThrows(HideException.Authentication.class,
                () -> Hide.verifyEpochChainBound(Fixtures.BINDING_IDENTITY_LOG,
                    Fixtures.BINDING_RECOVERY, Fixtures.BINDING_ROOT, Fixtures.EPOCH_CHAIN,
                    Fixtures.BINDING_EPOCH_STRANGER),
                "a stranger's binding");
            }

            private static void checkpoint() {
            Hide.Checkpoint verified = Hide.verifyCheckpoint(Fixtures.CHECKPOINT_3,
                "log.example/hide", Fixtures.CHECKPOINT_LOG_KEY);
            assertTrue(verified.size() == 3, "the checkpoint size is 3");
            assertTrue(verified.root().length == 32, "the checkpoint root is 32 bytes");
            }

            private static void checkpointRefused() {
            assertThrows(HideException.Authentication.class,
                () -> Hide.verifyCheckpoint(Fixtures.CHECKPOINT_TAMPERED, "log.example/hide",
                    Fixtures.CHECKPOINT_LOG_KEY),
                "a tampered note");
            assertThrows(HideException.Authentication.class,
                () -> Hide.verifyCheckpoint(Fixtures.CHECKPOINT_3, "other.example",
                    Fixtures.CHECKPOINT_LOG_KEY),
                "another origin");
            assertThrows(HideException.Authentication.class,
                () -> Hide.verifyCheckpoint(Fixtures.CHECKPOINT_3, "log.example/hide",
                    Fixtures.CHECKPOINT_WITNESS_KEY),
                "a witness key");
            }

    private static void roundTrip() {
        try (SecretKey secret = SecretKey.generate()) {
            byte[] publicKey = secret.publicKey();
            assertTrue(publicKey.length == Hide.PUBLIC_KEY_LEN, "public key length");

            byte[] message = "nume,suma\nAna,9000\n".getBytes(UTF_8);
            byte[] box = Hide.encrypt(message, List.of(publicKey), "salarii.csv", "text/csv");
            assertTrue(!contains(box, "Ana".getBytes(UTF_8)), "plaintext leaked");

            Hide.Decrypted opened = Hide.decrypt(box, secret);
            assertTrue(Arrays.equals(opened.data(), message), "payload round trip");
            assertTrue("salarii.csv".equals(opened.filename()), "filename");
            assertTrue("text/csv".equals(opened.mediaType()), "media type");
        }
    }

    private static void mutations() {
        try (SecretKey secret = SecretKey.generate()) {
            byte[] box = Hide.encrypt("confidential".getBytes(UTF_8),
                    List.of(secret.publicKey()), null, null);
            for (int offset : new int[] { 0, 8, 15, 40, box.length / 2, box.length - 1 }) {
                byte[] damaged = box.clone();
                damaged[offset] ^= 0x40;
                assertThrows(() -> Hide.decrypt(damaged, secret), "mutation at " + offset);
            }
        }
    }

    private static void truncation() {
        try (SecretKey secret = SecretKey.generate()) {
            byte[] box = Hide.encrypt("payload".getBytes(UTF_8),
                    List.of(secret.publicKey()), null, null);
            byte[] shorter = Arrays.copyOf(box, box.length - 1);
            byte[] longer = Arrays.copyOf(box, box.length + 1);
            assertThrows(() -> Hide.decrypt(shorter, secret), "truncation");
            assertThrows(() -> Hide.decrypt(longer, secret), "trailing data");
        }
    }

    private static void wrongKey() {
        try (SecretKey alice = SecretKey.generate(); SecretKey bob = SecretKey.generate()) {
            byte[] box = Hide.encrypt("for alice".getBytes(UTF_8),
                    List.of(alice.publicKey()), null, null);
            try {
                Hide.decrypt(box, bob);
                fail("the wrong key decrypted");
            } catch (HideException.NoMatchingRecipient expected) {
                // Correct.
            }
        }
    }

    private static void manyRecipients() {
        try (SecretKey a = SecretKey.generate();
             SecretKey b = SecretKey.generate();
             SecretKey c = SecretKey.generate()) {
            byte[] box = Hide.encrypt("shared".getBytes(UTF_8),
                    List.of(a.publicKey(), b.publicKey(), c.publicKey()), null, null);
            for (SecretKey key : List.of(a, b, c)) {
                assertTrue("shared".equals(new String(Hide.decrypt(box, key).data(), UTF_8)),
                        "every recipient decrypts");
            }
        }
    }

    private static void protectedKeys() {
        byte[] publicKey;
        byte[] sealed;
        try (SecretKey secret = SecretKey.generate()) {
            publicKey = secret.publicKey();
            sealed = secret.protect("correct horse battery");
        }
        assertTrue("protected".equals(Hide.inspectKey(sealed)), "inspect reports protected");

        try {
            SecretKey.load(sealed, "wrong");
            fail("a wrong passphrase was accepted");
        } catch (HideException.WrongPassphrase expected) {
            // Correct.
        }
        try {
            SecretKey.load(sealed, null);
            fail("a protected key opened without a passphrase");
        } catch (HideException.WrongPassphrase expected) {
            // Correct.
        }

        try (SecretKey reopened = SecretKey.load(sealed, "correct horse battery")) {
            assertTrue(Arrays.equals(reopened.publicKey(), publicKey), "same key reopened");
        }
    }

    private static void shortPassphrase() {
        try (SecretKey secret = SecretKey.generate()) {
            assertThrows(() -> secret.protect("short"), "short passphrase");
        }
    }

    private static void armor() {
        try (SecretKey secret = SecretKey.generate()) {
            byte[] publicKey = secret.publicKey();
            String text = Hide.armorPublicKey(publicKey);
            assertTrue(text.startsWith("hide-public-key:"), "armor prefix");
            assertTrue(Arrays.equals(Hide.dearmorPublicKey(text), publicKey), "armor round trip");
            assertThrows(() -> Hide.dearmorPublicKey("not a key"), "rubbish armor");
        }
    }

    private static void bounds() {
        try (SecretKey secret = SecretKey.generate()) {
            byte[] publicKey = secret.publicKey();
            assertThrows(() -> Hide.encrypt(new byte[] { 1 }, List.of(), null, null),
                    "zero recipients");
            byte[][] many = new byte[65][];
            Arrays.fill(many, publicKey);
            assertThrows(() -> Hide.encrypt(new byte[] { 1 }, List.of(many), null, null),
                    "65 recipients");
            assertThrows(() -> Hide.encrypt(new byte[] { 1 }, List.of(new byte[] { 1 }), null, null),
                    "short public key");
        }
    }

    private static void closedKey() {
        SecretKey secret = SecretKey.generate();
        assertTrue(!secret.toString().contains("="), "toString hides key material");
        secret.close();
        secret.close();
        assertThrows(secret::publicKey, "closed key");
    }

    private static void emptyPayload() {
        try (SecretKey secret = SecretKey.generate()) {
            byte[] box = Hide.encrypt(new byte[0], List.of(secret.publicKey()), null, null);
            assertTrue(Hide.decrypt(box, secret).data().length == 0, "empty payload");
        }
    }

    private static void garbage() {
        try (SecretKey secret = SecretKey.generate()) {
            assertThrows(() -> Hide.decrypt("not a container".getBytes(UTF_8), secret), "garbage");
        }
    }

    private static final String PASSPHRASE = "correct horse battery";

    private static SigningIdentity newIdentity() {
        return SigningIdentity.load(SigningIdentity.generate(PASSPHRASE), PASSPHRASE);
    }

    private static void signatures() {
        try (SigningIdentity identity = newIdentity()) {
            byte[] publicKey = identity.publicKey();
            assertTrue(publicKey.length == Hide.VERIFYING_KEY_LEN, "verifying key length");

            byte[] context = "invoice".getBytes(UTF_8);
            byte[] message = "pay 9000 RON".getBytes(UTF_8);
            byte[] signature = identity.sign(context, message);
            assertTrue(signature.length == Hide.SIGNATURE_LEN, "signature length");

            Hide.verify(publicKey, context, message, signature);
        }
    }

    private static void changedMessage() {
        try (SigningIdentity identity = newIdentity()) {
            byte[] context = "invoice".getBytes(UTF_8);
            byte[] signature = identity.sign(context, "pay 10".getBytes(UTF_8));
            byte[] publicKey = identity.publicKey();
            assertThrows(() -> Hide.verify(publicKey, context, "pay 90".getBytes(UTF_8), signature),
                    "altered message");
        }
    }

    private static void differentContext() {
        try (SigningIdentity identity = newIdentity()) {
            byte[] message = "same bytes".getBytes(UTF_8);
            byte[] signature = identity.sign("login".getBytes(UTF_8), message);
            byte[] publicKey = identity.publicKey();
            assertThrows(
                    () -> Hide.verify(publicKey, "payment".getBytes(UTF_8), message, signature),
                    "context substitution");
        }
    }

    private static void impersonation() {
        try (SigningIdentity alice = newIdentity(); SigningIdentity mallory = newIdentity()) {
            byte[] context = "invoice".getBytes(UTF_8);
            byte[] message = "from alice".getBytes(UTF_8);
            byte[] signature = mallory.sign(context, message);
            byte[] alicePublic = alice.publicKey();
            assertThrows(() -> Hide.verify(alicePublic, context, message, signature),
                    "impersonation");
        }
    }

    /** Spec §15.2: the generic API must not mint protocol signatures. */
    private static void reservedContext() {
        try (SigningIdentity identity = newIdentity()) {
            for (String context : new String[] {"HIDE/0.6 identity entry", "HIDE/1.0 container", "HIDE/"}) {
                assertThrows(IllegalArgumentException.class,
                        () -> identity.sign(context.getBytes(UTF_8), "m".getBytes(UTF_8)),
                        "reserved context " + context);
            }
        }
    }

    private static void encryptionOnlyKey() {
        byte[] sealed;
        try (SecretKey secret = SecretKey.generate()) {
            sealed = secret.protect(PASSPHRASE);
        }
        try {
            SigningIdentity.load(sealed, PASSPHRASE);
            fail("a key with no signing seed loaded");
        } catch (HideException.NotAKey expected) {
            // Correct.
        }
    }

    private static void challengeOnce() {
        try (SigningIdentity identity = newIdentity(); SpentNonces spent = new SpentNonces()) {
            byte[] publicKey = identity.publicKey();
            byte[] challenge = Hide.newChallenge("api.example", 1_000, 60);
            byte[] answer = identity.answer(challenge);

            spent.accept(challenge, answer, publicKey, 1_010);
            try {
                spent.accept(challenge, answer, publicKey, 1_020);
                fail("a replayed answer was accepted");
            } catch (HideException.ChallengeReplayed expected) {
                // Correct.
            }
        }
    }

    private static void challengeExpiry() {
        try (SigningIdentity identity = newIdentity(); SpentNonces spent = new SpentNonces()) {
            byte[] publicKey = identity.publicKey();
            byte[] challenge = Hide.newChallenge("api.example", 1_000, 60);
            byte[] answer = identity.answer(challenge);
            try {
                spent.accept(challenge, answer, publicKey, 5_000);
                fail("an expired answer was accepted");
            } catch (HideException.ChallengeExpired expected) {
                // Correct.
            }
        }
    }

    private static boolean contains(byte[] haystack, byte[] needle) {
        outer:
        for (int i = 0; i + needle.length <= haystack.length; i++) {
            for (int j = 0; j < needle.length; j++) {
                if (haystack[i + j] != needle[j]) {
                    continue outer;
                }
            }
            return true;
        }
        return false;
    }

    private static void run(String name, Runnable body) {
        try {
            body.run();
            System.out.println("PASS " + name);
        } catch (Throwable error) {
            failures++;
            System.out.println("FAIL " + name + ": " + error);
        }
    }

    private static void assertTrue(boolean condition, String what) {
        if (!condition) {
            throw new AssertionError(what);
        }
    }

    private static void assertThrows(Runnable body, String what) {
        try {
            body.run();
        } catch (RuntimeException expected) {
            return;
        }
        throw new AssertionError("expected a failure: " + what);
    }

    /** The exact type matters here: malformed and unverified must stay distinct. */
    private static void assertThrows(Class<? extends RuntimeException> expected, Runnable body,
                                     String what) {
        try {
            body.run();
        } catch (RuntimeException error) {
            if (expected.isInstance(error)) {
                return;
            }
            throw new AssertionError(what + " threw " + error.getClass().getSimpleName()
                    + ", wanted " + expected.getSimpleName());
        }
        throw new AssertionError("expected a failure: " + what);
    }

    private static void fail(String what) {
        throw new AssertionError(what);
    }
}
