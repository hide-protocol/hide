package org.hideprotocol;

import static java.nio.charset.StandardCharsets.UTF_8;

import java.util.Arrays;
import java.util.List;

/**
 * A dependency-free test runner, so the SDK can be verified without pulling a
 * build tool into the repository. Run with:
 *
 * <pre>
 * java --enable-native-access=ALL-UNNAMED -Dhide.library=&lt;path&gt; HideTest.java
 * </pre>
 */
public final class HideTest {

    private static int failures;

    public static void main(String[] args) {
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
        run("an identity cannot be impersonated", HideTest::impersonation);
        run("an encryption-only key cannot sign", HideTest::encryptionOnlyKey);
        run("a challenge is answered once", HideTest::challengeOnce);
        run("a late answer is expired", HideTest::challengeExpiry);

        if (failures > 0) {
            System.err.println(failures + " test(s) failed");
            System.exit(1);
        }
        System.out.println("all tests passed");
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

    private static void fail(String what) {
        throw new AssertionError(what);
    }
}
