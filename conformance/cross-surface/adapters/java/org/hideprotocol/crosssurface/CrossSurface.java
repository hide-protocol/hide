package org.hideprotocol.crosssurface;

import java.nio.file.Files;
import java.nio.file.Path;
import java.util.List;
import org.hideprotocol.Hide;
import org.hideprotocol.SecretKey;

/**
 * Drives the Java SDK for the cross-surface interop matrix. Two commands:
 *
 * <pre>
 * CrossSurface encrypt &lt;public-key&gt; &lt;plaintext&gt; &lt;out-container&gt;
 * CrossSurface decrypt &lt;secret-key&gt; &lt;container&gt; &lt;out-plaintext&gt;
 * </pre>
 *
 * <p>Compiled from the same source tree as the SDK, so the matrix tests what is
 * here. The native core is found through {@code HIDE_LIBRARY} and
 * {@code HIDE_ALLOW_LIBRARY_OVERRIDE}, which the harness exports.
 */
public final class CrossSurface {

    private CrossSurface() {
    }

    public static void main(String[] args) throws Exception {
        if (args.length != 4) {
            System.err.println("usage: CrossSurface encrypt|decrypt <key> <input> <output>");
            System.exit(2);
        }
        String command = args[0];
        byte[] key = Files.readAllBytes(Path.of(args[1]));
        byte[] input = Files.readAllBytes(Path.of(args[2]));
        Path output = Path.of(args[3]);

        switch (command) {
            case "encrypt" -> Files.write(output, Hide.encrypt(input, List.of(key), "java.txt", null));
            // A protected key file would need a passphrase, which a
            // cross-surface vector never carries; the matrix uses raw seeds.
            case "decrypt" -> {
                try (SecretKey secret = SecretKey.load(key, null)) {
                    Files.write(output, Hide.decrypt(input, secret).data());
                }
            }
            default -> {
                System.err.println("unknown command: " + command);
                System.exit(2);
            }
        }
    }
}
