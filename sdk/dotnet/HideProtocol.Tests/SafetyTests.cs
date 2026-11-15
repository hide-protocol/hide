using System.Reflection;
using System.Runtime.CompilerServices;
using System.Runtime.InteropServices;
using HideProtocol;
using Xunit;

namespace HideProtocol.Tests;

public class SafetyTests
{
    private const string Passphrase = "correct horse battery";

    // The core reads every `const char *` up to the first NUL, so a binding
    // that passed a string straight through would seal a key under
    // "longenough" when the caller typed "longenough\0rest".
    [Fact]
    public void AnEmbeddedNulIsRefusedInEveryCString()
    {
        const string cut = "longenough";
        const string withNul = cut + "\0rest";

        using SecretKey secret = SecretKey.Generate();
        byte[] publicKey = secret.PublicKey();
        byte[] sealedKey = secret.Protect(cut);
        byte[] identityFile = SigningIdentity.Generate(cut);
        string armored = Hide.ArmorPublicKey(publicKey);

        Assert.Throws<ArgumentException>(() => secret.Protect(withNul));
        Assert.Throws<ArgumentException>(() => SecretKey.Open(sealedKey, withNul));
        Assert.Throws<ArgumentException>(() => SigningIdentity.Generate(withNul));
        Assert.Throws<ArgumentException>(() => SigningIdentity.Load(identityFile, withNul));
        Assert.Throws<ArgumentException>(() => Hide.Encrypt("x"u8, [publicKey], "safe.txt\0evil"));
        Assert.Throws<ArgumentException>(() => Hide.Encrypt("x"u8, [publicKey], null, "text/pl\0ain"));
        Assert.Throws<ArgumentException>(() => Hide.NewChallenge("app.example\0.evil.example", 1_000, 60));
        Assert.Throws<ArgumentException>(() => Hide.DearmorPublicKey(armored + "\0trailing"));
        Assert.Throws<ArgumentException>(() =>
            Hide.VerifyCheckpoint(Fixtures.Checkpoint3, "log.example/hide\0", Fixtures.CheckpointLogKey));

        // The untruncated values still work, so the refusals above are about
        // the NUL and nothing else.
        using SecretKey reopened = SecretKey.Open(sealedKey, cut);
        Assert.Equal(publicKey, reopened.PublicKey());
    }

    // Servers share one record between request threads. However many of them
    // present the same valid answer at once, exactly one may be told it is
    // fresh, and the record must survive it.
    [Fact]
    public void OneAnswerIsAcceptedOnceAcrossThreads()
    {
        const int threads = 16;
        // Without the lock roughly one round in ten goes wrong, so a handful
        // of rounds would pass by luck.
        const int rounds = 120;

        using SigningIdentity prover = SigningIdentity.Load(SigningIdentity.Generate(Passphrase), Passphrase);
        byte[] publicKey = prover.PublicKey();
        using SpentNonces spent = new();

        for (int round = 0; round < rounds; round++)
        {
            byte[] challenge = Hide.NewChallenge("api.example", 1_000, 60);
            byte[] answer = prover.Answer(challenge);

            int accepted = 0;
            int replayed = 0;
            int other = 0;
            using Barrier barrier = new(threads);
            Thread[] workers = new Thread[threads];
            for (int index = 0; index < threads; index++)
            {
                workers[index] = new Thread(() =>
                {
                    barrier.SignalAndWait();
                    try
                    {
                        spent.Accept(challenge, answer, publicKey, 1_010);
                        Interlocked.Increment(ref accepted);
                    }
                    catch (ChallengeReplayedException)
                    {
                        Interlocked.Increment(ref replayed);
                    }
                    catch (Exception)
                    {
                        Interlocked.Increment(ref other);
                    }
                });
                workers[index].Start();
            }

            foreach (Thread worker in workers)
            {
                worker.Join();
            }

            Assert.True(
                accepted == 1 && replayed == threads - 1 && other == 0,
                $"round {round}: {accepted} accepted, {replayed} replayed, {other} other; wanted 1, {threads - 1}, 0");
        }
    }

    // A handle whose last use is a native call is unreachable for the whole of
    // that call unless the binding keeps it alive, and its finalizer then frees
    // the key the core is still reading. Each round ends an object's life in a
    // native call while another thread forces collections and finalizers; a
    // freed key shows up as a crash or as output that is no longer this key's.
    //
    // The window only opens in fully optimised code (-c Release with
    // DOTNET_TieredCompilation=0); unoptimised code keeps every local alive
    // to the end of its method. In a Debug run this is a smoke test, and
    // EveryNativeCallThatUsesAHandleTakesASafeHandle is the guard.
    [Fact]
    public void HandlesStayAliveForTheWholeNativeCall()
    {
        using CancellationTokenSource stop = new();
        Thread collector = new(() =>
        {
            while (!stop.IsCancellationRequested)
            {
                GC.Collect();
                GC.WaitForPendingFinalizers();
            }
        });
        collector.Start();

        try
        {
            byte[] message = "payload"u8.ToArray();
            byte[] context = "example/dotnet lifetime"u8.ToArray();
            for (int round = 0; round < 6; round++)
            {
                SealWithoutKeepingTheKey(message, out byte[] box, out byte[] sealedKey);
                using (SecretKey reopened = SecretKey.Open(sealedKey, Passphrase))
                {
                    // Sealing a freed key yields some other key, or nothing.
                    Assert.Equal(message, Hide.Decrypt(box, reopened).Plaintext);
                }

                SignWithoutKeepingTheIdentity(context, message, out byte[] verifying, out byte[] signature);
                Hide.Verify(verifying, context, message, signature);

                AcceptWithoutKeepingTheRecord();
            }
        }
        finally
        {
            stop.Cancel();
            collector.Join();
        }
    }

    [MethodImpl(MethodImplOptions.NoInlining)]
    private static void SealWithoutKeepingTheKey(byte[] message, out byte[] box, out byte[] sealedKey)
    {
        SecretKey key = SecretKey.Generate();
        box = Hide.Encrypt(message, [key.PublicKey()]);
        // The last use of `key`, and the longest call there is: Argon2.
        sealedKey = key.Protect(Passphrase);
    }

    [MethodImpl(MethodImplOptions.NoInlining)]
    private static void SignWithoutKeepingTheIdentity(
        byte[] context, byte[] message, out byte[] verifying, out byte[] signature)
    {
        SigningIdentity signer = SigningIdentity.Load(SigningIdentity.Generate(Passphrase), Passphrase);
        verifying = signer.PublicKey();
        signature = signer.Sign(context, message);
    }

    [MethodImpl(MethodImplOptions.NoInlining)]
    private static void AcceptWithoutKeepingTheRecord()
    {
        using SigningIdentity prover = SigningIdentity.Load(SigningIdentity.Generate(Passphrase), Passphrase);
        byte[] publicKey = prover.PublicKey();
        byte[] challenge = Hide.NewChallenge("api.example", 1_000, 60);
        byte[] answer = prover.Answer(challenge);

        SpentNonces spent = new();
        spent.Accept(challenge, answer, publicKey, 1_010);
    }

    // What actually keeps a handle alive across a native call is the type of
    // the P/Invoke parameter: the marshaller holds a reference on a SafeHandle
    // until the call returns, and holds nothing for an IntPtr. So a handle may
    // cross as a bare pointer in exactly two places: where the core creates it
    // (an out-pointer or a return value) and where a SafeHandle releases it.
    [Fact]
    public void EveryNativeCallThatUsesAHandleTakesASafeHandle()
    {
        MethodInfo[] imports = typeof(Native)
            .GetMethods(BindingFlags.Static | BindingFlags.NonPublic | BindingFlags.Public)
            .Where(method => method.Name.StartsWith("hide_", StringComparison.Ordinal))
            .ToArray();
        Assert.True(imports.Length >= 35, $"only {imports.Length} native functions were found");

        string[] barePointer = imports
            .Where(method => method.GetParameters().Any(parameter => parameter.ParameterType == typeof(IntPtr)))
            .Select(method => method.Name)
            .Order(StringComparer.Ordinal)
            .ToArray();
        string[] releases = ["hide_secret_key_free", "hide_signing_identity_free", "hide_spent_nonces_free"];
        Assert.Equal(releases, barePointer);

        string[] safe = imports
            .Where(method => method.GetParameters()
                .Any(parameter => typeof(SafeHandle).IsAssignableFrom(parameter.ParameterType)))
            .Select(method => method.Name)
            .Order(StringComparer.Ordinal)
            .ToArray();
        string[] uses =
        [
            "hide_challenge_accept",
            "hide_challenge_answer",
            "hide_decrypt",
            "hide_secret_key_protect",
            "hide_secret_key_public",
            "hide_sign_message",
            "hide_signing_identity_public",
        ];
        Assert.Equal(uses, safe);
    }

    [Fact]
    public void ADisposedRecordIsUnusable()
    {
        using SigningIdentity prover = SigningIdentity.Load(SigningIdentity.Generate(Passphrase), Passphrase);
        byte[] publicKey = prover.PublicKey();
        byte[] challenge = Hide.NewChallenge("api.example", 1_000, 60);
        byte[] answer = prover.Answer(challenge);

        SpentNonces spent = new();
        spent.Dispose();
        spent.Dispose();

        Assert.Throws<ObjectDisposedException>(() => spent.Accept(challenge, answer, publicKey, 1_010));
    }

    // Decrypt takes the key as an argument rather than as `this`, so its
    // disposed check is a separate code path from the instance methods.
    [Fact]
    public void ADisposedKeyCannotDecrypt()
    {
        SecretKey secret = SecretKey.Generate();
        byte[] box = Hide.Encrypt("x"u8, [secret.PublicKey()]);
        secret.Dispose();

        Assert.Throws<ObjectDisposedException>(() => Hide.Decrypt(box, secret));
    }
}
