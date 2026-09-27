using System.Runtime.InteropServices;

namespace HideProtocol;

/// <summary>A verified payload. Holding one of these means it authenticated.</summary>
/// <param name="Plaintext">The decrypted bytes.</param>
/// <param name="FileName">Attacker-controlled: never use it to choose an output path.</param>
/// <param name="MediaType">Attacker-controlled, advisory only.</param>
public sealed record Decrypted(byte[] Plaintext, string? FileName, string? MediaType);

/// <summary>Kind of a stored key, as reported without needing the passphrase.</summary>
public enum KeyKind
{
    Raw,
    Protected,
}

/// <summary>
/// HIDE — encrypt to a person, not to a key.
///
/// EXPERIMENTAL AND UNAUDITED. A successful decryption proves the data was not
/// altered; it does NOT prove who created it.
/// </summary>
public static unsafe class Hide
{
    public const int PublicKeyLength = 1216;
    public const int MinPassphraseLength = 8;
    public const int SignatureLength = 3373;
    public const int VerifyingKeyLength = 1984;
    public const int NonceLength = 32;

    private const int MaxRecipients = 64;

    /// <summary>The version of the native library.</summary>
    public static string Version =>
        Marshal.PtrToStringUTF8((IntPtr)Native.hide_version()) ?? string.Empty;

    /// <summary>Encrypts for 1..64 recipient public keys.</summary>
    public static byte[] Encrypt(
        ReadOnlySpan<byte> plaintext,
        IReadOnlyList<byte[]> recipients,
        string? filename = null,
        string? mediaType = null)
    {
        ArgumentNullException.ThrowIfNull(recipients);
        if (recipients.Count is < 1 or > MaxRecipients)
        {
            throw new ArgumentException(
                $"there must be between 1 and {MaxRecipients} recipients", nameof(recipients));
        }

        byte[] joined = new byte[recipients.Count * PublicKeyLength];
        for (int index = 0; index < recipients.Count; index++)
        {
            byte[] key = recipients[index]
                ?? throw new ArgumentException("a recipient key was null", nameof(recipients));
            if (key.Length != PublicKeyLength)
            {
                throw new ArgumentException(
                    $"a public key is {PublicKeyLength} bytes, got {key.Length}",
                    nameof(recipients));
            }

            key.CopyTo(joined, index * PublicKeyLength);
        }

        using Utf8String name = Utf8String.Create(filename, nameof(filename));
        using Utf8String media = Utf8String.Create(mediaType, nameof(mediaType));
        HideBuffer output = Native.hide_buffer_empty();

        fixed (byte* text = plaintext)
        fixed (byte* keys = joined)
        {
            Interop.Check(Native.hide_encrypt(
                text,
                (nuint)plaintext.Length,
                keys,
                (nuint)recipients.Count,
                name.Pointer,
                media.Pointer,
                &output));
        }

        return Interop.Take(ref output);
    }

    /// <summary>
    /// Decrypts and verifies. Nothing is returned unless the whole payload
    /// authenticates.
    /// </summary>
    public static Decrypted Decrypt(ReadOnlySpan<byte> container, SecretKey secret)
    {
        ArgumentNullException.ThrowIfNull(secret);
        IntPtr handle = secret.Alive();

        HideBuffer output = Native.hide_buffer_empty();
        HideBuffer filename = Native.hide_buffer_empty();
        HideBuffer mediaType = Native.hide_buffer_empty();

        fixed (byte* data = container)
        {
            Interop.Check(Native.hide_decrypt(
                data, (nuint)container.Length, handle, &output, &filename, &mediaType));
        }

        return new Decrypted(
            Interop.Take(ref output),
            Interop.TakeText(ref filename),
            Interop.TakeText(ref mediaType));
    }

    /// <summary>Renders a public key as pasteable text.</summary>
    public static string ArmorPublicKey(ReadOnlySpan<byte> publicKey)
    {
        HideBuffer output = Native.hide_buffer_empty();
        fixed (byte* data = publicKey)
        {
            Interop.Check(Native.hide_public_key_armor(data, (nuint)publicKey.Length, &output));
        }

        return Interop.TakeText(ref output) ?? string.Empty;
    }

    public static byte[] DearmorPublicKey(string text)
    {
        ArgumentNullException.ThrowIfNull(text);
        using Utf8String encoded = Utf8String.Create(text, nameof(text));
        HideBuffer output = Native.hide_buffer_empty();
        Interop.Check(Native.hide_public_key_dearmor(encoded.Pointer, &output));
        return Interop.Take(ref output);
    }

    /// <summary>Reports whether stored key bytes are raw or passphrase-protected.</summary>
    public static KeyKind InspectKey(ReadOnlySpan<byte> data)
    {
        int kind = -1;
        fixed (byte* pointer = data)
        {
            Interop.Check(Native.hide_inspect_key(pointer, (nuint)data.Length, &kind));
        }

        return kind == Native.KeyProtected ? KeyKind.Protected : KeyKind.Raw;
    }

    /// <summary>
    /// Throws unless both the Ed25519 and ML-DSA halves verify. It returns void
    /// rather than a bool so that a caller who forgets to check cannot treat
    /// every failure as a pass.
    /// </summary>
    public static void Verify(
        ReadOnlySpan<byte> publicKey,
        ReadOnlySpan<byte> context,
        ReadOnlySpan<byte> message,
        ReadOnlySpan<byte> signature)
    {
        fixed (byte* key = publicKey)
        fixed (byte* contextPointer = context)
        fixed (byte* messagePointer = message)
        fixed (byte* signaturePointer = signature)
        {
            Interop.Check(Native.hide_verify_message(
                key,
                (nuint)publicKey.Length,
                contextPointer,
                (nuint)context.Length,
                messagePointer,
                (nuint)message.Length,
                signaturePointer,
                (nuint)signature.Length));
        }
    }

    /// <summary>
    /// Creates a challenge for a prover to answer. A detached signature proves
    /// possession at some point, to nobody in particular, and can be replayed;
    /// a challenge binds a random nonce, an audience and an expiry.
    /// </summary>
    public static byte[] NewChallenge(string audience, ulong now, ulong validFor)
    {
        ArgumentNullException.ThrowIfNull(audience);
        using Utf8String target = Utf8String.Create(audience, nameof(audience));
        HideBuffer output = Native.hide_buffer_empty();
        Interop.Check(Native.hide_challenge_new(target.Pointer, now, validFor, &output));
        return Interop.Take(ref output);
    }

    /// <summary>
    /// Replays an identity log and returns how many devices it trusts now.
    ///
    /// Throws <see cref="MalformedException"/> for a log that does not decode and
    /// <see cref="AuthenticationException"/> for one that decodes but does not
    /// verify — the distinction that tells corruption from forgery. It returns a
    /// count rather than a bool so that a caller who forgets to check cannot
    /// treat every failure as a pass.
    /// </summary>
    public static int VerifyIdentity(ReadOnlySpan<byte> log, ReadOnlySpan<byte> recoveryKey)
    {
        nuint devices = 0;
        fixed (byte* logPointer = log)
        fixed (byte* recoveryPointer = recoveryKey)
        {
            Interop.Check(Native.hide_identity_verify(
                logPointer,
                (nuint)log.Length,
                recoveryPointer,
                (nuint)recoveryKey.Length,
                &devices));
        }

        return checked((int)devices);
    }

    /// <summary>
    /// Whether the log trusts this device right now.
    ///
    /// A bool is right here — this is a membership query, not a cryptographic
    /// check. The log is still verified first, so false means "not a member",
    /// never "did not verify".
    /// </summary>
    public static bool IdentityTrustsDevice(
        ReadOnlySpan<byte> log,
        ReadOnlySpan<byte> recoveryKey,
        ReadOnlySpan<byte> devicePublicKey)
    {
        int trusted = 0;
        fixed (byte* logPointer = log)
        fixed (byte* recoveryPointer = recoveryKey)
        fixed (byte* devicePointer = devicePublicKey)
        {
            Interop.Check(Native.hide_identity_trusts_device(
                logPointer,
                (nuint)log.Length,
                recoveryPointer,
                (nuint)recoveryKey.Length,
                devicePointer,
                (nuint)devicePublicKey.Length,
                &trusted));
        }

        return trusted != 0;
    }

    /// <summary>The head link: 32 bytes naming this exact history.</summary>
    public static byte[] IdentityHead(ReadOnlySpan<byte> log, ReadOnlySpan<byte> recoveryKey)
    {
        HideBuffer output = Native.hide_buffer_empty();
        fixed (byte* logPointer = log)
        fixed (byte* recoveryPointer = recoveryKey)
        {
            Interop.Check(Native.hide_identity_head(
                logPointer,
                (nuint)log.Length,
                recoveryPointer,
                (nuint)recoveryKey.Length,
                &output));
        }

        return Interop.Take(ref output);
    }

    /// <summary>
    /// Verifies a log as a relying party and returns how many devices it trusts
    /// now. Its root must equal <paramref name="pinnedRoot"/>, the 32-byte
    /// identity root trusted out of band, and <paramref name="recoveryBinding"/>
    /// establishes the recovery key, so a Recover appended under a stranger's
    /// key does not verify.
    ///
    /// Throws as <see cref="VerifyIdentity"/> does: <see cref="MalformedException"/>
    /// for bytes that do not decode, <see cref="AuthenticationException"/> for a
    /// log that is not this identity's.
    /// </summary>
    public static int VerifyIdentityPinned(
        ReadOnlySpan<byte> log,
        ReadOnlySpan<byte> recoveryBinding,
        ReadOnlySpan<byte> pinnedRoot)
    {
        nuint devices = 0;
        fixed (byte* logPointer = log)
        fixed (byte* bindingPointer = recoveryBinding)
        fixed (byte* rootPointer = pinnedRoot)
        {
            Interop.Check(Native.hide_identity_verify_pinned(
                logPointer,
                (nuint)log.Length,
                bindingPointer,
                (nuint)recoveryBinding.Length,
                rootPointer,
                (nuint)pinnedRoot.Length,
                &devices));
        }

        return checked((int)devices);
    }

    /// <summary>
    /// Verifies a published epoch history and returns how many epochs it holds.
    /// </summary>
    public static int VerifyEpochChain(ReadOnlySpan<byte> chain)
    {
        nuint epochs = 0;
        fixed (byte* pointer = chain)
        {
            Interop.Check(Native.hide_epoch_verify(pointer, (nuint)chain.Length, &epochs));
        }

        return checked((int)epochs);
    }

    /// <summary>
    /// Verifies an epoch chain AND that it belongs to the pinned identity:
    /// <paramref name="epochBinding"/> must be signed, over this chain, by a
    /// device the log trusts now. Returns how many epochs the chain holds.
    ///
    /// A chain that verifies on its own proves only that it is
    /// self-consistent; anyone can publish one. This is the check that says
    /// whose it is.
    /// </summary>
    public static int VerifyEpochChainBound(
        ReadOnlySpan<byte> log,
        ReadOnlySpan<byte> recoveryBinding,
        ReadOnlySpan<byte> pinnedRoot,
        ReadOnlySpan<byte> chain,
        ReadOnlySpan<byte> epochBinding)
    {
        nuint epochs = 0;
        fixed (byte* logPointer = log)
        fixed (byte* bindingPointer = recoveryBinding)
        fixed (byte* rootPointer = pinnedRoot)
        fixed (byte* chainPointer = chain)
        fixed (byte* epochPointer = epochBinding)
        {
            Interop.Check(Native.hide_epoch_verify_bound(
                logPointer,
                (nuint)log.Length,
                bindingPointer,
                (nuint)recoveryBinding.Length,
                rootPointer,
                (nuint)pinnedRoot.Length,
                chainPointer,
                (nuint)chain.Length,
                epochPointer,
                (nuint)epochBinding.Length,
                &epochs));
        }

        return checked((int)epochs);
    }

    /// <summary>
    /// The public key a sender should encrypt to for <paramref name="epoch"/>.
    /// The chain is verified first, so a key is never returned from a history
    /// that does not hold together. An epoch beyond the chain throws
    /// <see cref="ArgumentException"/>.
    /// </summary>
    public static byte[] EpochPublicKey(ReadOnlySpan<byte> chain, ulong epoch)
    {
        HideBuffer output = Native.hide_buffer_empty();
        fixed (byte* pointer = chain)
        {
            Interop.Check(Native.hide_epoch_public_key(
                pointer, (nuint)chain.Length, epoch, &output));
        }

        return Interop.Take(ref output);
    }

    /// <summary>
    /// Checks that <paramref name="leaf"/> is entry <paramref name="index"/> of a
    /// log of <paramref name="size"/> entries under <paramref name="root"/>.
    /// <paramref name="path"/> is the concatenated 32-byte hashes; any other
    /// length throws <see cref="ArgumentException"/>.
    ///
    /// Returns void rather than a bool, for the same reason
    /// <see cref="Verify"/> does.
    /// </summary>
    public static void VerifyInclusion(
        ReadOnlySpan<byte> leaf,
        ulong index,
        ulong size,
        ReadOnlySpan<byte> path,
        ReadOnlySpan<byte> root)
    {
        fixed (byte* leafPointer = leaf)
        fixed (byte* pathPointer = path)
        fixed (byte* rootPointer = root)
        {
            Interop.Check(Native.hide_transparency_verify_inclusion(
                leafPointer,
                (nuint)leaf.Length,
                index,
                size,
                pathPointer,
                (nuint)path.Length,
                rootPointer,
                (nuint)root.Length));
        }
    }

    /// <summary>
    /// Checks that <paramref name="oldRoot"/> really is the root the log had
    /// before it grew to <paramref name="newRoot"/>. This is the check that
    /// catches a rewritten history.
    /// </summary>
    public static void VerifyConsistency(
        ulong oldSize,
        ulong newSize,
        ReadOnlySpan<byte> path,
        ReadOnlySpan<byte> oldRoot,
        ReadOnlySpan<byte> newRoot)
    {
        fixed (byte* pathPointer = path)
        fixed (byte* oldPointer = oldRoot)
        fixed (byte* newPointer = newRoot)
        {
            Interop.Check(Native.hide_transparency_verify_consistency(
                oldSize,
                newSize,
                pathPointer,
                (nuint)path.Length,
                oldPointer,
                (nuint)oldRoot.Length,
                newPointer,
                (nuint)newRoot.Length));
        }
    }

    /// <summary>
    /// Verifies a C2SP signed checkpoint note from the log named
    /// <paramref name="origin"/>, signed with HIDE-Sign under
    /// <paramref name="logPublicKey"/>, and returns the tree size and the
    /// 32-byte root it commits to.
    ///
    /// A note signed by any other key — a witness, say — or naming another
    /// origin throws <see cref="AuthenticationException"/>; nothing is returned
    /// from a note that did not verify.
    /// </summary>
    public static (ulong Size, byte[] Root) VerifyCheckpoint(
        ReadOnlySpan<byte> note,
        string origin,
        ReadOnlySpan<byte> logPublicKey)
    {
        ArgumentNullException.ThrowIfNull(origin);
        using Utf8String name = Utf8String.Create(origin, nameof(origin));
        ulong size = 0;
        HideBuffer root = Native.hide_buffer_empty();
        fixed (byte* notePointer = note)
        fixed (byte* keyPointer = logPublicKey)
        {
            Interop.Check(Native.hide_checkpoint_verify(
                notePointer,
                (nuint)note.Length,
                name.Pointer,
                keyPointer,
                (nuint)logPublicKey.Length,
                &size,
                &root));
        }

        return (size, Interop.Take(ref root));
    }
}
