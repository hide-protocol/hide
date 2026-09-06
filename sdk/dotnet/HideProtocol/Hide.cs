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
}
