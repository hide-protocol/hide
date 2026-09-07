namespace HideProtocol;

/// <summary>
/// A signing key. The seed stays inside the native library and is never exposed
/// to managed code. Dispose it when finished.
/// </summary>
public sealed unsafe class SigningIdentity : IDisposable
{
    private IntPtr _handle;

    private SigningIdentity(IntPtr handle) => _handle = handle;

    /// <summary>
    /// Creates an identity, returning the sealed key file to store. One seed
    /// backs both encryption and signing, so there is a single thing to back
    /// up. A forgotten passphrase cannot be recovered: there is no escrow.
    /// </summary>
    public static byte[] Generate(string passphrase)
    {
        ArgumentNullException.ThrowIfNull(passphrase);
        if (passphrase.Length < Hide.MinPassphraseLength)
        {
            throw new ArgumentException(
                $"the passphrase must be at least {Hide.MinPassphraseLength} characters",
                nameof(passphrase));
        }

        using Utf8String pass = Utf8String.Create(passphrase, nameof(passphrase));
        HideBuffer output = Native.hide_buffer_empty();
        Interop.Check(Native.hide_identity_generate(pass.Pointer, &output));
        return Interop.Take(ref output);
    }

    /// <summary>
    /// Loads a signing identity. A key file written before signatures existed
    /// carries no signing seed and is refused rather than silently downgraded.
    /// </summary>
    public static SigningIdentity Load(ReadOnlySpan<byte> data, string? passphrase = null)
    {
        IntPtr handle = IntPtr.Zero;
        using Utf8String pass = Utf8String.Create(passphrase, nameof(passphrase));
        fixed (byte* pointer = data)
        {
            Interop.Check(Native.hide_signing_identity_open(
                pointer, (nuint)data.Length, pass.Pointer, &handle));
        }

        return new SigningIdentity(handle);
    }

    /// <summary>The shareable verifying key, for others to check signatures with.</summary>
    public byte[] PublicKey()
    {
        IntPtr handle = Alive();
        HideBuffer output = Native.hide_buffer_empty();
        Interop.Check(Native.hide_signing_identity_public(handle, &output));
        return Interop.Take(ref output);
    }

    /// <summary>
    /// Signs <paramref name="message"/> under <paramref name="context"/>, which
    /// separates uses of one identity. Never let a remote party choose it.
    /// </summary>
    public byte[] Sign(ReadOnlySpan<byte> context, ReadOnlySpan<byte> message)
    {
        IntPtr handle = Alive();
        HideBuffer output = Native.hide_buffer_empty();
        fixed (byte* contextPointer = context)
        fixed (byte* messagePointer = message)
        {
            Interop.Check(Native.hide_sign_message(
                handle,
                contextPointer,
                (nuint)context.Length,
                messagePointer,
                (nuint)message.Length,
                &output));
        }

        return Interop.Take(ref output);
    }

    /// <summary>Answers a challenge, proving possession to whoever issued it.</summary>
    public byte[] Answer(ReadOnlySpan<byte> challenge)
    {
        IntPtr handle = Alive();
        HideBuffer output = Native.hide_buffer_empty();
        fixed (byte* pointer = challenge)
        {
            Interop.Check(Native.hide_challenge_answer(
                handle, pointer, (nuint)challenge.Length, &output));
        }

        return Interop.Take(ref output);
    }

    private IntPtr Alive() =>
        _handle == IntPtr.Zero ? throw new ObjectDisposedException(nameof(SigningIdentity)) : _handle;

    public void Dispose()
    {
        if (_handle != IntPtr.Zero)
        {
            Native.hide_signing_identity_free(_handle);
            _handle = IntPtr.Zero;
        }

        GC.SuppressFinalize(this);
    }

    ~SigningIdentity() => Dispose();

    // Never render key material, not even a fingerprint of it.
    public override string ToString() =>
        $"HideProtocol.SigningIdentity ({(_handle == IntPtr.Zero ? "disposed" : "open")})";
}
