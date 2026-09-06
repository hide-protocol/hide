namespace HideProtocol;

/// <summary>
/// A secret key. The bytes stay inside the native library and are never exposed
/// to managed code. Dispose it when finished.
/// </summary>
public sealed unsafe class SecretKey : IDisposable
{
    private IntPtr _handle;

    private SecretKey(IntPtr handle) => _handle = handle;

    public static SecretKey Generate()
    {
        IntPtr handle = IntPtr.Zero;
        HideBuffer publicKey = Native.hide_buffer_empty();
        Interop.Check(Native.hide_keypair_generate(&handle, &publicKey));
        Interop.Take(ref publicKey);
        return new SecretKey(handle);
    }

    /// <summary>Loads a key file. A protected key without its passphrase fails.</summary>
    public static SecretKey Open(ReadOnlySpan<byte> bytes, string? passphrase = null)
    {
        IntPtr handle = IntPtr.Zero;
        using Utf8String pass = Utf8String.Create(passphrase, nameof(passphrase));
        fixed (byte* data = bytes)
        {
            Interop.Check(Native.hide_secret_key_open(
                data, (nuint)bytes.Length, pass.Pointer, &handle));
        }

        return new SecretKey(handle);
    }

    public byte[] PublicKey()
    {
        IntPtr handle = Alive();
        HideBuffer output = Native.hide_buffer_empty();
        Interop.Check(Native.hide_secret_key_public(handle, &output));
        return Interop.Take(ref output);
    }

    /// <summary>
    /// Seals this key with a passphrase, for writing to disk. A forgotten
    /// passphrase cannot be recovered: there is no escrow.
    /// </summary>
    public byte[] Protect(string passphrase)
    {
        ArgumentNullException.ThrowIfNull(passphrase);
        IntPtr handle = Alive();
        if (passphrase.Length < Hide.MinPassphraseLength)
        {
            throw new ArgumentException(
                $"the passphrase must be at least {Hide.MinPassphraseLength} characters",
                nameof(passphrase));
        }

        using Utf8String pass = Utf8String.Create(passphrase, nameof(passphrase));
        HideBuffer output = Native.hide_buffer_empty();
        Interop.Check(Native.hide_secret_key_protect(handle, pass.Pointer, &output));
        return Interop.Take(ref output);
    }

    internal IntPtr Alive() =>
        _handle == IntPtr.Zero ? throw new ObjectDisposedException(nameof(SecretKey)) : _handle;

    public void Dispose()
    {
        if (_handle != IntPtr.Zero)
        {
            Native.hide_secret_key_free(_handle);
            _handle = IntPtr.Zero;
        }

        GC.SuppressFinalize(this);
    }

    ~SecretKey() => Dispose();

    // Never render key material, not even a fingerprint of it.
    public override string ToString() =>
        $"HideProtocol.SecretKey ({(_handle == IntPtr.Zero ? "disposed" : "open")})";
}
