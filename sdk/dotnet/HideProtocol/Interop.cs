using System.Runtime.InteropServices;
using System.Text;

namespace HideProtocol;

/// <summary>Owns a NUL-terminated UTF-8 copy of a string for the duration of a call.</summary>
internal readonly unsafe struct Utf8String : IDisposable
{
    private readonly IntPtr _pointer;

    private Utf8String(IntPtr pointer) => _pointer = pointer;

    /// <summary>A null string becomes a genuine null pointer, never an empty string.</summary>
    internal static Utf8String Create(string? value, string parameterName)
    {
        if (value is null)
        {
            return new Utf8String(IntPtr.Zero);
        }

        // The C ABI takes these NUL-terminated, so an embedded NUL would be
        // silently truncated. Refuse rather than send something different.
        if (value.Contains('\0'))
        {
            throw new ArgumentException("the value must not contain a NUL character", parameterName);
        }

        return new Utf8String(Marshal.StringToCoTaskMemUTF8(value));
    }

    internal byte* Pointer => (byte*)_pointer;

    public void Dispose()
    {
        if (_pointer != IntPtr.Zero)
        {
            Marshal.FreeCoTaskMem(_pointer);
        }
    }
}

internal static unsafe class Interop
{
    internal static void Check(int code)
    {
        if (code == Native.Ok)
        {
            return;
        }

        string message = Marshal.PtrToStringUTF8((IntPtr)Native.hide_error_message(code))
            ?? $"HIDE error {code}";

        throw code switch
        {
            Native.ErrInvalidArgument => new ArgumentException(message),
            Native.ErrTooLarge => new ArgumentException(message),
            Native.ErrWrongPassphrase => new WrongPassphraseException(message),
            Native.ErrNotAKey => new NotAKeyException(message),
            Native.ErrAuthentication => new AuthenticationException(message),
            Native.ErrMalformed => new AuthenticationException(message),
            Native.ErrNoMatchingRecipient => new NoMatchingRecipientException(message),
            Native.ErrChallengeExpired => new ChallengeExpiredException(message),
            Native.ErrChallengeReplayed => new ChallengeReplayedException(message),
            _ => (Exception)new HideException(message),
        };
    }

    /// <summary>Copies a native buffer into managed bytes and frees the original.</summary>
    internal static byte[] Take(ref HideBuffer buffer)
    {
        try
        {
            if (buffer.Data is null || buffer.Len == 0)
            {
                return [];
            }

            return new ReadOnlySpan<byte>(buffer.Data, checked((int)buffer.Len)).ToArray();
        }
        finally
        {
            fixed (HideBuffer* pointer = &buffer)
            {
                Native.hide_buffer_free(pointer);
            }
        }
    }

    /// <summary>
    /// Metadata arrives as length-prefixed UTF-8 and may legitimately contain NUL,
    /// so it is decoded with the buffer's explicit length. Empty means absent.
    /// </summary>
    internal static string? TakeText(ref HideBuffer buffer)
    {
        byte[] raw = Take(ref buffer);
        return DecodeText(raw);
    }

    /// <summary>
    /// Decodes length-delimited UTF-8. Never scan for a terminator: metadata is
    /// attacker-controlled and an embedded NUL would silently truncate the value.
    /// </summary>
    internal static string? DecodeText(ReadOnlySpan<byte> raw) =>
        raw.Length == 0 ? null : Encoding.UTF8.GetString(raw);
}
