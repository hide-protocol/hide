namespace HideProtocol;

/// <summary>
/// The verifier's record of answered challenges. Replay can only be detected by
/// the verifier — a replayed answer is a genuine signature and nothing about it
/// is invalid on its own — so this must outlive a single request.
/// </summary>
public sealed unsafe class SpentNonces : IDisposable
{
    private IntPtr _handle;

    public SpentNonces()
    {
        _handle = Native.hide_spent_nonces_new();
        if (_handle == IntPtr.Zero)
        {
            throw new HideException("could not allocate the nonce record");
        }
    }

    /// <summary>
    /// Accepts an answer exactly once. Throws <see cref="ChallengeReplayedException"/>
    /// the second time, <see cref="ChallengeExpiredException"/> after the window,
    /// and <see cref="AuthenticationException"/> if it does not verify.
    /// </summary>
    public void Accept(
        ReadOnlySpan<byte> challenge,
        ReadOnlySpan<byte> signature,
        ReadOnlySpan<byte> publicKey,
        ulong now)
    {
        IntPtr handle = _handle == IntPtr.Zero
            ? throw new ObjectDisposedException(nameof(SpentNonces))
            : _handle;

        fixed (byte* challengePointer = challenge)
        fixed (byte* signaturePointer = signature)
        fixed (byte* publicKeyPointer = publicKey)
        {
            Interop.Check(Native.hide_challenge_accept(
                handle,
                challengePointer,
                (nuint)challenge.Length,
                signaturePointer,
                (nuint)signature.Length,
                publicKeyPointer,
                (nuint)publicKey.Length,
                now));
        }
    }

    public void Dispose()
    {
        if (_handle != IntPtr.Zero)
        {
            Native.hide_spent_nonces_free(_handle);
            _handle = IntPtr.Zero;
        }

        GC.SuppressFinalize(this);
    }

    ~SpentNonces() => Dispose();
}
