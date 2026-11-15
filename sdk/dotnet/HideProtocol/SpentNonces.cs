namespace HideProtocol;

/// <summary>
/// The verifier's record of answered challenges. Replay can only be detected by
/// the verifier — a replayed answer is a genuine signature and nothing about it
/// is invalid on its own — so this must outlive a single request.
///
/// Safe for concurrent use: <see cref="Accept"/> serialises on an internal
/// lock, so one record can be shared by every request thread. The record is
/// in-process memory; it is not shared across processes or restarts.
/// </summary>
public sealed unsafe class SpentNonces : IDisposable
{
    private readonly SpentNoncesHandle _handle;

    // The record is mutated by every Accept, and the core does not lock it.
    private readonly object _gate = new();

    /// <summary>
    /// Creates a record for the audience <paramref name="audience"/>: the same
    /// name that was passed to <see cref="Hide.NewChallenge"/>. An answer
    /// minted for a different audience is refused with
    /// <see cref="ChallengeAudienceException"/>, so a challenge relayed from
    /// another service cannot be answered here. A record built with an empty
    /// audience accepts nothing.
    /// </summary>
    public SpentNonces(string audience)
    {
        ArgumentNullException.ThrowIfNull(audience);
        using Utf8String target = Utf8String.Create(audience, nameof(audience));
        IntPtr handle = Native.hide_spent_nonces_new(target.Pointer);
        if (handle == IntPtr.Zero)
        {
            throw new HideException("could not allocate the nonce record");
        }

        _handle = new SpentNoncesHandle(handle);
    }

    /// <summary>
    /// Accepts an answer exactly once. Throws <see cref="ChallengeReplayedException"/>
    /// the second time, <see cref="ChallengeExpiredException"/> after the window,
    /// <see cref="ChallengeAudienceException"/> when the challenge names another
    /// audience or this record's audience is empty, and
    /// <see cref="AuthenticationException"/> if it does not verify.
    /// </summary>
    public void Accept(
        ReadOnlySpan<byte> challenge,
        ReadOnlySpan<byte> signature,
        ReadOnlySpan<byte> publicKey,
        ulong now)
    {
        SpentNoncesHandle handle = _handle.IsClosed
            ? throw new ObjectDisposedException(nameof(SpentNonces))
            : _handle;

        fixed (byte* challengePointer = challenge)
        fixed (byte* signaturePointer = signature)
        fixed (byte* publicKeyPointer = publicKey)
        {
            int code;
            lock (_gate)
            {
                code = Native.hide_challenge_accept(
                    handle,
                    challengePointer,
                    (nuint)challenge.Length,
                    signaturePointer,
                    (nuint)signature.Length,
                    publicKeyPointer,
                    (nuint)publicKey.Length,
                    now);
            }

            Interop.Check(code);
        }
    }

    /// <summary>Releases the record. Safe to call twice.</summary>
    public void Dispose() => _handle.Dispose();
}
