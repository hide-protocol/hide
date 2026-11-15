using System.Runtime.InteropServices;

namespace HideProtocol;

// The native handles are SafeHandles rather than bare IntPtr fields for one
// reason: a P/Invoke that takes a SafeHandle holds a reference on it for the
// whole call. With an IntPtr the owning object is unreachable as soon as the
// pointer has been read, so its finalizer could free the key while the core
// was still using it (most easily during Protect, which runs Argon2). The
// reference count also makes Dispose from another thread safe: the release is
// deferred until the call in flight has returned.

/// <summary>Owns a HideSecretKey.</summary>
internal sealed class SecretKeyHandle : SafeHandle
{
    internal SecretKeyHandle(IntPtr secret)
        : base(IntPtr.Zero, ownsHandle: true) => SetHandle(secret);

    public override bool IsInvalid => handle == IntPtr.Zero;

    protected override bool ReleaseHandle()
    {
        Native.hide_secret_key_free(handle);
        return true;
    }
}

/// <summary>Owns a HideSigningIdentity.</summary>
internal sealed class SigningIdentityHandle : SafeHandle
{
    internal SigningIdentityHandle(IntPtr identity)
        : base(IntPtr.Zero, ownsHandle: true) => SetHandle(identity);

    public override bool IsInvalid => handle == IntPtr.Zero;

    protected override bool ReleaseHandle()
    {
        Native.hide_signing_identity_free(handle);
        return true;
    }
}

/// <summary>Owns a HideSpentNonces.</summary>
internal sealed class SpentNoncesHandle : SafeHandle
{
    internal SpentNoncesHandle(IntPtr spent)
        : base(IntPtr.Zero, ownsHandle: true) => SetHandle(spent);

    public override bool IsInvalid => handle == IntPtr.Zero;

    protected override bool ReleaseHandle()
    {
        Native.hide_spent_nonces_free(handle);
        return true;
    }
}
