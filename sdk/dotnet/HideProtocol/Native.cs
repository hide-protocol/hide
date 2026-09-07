using System.Runtime.InteropServices;

namespace HideProtocol;

/// <summary>The HideBuffer struct from hide.h: pointer, length, capacity.</summary>
[StructLayout(LayoutKind.Sequential)]
internal unsafe struct HideBuffer
{
    public byte* Data;
    public nuint Len;
    public nuint Capacity;
}

internal static unsafe partial class Native
{
    internal const string LibraryName = "hide_ffi";

    internal const int Ok = 0;
    internal const int ErrInvalidArgument = 1;
    internal const int ErrWrongPassphrase = 2;
    internal const int ErrNotAKey = 3;
    internal const int ErrAuthentication = 4;
    internal const int ErrNoMatchingRecipient = 5;
    internal const int ErrMalformed = 6;
    internal const int ErrTooLarge = 7;
    internal const int ErrChallengeExpired = 8;
    internal const int ErrChallengeReplayed = 9;

    internal const int KeyRaw = 0;
    internal const int KeyProtected = 1;

    // Runs before the first P/Invoke, since every one of them is a member of this class.
    static Native() =>
        NativeLibrary.SetDllImportResolver(typeof(Native).Assembly, Resolve);

    private static string[] CandidateNames()
    {
        if (OperatingSystem.IsWindows())
        {
            return ["hide_ffi.dll"];
        }

        return OperatingSystem.IsMacOS() ? ["libhide_ffi.dylib"] : ["libhide_ffi.so"];
    }

    private static IntPtr Resolve(string name, System.Reflection.Assembly assembly, DllImportSearchPath? path)
    {
        if (name != LibraryName)
        {
            return IntPtr.Zero;
        }

        // Developers running against a cargo build tree point this at the .dll/.so.
        string? over = Environment.GetEnvironmentVariable("HIDE_LIBRARY");
        if (!string.IsNullOrEmpty(over) && File.Exists(over)
            && NativeLibrary.TryLoad(over, out IntPtr handle))
        {
            return handle;
        }

        string? beside = Path.GetDirectoryName(assembly.Location);
        if (!string.IsNullOrEmpty(beside))
        {
            foreach (string candidate in CandidateNames())
            {
                string full = Path.Combine(beside, candidate);
                if (File.Exists(full) && NativeLibrary.TryLoad(full, out handle))
                {
                    return handle;
                }
            }
        }

        foreach (string candidate in CandidateNames())
        {
            if (NativeLibrary.TryLoad(candidate, assembly, path, out handle))
            {
                return handle;
            }
        }

        return NativeLibrary.TryLoad(LibraryName, assembly, path, out handle) ? handle : IntPtr.Zero;
    }

    [LibraryImport(LibraryName)]
    internal static partial byte* hide_error_message(int code);

    [LibraryImport(LibraryName)]
    internal static partial byte* hide_version();

    [LibraryImport(LibraryName)]
    internal static partial HideBuffer hide_buffer_empty();

    [LibraryImport(LibraryName)]
    internal static partial void hide_buffer_free(HideBuffer* buffer);

    [LibraryImport(LibraryName)]
    internal static partial int hide_keypair_generate(IntPtr* outSecret, HideBuffer* outPublic);

    [LibraryImport(LibraryName)]
    internal static partial int hide_inspect_key(byte* data, nuint len, int* outKind);

    [LibraryImport(LibraryName)]
    internal static partial int hide_secret_key_open(byte* data, nuint len, byte* passphrase, IntPtr* outSecret);

    [LibraryImport(LibraryName)]
    internal static partial int hide_secret_key_protect(IntPtr secret, byte* passphrase, HideBuffer* @out);

    [LibraryImport(LibraryName)]
    internal static partial int hide_secret_key_public(IntPtr secret, HideBuffer* @out);

    [LibraryImport(LibraryName)]
    internal static partial void hide_secret_key_free(IntPtr secret);

    [LibraryImport(LibraryName)]
    internal static partial int hide_public_key_armor(byte* data, nuint len, HideBuffer* @out);

    [LibraryImport(LibraryName)]
    internal static partial int hide_public_key_dearmor(byte* text, HideBuffer* @out);

    [LibraryImport(LibraryName)]
    internal static partial int hide_encrypt(
        byte* plaintext,
        nuint plaintextLen,
        byte* recipients,
        nuint recipientCount,
        byte* filename,
        byte* mediaType,
        HideBuffer* @out);

    [LibraryImport(LibraryName)]
    internal static partial int hide_decrypt(
        byte* container,
        nuint containerLen,
        IntPtr secret,
        HideBuffer* @out,
        HideBuffer* outFilename,
        HideBuffer* outMediaType);

    [LibraryImport(LibraryName)]
    internal static partial int hide_identity_generate(byte* passphrase, HideBuffer* outKeyFile);

    [LibraryImport(LibraryName)]
    internal static partial int hide_signing_identity_open(
        byte* data, nuint len, byte* passphrase, IntPtr* outIdentity);

    [LibraryImport(LibraryName)]
    internal static partial int hide_signing_identity_public(IntPtr identity, HideBuffer* @out);

    [LibraryImport(LibraryName)]
    internal static partial void hide_signing_identity_free(IntPtr identity);

    [LibraryImport(LibraryName)]
    internal static partial int hide_sign_message(
        IntPtr identity,
        byte* context,
        nuint contextLen,
        byte* message,
        nuint messageLen,
        HideBuffer* @out);

    [LibraryImport(LibraryName)]
    internal static partial int hide_verify_message(
        byte* publicKey,
        nuint publicKeyLen,
        byte* context,
        nuint contextLen,
        byte* message,
        nuint messageLen,
        byte* signature,
        nuint signatureLen);

    [LibraryImport(LibraryName)]
    internal static partial int hide_challenge_new(
        byte* audience, ulong now, ulong validFor, HideBuffer* @out);

    [LibraryImport(LibraryName)]
    internal static partial int hide_challenge_answer(
        IntPtr identity, byte* challenge, nuint challengeLen, HideBuffer* @out);

    [LibraryImport(LibraryName)]
    internal static partial IntPtr hide_spent_nonces_new();

    [LibraryImport(LibraryName)]
    internal static partial void hide_spent_nonces_free(IntPtr spent);

    [LibraryImport(LibraryName)]
    internal static partial int hide_challenge_accept(
        IntPtr spent,
        byte* challenge,
        nuint challengeLen,
        byte* signature,
        nuint signatureLen,
        byte* publicKey,
        nuint publicKeyLen,
        ulong now);

    [LibraryImport(LibraryName)]
    internal static partial int hide_identity_verify(
        byte* log, nuint logLen, byte* recovery, nuint recoveryLen, nuint* outDevices);

    [LibraryImport(LibraryName)]
    internal static partial int hide_identity_trusts_device(
        byte* log,
        nuint logLen,
        byte* recovery,
        nuint recoveryLen,
        byte* devicePublic,
        nuint devicePublicLen,
        int* outTrusted);

    [LibraryImport(LibraryName)]
    internal static partial int hide_identity_head(
        byte* log, nuint logLen, byte* recovery, nuint recoveryLen, HideBuffer* @out);

    [LibraryImport(LibraryName)]
    internal static partial int hide_epoch_verify(byte* chain, nuint chainLen, nuint* outEpochs);

    [LibraryImport(LibraryName)]
    internal static partial int hide_epoch_public_key(
        byte* chain, nuint chainLen, ulong epoch, HideBuffer* @out);

    [LibraryImport(LibraryName)]
    internal static partial int hide_transparency_verify_inclusion(
        byte* leaf,
        nuint leafLen,
        ulong index,
        ulong size,
        byte* path,
        nuint pathLen,
        byte* root,
        nuint rootLen);

    [LibraryImport(LibraryName)]
    internal static partial int hide_transparency_verify_consistency(
        ulong oldSize,
        ulong newSize,
        byte* path,
        nuint pathLen,
        byte* oldRoot,
        nuint oldRootLen,
        byte* newRoot,
        nuint newRootLen);
}
