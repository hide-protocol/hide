using System.Reflection;
using System.Runtime.InteropServices;

// Defence in depth. The resolver below only ever loads an absolute path, so
// the runtime's own probing is never reached for hide_ffi; if it ever were,
// this keeps the working directory and PATH out of the search.
[assembly: DefaultDllImportSearchPaths(
    DllImportSearchPath.AssemblyDirectory | DllImportSearchPath.SafeDirectories)]

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

    /// <summary>The runtime identifiers the package ships a compiled core for.</summary>
    internal static readonly string[] PackagedRids =
    [
        "linux-x64", "linux-arm64", "linux-musl-x64",
        "win-x64", "win-arm64",
        "osx-x64", "osx-arm64",
    ];

    // Loaded once. A failure is cached too, so every call reports the same
    // clear error instead of whatever the second attempt happens to hit.
    private static readonly Lazy<(IntPtr Handle, string Path)> Library =
        new(Load, LazyThreadSafetyMode.ExecutionAndPublication);

    // Runs before the first P/Invoke, since every one of them is a member of this class.
    static Native() =>
        NativeLibrary.SetDllImportResolver(typeof(Native).Assembly, Resolve);

    /// <summary>The absolute path the core was loaded from.</summary>
    internal static string LibraryPath => Library.Value.Path;

    /// <summary>
    /// The release this binding was built as: the assembly version, which the
    /// project file sets from its &lt;Version&gt;.
    /// </summary>
    internal static string BindingVersion
    {
        get
        {
            Version version = typeof(Native).Assembly.GetName().Version ?? new Version(0, 0, 0);
            return $"{version.Major}.{version.Minor}.{version.Build}";
        }
    }

    private static IntPtr Resolve(string name, Assembly assembly, DllImportSearchPath? path) =>
        name == LibraryName ? Library.Value.Handle : IntPtr.Zero;

    private static (IntPtr Handle, string Path) Load()
    {
        string path = Locate(
            Environment.GetEnvironmentVariable("HIDE_LIBRARY"),
            Environment.GetEnvironmentVariable("HIDE_ALLOW_LIBRARY_OVERRIDE") == "1",
            SearchDirectories(),
            PackageRoots(),
            PackagedRid(
                OperatingSystem.IsWindows(),
                OperatingSystem.IsMacOS(),
                OperatingSystem.IsLinux(),
                IsMusl(),
                RuntimeInformation.ProcessArchitecture),
            FileName(OperatingSystem.IsWindows(), OperatingSystem.IsMacOS()),
            RuntimeInformation.RuntimeIdentifier);

        IntPtr handle;
        try
        {
            // An absolute path: the operating system's search order is not consulted.
            handle = NativeLibrary.Load(path);
        }
        catch (Exception error) when (error is DllNotFoundException or BadImageFormatException)
        {
            throw new DllNotFoundException(
                $"the HIDE native library at {path} could not be loaded: {error.Message}", error);
        }

        if (!NativeLibrary.TryGetExport(handle, "hide_version", out IntPtr export))
        {
            throw new DllNotFoundException($"{path} is not a HIDE native library: it has no hide_version");
        }

        string? core = Marshal.PtrToStringUTF8((IntPtr)((delegate* unmanaged[Cdecl]<byte*>)export)());
        string? problem = VersionMismatch(BindingVersion, core);
        if (problem is not null)
        {
            throw new HideException($"{problem} (loaded from {path})");
        }

        return (handle, path);
    }

    /// <summary>
    /// Finds the core as an absolute path, or throws. Free of process state so
    /// it can be tested directly.
    ///
    /// The library is never handed to the operating system loader by bare
    /// name: that search covers the working directory and PATH on Windows and
    /// LD_LIBRARY_PATH / DYLD_LIBRARY_PATH elsewhere, so whoever controls any
    /// of those would choose the cryptographic core.
    /// </summary>
    internal static string Locate(
        string? overridePath,
        bool allowOverride,
        IReadOnlyList<string> directories,
        IReadOnlyList<string> packageRoots,
        string? rid,
        string fileName,
        string describedRid)
    {
        // Developers running against a cargo build tree point HIDE_LIBRARY at the
        // .dll/.so. It replaces the whole cryptographic core, so one settable env
        // var must not be enough: it is honoured only with an explicit second opt-in.
        string note = string.Empty;
        if (!string.IsNullOrEmpty(overridePath))
        {
            if (!allowOverride)
            {
                note = " HIDE_LIBRARY is set but was ignored, because HIDE_ALLOW_LIBRARY_OVERRIDE=1 is not.";
            }
            else if (File.Exists(overridePath))
            {
                return Path.GetFullPath(overridePath);
            }
            else
            {
                note = $" HIDE_LIBRARY names {overridePath}, which is not a file.";
            }
        }

        if (rid is null)
        {
            throw new PlatformNotSupportedException(
                $"the HideProtocol package has no native library for this platform (runtime identifier "
                + $"{describedRid}); it ships {string.Join(", ", PackagedRids)}. Build the core with "
                + "`cargo build --release -p hide-ffi` and set HIDE_LIBRARY to it together with "
                + $"HIDE_ALLOW_LIBRARY_OVERRIDE=1.{note}");
        }

        string packaged = Path.Combine("runtimes", rid, "native", fileName);
        foreach (string directory in directories)
        {
            foreach (string candidate in new[] { Path.Combine(directory, fileName), Path.Combine(directory, packaged) })
            {
                if (Path.IsPathFullyQualified(candidate) && File.Exists(candidate))
                {
                    return Path.GetFullPath(candidate);
                }
            }
        }

        foreach (string root in packageRoots)
        {
            string candidate = Path.Combine(root, packaged);
            if (Path.IsPathFullyQualified(candidate) && File.Exists(candidate))
            {
                return Path.GetFullPath(candidate);
            }
        }

        throw new DllNotFoundException(
            $"the HIDE native library ({fileName}, runtime identifier {rid}) was not found beside the "
            + "application or the HideProtocol assembly, nor under runtimes/" + rid + "/native. It is never "
            + "looked up by name through the system loader, so the working directory, PATH and "
            + "LD_LIBRARY_PATH are not searched. Developers: set HIDE_LIBRARY to the file produced by "
            + $"`cargo build --release -p hide-ffi` AND HIDE_ALLOW_LIBRARY_OVERRIDE=1.{note}");
    }

    /// <summary>
    /// The runtimes/&lt;rid&gt; folder this process needs, or null when the
    /// package ships no core for it.
    /// </summary>
    internal static string? PackagedRid(
        bool windows, bool macOS, bool linux, bool musl, Architecture architecture)
    {
        string? system = windows ? "win" : macOS ? "osx" : linux ? (musl ? "linux-musl" : "linux") : null;
        string? machine = architecture switch
        {
            Architecture.X64 => "x64",
            Architecture.Arm64 => "arm64",
            _ => null,
        };
        if (system is null || machine is null)
        {
            return null;
        }

        string rid = $"{system}-{machine}";
        return Array.IndexOf(PackagedRids, rid) >= 0 ? rid : null;
    }

    internal static string FileName(bool windows, bool macOS) =>
        windows ? "hide_ffi.dll" : macOS ? "libhide_ffi.dylib" : "libhide_ffi.so";

    private static bool IsMusl()
    {
        string rid = RuntimeInformation.RuntimeIdentifier;
        return rid.Contains("musl", StringComparison.OrdinalIgnoreCase)
            || rid.StartsWith("alpine", StringComparison.OrdinalIgnoreCase);
    }

    /// <summary>
    /// Absolute directories that belong to the application: its base directory,
    /// the directory of this assembly, and the native search directories the
    /// host computed from the application's own dependency manifest.
    /// </summary>
    private static List<string> SearchDirectories()
    {
        List<string> directories = [];
        Add(directories, AppContext.BaseDirectory);
        Add(directories, Path.GetDirectoryName(typeof(Native).Assembly.Location));
        if (AppContext.GetData("NATIVE_DLL_SEARCH_DIRECTORIES") is string listed)
        {
            foreach (string directory in listed.Split(Path.PathSeparator, StringSplitOptions.RemoveEmptyEntries))
            {
                Add(directories, directory);
            }
        }

        return directories;
    }

    /// <summary>
    /// When the assembly is loaded straight from a NuGet package folder
    /// (&lt;package&gt;/lib/&lt;tfm&gt;/), the package root two levels up holds runtimes/.
    /// </summary>
    private static List<string> PackageRoots()
    {
        List<string> roots = [];
        string? beside = Path.GetDirectoryName(typeof(Native).Assembly.Location);
        if (!string.IsNullOrEmpty(beside))
        {
            Add(roots, Path.GetDirectoryName(Path.GetDirectoryName(Path.TrimEndingDirectorySeparator(beside))));
        }

        return roots;
    }

    private static void Add(List<string> directories, string? directory)
    {
        if (!string.IsNullOrEmpty(directory) && Path.IsPathFullyQualified(directory)
            && !directories.Contains(directory))
        {
            directories.Add(directory);
        }
    }

    /// <summary>
    /// Null when the core is the release this binding was built as, otherwise
    /// the reason it is refused. Only major.minor.patch is compared; a
    /// pre-release or build suffix is ignored. A stale core would still load,
    /// and would silently lack whatever the newer release enforces.
    /// </summary>
    internal static string? VersionMismatch(string binding, string? core)
    {
        (int, int, int)? want = ParseVersion(binding);
        (int, int, int)? got = ParseVersion(core);
        if (want is not null && got is not null && want == got)
        {
            return null;
        }

        return $"this binding is version {binding} but the HIDE native library reports \"{core}\"; "
            + "use the library built from the same release";
    }

    private static (int, int, int)? ParseVersion(string? text)
    {
        if (text is null)
        {
            return null;
        }

        int cut = text.IndexOfAny(['-', '+']);
        string[] parts = (cut < 0 ? text : text[..cut]).Split('.');
        if (parts.Length != 3)
        {
            return null;
        }

        int[] numbers = new int[3];
        for (int index = 0; index < 3; index++)
        {
            string part = parts[index];
            if (part.Length is 0 or > 9 || !part.All(char.IsAsciiDigit))
            {
                return null;
            }

            numbers[index] = int.Parse(part, System.Globalization.CultureInfo.InvariantCulture);
        }

        return (numbers[0], numbers[1], numbers[2]);
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
    internal static partial int hide_secret_key_protect(SecretKeyHandle secret, byte* passphrase, HideBuffer* @out);

    [LibraryImport(LibraryName)]
    internal static partial int hide_secret_key_public(SecretKeyHandle secret, HideBuffer* @out);

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
        SecretKeyHandle secret,
        HideBuffer* @out,
        HideBuffer* outFilename,
        HideBuffer* outMediaType);

    [LibraryImport(LibraryName)]
    internal static partial int hide_identity_generate(byte* passphrase, HideBuffer* outKeyFile);

    [LibraryImport(LibraryName)]
    internal static partial int hide_signing_identity_open(
        byte* data, nuint len, byte* passphrase, IntPtr* outIdentity);

    [LibraryImport(LibraryName)]
    internal static partial int hide_signing_identity_public(SigningIdentityHandle identity, HideBuffer* @out);

    [LibraryImport(LibraryName)]
    internal static partial void hide_signing_identity_free(IntPtr identity);

    [LibraryImport(LibraryName)]
    internal static partial int hide_sign_message(
        SigningIdentityHandle identity,
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
        SigningIdentityHandle identity, byte* challenge, nuint challengeLen, HideBuffer* @out);

    [LibraryImport(LibraryName)]
    internal static partial IntPtr hide_spent_nonces_new();

    [LibraryImport(LibraryName)]
    internal static partial void hide_spent_nonces_free(IntPtr spent);

    [LibraryImport(LibraryName)]
    internal static partial int hide_challenge_accept(
        SpentNoncesHandle spent,
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
    internal static partial int hide_identity_verify_pinned(
        byte* log,
        nuint logLen,
        byte* recoveryBinding,
        nuint recoveryBindingLen,
        byte* pinnedRoot,
        nuint pinnedRootLen,
        nuint* outDevices);

    [LibraryImport(LibraryName)]
    internal static partial int hide_epoch_verify_bound(
        byte* log,
        nuint logLen,
        byte* recoveryBinding,
        nuint recoveryBindingLen,
        byte* pinnedRoot,
        nuint pinnedRootLen,
        byte* chain,
        nuint chainLen,
        byte* epochBinding,
        nuint epochBindingLen,
        nuint* outEpochs);

    [LibraryImport(LibraryName)]
    internal static partial int hide_checkpoint_verify(
        byte* note,
        nuint noteLen,
        byte* origin,
        byte* logPublic,
        nuint logPublicLen,
        ulong* outSize,
        HideBuffer* outRoot);

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
