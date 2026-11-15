using System.Diagnostics;
using System.Runtime.InteropServices;
using HideProtocol;
using Xunit;

namespace HideProtocol.Tests;

/// <summary>
/// Which native library a process loads decides which cryptography it runs,
/// so the search is tested twice: as a pure function, and by starting fresh
/// processes in a layout and environment the test controls.
/// </summary>
public sealed class LoadingTests : IClassFixture<LoadingTests.Stage>
{
    private readonly Stage _stage;

    public LoadingTests(Stage stage) => _stage = stage;

    // HIDE_LIBRARY replaces the whole cryptographic core. On its own it must
    // change nothing, whether it names a real library or not.
    [Fact]
    public void ALibraryOverrideWithoutTheOptInIsIgnored()
    {
        string missing = Path.Combine(_stage.Root, "no-such-directory", _stage.FileName);

        Child nothing = _stage.Probe(_stage.With, _stage.Root, new() { ["HIDE_LIBRARY"] = missing });
        _stage.AssertLoadedFrom("with", nothing);

        Child real = _stage.Probe(_stage.With, _stage.Root, new() { ["HIDE_LIBRARY"] = _stage.Spare });
        _stage.AssertLoadedFrom("with", real);

        // With nothing beside the application the override is still not used.
        Child alone = _stage.Probe(_stage.Without, _stage.Root, new() { ["HIDE_LIBRARY"] = _stage.Spare });
        Assert.True(
            alone.ExitCode == Tests.Probe.LoadFailed && alone.Output.Contains("was ignored"),
            $"an override without the opt-in was honoured: exit {alone.ExitCode}, output: {alone.Output}");
    }

    [Fact]
    public void ALibraryOverrideWithTheOptInIsUsed()
    {
        Child both = _stage.Probe(_stage.With, _stage.Root, new()
        {
            ["HIDE_LIBRARY"] = _stage.Spare,
            ["HIDE_ALLOW_LIBRARY_OVERRIDE"] = "1",
        });
        _stage.AssertLoadedFrom("spare", both);

        // Anything but exactly "1" is not an opt-in.
        Child almost = _stage.Probe(_stage.With, _stage.Root, new()
        {
            ["HIDE_LIBRARY"] = _stage.Spare,
            ["HIDE_ALLOW_LIBRARY_OVERRIDE"] = "true",
        });
        _stage.AssertLoadedFrom("with", almost);
    }

    // A copy of the core in the working directory and on every search path the
    // system loader honours must not be picked up: whoever controls one of
    // those would otherwise choose the cryptographic core.
    [Fact]
    public void TheLibraryIsNeverTakenFromTheWorkingDirectoryOrASearchPath()
    {
        string planted = Path.GetDirectoryName(_stage.Planted)!;
        Child child = _stage.Probe(_stage.Without, planted, new()
        {
            ["PATH"] = planted + Path.PathSeparator + Environment.GetEnvironmentVariable("PATH"),
            ["LD_LIBRARY_PATH"] = planted,
            ["DYLD_LIBRARY_PATH"] = planted,
        });

        Assert.True(
            child.ExitCode == Tests.Probe.LoadFailed
                && child.Output.Contains("was not found")
                && !child.Output.Contains("LIBRARY="),
            $"a planted library was loaded, or the failure was not the expected one: exit {child.ExitCode}, "
                + $"output: {child.Output}");
    }

    [Fact]
    public void TheSearchReturnsAnAbsolutePathOrThrows()
    {
        const string name = "placeholder-core.bin";
        const string rid = "linux-x64";
        string root = Path.Combine(_stage.Root, "locate");
        string beside = Directory.CreateDirectory(Path.Combine(root, "beside")).FullName;
        string app = Directory.CreateDirectory(Path.Combine(root, "app")).FullName;
        string package = Directory.CreateDirectory(Path.Combine(root, "package")).FullName;
        string empty = Directory.CreateDirectory(Path.Combine(root, "empty")).FullName;
        string elsewhere = Directory.CreateDirectory(Path.Combine(root, "elsewhere")).FullName;

        string besideFile = Touch(Path.Combine(beside, name));
        string appFile = Touch(Path.Combine(app, "runtimes", rid, "native", name));
        string otherRid = Touch(Path.Combine(empty, "runtimes", "win-x64", "native", name));
        string packageFile = Touch(Path.Combine(package, "runtimes", rid, "native", name));
        string spare = Touch(Path.Combine(elsewhere, "spare.bin"));
        string missing = Path.Combine(elsewhere, "missing.bin");

        string Locate(string? over, bool allow, string[] directories, string[] roots, string? id = rid) =>
            Native.Locate(over, allow, directories, roots, id, name, "test-rid");

        Assert.Equal(besideFile, Locate(null, false, [beside], []));
        Assert.Equal(appFile, Locate(null, false, [app], []));
        Assert.Equal(packageFile, Locate(null, false, [empty], [package]));
        Assert.Equal(besideFile, Locate(null, false, [empty, beside], [package]));

        // The gate: without the opt-in an override is ignored, whatever it names.
        Assert.Equal(besideFile, Locate(spare, false, [beside], []));
        Assert.Equal(besideFile, Locate(missing, false, [beside], []));
        Assert.Equal(spare, Locate(spare, true, [beside], []));
        Assert.Equal(besideFile, Locate(missing, true, [beside], []));
        // The override wins even where the package has nothing for the platform.
        Assert.Equal(spare, Locate(spare, true, [], [], id: null));

        Assert.True(Path.IsPathFullyQualified(Locate(null, false, [beside], [])));

        // Nothing found is an error that says so; a bare name is never left
        // for the system loader to resolve.
        DllNotFoundException none = Assert.Throws<DllNotFoundException>(() => Locate(null, false, [empty], []));
        Assert.Contains("was not found", none.Message);
        Assert.Contains(rid, none.Message);
        Assert.True(File.Exists(otherRid)); // another platform's copy is not this platform's
        Assert.Contains(
            "was ignored", Assert.Throws<DllNotFoundException>(() => Locate(spare, false, [empty], [])).Message);
        Assert.Contains(
            "is not a file", Assert.Throws<DllNotFoundException>(() => Locate(missing, true, [empty], [])).Message);
        // A directory is not a library.
        Assert.Throws<DllNotFoundException>(() => Locate(elsewhere, true, [empty], []));
        // A relative directory would resolve against the working directory.
        Assert.Throws<DllNotFoundException>(() => Locate(null, false, ["."], ["."]));
    }

    [Fact]
    public void AnUnsupportedPlatformIsNamedInTheError()
    {
        PlatformNotSupportedException error = Assert.Throws<PlatformNotSupportedException>(() =>
            Native.Locate(null, false, [_stage.With], [], null, "libhide_ffi.so", "freebsd-x64"));

        Assert.Contains("freebsd-x64", error.Message);
        Assert.Contains("linux-musl-x64", error.Message);
        Assert.Contains("HIDE_ALLOW_LIBRARY_OVERRIDE", error.Message);
    }

    [Theory]
    [InlineData(true, false, false, false, Architecture.X64, "win-x64")]
    [InlineData(true, false, false, false, Architecture.Arm64, "win-arm64")]
    [InlineData(false, true, false, false, Architecture.X64, "osx-x64")]
    [InlineData(false, true, false, false, Architecture.Arm64, "osx-arm64")]
    [InlineData(false, false, true, false, Architecture.X64, "linux-x64")]
    [InlineData(false, false, true, false, Architecture.Arm64, "linux-arm64")]
    [InlineData(false, false, true, true, Architecture.X64, "linux-musl-x64")]
    [InlineData(false, false, true, true, Architecture.Arm64, null)]
    [InlineData(true, false, false, false, Architecture.X86, null)]
    [InlineData(false, false, true, false, Architecture.Arm, null)]
    [InlineData(false, false, false, false, Architecture.X64, null)]
    public void OnlyThePackagedPlatformsResolve(
        bool windows, bool macOS, bool linux, bool musl, Architecture architecture, string? expected)
    {
        Assert.Equal(expected, Native.PackagedRid(windows, macOS, linux, musl, architecture));
    }

    [Fact]
    public void ThisProcessLoadedAnAbsolutePath()
    {
        Assert.True(Path.IsPathFullyQualified(Native.LibraryPath));
        Assert.True(File.Exists(Native.LibraryPath));
    }

    [Fact]
    public void TheCoreIsTheVersionThisBindingWasBuiltAs()
    {
        Assert.Equal(Native.BindingVersion, Hide.Version);
    }

    [Theory]
    [InlineData("0.9.1", "0.9.1")]
    [InlineData("1.2.3", "1.2.3")]
    [InlineData("0.10.0", "0.10.0-rc.1")]
    [InlineData("0.10.0", "0.10.0+build.5")]
    public void TheSameReleaseIsAccepted(string binding, string core)
    {
        Assert.Null(Native.VersionMismatch(binding, core));
    }

    [Theory]
    [InlineData("0.9.0")]
    [InlineData("0.10.1")]
    [InlineData("1.9.1")]
    [InlineData("0.9.10")]
    [InlineData("0.9")]
    [InlineData("0.9.1.0")]
    [InlineData("")]
    [InlineData("v0.9.1")]
    [InlineData("0.+9.1")]
    [InlineData("garbage")]
    [InlineData(null)]
    public void AnotherReleaseIsRefused(string? core)
    {
        string? problem = Native.VersionMismatch("0.9.1", core);
        Assert.NotNull(problem);
        Assert.Contains("0.9.1", problem);
    }

    private static string Touch(string path)
    {
        Directory.CreateDirectory(Path.GetDirectoryName(path)!);
        File.WriteAllBytes(path, [1]);
        return Path.GetFullPath(path);
    }

    public sealed record Child(int ExitCode, string Output);

    /// <summary>
    /// Copies of the built test application and of the core in a scratch
    /// directory: one copy of the application with the core beside it, one
    /// without, a spare core to point an override at, and one planted where a
    /// lookup by bare name would find it.
    /// </summary>
    public sealed class Stage : IDisposable
    {
        private readonly string _marker = "hide-dotnet-test-" + Guid.NewGuid().ToString("N");

        public Stage()
        {
            // The name the binding looks for, not the name of the file this
            // run happens to be pointed at through the override.
            FileName = Native.FileName(OperatingSystem.IsWindows(), OperatingSystem.IsMacOS());
            Root = Path.Combine(Path.GetTempPath(), _marker);
            With = Path.Combine(Root, "with");
            Without = Path.Combine(Root, "without");
            Spare = Path.Combine(Root, "spare", FileName);
            Planted = Path.Combine(Root, "planted", FileName);

            CopyApplication(AppContext.BaseDirectory, With);
            CopyApplication(AppContext.BaseDirectory, Without);
            foreach (string copy in new[] { Path.Combine(With, FileName), Spare, Planted })
            {
                Directory.CreateDirectory(Path.GetDirectoryName(copy)!);
                File.Copy(Native.LibraryPath, copy);
            }
        }

        public string Root { get; }

        public string FileName { get; }

        public string With { get; }

        public string Without { get; }

        public string Spare { get; }

        public string Planted { get; }

        /// <summary>
        /// Starts the test assembly's probe in a fresh process. Both override
        /// variables are removed from its environment first, so it sees only
        /// what <paramref name="environment"/> sets.
        /// </summary>
        public Child Probe(string application, string workingDirectory, Dictionary<string, string?> environment)
        {
            ProcessStartInfo info = new(DotnetHost())
            {
                WorkingDirectory = workingDirectory,
                RedirectStandardOutput = true,
                RedirectStandardError = true,
                UseShellExecute = false,
            };
            info.ArgumentList.Add("exec");
            info.ArgumentList.Add(Path.Combine(application, "HideProtocol.Tests.dll"));
            info.ArgumentList.Add(Tests.Probe.Argument);
            info.Environment.Remove("HIDE_LIBRARY");
            info.Environment.Remove("HIDE_ALLOW_LIBRARY_OVERRIDE");
            foreach ((string key, string? value) in environment)
            {
                info.Environment[key] = value;
            }

            using Process process = Process.Start(info)
                ?? throw new InvalidOperationException("the probe process did not start");
            Task<string> error = process.StandardError.ReadToEndAsync();
            string output = process.StandardOutput.ReadToEnd();
            if (!process.WaitForExit(120_000))
            {
                process.Kill(entireProcessTree: true);
                throw new TimeoutException($"the probe did not finish: {output}");
            }

            return new Child(process.ExitCode, output + error.Result);
        }

        /// <summary>
        /// Compared by the tail of the path, which carries this run's unique
        /// directory: the temporary directory itself may be reported through a
        /// symbolic link or a short name.
        /// </summary>
        public void AssertLoadedFrom(string directory, Child child)
        {
            string tail = Path.Combine(_marker, directory, FileName);
            string? loaded = child.Output
                .Split('\n')
                .Select(line => line.Trim())
                .FirstOrDefault(line => line.StartsWith("LIBRARY=", StringComparison.Ordinal));

            Assert.True(
                child.ExitCode == 0 && loaded is not null && loaded.EndsWith(tail, StringComparison.OrdinalIgnoreCase),
                $"wanted the library in {tail}, got exit {child.ExitCode}, output: {child.Output}");
        }

        public void Dispose()
        {
            try
            {
                Directory.Delete(Root, recursive: true);
            }
            catch (Exception error) when (error is IOException or UnauthorizedAccessException)
            {
                // Scratch files in the temporary directory; nothing depends on them.
            }
        }

        /// <summary>The application without any copy of the core, wherever one was staged.</summary>
        private void CopyApplication(string source, string target)
        {
            foreach (string file in Directory.EnumerateFiles(source, "*", SearchOption.AllDirectories))
            {
                if (Path.GetFileName(file).Equals(FileName, StringComparison.OrdinalIgnoreCase))
                {
                    continue;
                }

                string copy = Path.Combine(target, Path.GetRelativePath(source, file));
                Directory.CreateDirectory(Path.GetDirectoryName(copy)!);
                File.Copy(file, copy);
            }
        }

        private static string DotnetHost()
        {
            string? host = Environment.GetEnvironmentVariable("DOTNET_HOST_PATH");
            if (!string.IsNullOrEmpty(host) && File.Exists(host))
            {
                return host;
            }

            string? current = Environment.ProcessPath;
            if (current is not null
                && Path.GetFileNameWithoutExtension(current).Equals("dotnet", StringComparison.OrdinalIgnoreCase))
            {
                return current;
            }

            // <root>/shared/Microsoft.NETCore.App/<version>/ holds the runtime.
            string root = Path.GetFullPath(Path.Combine(RuntimeEnvironment.GetRuntimeDirectory(), "..", "..", ".."));
            string beside = Path.Combine(root, OperatingSystem.IsWindows() ? "dotnet.exe" : "dotnet");
            return File.Exists(beside) ? beside : "dotnet";
        }
    }
}
