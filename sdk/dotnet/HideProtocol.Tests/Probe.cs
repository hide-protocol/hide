using HideProtocol;

namespace HideProtocol.Tests;

/// <summary>
/// The entry point of the test assembly. `dotnet test` never calls it; the
/// loading tests start this assembly as a child process with `--probe`, in a
/// directory layout and environment they control, to see which native library
/// a fresh process really loads.
/// </summary>
internal static class Probe
{
    internal const string Argument = "--probe";

    /// <summary>The child's exit code when the library could not be loaded.</summary>
    internal const int LoadFailed = 3;

    private static int Main(string[] args)
    {
        if (args is not [Argument])
        {
            Console.Error.WriteLine("this assembly is a test suite: run it with `dotnet test`");
            return 2;
        }

        try
        {
            Console.WriteLine($"LIBRARY={Native.LibraryPath}");
            Console.WriteLine($"VERSION={Hide.Version}");
            return 0;
        }
        catch (Exception error)
        {
            Console.WriteLine($"FAILED={error.GetType().Name}: {error.Message}");
            return LoadFailed;
        }
    }
}
