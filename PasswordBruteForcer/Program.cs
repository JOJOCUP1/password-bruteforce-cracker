using PasswordBruteForcer.Core;
using PasswordBruteForcer.UI;

namespace PasswordBruteForcer;

static class Program
{
    public static readonly char[] Charset = "abcdefghijklmnopqrstuvwxyz".ToCharArray();
    public const int MaxLength = 6;

    [STAThread]
    static int Main(string[] args)
    {
        if (args.Length > 0 && args[0] is "--benchmark")
            return RunBenchmark();

        ApplicationConfiguration.Initialize();
        Application.Run(new MainForm());
        return 0;
    }

    private static int RunBenchmark()
    {
        var hasher = new PasswordHasher();
        var gen = new PasswordGenerator(Charset);
        string password = gen.Generate();
        string targetHash = hasher.Hash(password);

        Console.WriteLine($"Password : {password}  (length {password.Length})");
        Console.WriteLine($"SHA-256  : {targetHash}");
        Console.WriteLine($"Cores    : {Environment.ProcessorCount}  |  Workers: {BruteForceEngine.RecommendedThreadCount}");
        Console.WriteLine();

        var combGen = new CombinationGenerator(Charset);
        var validator = new PasswordValidator(targetHash, hasher);

        Console.WriteLine("Single-threaded...");
        var single = new BruteForceEngine(combGen, validator, 1, MaxLength, maxThreads: 1)
            .Run(parallel: false, CancellationToken.None);
        Console.WriteLine($"  found={single.Password}  time={single.Elapsed.TotalMilliseconds:F0}ms  attempts={single.Attempts:N0}");

        Console.WriteLine("Multi-threaded...");
        var multi = new BruteForceEngine(combGen, validator, 1, MaxLength)
            .Run(parallel: true, CancellationToken.None);
        Console.WriteLine($"  found={multi.Password}  time={multi.Elapsed.TotalMilliseconds:F0}ms  attempts={multi.Attempts:N0}  threads={multi.ThreadCount}");
        Console.WriteLine();

        var logger = new PerformanceLogger();
        string report = logger.BuildComparison(single, multi, password);
        logger.Append(report);
        Console.WriteLine(report);

        bool ok = single.Found && multi.Found && single.Password == password && multi.Password == password;
        Console.WriteLine(ok ? "PASSED" : "FAILED");
        return ok ? 0 : 1;
    }
}
