using PasswordBruteForcer.Core;
using PasswordBruteForcer.UI;

namespace PasswordBruteForcer;

/// <summary>
/// Application entry point.
///  • No arguments              -> launches the Windows Forms GUI (the normal mode).
///  • "--benchmark"/"--selftest"-> runs a headless single-vs-multi comparison on the console,
///                                 useful for automated verification and for capturing the
///                                 performance numbers documented in the test report (Task 8).
/// </summary>
static class Program
{
    /// <summary>The alphabet the password is drawn from and the brute force searches: 'a'..'z'.</summary>
    public static readonly char[] Charset = "abcdefghijklmnopqrstuvwxyz".ToCharArray();

    /// <summary>Maximum candidate length the brute force will ever reach (Task 4c).</summary>
    public const int MaxLength = 6;

    [STAThread]
    static int Main(string[] args)
    {
        if (args.Length > 0 && (args[0] is "--benchmark" or "--selftest"))
            return RunBenchmark();
        if (args.Length > 0 && args[0] is "--throughput")
            return RunThroughput();
        if (args.Length > 0 && args[0] is "--capture")
            return RunCapture(args.Length > 1 ? args[1] : ".");

        ApplicationConfiguration.Initialize();
        Application.Run(new MainForm());
        return 0;
    }

    /// <summary>
    /// Renders screenshots of the real GUI head-lessly (no visible window needed) by driving the
    /// form into representative states and saving each via <see cref="Control.DrawToBitmap"/>.
    /// Produces the figures used in the test report.
    /// </summary>
    private static int RunCapture(string outDir)
    {
        ApplicationConfiguration.Initialize();
        Directory.CreateDirectory(outDir);
        Capture("ready", Path.Combine(outDir, "screenshot_ready.png"));
        Capture("found", Path.Combine(outDir, "screenshot_found.png"));
        Capture("compare", Path.Combine(outDir, "screenshot_compare.png"));
        Console.WriteLine($"Screenshots written to: {Path.GetFullPath(outDir)}");
        return 0;

        static void Capture(string mode, string path)
        {
            using var form = new MainForm();
            // Show the form OFF-SCREEN so every child control's handle is realized and painted —
            // DrawToBitmap only renders controls that have been shown at least once.
            form.StartPosition = FormStartPosition.Manual;
            form.Location = new System.Drawing.Point(-4000, -4000);
            form.ShowInTaskbar = false;
            form.ClientSize = new System.Drawing.Size(880, 1000); // tall so the whole log is visible
            form.Show();
            Application.DoEvents();
            form.BuildDemoState(mode);
            Application.DoEvents();
            form.Refresh();
            Application.DoEvents();

            using var bmp = new System.Drawing.Bitmap(form.Width, form.Height);
            form.DrawToBitmap(bmp, new System.Drawing.Rectangle(0, 0, form.Width, form.Height));
            bmp.Save(path, System.Drawing.Imaging.ImageFormat.Png);
            form.Close();
            Console.WriteLine($"  {mode,-8} -> {path}");
        }
    }

    /// <summary>
    /// Fixed-work throughput test: exhaustively hash the entire length-1..5 keyspace with no
    /// early exit (the target cannot occur in that space), single-threaded then multi-threaded.
    /// Because the amount of work is identical and constant, this isolates pure parallel scaling
    /// from the "where does the password sit" luck of a normal crack-time comparison.
    /// </summary>
    private static int RunThroughput()
    {
        const int sweepMax = 5;
        var hasher = new PasswordHasher();
        var combinationGenerator = new CombinationGenerator(Charset);

        // A target that cannot exist as a 1..5 letter a-z string, so neither engine ever matches
        // and both sweep the complete keyspace.
        var validator = new PasswordValidator(hasher.Hash("Z9_not_in_search_space"), hasher);

        long space = 0;
        for (int len = 1; len <= sweepMax; len++) space += combinationGenerator.CombinationCount(len);

        Console.WriteLine("=== Raw throughput (full length 1..5 sweep, no early exit) ===");
        Console.WriteLine($"Keyspace swept    : {space:N0} candidates");
        Console.WriteLine($"Worker threads    : {BruteForceEngine.RecommendedThreadCount} (cores - 1)");
        Console.WriteLine();

        Console.WriteLine("Single-threaded sweep…");
        var single = new BruteForceEngine(combinationGenerator, validator, 1, sweepMax, maxThreads: 1)
            .Run(parallel: false, CancellationToken.None);
        Console.WriteLine($"  {single.Elapsed.TotalMilliseconds:F0} ms   {single.AttemptsPerSecond:N0} hashes/sec");

        Console.WriteLine("Multi-threaded sweep…");
        var multi = new BruteForceEngine(combinationGenerator, validator, 1, sweepMax)
            .Run(parallel: true, CancellationToken.None);
        Console.WriteLine($"  {multi.Elapsed.TotalMilliseconds:F0} ms   {multi.AttemptsPerSecond:N0} hashes/sec   ({multi.ThreadCount} threads)");
        Console.WriteLine();

        double speedup = multi.Elapsed.TotalMilliseconds > 0
            ? single.Elapsed.TotalMilliseconds / multi.Elapsed.TotalMilliseconds : 0;
        Console.WriteLine($"Throughput speed-up : {speedup:F2}x   (efficiency {speedup / multi.ThreadCount:P0})");

        // Correctness guard: both engines must have visited EVERY candidate exactly once.
        bool exact = single.Attempts == space && multi.Attempts == space;
        Console.WriteLine($"Keyspace coverage   : single={single.Attempts:N0}, multi={multi.Attempts:N0}, expected={space:N0} -> {(exact ? "EXACT" : "MISMATCH")}");
        return exact ? 0 : 1;
    }

    /// <summary>
    /// Headless self-test: generate a random password, hash it, then crack it once single-threaded
    /// and once multi-threaded, printing and logging the performance comparison.
    /// </summary>
    private static int RunBenchmark()
    {
        var hasher = new PasswordHasher();
        var passwordGenerator = new PasswordGenerator(Charset);

        string password = passwordGenerator.Generate();
        string targetHash = hasher.Hash(password);

        Console.WriteLine("=== Password Brute-Forcer — headless benchmark ===");
        Console.WriteLine($"CPU cores         : {Environment.ProcessorCount}");
        Console.WriteLine($"Worker threads    : {BruteForceEngine.RecommendedThreadCount} (cores - 1)");
        Console.WriteLine($"Salt (constant)   : {PasswordHasher.Salt}");
        Console.WriteLine($"Secret password   : {password}  (length {password.Length})");
        Console.WriteLine($"Target SHA-256    : {targetHash}");
        Console.WriteLine();

        // Generator and validator are built independently, then shared by both engines.
        var combinationGenerator = new CombinationGenerator(Charset);
        var validator = new PasswordValidator(targetHash, hasher);

        Console.WriteLine("Running SINGLE-threaded brute force...");
        var single = new BruteForceEngine(combinationGenerator, validator, 1, MaxLength, maxThreads: 1)
            .Run(parallel: false, CancellationToken.None);
        Console.WriteLine($"  found = {single.Password}  time = {single.Elapsed.TotalMilliseconds:F0} ms  attempts = {single.Attempts:N0}");

        Console.WriteLine("Running MULTI-threaded brute force...");
        var multi = new BruteForceEngine(combinationGenerator, validator, 1, MaxLength)
            .Run(parallel: true, CancellationToken.None);
        Console.WriteLine($"  found = {multi.Password}  time = {multi.Elapsed.TotalMilliseconds:F0} ms  attempts = {multi.Attempts:N0}  threads = {multi.ThreadCount}");
        Console.WriteLine($"  threads that did work = {multi.PerThreadAttempts.Count}");
        Console.WriteLine();

        var logger = new PerformanceLogger();
        string comparison = logger.BuildComparison(single, multi, password);
        logger.Append(comparison);
        Console.WriteLine(comparison);
        Console.WriteLine($"Comparison appended to: {logger.LogPath}");

        bool ok = single.Found && multi.Found && single.Password == password && multi.Password == password;
        Console.WriteLine(ok ? "SELF-TEST PASSED" : "SELF-TEST FAILED");
        return ok ? 0 : 1;
    }
}
