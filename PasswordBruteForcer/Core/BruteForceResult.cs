namespace PasswordBruteForcer.Core;

/// <summary>
/// Immutable summary of one brute-force run, returned by <see cref="BruteForceEngine.Run"/>.
/// Carries everything the GUI and the performance log need: the outcome, how long it took,
/// how many candidates were tried, how many threads were used, and a per-thread work breakdown
/// (concrete evidence that multiple threads ran in parallel — Task 5).
/// </summary>
public sealed class BruteForceResult
{
    /// <summary>True if the password was found before the search ended.</summary>
    public bool Found { get; init; }

    /// <summary>The cracked password, or <c>null</c> if not found / cancelled.</summary>
    public string? Password { get; init; }

    /// <summary>Wall-clock time the search took.</summary>
    public TimeSpan Elapsed { get; init; }

    /// <summary>Total number of candidate passwords hashed and checked.</summary>
    public long Attempts { get; init; }

    /// <summary>Number of worker threads used (1 for single-threaded, cores-1 for multi-threaded).</summary>
    public int ThreadCount { get; init; }

    /// <summary>True if this was a parallel (multi-threaded) run.</summary>
    public bool Parallel { get; init; }

    /// <summary>True if the user pressed Stop before the password was found.</summary>
    public bool Cancelled { get; init; }

    /// <summary>Maximum candidate length that was reached during the search.</summary>
    public int LengthReached { get; init; }

    /// <summary>
    /// Managed-thread-id =&gt; number of candidates that thread processed. Multiple non-trivial
    /// entries prove that the work was genuinely spread across parallel threads.
    /// </summary>
    public IReadOnlyDictionary<int, long> PerThreadAttempts { get; init; }
        = new Dictionary<int, long>();

    /// <summary>Throughput in candidates per second (0 if the run was instantaneous).</summary>
    public double AttemptsPerSecond =>
        Elapsed.TotalSeconds > 0 ? Attempts / Elapsed.TotalSeconds : 0;
}
