namespace PasswordBruteForcer.Core;

public sealed class BruteForceResult
{
    public bool Found { get; init; }
    public string? Password { get; init; }
    public TimeSpan Elapsed { get; init; }
    public long Attempts { get; init; }
    public int ThreadCount { get; init; }
    public bool Parallel { get; init; }
    public bool Cancelled { get; init; }
    public int LengthReached { get; init; }
    public IReadOnlyDictionary<int, long> PerThreadAttempts { get; init; } = new Dictionary<int, long>();
    public double AttemptsPerSecond => Elapsed.TotalSeconds > 0 ? Attempts / Elapsed.TotalSeconds : 0;
}
