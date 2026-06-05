using System.Collections.Concurrent;
using System.Diagnostics;

namespace PasswordBruteForcer.Core;

/// <summary>
/// The brute-force search engine. It ties together a <see cref="CombinationGenerator"/>
/// (produces candidates) and a <see cref="PasswordValidator"/> (checks candidates) and drives
/// the search either single-threaded or multi-threaded.
///
/// Requirements covered here:
///  • Task 4c — searches length 1, 2, 3, ... up to <see cref="MaxLength"/>; it does NOT know the
///    real password length in advance and always starts from length 1.
///  • Task 4d — multi-threading via Task-based parallelism (TPL).
///  • Task 4e — uses at most (CPU cores − 1) worker threads.
///  • Task 5  — for every length the keyspace is partitioned by first character across the
///    workers, so several threads hash candidates simultaneously (not a sequential sweep).
///    The SAME (cores − 1) long-running threads are reused for every length and march through
///    the lengths in lockstep via a <see cref="Barrier"/>.
///  • Task 6  — the instant any thread finds the password it cancels a shared token, which makes
///    every other worker stop immediately.
///
/// While running, the engine exposes live counters (<see cref="Attempts"/>, <see cref="CurrentLength"/>,
/// <see cref="Elapsed"/>, <see cref="CurrentLengthProgress"/>) that the GUI polls on a timer.
/// </summary>
public sealed class BruteForceEngine
{
    private readonly CombinationGenerator _generator;
    private readonly PasswordValidator _validator;
    private readonly int _minLength;
    private readonly int _maxLength;
    private readonly int _maxThreads;

    // ---- live, thread-safe progress state ----
    private long _attempts;                 // total candidates tried (updated with Interlocked)
    private long _attemptsAtLengthStart;    // _attempts value when the current length began
    private volatile int _currentLength;    // length currently being searched
    private volatile bool _isRunning;
    private string? _foundPassword;         // set once, via Interlocked.CompareExchange
    private readonly Stopwatch _stopwatch = new();
    private readonly ConcurrentDictionary<int, long> _threadWork = new();

    // Flush per-thread local counters into the shared total every this-many candidates,
    // to avoid hammering a single Interlocked counter from every thread on every hash.
    private const long FlushInterval = 8192;

    /// <summary>The recommended worker count for the machine: max(1, CPU cores − 1). Task 4e.</summary>
    public static int RecommendedThreadCount => Math.Max(1, Environment.ProcessorCount - 1);

    /// <param name="generator">Candidate generator (independent of validation).</param>
    /// <param name="validator">Candidate validator (independent of generation).</param>
    /// <param name="minLength">Smallest length to try (always 1 per Task 4c).</param>
    /// <param name="maxLength">Largest length to try (6 per Task 4c).</param>
    /// <param name="maxThreads">Worker cap for parallel runs; defaults to cores − 1.</param>
    public BruteForceEngine(CombinationGenerator generator, PasswordValidator validator,
                            int minLength = 1, int maxLength = 6, int? maxThreads = null)
    {
        _generator = generator ?? throw new ArgumentNullException(nameof(generator));
        _validator = validator ?? throw new ArgumentNullException(nameof(validator));
        _minLength = Math.Max(1, minLength);
        _maxLength = Math.Max(_minLength, maxLength);
        _maxThreads = maxThreads ?? RecommendedThreadCount;
    }

    public int MaxLength => _maxLength;
    public int MinLength => _minLength;
    public int MaxThreads => _maxThreads;

    // ---- live progress (polled by the UI timer) ----
    public bool IsRunning => _isRunning;
    public long Attempts => Interlocked.Read(ref _attempts);
    public int CurrentLength => _currentLength;
    public TimeSpan Elapsed => _stopwatch.Elapsed;

    /// <summary>Fraction (0..1) of the CURRENT length's keyspace explored so far.</summary>
    public double CurrentLengthProgress
    {
        get
        {
            int len = _currentLength;
            if (len <= 0) return 0;
            long total = _generator.CombinationCount(len);
            if (total <= 0) return 0;
            long done = Interlocked.Read(ref _attempts) - Interlocked.Read(ref _attemptsAtLengthStart);
            double fraction = (double)done / total;
            return fraction < 0 ? 0 : (fraction > 1 ? 1 : fraction);
        }
    }

    /// <summary>
    /// Runs the brute-force search. Set <paramref name="parallel"/> true for the multi-threaded
    /// attack (Task 4d/4e/5) or false for the single-threaded baseline used in the performance
    /// comparison (Task 8). Honours <paramref name="externalToken"/> (the GUI Stop button).
    /// </summary>
    public BruteForceResult Run(bool parallel, CancellationToken externalToken)
    {
        Reset();
        // Never spawn more workers than there are first characters to partition by.
        int workers = parallel ? Math.Min(_maxThreads, _generator.CharsetSize) : 1;
        _isRunning = true;
        _stopwatch.Start();

        // A linked source lets the FIRST finder cancel everyone (Task 6) while still respecting
        // the external Stop button.
        using var cts = CancellationTokenSource.CreateLinkedTokenSource(externalToken);

        try
        {
            if (parallel)
            {
                SearchAllLengthsParallel(workers, cts);
            }
            else
            {
                // Single-threaded baseline: sweep length 1, 2, 3, ... on this one thread.
                // Uses the SAME allocation-free cursor as the parallel path so the performance
                // comparison is fair (both differ only in the number of threads).
                int n = _generator.CharsetSize;
                for (int length = _minLength; length <= _maxLength; length++)
                {
                    if (cts.IsCancellationRequested || _foundPassword != null)
                        break;
                    BeginLength(length);
                    for (int firstChar = 0; firstChar < n; firstChar++)
                    {
                        if (cts.IsCancellationRequested || _foundPassword != null)
                            break;
                        RunPartition(_generator.Enumerate(firstChar, length), cts);
                    }
                }
            }
        }
        finally
        {
            _stopwatch.Stop();
            _isRunning = false;
        }

        string? found = _foundPassword;
        return new BruteForceResult
        {
            Found = found != null,
            Password = found,
            Elapsed = _stopwatch.Elapsed,
            Attempts = Interlocked.Read(ref _attempts),
            ThreadCount = workers,
            Parallel = parallel,
            Cancelled = found == null && externalToken.IsCancellationRequested,
            LengthReached = _currentLength,
            PerThreadAttempts = new Dictionary<int, long>(_threadWork)
        };
    }

    /// <summary>
    /// Multi-threaded search. Creates exactly <paramref name="workers"/> long-running worker
    /// threads ONCE and reuses them for every length. The workers advance through the lengths
    /// together using a <see cref="Barrier"/>; for each length, worker <c>id</c> sweeps the
    /// first characters {id, id+workers, id+2·workers, …} so the slices never overlap and every
    /// thread is busy at the same time (Task 5). At most <paramref name="workers"/> = (cores − 1)
    /// threads ever run (Task 4e).
    /// </summary>
    private void SearchAllLengthsParallel(int workers, CancellationTokenSource cts)
    {
        int n = _generator.CharsetSize;
        CancellationToken token = cts.Token;

        // The post-phase action runs once, on a single worker, each time all workers sync —
        // i.e. right before they start a new length. Phase number 0 maps to the first length.
        using var barrier = new Barrier(workers, b => BeginLength(_minLength + (int)b.CurrentPhaseNumber));

        void Worker(int id)
        {
            try
            {
                for (int length = _minLength; length <= _maxLength; length++)
                {
                    // Sync so every worker starts this length together (and progress state is set).
                    barrier.SignalAndWait(token);

                    for (int firstChar = id; firstChar < n; firstChar += workers)
                    {
                        if (token.IsCancellationRequested)
                            return;
                        RunPartition(_generator.Enumerate(firstChar, length), cts);
                    }

                    if (token.IsCancellationRequested)
                        return;
                }
            }
            catch (OperationCanceledException)
            {
                // Cancelled while blocked at the barrier (another worker found the password) — exit.
            }
            catch
            {
                // An unexpected failure must not leave peers blocked at the barrier forever:
                // cancel so they unblock, then let the error surface.
                cts.Cancel();
                throw;
            }
        }

        var tasks = new Task[workers];
        for (int w = 0; w < workers; w++)
        {
            int id = w;
            tasks[w] = Task.Factory.StartNew(
                () => Worker(id),
                token,
                TaskCreationOptions.LongRunning, // dedicated thread => provably parallel, capped count
                TaskScheduler.Default);
        }

        Task.WaitAll(tasks);
    }

    /// <summary>Marks the start of a new length: records it and snapshots the attempt counter.</summary>
    private void BeginLength(int length)
    {
        _currentLength = length;
        Interlocked.Exchange(ref _attemptsAtLengthStart, Interlocked.Read(ref _attempts));
    }

    /// <summary>
    /// Validates every candidate in <paramref name="candidates"/>. Shared by both the
    /// single-threaded sweep and each parallel worker. Keeps a thread-local counter and flushes
    /// it into the global total periodically to minimise contention. On a match it atomically
    /// records the password and cancels the shared token so all other workers stop at once (Task 6).
    /// </summary>
    private void RunPartition(CombinationGenerator.Cursor cursor, CancellationTokenSource cts)
    {
        CancellationToken token = cts.Token;
        long local = 0;
        long flushed = 0;

        try
        {
            while (cursor.MoveNext())
            {
                if (token.IsCancellationRequested)
                    break;

                local++;

                if (_validator.IsMatch(cursor.Current))
                {
                    // Materialise the winning candidate as a string exactly once, then record it.
                    // First thread to find it wins and stops everyone else immediately.
                    string candidate = new string(cursor.Current);
                    if (Interlocked.CompareExchange(ref _foundPassword, candidate, null) == null)
                        cts.Cancel();
                    break;
                }

                if (local - flushed >= FlushInterval)
                {
                    Interlocked.Add(ref _attempts, local - flushed);
                    flushed = local;
                }
            }
        }
        finally
        {
            if (local > flushed)
                Interlocked.Add(ref _attempts, local - flushed);
            // Record this thread's contribution (evidence of parallel work for the report).
            _threadWork.AddOrUpdate(Environment.CurrentManagedThreadId, local, (_, v) => v + local);
        }
    }

    private void Reset()
    {
        Interlocked.Exchange(ref _attempts, 0);
        Interlocked.Exchange(ref _attemptsAtLengthStart, 0);
        _currentLength = 0;
        _foundPassword = null;
        _threadWork.Clear();
        _stopwatch.Reset();
    }
}
