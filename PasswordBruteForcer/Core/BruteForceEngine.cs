using System.Collections.Concurrent;
using System.Diagnostics;

namespace PasswordBruteForcer.Core;

public sealed class BruteForceEngine
{
    private readonly CombinationGenerator _generator;
    private readonly PasswordValidator _validator;
    private readonly int _minLength;
    private readonly int _maxLength;
    private readonly int _maxThreads;

    private long _attempts;
    private long _attemptsAtLengthStart;
    private volatile int _currentLength;
    private volatile bool _isRunning;
    private string? _foundPassword;
    private readonly Stopwatch _stopwatch = new();
    private readonly ConcurrentDictionary<int, long> _threadWork = new();

    private const long FlushInterval = 8192;

    public static int RecommendedThreadCount => Math.Max(1, Environment.ProcessorCount - 1);

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
    public bool IsRunning => _isRunning;
    public long Attempts => Interlocked.Read(ref _attempts);
    public int CurrentLength => _currentLength;
    public TimeSpan Elapsed => _stopwatch.Elapsed;

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
            return Math.Clamp(fraction, 0, 1);
        }
    }

    public BruteForceResult Run(bool parallel, CancellationToken externalToken)
    {
        Reset();
        int workers = parallel ? Math.Min(_maxThreads, _generator.CharsetSize) : 1;
        _isRunning = true;
        _stopwatch.Start();

        using var cts = CancellationTokenSource.CreateLinkedTokenSource(externalToken);

        try
        {
            if (parallel)
                SearchAllLengthsParallel(workers, cts);
            else
            {
                int n = _generator.CharsetSize;
                for (int length = _minLength; length <= _maxLength; length++)
                {
                    if (cts.IsCancellationRequested || _foundPassword != null) break;
                    BeginLength(length);
                    for (int firstChar = 0; firstChar < n; firstChar++)
                    {
                        if (cts.IsCancellationRequested || _foundPassword != null) break;
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

    private void SearchAllLengthsParallel(int workers, CancellationTokenSource cts)
    {
        int n = _generator.CharsetSize;
        CancellationToken token = cts.Token;

        using var barrier = new Barrier(workers, b => BeginLength(_minLength + (int)b.CurrentPhaseNumber));

        void Worker(int id)
        {
            try
            {
                for (int length = _minLength; length <= _maxLength; length++)
                {
                    barrier.SignalAndWait(token);
                    for (int firstChar = id; firstChar < n; firstChar += workers)
                    {
                        if (token.IsCancellationRequested) return;
                        RunPartition(_generator.Enumerate(firstChar, length), cts);
                    }
                    if (token.IsCancellationRequested) return;
                }
            }
            catch (OperationCanceledException) { }
            catch
            {
                cts.Cancel();
                throw;
            }
        }

        var tasks = new Task[workers];
        for (int w = 0; w < workers; w++)
        {
            int id = w;
            tasks[w] = Task.Factory.StartNew(
                () => Worker(id), token,
                TaskCreationOptions.LongRunning,
                TaskScheduler.Default);
        }
        Task.WaitAll(tasks);
    }

    private void BeginLength(int length)
    {
        _currentLength = length;
        Interlocked.Exchange(ref _attemptsAtLengthStart, Interlocked.Read(ref _attempts));
    }

    private void RunPartition(CombinationGenerator.Cursor cursor, CancellationTokenSource cts)
    {
        CancellationToken token = cts.Token;
        long local = 0;
        long flushed = 0;

        try
        {
            while (cursor.MoveNext())
            {
                if (token.IsCancellationRequested) break;
                local++;

                if (_validator.IsMatch(cursor.Current))
                {
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
