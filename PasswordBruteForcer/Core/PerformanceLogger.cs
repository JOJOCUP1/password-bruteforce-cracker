using System.Text;

namespace PasswordBruteForcer.Core;

public sealed class PerformanceLogger
{
    private readonly string _path;
    public string LogPath => _path;

    public PerformanceLogger(string? path = null)
        => _path = path ?? Path.Combine(AppContext.BaseDirectory, "performance_log.txt");

    public string BuildComparison(BruteForceResult single, BruteForceResult multi, string? actualPassword)
    {
        double singleMs = single.Elapsed.TotalMilliseconds;
        double multiMs = multi.Elapsed.TotalMilliseconds;
        double speedup = multiMs > 0 ? singleMs / multiMs : 0;
        double efficiency = multi.ThreadCount > 0 ? speedup / multi.ThreadCount : 0;

        var sb = new StringBuilder();
        sb.AppendLine("==================== PERFORMANCE COMPARISON ====================");
        sb.AppendLine($"Timestamp        : {DateTime.Now:yyyy-MM-dd HH:mm:ss}");
        sb.AppendLine($"Machine cores    : {Environment.ProcessorCount}");
        if (actualPassword is not null)
            sb.AppendLine($"Target password  : \"{actualPassword}\" (length {actualPassword.Length})");
        sb.AppendLine();
        sb.AppendLine($"{"",-18}{"SINGLE-THREAD",-22}{"MULTI-THREAD",-22}");
        sb.AppendLine($"{"threads",-18}{single.ThreadCount,-22}{multi.ThreadCount,-22}");
        sb.AppendLine($"{"found password",-18}{Show(single.Password),-22}{Show(multi.Password),-22}");
        sb.AppendLine($"{"time (ms)",-18}{singleMs,-22:F1}{multiMs,-22:F1}");
        sb.AppendLine($"{"attempts",-18}{single.Attempts,-22:N0}{multi.Attempts,-22:N0}");
        sb.AppendLine($"{"hashes/sec",-18}{single.AttemptsPerSecond,-22:N0}{multi.AttemptsPerSecond,-22:N0}");
        sb.AppendLine();
        sb.AppendLine($"Speed-up (single/multi) : {speedup:F2}x");
        sb.AppendLine($"Parallel efficiency     : {efficiency:P0}");
        sb.AppendLine("================================================================");
        return sb.ToString();

        static string Show(string? p) => p ?? "(not found)";
    }

    public void Append(string text)
        => File.AppendAllText(_path, text + Environment.NewLine);
}
