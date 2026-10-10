using System.Collections.Concurrent;
using System.Globalization;
using System.Text;

namespace Blazma.Agent;

/// <summary>
/// Plain-text diagnostic log in <c>out/agent.log</c>: UTF-8, appended, one timestamped line per
/// message, at most <see cref="MaxBytes"/> in total (later messages are dropped once it is full).
/// It is NOT signed and the host only ever shows it as text, so it must never contain secrets
/// such as the channel key. Opened with sharing flags so the host can read it while the agent runs.
/// Logging never throws: a log that cannot be written must not stop the analysis.
/// </summary>
internal sealed class AgentLog : IDisposable
{
    public const long MaxBytes = 1024 * 1024;
    private const int LimitedRepeats = 3;

    private static AgentLog? s_current;

    private readonly object _lock = new();
    private readonly long _maxBytes;
    private readonly ConcurrentDictionary<string, int> _repeats = new(StringComparer.Ordinal);
    private FileStream? _stream;
    private bool _full;

    public AgentLog(string path, long maxBytes = MaxBytes)
    {
        _maxBytes = maxBytes;
        try
        {
            _stream = new FileStream(path, FileMode.Append, FileAccess.Write, FileShare.ReadWrite | FileShare.Delete);
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException or ArgumentException or NotSupportedException)
        {
            _stream = null;
        }
    }

    /// <summary>Makes <paramref name="log"/> the target of the static helpers.</summary>
    public static void Use(AgentLog? log) => s_current = log;

    public static void Info(string message) => s_current?.Write("INFO", message, null);

    public static void Warn(string message, Exception? ex = null) => s_current?.Write("WARN", message, ex);

    public static void Error(string message, Exception? ex = null) => s_current?.Write("ERROR", message, ex);

    /// <summary>Logs the first few failures of one kind only, so a failure that repeats every second cannot fill the log.</summary>
    public static void Limited(string kind, string message, Exception? ex = null) => s_current?.WriteLimited(kind, message, ex);

    public void WriteLimited(string kind, string message, Exception? ex)
    {
        var count = _repeats.AddOrUpdate(kind, 1, (_, n) => n + 1);
        if (count <= LimitedRepeats) Write("ERROR", count == LimitedRepeats ? message + " (further failures of this kind are not logged)" : message, ex);
    }

    public void Write(string level, string message, Exception? ex)
    {
        var line = string.Create(CultureInfo.InvariantCulture, $"{DateTimeOffset.UtcNow:yyyy-MM-dd HH:mm:ss.fff}Z {level} [{Environment.CurrentManagedThreadId}] {message}");
        if (ex is not null) line += Environment.NewLine + "    " + ex.ToString().ReplaceLineEndings(Environment.NewLine + "    ");
        var bytes = Encoding.UTF8.GetBytes(line + Environment.NewLine);
        lock (_lock)
        {
            if (_stream is null || _full) return;
            try
            {
                var notice = Encoding.UTF8.GetBytes(string.Create(CultureInfo.InvariantCulture,
                    $"{DateTimeOffset.UtcNow:yyyy-MM-dd HH:mm:ss.fff}Z WARN The log reached its size limit; later messages are not written.{Environment.NewLine}"));
                if (_stream.Length + bytes.Length + notice.Length > _maxBytes)
                {
                    _full = true;
                    if (_stream.Length + notice.Length <= _maxBytes) _stream.Write(notice);
                }
                else
                {
                    _stream.Write(bytes);
                }
                _stream.Flush();
            }
            catch (Exception e) when (e is IOException or ObjectDisposedException or UnauthorizedAccessException)
            {
                // A diagnostic log is best effort.
            }
        }
    }

    public void Dispose()
    {
        lock (_lock)
        {
            _stream?.Dispose();
            _stream = null;
        }
        if (ReferenceEquals(s_current, this)) s_current = null;
    }
}
