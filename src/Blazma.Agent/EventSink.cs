using System.Collections.Concurrent;
using System.Diagnostics;
using System.Text;
using System.Text.Json;
using Blazma.Contracts;

namespace Blazma.Agent;

/// <summary>
/// Buffers observed events and writes them to <c>out/</c> as signed, atomically renamed
/// NDJSON chunks. Times are relative to the moment the sample was started.
/// </summary>
internal sealed class EventSink(string outDir, byte[] key, int maxEvents)
{
    private readonly ConcurrentQueue<AgentEventDto> _queue = new();
    private readonly Stopwatch _clock = new();
    private readonly object _flushLock = new();
    private long _sequence;
    private long _written;
    private long _dropped;
    private int _chunk;
    private long _sampleStartMs = long.MinValue;

    public long Written => Interlocked.Read(ref _written);
    public long Dropped => Interlocked.Read(ref _dropped);

    public void StartClock() => _clock.Start();

    /// <summary>Marks t=0. Events before this have negative relative times.</summary>
    public void MarkSampleStart() => _sampleStartMs = _clock.ElapsedMilliseconds;

    public long NowRelativeMs => _sampleStartMs == long.MinValue ? -_clock.ElapsedMilliseconds : _clock.ElapsedMilliseconds - _sampleStartMs;

    public void Add(string action, int pid, int ppid, long processStartMs, string processName, string? target, Dictionary<string, string>? details, string source)
    {
        if (Interlocked.Read(ref _sequence) >= maxEvents) { Interlocked.Increment(ref _dropped); return; }
        _queue.Enqueue(new AgentEventDto
        {
            Sequence = Interlocked.Increment(ref _sequence),
            TimestampUnixMs = DateTimeOffset.UtcNow.ToUnixTimeMilliseconds(),
            RelativeMs = NowRelativeMs,
            Action = action,
            ProcessId = pid,
            ParentProcessId = ppid,
            ProcessStartMs = processStartMs,
            ProcessName = processName,
            Target = target,
            Details = details,
            Source = source,
        });
    }

    public void Flush()
    {
        lock (_flushLock)
        {
            if (_queue.IsEmpty) return;
            var sb = new StringBuilder();
            var count = 0;
            while (count < 5000 && _queue.TryDequeue(out var e))
            {
                sb.Append(JsonSerializer.Serialize(e, ProtocolJson.Default.AgentEventDto)).Append('\n');
                count++;
            }
            WriteSigned(Protocol.EventChunkName(++_chunk), Encoding.UTF8.GetBytes(sb.ToString()));
            Interlocked.Add(ref _written, count);
            if (!_queue.IsEmpty) Flush();
        }
    }

    public void WriteSigned(string name, byte[] content) => WriteAtomic(name, SignedFile.Sign(content, key));

    public void WriteAtomic(string name, byte[] bytes)
    {
        var path = Path.Combine(outDir, name);
        var temp = path + Protocol.TempExtension;
        File.WriteAllBytes(temp, bytes);
        File.Move(temp, path, overwrite: true);
    }
}
