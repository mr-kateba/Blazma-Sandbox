using System.Text.Json;
using Blazma.Contracts;

namespace Blazma.Agent;

/// <summary>
/// Reads the host's control file (in the read-only folder) and applies each new sequence
/// once: a longer duration or "finish now". The duration only ever grows and is capped.
/// </summary>
internal sealed class ControlWatcher(string inDir, int initialSeconds)
{
    private int _sequence;

    public int DurationSeconds { get; private set; } = initialSeconds;
    public bool FinishRequested { get; private set; }

    public void Poll()
    {
        var path = Path.Combine(inDir, Protocol.ControlFile);
        try
        {
            if (!File.Exists(path)) return;
            var control = JsonSerializer.Deserialize(File.ReadAllBytes(path), ProtocolJson.Default.ControlDto);
            if (control is null || control.Sequence <= _sequence) return;
            _sequence = control.Sequence;
            DurationSeconds = Math.Clamp(Math.Max(DurationSeconds, control.DurationSeconds), 15, 1800);
            if (control.FinishNow) FinishRequested = true;
        }
        catch (Exception ex) when (ex is IOException or JsonException or UnauthorizedAccessException)
        {
        }
    }
}
