namespace Blazma.Core.Events;

/// <summary>
/// The unified event model. Every collector (process, file, registry, network, DNS,
/// system) is normalised into this one shape so the timeline, correlation, rules and
/// storage all work on a single stream.
/// </summary>
public sealed record AnalysisEvent
{
    private static readonly IReadOnlyDictionary<string, string> NoDetails = new Dictionary<string, string>();

    /// <summary>Monotonic, unique within an analysis. Evidence points at events by sequence.</summary>
    public required long Sequence { get; init; }

    public required DateTimeOffset Timestamp { get; init; }

    /// <summary>Time since the sample was started (negative for baseline activity).</summary>
    public required TimeSpan RelativeTime { get; init; }

    public required EventCategory Category { get; init; }

    public required EventAction Action { get; init; }

    public int ProcessId { get; init; }

    public int ParentProcessId { get; init; }

    public ProcessKey? Process { get; init; }

    public string ProcessName { get; init; } = string.Empty;

    /// <summary>What the action was applied to: a path, a registry key, an endpoint, a domain.</summary>
    public string? Target { get; init; }

    public IReadOnlyDictionary<string, string> Details { get; init; } = NoDetails;

    public Severity Severity { get; init; } = Severity.Informational;

    /// <summary>Which collector produced the event (e.g. "etw.kernel.process", "demo").</summary>
    public string Source { get; init; } = string.Empty;

    public string? CorrelationId { get; init; }

    public string? Detail(string key) => Details.TryGetValue(key, out var v) ? v : null;
}
