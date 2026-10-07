using Blazma.Core.Analysis;
using Blazma.Core.Events;
using Blazma.Core.Findings;
using Blazma.Core.Samples;
using Blazma.Core.Snapshots;
using Blazma.Core.Text;

namespace Blazma.Core.Abstractions;

/// <summary>Reads a file without executing it.</summary>
public interface IStaticAnalyzer
{
    Task<StaticReport> AnalyzeAsync(string path, CancellationToken cancellationToken);
}

public enum ProviderReadiness { Ready, NotSupported, NeedsSetup, Unavailable }

public sealed record ProviderCheck(string Id, LocalizedText Label, bool Passed, LocalizedText Detail);

public sealed record ProviderAvailability(ProviderReadiness Readiness, IReadOnlyList<ProviderCheck> Checks)
{
    public bool IsReady => Readiness == ProviderReadiness.Ready;
}

public sealed record SandboxSessionRequest(Guid AnalysisId, string SamplePath, SampleInfo Sample, AnalysisOptions Options);

/// <summary>A live signal from the analysis environment.</summary>
public abstract record SessionSignal;

public sealed record EventsSignal(IReadOnlyList<AnalysisEvent> Events) : SessionSignal;

public sealed record HeartbeatSignal(DateTimeOffset At) : SessionSignal;

public sealed record MonitoringInterruptedSignal(string Reason) : SessionSignal;

public sealed record CollectedArtifacts(
    IReadOnlyList<AnalysisEvent> RemainingEvents,
    SystemSnapshot? Baseline,
    SystemSnapshot? After,
    bool AgentCompleted);

/// <summary>
/// The isolation boundary. A provider owns everything that crosses between the host and
/// the analysis environment. The sample never runs on the host.
/// </summary>
public interface ISandboxProvider
{
    string Id { get; }
    LocalizedText DisplayName { get; }

    /// <summary>Demo providers produce synthetic data and must be labelled as such everywhere.</summary>
    bool IsDemo { get; }

    Task<ProviderAvailability> CheckAvailabilityAsync(CancellationToken cancellationToken);

    Task<ISandboxSession> CreateSessionAsync(SandboxSessionRequest request, CancellationToken cancellationToken);
}

/// <summary>One analysis environment. Its methods map one-to-one onto <see cref="AnalysisStage"/>s.</summary>
public interface ISandboxSession : IAsyncDisposable
{
    Task CreateEnvironmentAsync(CancellationToken cancellationToken);
    Task BootAsync(CancellationToken cancellationToken);
    Task DeployAgentAsync(CancellationToken cancellationToken);
    Task TransferSampleAsync(CancellationToken cancellationToken);

    /// <summary>Runs the sample and streams signals until the duration elapses or the agent reports completion.</summary>
    IAsyncEnumerable<SessionSignal> ExecuteAsync(CancellationToken cancellationToken);

    Task<CollectedArtifacts> CollectAsync(CancellationToken cancellationToken);

    /// <summary>Destroys the environment. Must be safe to call more than once and after failures.</summary>
    Task ShutdownAsync(CancellationToken cancellationToken);
}

public sealed record EventQuery
{
    public Guid AnalysisId { get; init; }
    public IReadOnlyCollection<EventCategory>? Categories { get; init; }
    public Severity? MinSeverity { get; init; }
    public int? ProcessId { get; init; }
    public string? Text { get; init; }
    public TimeSpan? From { get; init; }
    public TimeSpan? To { get; init; }
    public int Offset { get; init; }
    public int Limit { get; init; } = 500;
}

public enum SearchSource { Timeline, Process, File, Registry, Network, Indicator, Finding }

public sealed record SearchHit(Guid AnalysisId, string FileName, SearchSource Source, string Title, string Snippet, long? EventSequence);

public interface IAnalysisRepository
{
    Task InitializeAsync(CancellationToken cancellationToken);
    Task SaveAsync(AnalysisResult result, CancellationToken cancellationToken);
    Task<AnalysisResult?> LoadAsync(Guid id, bool includeEvents, CancellationToken cancellationToken);
    Task<IReadOnlyList<AnalysisSummary>> ListAsync(int limit, int offset, CancellationToken cancellationToken);
    Task<IReadOnlyList<AnalysisEvent>> QueryEventsAsync(EventQuery query, CancellationToken cancellationToken);
    Task<int> CountEventsAsync(EventQuery query, CancellationToken cancellationToken);
    Task<IReadOnlyList<SearchHit>> SearchAsync(string text, int limit, CancellationToken cancellationToken);
    Task<DashboardStats> GetStatsAsync(DateTimeOffset now, CancellationToken cancellationToken);
    Task DeleteAsync(Guid id, CancellationToken cancellationToken);
    Task<int> PurgeOlderThanAsync(DateTimeOffset cutoff, CancellationToken cancellationToken);
}

public sealed record ExportOptions(string Language, bool Redact, bool IncludeRawEvents, bool IncludeTimeline, bool IncludeStatic, bool IncludeIndicators, int TimelineLimit);

public interface IReportExporter
{
    string Format { get; }
    string FileExtension { get; }
    Task ExportAsync(AnalysisResult result, Stream destination, ExportOptions options, CancellationToken cancellationToken);
}

/// <summary>
/// Future local AI. Takes the structured result, never the sample. Not required to run Blazma.
/// </summary>
public interface IAiProvider
{
    string Id { get; }
    bool IsAvailable { get; }
    Task<string> AskAsync(AnalysisResult result, string question, string language, CancellationToken cancellationToken);
}

/// <summary>Future reputation lookups. Must be opt-in; the default implementation never leaves the machine.</summary>
public interface IReputationProvider
{
    string Id { get; }
    bool IsRemote { get; }
    Task<string?> LookupAsync(string sha256, CancellationToken cancellationToken);
}
