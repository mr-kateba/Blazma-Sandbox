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

/// <param name="ArtifactsFolder">Host folder where the session stores validated artifacts (screenshots, dropped files, memory, capture).</param>
public sealed record SandboxSessionRequest(Guid AnalysisId, string SamplePath, SampleInfo Sample, AnalysisOptions Options, string? ArtifactsFolder = null);

/// <summary>A live signal from the analysis environment.</summary>
public abstract record SessionSignal;

public sealed record EventsSignal(IReadOnlyList<AnalysisEvent> Events) : SessionSignal;

public sealed record HeartbeatSignal(DateTimeOffset At) : SessionSignal;

public sealed record MonitoringInterruptedSignal(string Reason) : SessionSignal;
public sealed record ScreenshotSignal(CollectedScreenshot Screenshot) : SessionSignal;

/// <summary>A screenshot already validated and written as PNG by the host.</summary>
public sealed record CollectedScreenshot(TimeSpan RelativeTime, string Path, int Width, int Height);

/// <summary>A dropped file copied out of the sandbox, validated, and stored defanged on the host.</summary>
public sealed record CollectedDroppedFile(string OriginalPath, string ProcessName, string StoredPath, string Sha256, long Size);

/// <summary>A memory region dumped by the agent, validated and stored on the host.</summary>
public sealed record CollectedMemoryRegion(int ProcessId, string ProcessName, ulong BaseAddress, long Size, string Protection, MemoryRegionKind Kind, string StoredPath, string Sha256);

public sealed record CollectedArtifacts(
    IReadOnlyList<AnalysisEvent> RemainingEvents,
    SystemSnapshot? Baseline,
    SystemSnapshot? After,
    bool AgentCompleted)
{
    public IReadOnlyList<CollectedScreenshot> Screenshots { get; init; } = [];
    public IReadOnlyList<CollectedDroppedFile> DroppedFiles { get; init; } = [];
    public IReadOnlyList<CollectedMemoryRegion> MemoryRegions { get; init; } = [];
    public string? PcapPath { get; init; }
}

/// <summary>Live controls for a running analysis. Optional: providers that cannot support them simply do not implement it.</summary>
public interface IInteractiveSession
{
    /// <summary>Adds time to the running analysis (capped by <see cref="AnalysisOptions.MaxDuration"/>).</summary>
    Task ExtendAsync(TimeSpan extra, CancellationToken cancellationToken);

    /// <summary>Ends the run now and collects what was observed so far.</summary>
    Task FinishNowAsync(CancellationToken cancellationToken);
}

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

    /// <summary>
    /// Readiness for a run with this network policy. Providers whose checks depend on it (a VM
    /// with a connected adapter is acceptable only when the analysis enables the network)
    /// override this; the rest answer the same as the overload without a policy.
    /// </summary>
    Task<ProviderAvailability> CheckAvailabilityAsync(NetworkPolicy network, CancellationToken cancellationToken) => CheckAvailabilityAsync(cancellationToken);

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
/// Optional AI. Takes the structured (and redacted) result, never the sample. Only local
/// endpoints are allowed by default. Not required to run Blazma.
/// </summary>
public interface IAiProvider
{
    string Id { get; }
    bool IsAvailable { get; }
    Task<string> AskAsync(AnalysisResult result, string question, string language, CancellationToken cancellationToken);
}

/// <summary>Hash reputation. Remote providers are opt-in and send the SHA-256 only, never the file.</summary>
public interface IReputationProvider
{
    string Id { get; }
    LocalizedText DisplayName { get; }
    bool IsRemote { get; }

    /// <summary>False until the user has enabled the provider and given it what it needs (an API key).</summary>
    bool IsConfigured { get; }

    Task<ReputationResult> LookupAsync(string sha256, CancellationToken cancellationToken);
}

/// <summary>Scans bytes with the user's YARA rules.</summary>
public interface IYaraScanner
{
    int RuleCount { get; }
    IReadOnlyList<string> LoadErrors { get; }
    IReadOnlyList<YaraMatch> Scan(ReadOnlySpan<byte> data, string target);
}

/// <summary>
/// Static analysis of a file the host did not choose (dropped file, memory dump). The app
/// runs it out of process, like the main sample, because the bytes are hostile.
/// </summary>
public interface IArtifactInspector
{
    Task<StaticReport?> InspectAsync(string path, string displayName, CancellationToken cancellationToken);
}

/// <summary>Protects secrets such as API keys at rest (DPAPI on Windows).</summary>
public interface ISecretProtector
{
    bool IsStrong { get; }
    string Protect(string plaintext);
    string? Unprotect(string stored);
}
