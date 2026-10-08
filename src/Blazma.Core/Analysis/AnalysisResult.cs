using Blazma.Core.Events;
using Blazma.Core.Findings;
using Blazma.Core.Indicators;
using Blazma.Core.Processes;
using Blazma.Core.Samples;
using Blazma.Core.Snapshots;

namespace Blazma.Core.Analysis;

/// <summary>Everything produced by one analysis. This is what reports, storage and Ask Blazma read.</summary>
public sealed class AnalysisResult
{
    public const int SchemaVersion = 2;

    public required Guid AnalysisId { get; init; }
    public required SampleInfo Sample { get; init; }
    public StaticReport? Static { get; init; }
    public required AnalysisOptions Options { get; init; }
    public required string ProviderId { get; init; }
    public bool IsDemo { get; init; }

    public required DateTimeOffset StartedAt { get; init; }
    public DateTimeOffset? CompletedAt { get; set; }
    public AnalysisStage FinalStage { get; set; } = AnalysisStage.Completed;
    public string? FailureReason { get; set; }

    public IReadOnlyList<AnalysisEvent> Events { get; set; } = [];
    public IReadOnlyList<ProcessNode> ProcessRoots { get; set; } = [];
    public IReadOnlyList<Finding> Findings { get; set; } = [];
    public RiskAssessment Risk { get; set; } = RiskAssessment.Empty;
    public IReadOnlyList<BehaviorChain> Chains { get; set; } = [];
    public IReadOnlyList<PersistenceDetection> Persistence { get; set; } = [];
    public IReadOnlyList<Indicator> Indicators { get; set; } = [];
    public SnapshotDiff? SystemChanges { get; set; }

    public IReadOnlyList<ScreenshotInfo> Screenshots { get; set; } = [];
    public IReadOnlyList<DroppedFileInfo> DroppedFiles { get; set; } = [];
    public IReadOnlyList<MemoryArtifact> MemoryArtifacts { get; set; } = [];
    public IReadOnlyList<ReputationResult> Reputation { get; set; } = [];

    /// <summary>Configuration-like values found anywhere in this analysis (sample, dropped files, memory).</summary>
    public IReadOnlyList<ExtractedArtifact> Artifacts { get; set; } = [];

    /// <summary>Network capture (pcapng), relative to the artifact folder. Only when the real network was enabled.</summary>
    public string? PcapFile { get; set; }

    /// <summary>All YARA matches: the sample, dropped files and memory.</summary>
    public IEnumerable<YaraMatch> AllYaraMatches =>
        (Static?.YaraMatches ?? []).Concat(DroppedFiles.SelectMany(d => d.Static?.YaraMatches ?? [])).Concat(MemoryArtifacts.SelectMany(m => m.YaraMatches));

    /// <summary>The agent stopped reporting before the analysis ended. Data may be incomplete.</summary>
    public bool MonitoringInterrupted { get; set; }

    /// <summary>Background events outside the analyzed process tree that were filtered as noise.</summary>
    public int SuppressedNoiseEvents { get; set; }

    public TimeSpan? Duration => CompletedAt is { } c ? c - StartedAt : null;

    public IEnumerable<ProcessNode> AllProcesses => ProcessRoots.SelectMany(r => r.SelfAndDescendants());
}
