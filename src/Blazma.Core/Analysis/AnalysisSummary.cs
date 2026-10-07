using Blazma.Core.Findings;
using Blazma.Core.Samples;

namespace Blazma.Core.Analysis;

/// <summary>A row in History and on the dashboard. Cheap to load in bulk.</summary>
public sealed record AnalysisSummary
{
    public required Guid Id { get; init; }
    public required string FileName { get; init; }
    public required string Sha256 { get; init; }
    public required FileKind Kind { get; init; }
    public required DateTimeOffset StartedAt { get; init; }
    public DateTimeOffset? CompletedAt { get; init; }
    public required AnalysisStage Stage { get; init; }
    public int Score { get; init; }
    public Verdict Verdict { get; init; }
    public required string ProviderId { get; init; }
    public bool IsDemo { get; init; }
    public int EventCount { get; init; }
    public int FindingCount { get; init; }

    public TimeSpan? Duration => CompletedAt is { } c ? c - StartedAt : null;
}

public sealed record DashboardStats(int AnalysesToday, int HighRisk, int Suspicious, int LowRisk, int Total);
