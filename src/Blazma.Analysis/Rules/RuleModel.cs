using Blazma.Analysis.Engine;
using Blazma.Core.Analysis;
using Blazma.Core.Events;
using Blazma.Core.Findings;
using Blazma.Core.Processes;
using Blazma.Core.Samples;
using Blazma.Core.Settings;
using Blazma.Core.Text;

namespace Blazma.Analysis.Rules;

public sealed record RuleMetadata
{
    public required string Id { get; init; }
    public required string Version { get; init; }
    public required LocalizedText Name { get; init; }
    public required LocalizedText Description { get; init; }
    public required FindingCategory Category { get; init; }
    public required Severity Severity { get; init; }

    /// <summary>Default points added to the score. Users can override it per rule.</summary>
    public required int Weight { get; init; }

    public IReadOnlyList<string> AttackTechniques { get; init; } = [];
    public IReadOnlyList<string> References { get; init; } = [];

    /// <summary>"built-in" or the name of the user rule pack it came from.</summary>
    public string Origin { get; init; } = "built-in";
}

/// <summary>Everything a rule can look at. Rules are read-only consumers of the context.</summary>
public sealed class RuleContext
{
    public required IReadOnlyList<AnalysisEvent> Events { get; init; }
    public required ProcessGraph Graph { get; init; }
    public required IReadOnlyList<PersistenceDetection> Persistence { get; init; }
    public required NetworkMap Network { get; init; }
    public required SampleInfo Sample { get; init; }
    public StaticReport? Static { get; init; }
    public bool MonitoringInterrupted { get; init; }
    public IReadOnlyList<WatchlistEntry> Watchlist { get; init; } = [];
    public IReadOnlyList<string> TrustedPublishers { get; init; } = [];

    public IReadOnlyList<DroppedFileInfo> DroppedFiles { get; init; } = [];
    public IReadOnlyList<MemoryArtifact> MemoryArtifacts { get; init; } = [];
    public IReadOnlyList<ReputationResult> Reputation { get; init; } = [];

    /// <summary>Configuration-like values found anywhere in the analysis.</summary>
    public IReadOnlyList<ExtractedArtifact> Artifacts { get; init; } = [];

    public bool UseCapabilities { get; init; } = true;

    public IEnumerable<AnalysisEvent> TreeEvents => Events.Where(Graph.InAnalyzedTree);

    public ProcessNode? NodeOf(AnalysisEvent e) => Graph.Resolve(e);
}

/// <summary>
/// A detection rule. Rules never decide "malware": they recognise one behaviour, attach
/// the evidence and say how much it should count.
/// </summary>
public interface IRule
{
    RuleMetadata Metadata { get; }

    /// <summary>Returns zero or one finding. A rule groups all of its evidence into a single finding so repeated behaviour is not counted twice.</summary>
    Finding? Evaluate(RuleContext context);
}

public abstract class Rule : IRule
{
    public abstract RuleMetadata Metadata { get; }

    public abstract Finding? Evaluate(RuleContext context);

    protected Finding? Build(IReadOnlyList<Evidence> evidence, LocalizedText? explanation = null, IEnumerable<ProcessKey>? processes = null, TimeSpan? firstSeen = null, Severity? severity = null)
    {
        if (evidence.Count == 0) return null;
        var m = Metadata;
        return new Finding
        {
            Id = m.Id,
            RuleId = m.Id,
            RuleVersion = m.Version,
            Title = m.Name,
            Explanation = explanation ?? m.Description,
            Category = m.Category,
            Severity = severity ?? m.Severity,
            Points = m.Weight,
            Evidence = evidence,
            AttackTechniques = m.AttackTechniques,
            Processes = processes?.Distinct().ToList() ?? [],
            FirstSeen = firstSeen,
        };
    }

    protected static Evidence EventEvidence(string kind, AnalysisEvent e, LocalizedText description, string? technical = null) => new()
    {
        Kind = kind,
        Description = description,
        Technical = technical ?? e.Target,
        EventSequences = [e.Sequence],
    };
}
