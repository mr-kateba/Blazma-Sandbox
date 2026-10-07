using Blazma.Core.Events;
using Blazma.Core.Text;

namespace Blazma.Core.Findings;

/// <summary>
/// Where a statement in a report comes from. The UI and exports label every finding with
/// it so a reader can always tell what was seen from what was concluded.
/// </summary>
public enum Provenance
{
    ObservedFact,
    RuleInference,
    AiInterpretation,
}

public enum FindingCategory
{
    Persistence,
    Execution,
    FileSystem,
    Registry,
    Network,
    DefenseEvasion,
    Impact,
    Static,
    Monitoring,
    Watchlist,
    Sequence,
}

/// <summary>One piece of proof for a finding, pointing back to the events it rests on.</summary>
public sealed record Evidence
{
    public required string Kind { get; init; }
    public required LocalizedText Description { get; init; }
    public string? Technical { get; init; }
    public IReadOnlyList<long> EventSequences { get; init; } = [];
}

/// <summary>
/// A behaviour worth the user's attention. Every finding has at least one piece of
/// evidence; a finding without proof is never produced.
/// </summary>
public sealed record Finding
{
    public required string Id { get; init; }
    public required string RuleId { get; init; }
    public required string RuleVersion { get; init; }
    public required LocalizedText Title { get; init; }

    /// <summary>The human explanation: what happened and why it matters, without jargon.</summary>
    public required LocalizedText Explanation { get; init; }

    public required FindingCategory Category { get; init; }
    public required Severity Severity { get; init; }

    /// <summary>Points this finding adds to the risk score (after overrides and caps are applied by the risk engine).</summary>
    public required int Points { get; init; }

    public required IReadOnlyList<Evidence> Evidence { get; init; }
    public IReadOnlyList<string> AttackTechniques { get; init; } = [];
    public IReadOnlyList<ProcessKey> Processes { get; init; } = [];
    public TimeSpan? FirstSeen { get; init; }
    public Provenance Provenance { get; init; } = Provenance.RuleInference;

    public IEnumerable<long> AllEventSequences => Evidence.SelectMany(e => e.EventSequences).Distinct();
}
