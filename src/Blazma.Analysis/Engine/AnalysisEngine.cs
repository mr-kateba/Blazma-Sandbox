using Blazma.Analysis.Rules;
using Blazma.Core.Analysis;
using Blazma.Core.Events;
using Blazma.Core.Findings;
using Blazma.Core.Settings;
using Blazma.Core.Snapshots;

namespace Blazma.Analysis.Engine;

/// <summary>The detection settings the engine needs, copied from the user's settings at the start of a run.</summary>
public sealed record EngineSettings
{
    public RiskThresholds Thresholds { get; init; } = RiskThresholds.Default;
    public IReadOnlyDictionary<string, RuleOverride> RuleOverrides { get; init; } = new Dictionary<string, RuleOverride>();
    public IReadOnlyList<WatchlistEntry> Watchlist { get; init; } = [];
    public bool SuppressBackgroundNoise { get; init; } = true;
    public IReadOnlyList<string> NoiseAllowlist { get; init; } = [];
    public IReadOnlyList<string> TrustedPublishers { get; init; } = [];

    public static EngineSettings From(DetectionSettings d) => new()
    {
        Thresholds = d.Thresholds,
        RuleOverrides = new Dictionary<string, RuleOverride>(d.RuleOverrides, StringComparer.OrdinalIgnoreCase),
        Watchlist = d.Watchlist.ToList(),
        SuppressBackgroundNoise = d.SuppressBackgroundNoise,
        NoiseAllowlist = d.NoiseAllowlist.ToList(),
        TrustedPublishers = d.TrustedPublishers.ToList(),
    };
}

/// <summary>
/// Post-processing: order → build the process tree → filter noise → detect persistence →
/// correlate → run rules → score → extract indicators → diff snapshots. Deterministic: the
/// same events and settings always produce the same result.
/// </summary>
public sealed class AnalysisEngine(RuleEngine rules)
{
    public RuleEngine Rules => rules;

    public void Process(AnalysisResult result, IReadOnlyList<AnalysisEvent> rawEvents, SystemSnapshot? baseline, SystemSnapshot? after, EngineSettings settings)
    {
        var ordered = Order(rawEvents);
        var fullGraph = ProcessGraph.Build(ordered);
        var noise = NoiseFilter.Apply(ordered, fullGraph, settings.SuppressBackgroundNoise, settings.NoiseAllowlist);
        var events = noise.Kept;
        var graph = noise.Suppressed > 0 ? ProcessGraph.Build(events) : fullGraph;

        var persistence = PersistenceDetector.Detect(events, graph);
        var network = NetworkMap.Build(events);
        var context = new RuleContext
        {
            Events = events,
            Graph = graph,
            Persistence = persistence,
            Network = network,
            Sample = result.Sample,
            Static = result.Static,
            MonitoringInterrupted = result.MonitoringInterrupted,
            Watchlist = settings.Watchlist,
            TrustedPublishers = settings.TrustedPublishers,
        };

        var findings = rules.Evaluate(context, settings.RuleOverrides);

        result.Events = events;
        result.SuppressedNoiseEvents = noise.Suppressed;
        result.ProcessRoots = graph.Roots;
        result.Persistence = persistence;
        result.Chains = CorrelationEngine.BuildChains(events, graph, persistence, network);
        result.Findings = findings;
        result.Risk = RiskEngine.Assess(findings, settings.Thresholds);
        result.Indicators = IndicatorExtractor.Extract(result.Sample, events, graph, persistence, findings, settings.Watchlist);
        result.SystemChanges = baseline is not null && after is not null ? SnapshotDiffer.Diff(baseline, after) : null;
    }

    /// <summary>Stable timeline order: by relative time, then by the agent's sequence number.</summary>
    public static IReadOnlyList<AnalysisEvent> Order(IEnumerable<AnalysisEvent> events) =>
        events.OrderBy(e => e.RelativeTime).ThenBy(e => e.Sequence).ToList();
}
