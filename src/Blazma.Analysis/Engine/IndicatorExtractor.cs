using Blazma.Analysis.Text;
using Blazma.Core.Events;
using Blazma.Core.Findings;
using Blazma.Core.Indicators;
using Blazma.Core.Processes;
using Blazma.Core.Samples;
using Blazma.Core.Settings;

namespace Blazma.Analysis.Engine;

/// <summary>
/// Collects indicators and grades them only by evidence: an indicator rises above
/// "Observed" when a finding refers to one of its events, or when the user's watchlist
/// names it. Nothing is labelled malicious on its own.
/// </summary>
public static class IndicatorExtractor
{
    private const int MaxPerType = 200;

    public static IReadOnlyList<Indicator> Extract(
        SampleInfo sample,
        IReadOnlyList<AnalysisEvent> events,
        ProcessGraph graph,
        IReadOnlyList<PersistenceDetection> persistence,
        IReadOnlyList<Finding> findings,
        IReadOnlyList<WatchlistEntry> watchlist)
    {
        var severityBySeq = new Dictionary<long, Severity>();
        foreach (var f in findings)
            foreach (var seq in f.AllEventSequences)
                if (!severityBySeq.TryGetValue(seq, out var s) || s < f.Severity) severityBySeq[seq] = f.Severity;

        var list = new List<Indicator>();
        var seen = new HashSet<(IndicatorType, string)>();

        void Add(IndicatorType type, string? value, string source, IEnumerable<long> sequences)
        {
            if (string.IsNullOrWhiteSpace(value) || list.Count(i => i.Type == type) >= MaxPerType) return;
            if (!seen.Add((type, value.ToLowerInvariant()))) return;
            var seqs = sequences.Distinct().ToList();
            var worst = seqs.Select(q => severityBySeq.TryGetValue(q, out var s) ? s : Severity.Informational).DefaultIfEmpty(Severity.Informational).Max();
            var status = worst >= Severity.High ? IndicatorStatus.HighRisk
                : worst >= Severity.Medium ? IndicatorStatus.Suspicious
                : IndicatorStatus.Observed;
            if (IsWatchlisted(type, value, watchlist)) status = IndicatorStatus.WatchlistMatch;
            list.Add(new Indicator(type, value, status, source, seqs));
        }

        list.Add(new Indicator(IndicatorType.Sha256, sample.Sha256, IsWatchlisted(IndicatorType.Sha256, sample.Sha256, watchlist) ? IndicatorStatus.WatchlistMatch : IndicatorStatus.Informational, "sample", []));
        seen.Add((IndicatorType.Sha256, sample.Sha256.ToLowerInvariant()));

        var tree = events.Where(graph.InAnalyzedTree).ToList();
        foreach (var e in tree.Where(e => e.Detail(DetailKeys.Sha256) is not null))
            Add(IndicatorType.Sha256, e.Detail(DetailKeys.Sha256), "dropped-file", [e.Sequence]);

        foreach (var g in tree.Where(e => e.Action == EventAction.DnsQuery).GroupBy(e => e.Detail(DetailKeys.QueryName) ?? e.Target ?? string.Empty, StringComparer.OrdinalIgnoreCase))
            Add(IndicatorType.Domain, g.Key, "dns", g.Select(e => e.Sequence));

        foreach (var g in tree.Where(e => e.Category == EventCategory.Network && NetworkMap.IsExternal(e)).GroupBy(e => e.Detail(DetailKeys.RemoteAddress) ?? e.Target ?? string.Empty, StringComparer.OrdinalIgnoreCase))
            Add(IndicatorType.IpAddress, g.Key, "network", g.Select(e => e.Sequence));

        foreach (var (path, e) in graph.DroppedFiles.Where(kv => PathRules.IsExecutablePath(kv.Key)))
            Add(IndicatorType.FilePath, path, "dropped-file", [e.Sequence]);

        foreach (var p in persistence.Where(p => p.ByAnalyzedTree || p.PointsToDroppedFile))
        {
            var type = p.Target.StartsWith("HK", StringComparison.OrdinalIgnoreCase) ? IndicatorType.RegistryKey : IndicatorType.PersistenceArtifact;
            Add(type, p.Target, $"persistence:{p.Technique}", p.EventSequences);
        }

        foreach (var n in graph.Nodes.Values.Where(n => n.InAnalyzedTree).GroupBy(n => n.Name, StringComparer.OrdinalIgnoreCase))
            Add(IndicatorType.ProcessName, n.Key, "process", n.Select(x => x.StartEventSequence));

        return list;
    }

    private static bool IsWatchlisted(IndicatorType type, string value, IReadOnlyList<WatchlistEntry> watchlist) => watchlist.Any(w =>
        (w.Type, type) switch
        {
            (WatchlistEntryType.Sha256, IndicatorType.Sha256) => w.Value.Equals(value, StringComparison.OrdinalIgnoreCase),
            (WatchlistEntryType.Domain, IndicatorType.Domain) => Glob.IsMatch(value, w.Value),
            (WatchlistEntryType.IpAddress, IndicatorType.IpAddress) => w.Value.Equals(value, StringComparison.OrdinalIgnoreCase),
            (WatchlistEntryType.FilePath, IndicatorType.FilePath) => Glob.IsMatch(value, w.Value),
            (WatchlistEntryType.ProcessName, IndicatorType.ProcessName) => Glob.IsMatch(value, w.Value),
            _ => false,
        });
}
