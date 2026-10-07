using Blazma.Analysis.Text;
using Blazma.Core.Events;

namespace Blazma.Analysis.Engine;

/// <summary>
/// A clean Windows install is never quiet: indexing, updates and telemetry services run
/// constantly. Events outside the sample's process tree are treated as background noise,
/// except system-level effects in sensitive locations (persistence keys, service and task
/// stores), which are kept whoever performed them because system processes often act on
/// a sample's behalf.
/// </summary>
public static class NoiseFilter
{
    public sealed record Result(IReadOnlyList<AnalysisEvent> Kept, int Suppressed);

    public static Result Apply(IReadOnlyList<AnalysisEvent> events, ProcessGraph graph, bool suppressBackground, IReadOnlyCollection<string> allowlist)
    {
        var kept = new List<AnalysisEvent>(events.Count);
        var suppressed = 0;
        // Without an identified sample there is no tree to scope to; keeping everything is the safe choice.
        var canScope = suppressBackground && graph.Sample is not null;

        foreach (var e in events)
        {
            var node = graph.Resolve(e);
            var isSample = node?.IsSample == true;

            if (!isSample && allowlist.Count > 0 && MatchesAllowlist(e, allowlist))
            {
                suppressed++;
                continue;
            }

            if (canScope && !KeepEvenOutsideTree(e) && node?.InAnalyzedTree != true)
            {
                suppressed++;
                continue;
            }

            kept.Add(e);
        }
        return new Result(kept, suppressed);
    }

    private static bool KeepEvenOutsideTree(AnalysisEvent e)
    {
        if (e.Category == EventCategory.System) return true;
        if (e.RelativeTime < TimeSpan.Zero) return false;
        if (e.Action is EventAction.ServiceInstall or EventAction.ScheduledTaskCreate) return true;
        return PersistenceCatalog.IsSensitiveLocation(e);
    }

    private static bool MatchesAllowlist(AnalysisEvent e, IReadOnlyCollection<string> allowlist)
    {
        foreach (var entry in allowlist)
        {
            if (string.IsNullOrWhiteSpace(entry)) continue;
            if (Glob.IsMatch(e.ProcessName, entry)) return true;
            if (e.Target is not null && (entry.Contains('*') ? Glob.IsMatch(e.Target, entry) : e.Target.StartsWith(entry, StringComparison.OrdinalIgnoreCase)))
                return true;
        }
        return false;
    }
}
