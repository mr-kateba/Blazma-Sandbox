using Blazma.Analysis.Engine;
using Blazma.Core.Analysis;
using Blazma.Core.Events;
using Blazma.Core.Findings;

namespace Blazma.Analysis.Compare;

public sealed record SetDiff(IReadOnlyList<string> Added, IReadOnlyList<string> Removed, IReadOnlyList<string> Common);

/// <summary>What changed between two analyses, for example two versions of the same installer.</summary>
public sealed record AnalysisComparison
{
    public required Guid BaseId { get; init; }
    public required Guid TargetId { get; init; }
    public required string BaseName { get; init; }
    public required string TargetName { get; init; }
    public required int BaseScore { get; init; }
    public required int TargetScore { get; init; }
    public int ScoreDelta => TargetScore - BaseScore;
    public required SetDiff Processes { get; init; }
    public required SetDiff Endpoints { get; init; }
    public required SetDiff Domains { get; init; }
    public required SetDiff Persistence { get; init; }
    public required SetDiff DroppedFiles { get; init; }
    public required SetDiff Findings { get; init; }

    public bool SameSample { get; init; }
}

public static class AnalysisComparer
{
    public static AnalysisComparison Compare(AnalysisResult baseline, AnalysisResult target) => new()
    {
        BaseId = baseline.AnalysisId,
        TargetId = target.AnalysisId,
        BaseName = baseline.Sample.FileName,
        TargetName = target.Sample.FileName,
        BaseScore = baseline.Risk.Score,
        TargetScore = target.Risk.Score,
        SameSample = baseline.Sample.Sha256 == target.Sample.Sha256,
        Processes = Diff(ProcessNames(baseline), ProcessNames(target)),
        Endpoints = Diff(Endpoints(baseline), Endpoints(target)),
        Domains = Diff(Domains(baseline), Domains(target)),
        Persistence = Diff(baseline.Persistence.Select(p => $"{p.Technique}: {p.Target}"), target.Persistence.Select(p => $"{p.Technique}: {p.Target}")),
        DroppedFiles = Diff(Dropped(baseline), Dropped(target)),
        Findings = Diff(baseline.Findings.Select(f => $"{f.RuleId} {f.Title.En}"), target.Findings.Select(f => $"{f.RuleId} {f.Title.En}")),
    };

    /// <summary>The sample itself is named "&lt;sample&gt;" so a renamed file between versions is not reported as a new process.</summary>
    private static IEnumerable<string> ProcessNames(AnalysisResult r) =>
        r.AllProcesses.Where(p => p.InAnalyzedTree || r.AllProcesses.All(x => !x.InAnalyzedTree))
            .Select(p => p.IsSample ? "<sample>" : p.Name.ToLowerInvariant());

    private static IEnumerable<string> Endpoints(AnalysisResult r) =>
        r.Events.Where(e => e.Action == EventAction.NetworkConnect && NetworkMap.IsExternal(e)).Select(NetworkMap.Endpoint);

    private static IEnumerable<string> Domains(AnalysisResult r) =>
        r.Events.Where(e => e.Action == EventAction.DnsQuery).Select(e => (e.Detail(DetailKeys.QueryName) ?? e.Target ?? string.Empty).ToLowerInvariant());

    private static IEnumerable<string> Dropped(AnalysisResult r) =>
        r.Events.Where(e => e.Action == EventAction.FileCreate && Text.PathRules.IsExecutablePath(e.Target))
            .Select(e => Normalize(e.Target!, r));

    /// <summary>Paths differ by user name and sample name between runs; compare them in a neutral form.</summary>
    private static string Normalize(string path, AnalysisResult r)
    {
        var p = path;
        var users = p.IndexOf(@"\Users\", StringComparison.OrdinalIgnoreCase);
        if (users >= 0)
        {
            var next = p.IndexOf('\\', users + 7);
            if (next > 0) p = p[..(users + 7)] + "<user>" + p[next..];
        }
        return p.ToLowerInvariant();
    }

    private static SetDiff Diff(IEnumerable<string> a, IEnumerable<string> b)
    {
        var left = new HashSet<string>(a.Where(s => s.Length > 0), StringComparer.OrdinalIgnoreCase);
        var right = new HashSet<string>(b.Where(s => s.Length > 0), StringComparer.OrdinalIgnoreCase);
        return new SetDiff(
            right.Except(left, StringComparer.OrdinalIgnoreCase).Order(StringComparer.OrdinalIgnoreCase).ToList(),
            left.Except(right, StringComparer.OrdinalIgnoreCase).Order(StringComparer.OrdinalIgnoreCase).ToList(),
            left.Intersect(right, StringComparer.OrdinalIgnoreCase).Order(StringComparer.OrdinalIgnoreCase).ToList());
    }
}
