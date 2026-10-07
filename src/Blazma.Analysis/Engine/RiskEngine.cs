using Blazma.Core.Findings;

namespace Blazma.Analysis.Engine;

/// <summary>
/// Explainable scoring: the score is the sum of finding points, with a cap per category so
/// that many findings of one kind cannot dominate, clamped to 0-100. Every point in the
/// final number traces back to a listed contribution.
/// </summary>
public static class RiskEngine
{
    public static readonly IReadOnlyDictionary<FindingCategory, int> CategoryCaps = new Dictionary<FindingCategory, int>
    {
        [FindingCategory.Persistence] = 40,
        [FindingCategory.Execution] = 30,
        [FindingCategory.FileSystem] = 25,
        [FindingCategory.Registry] = 20,
        [FindingCategory.Network] = 25,
        [FindingCategory.DefenseEvasion] = 40,
        [FindingCategory.Impact] = 50,
        [FindingCategory.Static] = 15,
        [FindingCategory.Monitoring] = 10,
        [FindingCategory.Watchlist] = 30,
        [FindingCategory.Sequence] = 20,
    };

    public static RiskAssessment Assess(IReadOnlyList<Finding> findings, RiskThresholds thresholds)
    {
        if (!thresholds.IsValid) thresholds = RiskThresholds.Default;
        var used = new Dictionary<FindingCategory, int>();
        var contributions = new List<ScoreContribution>();

        foreach (var f in findings.OrderByDescending(f => f.Points).ThenBy(f => f.RuleId, StringComparer.Ordinal))
        {
            var cap = CategoryCaps.GetValueOrDefault(f.Category, 20);
            var already = used.GetValueOrDefault(f.Category);
            var points = Math.Max(0, Math.Min(f.Points, cap - already));
            used[f.Category] = already + points;
            contributions.Add(new ScoreContribution(f.Id, f.RuleId, f.Title, f.Category, points, points < f.Points));
        }

        var score = Math.Clamp(contributions.Sum(c => c.Points), 0, 100);
        return new RiskAssessment(score, thresholds.VerdictFor(score), contributions.Where(c => c.Points > 0 || c.Capped).ToList());
    }
}
