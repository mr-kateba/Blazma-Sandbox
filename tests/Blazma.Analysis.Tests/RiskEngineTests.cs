using Blazma.Analysis.Engine;
using Blazma.Core.Events;
using Blazma.Core.Findings;
using Blazma.Core.Text;

namespace Blazma.Analysis.Tests;

public class RiskEngineTests
{
    private static Finding F(string id, FindingCategory cat, int points) => new()
    {
        Id = id, RuleId = id, RuleVersion = "1", Title = LocalizedText.Same(id), Explanation = LocalizedText.Same(id),
        Category = cat, Severity = Severity.Medium, Points = points,
        Evidence = [new Evidence { Kind = "t", Description = LocalizedText.Same("e") }],
    };

    [Fact]
    public void Score_is_the_sum_of_contributions()
    {
        var risk = RiskEngine.Assess([F("A", FindingCategory.Persistence, 20), F("B", FindingCategory.Network, 10), F("C", FindingCategory.Execution, 5)], RiskThresholds.Default);
        Assert.Equal(35, risk.Score);
        Assert.Equal(risk.Score, risk.Contributions.Sum(c => c.Points));
        Assert.Equal(Verdict.Suspicious, risk.Verdict);
    }

    [Fact]
    public void Category_caps_stop_one_kind_of_finding_from_dominating()
    {
        var risk = RiskEngine.Assess([F("A", FindingCategory.Static, 10), F("B", FindingCategory.Static, 10), F("C", FindingCategory.Static, 10)], RiskThresholds.Default);
        Assert.Equal(RiskEngine.CategoryCaps[FindingCategory.Static], risk.Score);
        Assert.Contains(risk.Contributions, c => c.Capped);
    }

    [Fact]
    public void Score_never_exceeds_100()
    {
        var all = Enum.GetValues<FindingCategory>().Select((c, i) => F($"R{i}", c, 50)).ToList();
        Assert.Equal(100, RiskEngine.Assess(all, RiskThresholds.Default).Score);
    }

    [Fact]
    public void Custom_thresholds_change_the_verdict_and_invalid_ones_fall_back()
    {
        var findings = new[] { F("A", FindingCategory.Persistence, 30) };
        Assert.Equal(Verdict.HighRiskBehavior, RiskEngine.Assess(findings, new RiskThresholds(10, 25, 90)).Verdict);
        Assert.Equal(Verdict.Suspicious, RiskEngine.Assess(findings, new RiskThresholds(50, 40, 30)).Verdict);
    }
}
