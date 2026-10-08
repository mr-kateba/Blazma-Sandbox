using Blazma.Analysis.Rules;

namespace Blazma.Analysis.Tests;

public class RuleIdTests
{
    [Fact]
    public void Built_in_rule_ids_are_unique()
    {
        var ids = RuleEngine.BuiltInRules().Select(r => r.Metadata.Id).ToList();
        Assert.Equal(ids.Count, ids.Distinct(StringComparer.OrdinalIgnoreCase).Count());
    }
}
