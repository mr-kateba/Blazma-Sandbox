using Blazma.Analysis.Compare;
using Blazma.Analysis.Engine;
using Blazma.Analysis.Rules;
using Blazma.Core.Events;
using Blazma.Sandbox.Providers.Demo;

namespace Blazma.Analysis.Tests;

public class RulePackAndCompareTests
{
    [Fact]
    public void Example_rule_pack_loads_and_matches()
    {
        var (rules, errors) = JsonRulePack.Load(JsonRulePack.Example, "example.json");
        Assert.Empty(errors);
        var rule = Assert.Single(rules);
        Assert.Equal("USR-0001", rule.Metadata.Id);

        var ev = new Ev();
        var s = ev.Start(0, 100, 4, "s.exe", sample: true);
        ev.Dns(10, 100, s, "s.exe", "beacon.example.test");
        var result = new Core.Analysis.AnalysisResult
        {
            AnalysisId = Guid.NewGuid(), Sample = TestEngine.Sample(), Options = new(), ProviderId = "t", StartedAt = DateTimeOffset.UnixEpoch,
        };
        new AnalysisEngine(new RuleEngine(RuleEngine.BuiltInRules().Concat(rules))).Process(result, ev.Events, null, null, new EngineSettings());
        Assert.Contains(result.Findings, f => f.RuleId == "USR-0001");
    }

    [Theory]
    [InlineData("""{ "rules": [ { "id": "BLZ-P001", "name": { "en": "x" }, "match": { "action": "DnsQuery" } } ] }""")]
    [InlineData("""{ "rules": [ { "id": "USR-1", "name": { "en": "x" }, "weight": 500, "match": { "action": "DnsQuery" } } ] }""")]
    [InlineData("""{ "rules": [ { "id": "USR-1", "name": { "en": "x" }, "match": { } } ] }""")]
    public void Invalid_rules_are_rejected_with_a_reason(string json)
    {
        var (rules, errors) = JsonRulePack.Load(json, "bad.json");
        Assert.Empty(rules);
        Assert.Single(errors);
    }

    [Fact]
    public void Broken_json_is_reported_not_thrown()
    {
        var (rules, errors) = JsonRulePack.Load("{ not json", "broken.json");
        Assert.Empty(rules);
        Assert.Contains("invalid JSON", errors.Single(), StringComparison.Ordinal);
    }

    [Fact]
    public void Compare_shows_what_a_new_version_added()
    {
        var v1 = TestEngine.Run(DemoScenario.QuietTool("tool-1.2.exe", DateTimeOffset.UnixEpoch).Events, sampleName: "tool-1.2.exe");
        var v2 = TestEngine.Run(DemoScenario.PersistentUpdater("tool-1.3.exe", DateTimeOffset.UnixEpoch).Events, sampleName: "tool-1.3.exe");
        var diff = AnalysisComparer.Compare(v1, v2);

        Assert.Contains("updater.exe", diff.Processes.Added);
        Assert.Contains(diff.Endpoints.Added, e => e.StartsWith("198.51.100.7", StringComparison.Ordinal));
        Assert.NotEmpty(diff.Persistence.Added);
        Assert.True(diff.ScoreDelta > 40);
    }
}
