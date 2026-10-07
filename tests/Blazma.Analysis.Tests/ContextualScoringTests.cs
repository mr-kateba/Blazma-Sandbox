using Blazma.Analysis.Engine;
using Blazma.Core.Events;
using Blazma.Core.Findings;
using Blazma.Core.Processes;
using Blazma.Core.Settings;
using Blazma.Sandbox.Providers.Demo;

namespace Blazma.Analysis.Tests;

public class ContextualScoringTests
{
    [Fact]
    public void PowerShell_on_its_own_is_low_risk()
    {
        var ev = new Ev();
        var s = ev.Start(0, 100, 4, "setup.exe", @"C:\Users\u\Desktop\setup.exe", sample: true);
        ev.Start(500, 200, 100, "powershell.exe", cmd: "powershell.exe -File install.ps1");
        var result = TestEngine.Run(ev.Events);

        Assert.Contains(result.Findings, f => f.RuleId == "BLZ-E001");
        Assert.True(result.Risk.Score < 20, $"score {result.Risk.Score}");
        Assert.Equal(Verdict.LowRisk, result.Risk.Verdict);
    }

    [Fact]
    public void Full_drop_run_persist_connect_sequence_is_critical()
    {
        var scenario = DemoScenario.PersistentUpdater("setup.exe", DateTimeOffset.UnixEpoch, backgroundNoise: 0);
        var result = TestEngine.Run(scenario.Events);

        var ids = result.Findings.Select(f => f.RuleId).ToHashSet();
        Assert.Contains("BLZ-P001", ids); // Run key
        Assert.Contains("BLZ-P002", ids); // scheduled task
        Assert.Contains("BLZ-F001", ids); // exe in AppData
        Assert.Contains("BLZ-F002", ids); // dropped then run
        Assert.Contains("BLZ-E002", ids); // hidden encoded PowerShell
        Assert.Contains("BLZ-N002", ids); // dropped process went online
        Assert.Contains("BLZ-C001", ids); // the whole chain
        Assert.True(result.Risk.Score >= 75, $"score {result.Risk.Score}");
        Assert.Equal(Verdict.CriticalBehavior, result.Risk.Verdict);
    }

    [Fact]
    public void Every_finding_has_evidence_that_points_to_real_events()
    {
        var scenario = DemoScenario.PersistentUpdater("setup.exe", DateTimeOffset.UnixEpoch);
        var result = TestEngine.Run(scenario.Events);
        var sequences = result.Events.Select(e => e.Sequence).ToHashSet();
        Assert.NotEmpty(result.Findings);
        foreach (var f in result.Findings)
        {
            Assert.NotEmpty(f.Evidence);
            foreach (var seq in f.AllEventSequences) Assert.Contains(seq, sequences);
        }
    }

    [Fact]
    public void Behavior_chain_reads_from_sample_to_actions()
    {
        var scenario = DemoScenario.PersistentUpdater("setup.exe", DateTimeOffset.UnixEpoch);
        var result = TestEngine.Run(scenario.Events);
        var chain = Assert.Single(result.Chains, c => c.Title.En == "What updater.exe did");
        var kinds = chain.Steps.Select(s => s.Kind).ToList();
        Assert.Equal(ChainStepKind.Started, kinds[0]);
        Assert.True(kinds.IndexOf(ChainStepKind.Dropped) < kinds.IndexOf(ChainStepKind.Executed));
        Assert.True(kinds.IndexOf(ChainStepKind.Executed) < kinds.IndexOf(ChainStepKind.Persisted));
        Assert.Contains(ChainStepKind.Connected, kinds);
        Assert.Equal(Severity.Critical, chain.Severity);
    }

    [Fact]
    public void Disabled_rules_and_weight_overrides_are_respected()
    {
        var scenario = DemoScenario.PersistentUpdater("setup.exe", DateTimeOffset.UnixEpoch);
        var settings = new EngineSettings
        {
            RuleOverrides = new Dictionary<string, RuleOverride>(StringComparer.OrdinalIgnoreCase)
            {
                ["BLZ-C001"] = new() { Enabled = false },
                ["BLZ-P001"] = new() { Weight = 3 },
            },
        };
        var result = TestEngine.Run(scenario.Events, settings);
        Assert.DoesNotContain(result.Findings, f => f.RuleId == "BLZ-C001");
        Assert.Equal(3, result.Findings.Single(f => f.RuleId == "BLZ-P001").Points);
    }

    [Fact]
    public void Watchlist_matches_are_flagged()
    {
        var scenario = DemoScenario.PersistentUpdater("setup.exe", DateTimeOffset.UnixEpoch);
        var settings = new EngineSettings { Watchlist = [new WatchlistEntry(WatchlistEntryType.Domain, "*.contoso-update.example", "test")] };
        var result = TestEngine.Run(scenario.Events, settings);
        Assert.Contains(result.Findings, f => f.RuleId == "BLZ-W001");
        Assert.Contains(result.Indicators, i => i.Status == Core.Indicators.IndicatorStatus.WatchlistMatch);
    }

    [Fact]
    public void Indicators_are_never_marked_risky_without_a_finding()
    {
        var ev = new Ev();
        var s = ev.Start(0, 100, 4, "tool.exe", @"C:\Users\u\Downloads\tool.exe", sample: true);
        ev.Dns(100, 100, s, "tool.exe", "updates.example");
        var result = TestEngine.Run(ev.Events, sampleName: "tool.exe");
        var domain = result.Indicators.Single(i => i.Type == Core.Indicators.IndicatorType.Domain);
        Assert.Equal(Core.Indicators.IndicatorStatus.Observed, domain.Status);
    }
}
