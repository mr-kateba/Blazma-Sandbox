using Blazma.Analysis.Engine;
using Blazma.Core.Events;

namespace Blazma.Analysis.Tests;

public class TimelineAndGraphTests
{
    [Fact]
    public void Timeline_orders_by_time_then_sequence()
    {
        var ev = new Ev();
        var s = ev.Start(0, 100, 4, "a.exe", sample: true);
        ev.File(300, 100, s, "a.exe", EventAction.FileCreate, @"C:\x\3");
        ev.File(100, 100, s, "a.exe", EventAction.FileCreate, @"C:\x\1");
        ev.File(100, 100, s, "a.exe", EventAction.FileCreate, @"C:\x\2");
        var shuffled = ev.Events.OrderBy(_ => Guid.NewGuid()).ToList();

        var ordered = AnalysisEngine.Order(shuffled);
        Assert.Equal(["a.exe", @"C:\x\1", @"C:\x\2", @"C:\x\3"], ordered.Select(e => e.Target ?? e.ProcessName));
    }

    [Fact]
    public void Reused_pids_resolve_to_the_right_process_instance()
    {
        var ev = new Ev();
        var s = ev.Start(0, 100, 4, "sample.exe", sample: true);
        var first = ev.Start(100, 500, 100, "first.exe");
        ev.Exit(200, 500, first, "first.exe");
        var second = ev.Start(300, 500, 100, "second.exe");
        ev.File(400, 500, null, "?", EventAction.FileCreate, @"C:\t\x.txt");

        var graph = ProcessGraph.Build(AnalysisEngine.Order(ev.Events));
        var fileEvent = ev.Events.Last();
        Assert.Equal("second.exe", graph.Resolve(fileEvent)!.Name);
        Assert.Equal(2, graph.Sample!.Children.Count);
    }

    [Fact]
    public void Background_noise_outside_the_tree_is_suppressed_but_persistence_is_kept()
    {
        var ev = new Ev();
        var s = ev.Start(0, 100, 4, "setup.exe", sample: true);
        ev.File(50, 900, null, "SearchIndexer.exe", EventAction.FileWrite, @"C:\ProgramData\Microsoft\Search\x.edb");
        ev.Reg(60, 901, null, "svchost.exe", @"HKLM\Software\Microsoft\Windows\CurrentVersion\Run", "Thing", @"C:\x.exe");
        ev.File(70, 100, s, "setup.exe", EventAction.FileCreate, @"C:\Users\u\AppData\Local\Temp\a.txt");

        var result = TestEngine.Run(ev.Events);
        Assert.Equal(1, result.SuppressedNoiseEvents);
        Assert.Contains(result.Events, e => e.ProcessName == "svchost.exe");
        Assert.DoesNotContain(result.Events, e => e.ProcessName == "SearchIndexer.exe");
        // Persistence by an unrelated system process is shown but not scored.
        Assert.Contains(result.Persistence, p => !p.ByAnalyzedTree);
        Assert.DoesNotContain(result.Findings, f => f.RuleId == "BLZ-P001");
    }

    [Fact]
    public void Noise_allowlist_hides_matching_processes()
    {
        var ev = new Ev();
        var s = ev.Start(0, 100, 4, "setup.exe", sample: true);
        var child = ev.Start(10, 101, 100, "helper.exe");
        ev.File(20, 101, child, "helper.exe", EventAction.FileCreate, @"C:\Users\u\AppData\Local\Temp\h.tmp");
        var result = TestEngine.Run(ev.Events, new EngineSettings { NoiseAllowlist = ["helper.exe"] });
        Assert.DoesNotContain(result.Events, e => e.ProcessName == "helper.exe");
    }

    [Fact]
    public void Without_an_identified_sample_nothing_is_filtered()
    {
        var ev = new Ev();
        ev.Start(0, 100, 4, "unknown.exe");
        ev.File(10, 100, null, "unknown.exe", EventAction.FileCreate, @"C:\a.txt");
        var result = TestEngine.Run(ev.Events);
        Assert.Equal(0, result.SuppressedNoiseEvents);
        Assert.Equal(2, result.Events.Count);
    }
}
