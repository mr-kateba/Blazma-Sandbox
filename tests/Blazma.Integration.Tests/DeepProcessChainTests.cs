using Blazma.Analysis.Engine;
using Blazma.Analysis.Rules;
using Blazma.Core.Analysis;
using Blazma.Core.Events;
using Blazma.Core.Samples;

namespace Blazma.Integration.Tests;

/// <summary>A sample that keeps relaunching itself builds a long chain of processes; the run must still save and reopen.</summary>
public class DeepProcessChainTests
{
    [Fact]
    public async Task A_long_relaunch_chain_is_saved_and_loaded()
    {
        await using var f = await Fixture.CreateAsync();
        const int chain = 400;
        var events = new List<AnalysisEvent>();
        for (var i = 0; i < chain; i++)
        {
            var details = new Dictionary<string, string> { [DetailKeys.ImagePath] = @"C:\Users\WDAGUtilityAccount\Desktop\setup.exe" };
            if (i == 0) details[DetailKeys.IsSample] = "true";
            events.Add(new AnalysisEvent
            {
                Sequence = i + 1,
                Timestamp = DateTimeOffset.UnixEpoch.AddMilliseconds(i * 10),
                RelativeTime = TimeSpan.FromMilliseconds(i * 10),
                Category = EventCategory.Process,
                Action = EventAction.ProcessStart,
                ProcessId = 1000 + i,
                ParentProcessId = i == 0 ? 4 : 1000 + i - 1,
                Process = new ProcessKey(1000 + i, TimeSpan.FromMilliseconds(i * 10).Ticks),
                ProcessName = "setup.exe",
                Details = details,
                Source = "test",
            });
        }
        var result = new AnalysisResult
        {
            AnalysisId = Guid.NewGuid(),
            Sample = new SampleInfo { FileName = "setup.exe", Size = 10, Sha256 = new string('a', 64), Sha1 = new string('0', 40), Kind = FileKind.Executable },
            Options = new AnalysisOptions(),
            ProviderId = "demo",
            StartedAt = DateTimeOffset.UnixEpoch,
        };
        new AnalysisEngine(new RuleEngine(RuleEngine.BuiltInRules())).Process(result, events, null, null, new EngineSettings());

        Assert.Equal(chain, result.AllProcesses.Count());
        Assert.All(result.AllProcesses, p => Assert.True(p.InAnalyzedTree));
        Assert.True(result.ProcessRoots.Count > 1); // continued as new roots past the depth limit

        await f.Repository.SaveAsync(result, CancellationToken.None);
        var loaded = await f.Repository.LoadAsync(result.AnalysisId, includeEvents: true, CancellationToken.None);
        Assert.NotNull(loaded);
        Assert.Equal(chain, loaded.AllProcesses.Count());
        Assert.Equal(result.AllProcesses.Select(p => p.Pid), loaded.AllProcesses.Select(p => p.Pid));
    }
}
