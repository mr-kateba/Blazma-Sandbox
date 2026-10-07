using Blazma.Analysis.Engine;
using Blazma.Analysis.Rules;
using Blazma.Core.Analysis;
using Blazma.Core.Events;
using Blazma.Core.Samples;
using Blazma.Core.Snapshots;

namespace Blazma.Analysis.Tests;

internal static class TestEngine
{
    public static SampleInfo Sample(string name = "setup.exe") => new()
    {
        FileName = name,
        Size = 1024,
        Sha256 = new string('a', 64),
        Sha1 = new string('b', 40),
        Kind = FileKind.Executable,
    };

    public static AnalysisResult Run(IReadOnlyList<AnalysisEvent> events, EngineSettings? settings = null, StaticReport? stat = null,
        SystemSnapshot? before = null, SystemSnapshot? after = null, string sampleName = "setup.exe", bool interrupted = false)
    {
        var result = new AnalysisResult
        {
            AnalysisId = Guid.NewGuid(),
            Sample = stat?.Sample ?? Sample(sampleName),
            Static = stat,
            Options = new AnalysisOptions(),
            ProviderId = "test",
            StartedAt = DateTimeOffset.UnixEpoch,
            MonitoringInterrupted = interrupted,
        };
        new AnalysisEngine(new RuleEngine(RuleEngine.BuiltInRules())).Process(result, events, before, after, settings ?? new EngineSettings());
        return result;
    }
}
