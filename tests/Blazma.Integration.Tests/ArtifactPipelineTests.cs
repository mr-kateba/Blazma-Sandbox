using Blazma.Analysis.Pipeline;
using Blazma.Analysis.Static;
using Blazma.Core.Abstractions;
using Blazma.Core.Analysis;
using Blazma.Core.Findings;
using Blazma.Core.Samples;
using Blazma.Sandbox.Providers.Demo;

namespace Blazma.Integration.Tests;

/// <summary>In tests, artifacts are inspected in-process (the app does it in a separate process).</summary>
internal sealed class InProcessInspector : IArtifactInspector
{
    public List<string> Inspected { get; } = [];

    public async Task<StaticReport?> InspectAsync(string path, string displayName, CancellationToken cancellationToken)
    {
        Inspected.Add(displayName);
        return await new StaticAnalyzer().AnalyzeAsync(path, cancellationToken);
    }
}

public class ArtifactPipelineTests
{
    private static async Task<(Fixture F, AnalysisResult Result, InProcessInspector Inspector, string Folder)> RunAsync(Guid? id = null)
    {
        var f = await Fixture.CreateAsync();
        var inspector = new InProcessInspector();
        var folder = Path.Combine(f.Dir.FullName, "artifacts", "pending");
        var request = f.Request() with
        {
            ArtifactsFolder = folder,
            Inspector = inspector,
            Options = new AnalysisOptions { Duration = TimeSpan.FromMinutes(2), Network = NetworkPolicy.Simulated },
            Reputation = [new ReputationResult { ProviderId = "test", ProviderName = "Test service", Verdict = ReputationVerdict.Malicious, Detections = 40, Engines = 70, Family = "ContosoLoader" }],
        };
        var result = await f.Runner.RunAsync(request, new DemoSandboxProvider(TimeProvider.System, speed: 0), null, null, CancellationToken.None);
        return (f, result, inspector, folder);
    }

    [Fact]
    public async Task Demo_artifacts_flow_through_inspection_rules_and_storage()
    {
        var (f, result, inspector, folder) = await RunAsync();
        await using var _ = f;

        Assert.Equal(3, result.Screenshots.Count);
        Assert.All(result.Screenshots, s => Assert.True(File.Exists(Path.Combine(folder, s.FileName))));
        var dropped = Assert.Single(result.DroppedFiles);
        Assert.EndsWith(@"ContosoUpdate\updater.exe", dropped.OriginalPath, StringComparison.Ordinal);
        Assert.NotNull(dropped.Static);
        var memory = Assert.Single(result.MemoryArtifacts);
        Assert.True(memory.HasPeHeader);
        Assert.Equal(2, inspector.Inspected.Count);

        var rules = result.Findings.Select(x => x.RuleId).ToHashSet();
        Assert.Contains("BLZ-V001", rules);  // program image in memory
        Assert.Contains("BLZ-N005", rules);  // simulated contact
        Assert.Contains("BLZ-N006", rules);  // data sent
        Assert.Contains("BLZ-R101", rules);  // reputation
        Assert.Equal(FindingCategory.Memory, result.Findings.Single(x => x.RuleId == "BLZ-V001").Category);

        var loaded = await f.Repository.LoadAsync(result.AnalysisId, includeEvents: false, CancellationToken.None);
        Assert.NotNull(loaded);
        Assert.Equal(result.Screenshots, loaded!.Screenshots);
        Assert.Equal(dropped.Sha256, Assert.Single(loaded.DroppedFiles).Sha256);
        Assert.Equal(memory.BaseAddress, Assert.Single(loaded.MemoryArtifacts).BaseAddress);
        Assert.Equal("ContosoLoader", Assert.Single(loaded.Reputation).Family);
    }

    [Fact]
    public async Task Deleting_an_analysis_removes_its_artifacts()
    {
        var (f, result, _, folder) = await RunAsync();
        await using var _ = f;
        var stored = Path.Combine(f.Dir.FullName, "artifacts", result.AnalysisId.ToString("N"));
        Directory.Move(folder, stored);
        await f.Repository.DeleteAsync(result.AnalysisId, CancellationToken.None);
        Assert.False(Directory.Exists(stored));
    }

    [Fact]
    public async Task Without_an_artifacts_folder_nothing_is_written()
    {
        await using var f = await Fixture.CreateAsync();
        var result = await f.RunDemoAsync();
        Assert.Empty(result.Screenshots);
        Assert.Empty(result.DroppedFiles);
        Assert.Empty(result.MemoryArtifacts);
    }

    [Fact]
    public async Task Interactive_controls_reach_the_session_only_while_analyzing()
    {
        await using var f = await Fixture.CreateAsync();
        var control = new AnalysisControl();
        Assert.False(control.IsAvailable);
        await control.ExtendAsync(TimeSpan.FromMinutes(1)); // no run: ignored
        var seen = false;
        var progress = new SyncProgress<AnalysisProgress>();
        var request = f.Request() with { Control = control };
        await f.Runner.RunAsync(request, new DemoSandboxProvider(TimeProvider.System, speed: 0), progress, null, CancellationToken.None);
        seen = progress.Items.Any(p => p.Stage == AnalysisStage.Analyzing && p.CanControl);
        Assert.True(seen);
        Assert.False(control.IsAvailable);
    }
}
