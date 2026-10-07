using Blazma.Analysis.Pipeline;
using Blazma.Core.Abstractions;
using Blazma.Core.Analysis;
using Blazma.Core.Findings;
using Blazma.Core.Samples;
using Blazma.Core.Text;

namespace Blazma.Integration.Tests;

public class PipelineTests
{
    [Fact]
    public async Task Demo_analysis_runs_through_every_stage_in_order_and_is_stored()
    {
        await using var f = await Fixture.CreateAsync();
        var progress = new SyncProgress<AnalysisProgress>();
        var result = await f.RunDemoAsync(progress: progress);

        var stages = progress.Items.Select(p => p.Stage).Distinct().ToList();
        Assert.Equal(AnalysisStateMachine.Path, stages);
        Assert.Equal(AnalysisStage.Completed, result.FinalStage);
        Assert.True(result.IsDemo);
        Assert.True(result.SuppressedNoiseEvents > 0);
        Assert.Equal(Verdict.CriticalBehavior, result.Risk.Verdict);
        Assert.NotNull(result.SystemChanges);

        var loaded = await f.Repository.LoadAsync(result.AnalysisId, includeEvents: true, CancellationToken.None);
        Assert.NotNull(loaded);
        Assert.Equal(result.Risk.Score, loaded!.Risk.Score);
        Assert.Equal(result.Findings.Count, loaded.Findings.Count);
        Assert.Equal(result.Events.Count, loaded.Events.Count);
        Assert.Equal(result.AllProcesses.Count(), loaded.AllProcesses.Count());
        Assert.True(loaded.IsDemo);
        Assert.Equal(result.Chains.Count, loaded.Chains.Count);
    }

    [Fact]
    public async Task History_search_and_stats_see_the_analysis()
    {
        await using var f = await Fixture.CreateAsync();
        var high = await f.RunDemoAsync("setup.exe");
        var low = await f.RunDemoAsync("viewer-tool.exe");

        var list = await f.Repository.ListAsync(10, 0, CancellationToken.None);
        Assert.Equal(2, list.Count);
        Assert.Equal(low.AnalysisId, list[0].Id);

        var hits = await f.Repository.SearchAsync("powershell", 50, CancellationToken.None);
        Assert.Contains(hits, h => h.AnalysisId == high.AnalysisId && h.Source == SearchSource.Process);
        var portHits = await f.Repository.SearchAsync("198.51.100.7", 50, CancellationToken.None);
        Assert.Contains(portHits, h => h.Source is SearchSource.Network or SearchSource.Indicator);

        var stats = await f.Repository.GetStatsAsync(DateTimeOffset.Now, CancellationToken.None);
        Assert.Equal(2, stats.AnalysesToday);
        Assert.Equal(1, stats.HighRisk);
        Assert.Equal(1, stats.LowRisk);
    }

    [Fact]
    public async Task Paged_event_queries_filter_by_category_and_text()
    {
        await using var f = await Fixture.CreateAsync();
        var r = await f.RunDemoAsync();
        var registry = await f.Repository.QueryEventsAsync(new EventQuery { AnalysisId = r.AnalysisId, Categories = [Core.Events.EventCategory.Registry] }, CancellationToken.None);
        Assert.NotEmpty(registry);
        Assert.All(registry, e => Assert.Equal(Core.Events.EventCategory.Registry, e.Category));

        var page = await f.Repository.QueryEventsAsync(new EventQuery { AnalysisId = r.AnalysisId, Offset = 2, Limit = 3 }, CancellationToken.None);
        Assert.Equal(3, page.Count);
        Assert.Equal(r.Events.Skip(2).Take(3).Select(e => e.Sequence), page.Select(e => e.Sequence));

        var text = await f.Repository.CountEventsAsync(new EventQuery { AnalysisId = r.AnalysisId, Text = "updater.exe" }, CancellationToken.None);
        Assert.True(text > 0);
    }

    [Fact]
    public async Task Unsupported_file_types_fail_with_a_clear_reason()
    {
        await using var f = await Fixture.CreateAsync();
        var ex = await Assert.ThrowsAsync<AnalysisFailedException>(() =>
            f.Runner.RunAsync(f.Request("notes.txt", FileKind.Unknown), new Sandbox.Providers.Demo.DemoSandboxProvider(TimeProvider.System, 0), null, null, CancellationToken.None));
        Assert.Contains("cannot run this type of file", ex.Reason, StringComparison.Ordinal);
        var stored = Assert.Single(await f.Repository.ListAsync(10, 0, CancellationToken.None));
        Assert.Equal(AnalysisStage.Failed, stored.Stage);
    }

    [Fact]
    public async Task Provider_failure_is_recorded_and_the_environment_is_shut_down()
    {
        await using var f = await Fixture.CreateAsync();
        var provider = new FailingProvider();
        await Assert.ThrowsAsync<AnalysisFailedException>(() => f.Runner.RunAsync(f.Request(), provider, null, null, CancellationToken.None));
        Assert.True(provider.Session.ShutdownCalls >= 1);
        Assert.Equal(AnalysisStage.Failed, (await f.Repository.ListAsync(1, 0, CancellationToken.None))[0].Stage);
    }

    [Fact]
    public async Task Cancellation_is_recorded_as_cancelled()
    {
        await using var f = await Fixture.CreateAsync();
        using var cts = new CancellationTokenSource();
        var progress = new CancellingProgress(cts, AnalysisStage.Analyzing);
        await Assert.ThrowsAnyAsync<OperationCanceledException>(() =>
            f.Runner.RunAsync(f.Request(), new Sandbox.Providers.Demo.DemoSandboxProvider(TimeProvider.System, speed: 50), progress, null, cts.Token));
        Assert.Equal(AnalysisStage.Cancelled, (await f.Repository.ListAsync(1, 0, CancellationToken.None))[0].Stage);
    }

    [Fact]
    public async Task Event_cap_is_enforced_and_noted()
    {
        await using var f = await Fixture.CreateAsync();
        var request = f.Request() with { MaxEvents = 10 };
        var r = await f.Runner.RunAsync(request, new Sandbox.Providers.Demo.DemoSandboxProvider(TimeProvider.System, 0), null, null, CancellationToken.None);
        Assert.Contains(r.Events, e => e.Action == Core.Events.EventAction.AnalysisNote);
    }

    [Fact]
    public async Task Handles_100k_events_with_paged_reads()
    {
        await using var f = await Fixture.CreateAsync();
        var sw = System.Diagnostics.Stopwatch.StartNew();
        var r = await f.RunDemoAsync("stress.exe");
        var total = await f.Repository.CountEventsAsync(new EventQuery { AnalysisId = r.AnalysisId }, CancellationToken.None);
        Assert.True(total >= 100_000, $"{total} events");

        var pageWatch = System.Diagnostics.Stopwatch.StartNew();
        var page = await f.Repository.QueryEventsAsync(new EventQuery { AnalysisId = r.AnalysisId, Offset = 90_000, Limit = 200 }, CancellationToken.None);
        Assert.Equal(200, page.Count);
        Assert.True(pageWatch.Elapsed < TimeSpan.FromSeconds(2), $"page took {pageWatch.Elapsed}");
        Assert.True(sw.Elapsed < TimeSpan.FromMinutes(2), $"run took {sw.Elapsed}");
    }

    private sealed class CancellingProgress(CancellationTokenSource cts, AnalysisStage at) : IProgress<AnalysisProgress>
    {
        public void Report(AnalysisProgress value) { if (value.Stage == at) cts.Cancel(); }
    }

    private sealed class FailingProvider : ISandboxProvider
    {
        public FailingSession Session { get; } = new();
        public string Id => "failing";
        public LocalizedText DisplayName => LocalizedText.Same("failing");
        public bool IsDemo => false;
        public Task<ProviderAvailability> CheckAvailabilityAsync(CancellationToken ct) => Task.FromResult(new ProviderAvailability(ProviderReadiness.Ready, []));
        public Task<ISandboxSession> CreateSessionAsync(SandboxSessionRequest request, CancellationToken ct) => Task.FromResult<ISandboxSession>(Session);
    }

    private sealed class FailingSession : ISandboxSession
    {
        public int ShutdownCalls { get; private set; }
        public Task CreateEnvironmentAsync(CancellationToken ct) => Task.CompletedTask;
        public Task BootAsync(CancellationToken ct) => throw new InvalidOperationException("Virtualization component unavailable.");
        public Task DeployAgentAsync(CancellationToken ct) => Task.CompletedTask;
        public Task TransferSampleAsync(CancellationToken ct) => Task.CompletedTask;
        public async IAsyncEnumerable<SessionSignal> ExecuteAsync([System.Runtime.CompilerServices.EnumeratorCancellation] CancellationToken ct) { await Task.Yield(); yield break; }
        public Task<CollectedArtifacts> CollectAsync(CancellationToken ct) => Task.FromResult(new CollectedArtifacts([], null, null, true));
        public Task ShutdownAsync(CancellationToken ct) { ShutdownCalls++; return Task.CompletedTask; }
        public ValueTask DisposeAsync() => ValueTask.CompletedTask;
    }
}
