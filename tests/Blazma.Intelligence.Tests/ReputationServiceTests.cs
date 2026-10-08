using Blazma.Core.Abstractions;
using Blazma.Core.Analysis;
using Blazma.Core.Text;
using Blazma.Intelligence.Reputation;

namespace Blazma.Intelligence.Tests;

public class ReputationServiceTests
{
    private const string Hash = "275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f";

    private sealed class StubProvider(string id, Func<CancellationToken, Task<ReputationResult>> lookup, bool remote = true, bool configured = true) : IReputationProvider
    {
        public int Calls;
        public string Id => id;
        public LocalizedText DisplayName => LocalizedText.Same(id);
        public bool IsRemote => remote;
        public bool IsConfigured => configured;

        public Task<ReputationResult> LookupAsync(string sha256, CancellationToken cancellationToken)
        {
            Interlocked.Increment(ref Calls);
            return lookup(cancellationToken);
        }
    }

    private static ReputationResult Ok(string id, ReputationVerdict verdict = ReputationVerdict.NotFound) =>
        new() { ProviderId = id, ProviderName = id, Verdict = verdict };

    [Fact]
    public async Task Runs_concurrently_and_keeps_provider_order()
    {
        var gate = new TaskCompletionSource();
        var started = 0;
        async Task<ReputationResult> Wait(string id, int delayMs)
        {
            if (Interlocked.Increment(ref started) == 3) gate.SetResult();
            await gate.Task.WaitAsync(TimeSpan.FromSeconds(10));
            await Task.Delay(delayMs);
            return Ok(id);
        }

        var service = new ReputationService(
        [
            new StubProvider("slow", _ => Wait("slow", 150)),
            new StubProvider("medium", _ => Wait("medium", 50)),
            new StubProvider("fast", _ => Wait("fast", 0)),
        ]);
        var results = await service.LookupAsync(Hash, CancellationToken.None);
        Assert.Equal(["slow", "medium", "fast"], results.Select(r => r.ProviderId));
    }

    [Fact]
    public async Task One_failure_never_breaks_the_others()
    {
        var service = new ReputationService(
        [
            new StubProvider("throws", _ => throw new InvalidOperationException("boom")),
            new StubProvider("faults", _ => Task.FromException<ReputationResult>(new HttpRequestException("x"))),
            new StubProvider("good", _ => Task.FromResult(Ok("good", ReputationVerdict.Malicious))),
        ]);
        var results = await service.LookupAsync(Hash, CancellationToken.None);
        Assert.Equal(3, results.Count);
        Assert.NotNull(results[0].Error);
        Assert.Equal("throws", results[0].ProviderId);
        Assert.DoesNotContain("boom", results[0].Error, StringComparison.Ordinal);
        Assert.NotNull(results[1].Error);
        Assert.Equal(ReputationVerdict.Malicious, results[2].Verdict);
    }

    [Fact]
    public async Task Skips_unconfigured_and_optionally_remote_providers()
    {
        var local = new StubProvider("local", _ => Task.FromResult(Ok("local")), remote: false);
        var remote = new StubProvider("remote", _ => Task.FromResult(Ok("remote")));
        var off = new StubProvider("off", _ => Task.FromResult(Ok("off")), configured: false);
        var service = new ReputationService([local, remote, off]);

        Assert.Equal(["local", "remote"], (await service.LookupAsync(Hash, CancellationToken.None)).Select(r => r.ProviderId));
        Assert.Equal(["local"], (await service.LookupAsync(Hash, includeRemote: false, CancellationToken.None)).Select(r => r.ProviderId));
        Assert.Equal(0, off.Calls);
        Assert.True(service.HasRemoteProviders);
    }

    [Fact]
    public async Task Cancellation_is_shared_and_surfaces_to_the_caller()
    {
        var tokens = new List<CancellationToken>();
        async Task<ReputationResult> Hang(CancellationToken ct)
        {
            lock (tokens) tokens.Add(ct);
            await Task.Delay(Timeout.Infinite, ct);
            return Ok("never");
        }

        using var cts = new CancellationTokenSource(TimeSpan.FromMilliseconds(100));
        var service = new ReputationService([new StubProvider("a", Hang), new StubProvider("b", Hang)]);
        await Assert.ThrowsAnyAsync<OperationCanceledException>(() => service.LookupAsync(Hash, cts.Token));
        Assert.All(tokens, t => Assert.True(t.IsCancellationRequested));
    }
}
