using Blazma.Core.Abstractions;
using Blazma.Core.Analysis;
using Blazma.Core.Text;
using Blazma.Sandbox.Providers.Demo;

namespace Blazma.Integration.Tests;

public class NetworkDestinationPipelineTests
{
    /// <summary>Records the names it is asked about and answers from a table, like the DNS-over-HTTPS resolver would.</summary>
    private sealed class RecordingResolver(bool enabled) : IHostDomainResolver
    {
        public List<string> Asked { get; } = [];
        public bool IsEnabled => enabled;

        public Task<IReadOnlyList<HostResolution>> ResolveAsync(IEnumerable<string> domains, CancellationToken cancellationToken)
        {
            Asked.AddRange(domains);
            IReadOnlyList<HostResolution> results = Asked.Select(d => new HostResolution { Domain = d, Status = HostResolutionStatus.Resolved, Addresses = ["198.51.100.99"], Resolver = "test" }).ToList();
            return Task.FromResult(results);
        }
    }

    /// <summary>The demo's events, presented as a real environment (the lookup never runs for demo data).</summary>
    private sealed class NotDemo(ISandboxProvider inner) : ISandboxProvider
    {
        public string Id => "test-real";
        public LocalizedText DisplayName => inner.DisplayName;
        public bool IsDemo => false;
        public Task<ProviderAvailability> CheckAvailabilityAsync(CancellationToken cancellationToken) => inner.CheckAvailabilityAsync(cancellationToken);
        public Task<ISandboxSession> CreateSessionAsync(SandboxSessionRequest request, CancellationToken cancellationToken) => inner.CreateSessionAsync(request, cancellationToken);
    }

    [Fact]
    public async Task Destinations_and_host_lookups_are_stored_with_the_report()
    {
        await using var f = await Fixture.CreateAsync();
        var resolver = new RecordingResolver(enabled: true);
        var result = await f.Runner.RunAsync(f.Request() with { HostResolver = resolver }, new NotDemo(new DemoSandboxProvider(TimeProvider.System, speed: 0)), null, null, CancellationToken.None);

        Assert.Contains(result.NetworkDestinations, d => d.Address == "192.0.2.77" && d.Status == DestinationStatus.Failed);
        // Only names are sent, and only names the programs contacted or looked up.
        Assert.NotEmpty(resolver.Asked);
        Assert.All(resolver.Asked, n => Assert.False(System.Net.IPAddress.TryParse(n, out _)));
        Assert.Contains("api.contoso-update.example", resolver.Asked);
        Assert.DoesNotContain("settings-win.data.microsoft.com", resolver.Asked); // background noise

        var loaded = await f.Repository.LoadAsync(result.AnalysisId, includeEvents: false, CancellationToken.None);
        Assert.NotNull(loaded);
        Assert.Equal(result.NetworkDestinations, loaded!.NetworkDestinations, new DestinationComparer());
        Assert.Equal(resolver.Asked.Count, loaded.HostResolutions.Count);
        Assert.Equal(["198.51.100.99"], loaded.HostResolutions[0].Addresses);
    }

    [Fact]
    public async Task Nothing_is_looked_up_for_demo_data_or_when_the_setting_is_off()
    {
        await using var f = await Fixture.CreateAsync();
        var on = new RecordingResolver(enabled: true);
        var demo = await f.Runner.RunAsync(f.Request() with { HostResolver = on }, new DemoSandboxProvider(TimeProvider.System, speed: 0), null, null, CancellationToken.None);
        Assert.Empty(on.Asked);
        Assert.Empty(demo.HostResolutions);
        Assert.NotEmpty(demo.NetworkDestinations);

        var off = new RecordingResolver(enabled: false);
        var real = await f.Runner.RunAsync(f.Request() with { HostResolver = off }, new NotDemo(new DemoSandboxProvider(TimeProvider.System, speed: 0)), null, null, CancellationToken.None);
        Assert.Empty(off.Asked);
        Assert.Empty(real.HostResolutions);
    }

    private sealed class DestinationComparer : IEqualityComparer<NetworkDestination>
    {
        public bool Equals(NetworkDestination? x, NetworkDestination? y) =>
            x is not null && y is not null && x.Endpoint == y.Endpoint && x.Protocol == y.Protocol && x.Status == y.Status && x.Count == y.Count
            && x.Domain == y.Domain && x.FirstSeen == y.FirstSeen && x.Processes.SequenceEqual(y.Processes) && x.EventSequences.SequenceEqual(y.EventSequences);

        public int GetHashCode(NetworkDestination obj) => obj.Endpoint.GetHashCode(StringComparison.Ordinal);
    }
}
