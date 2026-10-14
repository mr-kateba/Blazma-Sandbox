using System.Net;
using System.Text;
using Blazma.Core.Analysis;
using Blazma.Core.Settings;
using Blazma.Intelligence.Net;

namespace Blazma.Intelligence.Tests;

public class DnsOverHttpsResolverTests
{
    private static readonly IntegrationSettings On = new() { ResolveContactedDomains = true };

    private static HttpResponseMessage Json(string json) => new(HttpStatusCode.OK) { Content = new StringContent(json, Encoding.UTF8, "application/dns-json") };

    /// <summary>A resolver that answers A and AAAA queries from a table, and NXDOMAIN for anything else.</summary>
    private static FakeHandler Resolver(Dictionary<string, string> answers) => new((request, _) =>
    {
        var query = System.Web.HttpUtility.ParseQueryString(request.RequestUri!.Query);
        var key = $"{query["name"]}/{query["type"]}";
        return Task.FromResult(answers.TryGetValue(key, out var json) ? Json(json) : Json("""{"Status":3,"Answer":[]}"""));
    });

    [Fact]
    public async Task Is_off_by_default_and_sends_nothing()
    {
        var handler = FakeHandler.Status(HttpStatusCode.OK);
        var resolver = new DnsOverHttpsResolver(handler.Client(), () => new IntegrationSettings());

        Assert.False(new IntegrationSettings().ResolveContactedDomains);
        Assert.False(resolver.IsEnabled);
        Assert.Empty(await resolver.ResolveAsync(["c2.example.net"], CancellationToken.None));
        Assert.Empty(handler.Requests);
    }

    [Fact]
    public async Task Sends_only_the_name_to_the_public_resolver_and_reads_the_addresses()
    {
        var handler = Resolver(new()
        {
            ["cdn.contoso.com/A"] = """{"Status":0,"Answer":[{"name":"cdn.contoso.com.","type":5,"TTL":60,"data":"edge.contoso.net."},{"name":"edge.contoso.net.","type":1,"TTL":60,"data":"203.0.113.7"},{"name":"edge.contoso.net.","type":1,"TTL":60,"data":"not-an-ip"}]}""",
            ["cdn.contoso.com/AAAA"] = """{"Status":0,"Answer":[{"type":28,"data":"2001:db8::7"},{"type":28,"data":"203.0.113.9"}]}""",
        });
        var time = new FixedTime(new DateTimeOffset(2026, 10, 10, 9, 0, 0, TimeSpan.Zero));
        var resolver = new DnsOverHttpsResolver(handler.Client(), () => On, time: time);

        var result = Assert.Single(await resolver.ResolveAsync(["CDN.Contoso.com."], CancellationToken.None));

        Assert.Equal("cdn.contoso.com", result.Domain);
        Assert.Equal(HostResolutionStatus.Resolved, result.Status);
        Assert.Equal(["203.0.113.7", "2001:db8::7"], result.Addresses);
        Assert.Equal("cloudflare-dns.com", result.Resolver);
        Assert.Equal(time.Now, result.ResolvedAt);
        Assert.Equal(2, handler.Requests.Count);
        foreach (var request in handler.Requests)
        {
            Assert.Equal(HttpMethod.Get, request.Method);
            Assert.Equal("cloudflare-dns.com", request.RequestUri!.Host);
            Assert.Equal("https", request.RequestUri.Scheme);
            Assert.Matches(@"^\?name=cdn\.contoso\.com&type=(A|AAAA)$", request.RequestUri.Query);
            Assert.Contains("application/dns-json", request.Headers.Accept.ToString(), StringComparison.Ordinal);
            Assert.Null(request.Content);
            Assert.False(request.Headers.Contains("Authorization"));
        }
    }

    [Fact]
    public async Task Ip_addresses_local_and_reserved_names_are_never_sent()
    {
        var handler = Resolver([]);
        var resolver = new DnsOverHttpsResolver(handler.Client(), () => On);

        var results = await resolver.ResolveAsync(["203.0.113.5", "2001:db8::1", "printer.local", "localhost", "intranet", "x.test", "update.example", "bad name.com", "", "known.org"], CancellationToken.None);

        Assert.Equal(["known.org"], results.Select(r => r.Domain));
        Assert.Equal(HostResolutionStatus.NotFound, results[0].Status);
        Assert.All(handler.Requests, r => Assert.Contains("name=known.org", r.RequestUri!.Query, StringComparison.Ordinal));
    }

    [Fact]
    public async Task The_number_of_domains_is_capped()
    {
        var handler = Resolver([]);
        var resolver = new DnsOverHttpsResolver(handler.Client(), () => On, new DnsOverHttpsOptions { MaxDomains = 3 });

        var results = await resolver.ResolveAsync(Enumerable.Range(0, 10).Select(i => $"host{i}.example.com"), CancellationToken.None);

        Assert.Equal(3, results.Count);
        Assert.Equal(6, handler.Requests.Count);
    }

    [Fact]
    public async Task Failures_become_results_not_exceptions()
    {
        var resolver = new DnsOverHttpsResolver(FakeHandler.Status(HttpStatusCode.ServiceUnavailable).Client(), () => On);
        var failed = Assert.Single(await resolver.ResolveAsync(["down.example.com"], CancellationToken.None));
        Assert.Equal(HostResolutionStatus.Failed, failed.Status);
        Assert.Contains("503", failed.Error, StringComparison.Ordinal);

        var garbage = new DnsOverHttpsResolver(new FakeHandler((_, _) => Task.FromResult(Json("<html>"))).Client(), () => On);
        Assert.Equal(HostResolutionStatus.Failed, Assert.Single(await garbage.ResolveAsync(["x.example.com"], CancellationToken.None)).Status);

        var servfail = new DnsOverHttpsResolver(new FakeHandler((_, _) => Task.FromResult(Json("""{"Status":2}"""))).Client(), () => On);
        Assert.Contains("DNS error 2", Assert.Single(await servfail.ResolveAsync(["x.example.com"], CancellationToken.None)).Error, StringComparison.Ordinal);

        var redirect = new DnsOverHttpsResolver(FakeHandler.Status(HttpStatusCode.Found).Client(), () => On);
        Assert.Contains("redirect", Assert.Single(await redirect.ResolveAsync(["x.example.com"], CancellationToken.None)).Error, StringComparison.Ordinal);
    }

    [Fact]
    public async Task Oversized_answers_and_slow_resolvers_are_cut_off()
    {
        var endless = FakeHandler.Endless();
        var big = new DnsOverHttpsResolver(endless.Client(), () => On, new DnsOverHttpsOptions { MaxResponseBytes = 4096 });
        var tooLarge = Assert.Single(await big.ResolveAsync(["x.example.com"], CancellationToken.None));
        Assert.Equal(HostResolutionStatus.Failed, tooLarge.Status);
        Assert.Contains("larger", tooLarge.Error, StringComparison.Ordinal);

        var slow = new DnsOverHttpsResolver(FakeHandler.Hang().Client(), () => On, new DnsOverHttpsOptions { Timeout = TimeSpan.FromMilliseconds(50), TotalTimeout = TimeSpan.FromMilliseconds(400) });
        var results = await slow.ResolveAsync(["a.example.com", "b.example.com", "c.example.com", "d.example.com", "e.example.com"], CancellationToken.None);
        Assert.Equal(5, results.Count);
        Assert.All(results, r => Assert.Equal(HostResolutionStatus.Failed, r.Status));
    }

    [Fact]
    public async Task The_callers_cancellation_is_not_swallowed()
    {
        using var cts = new CancellationTokenSource();
        var resolver = new DnsOverHttpsResolver(FakeHandler.Hang().Client(), () => On);
        var task = resolver.ResolveAsync(["a.example.com"], cts.Token);
        cts.Cancel();
        await Assert.ThrowsAnyAsync<OperationCanceledException>(() => task);
    }

    private sealed class FixedTime(DateTimeOffset now) : TimeProvider
    {
        public DateTimeOffset Now => now;
        public override DateTimeOffset GetUtcNow() => now;
    }
}
