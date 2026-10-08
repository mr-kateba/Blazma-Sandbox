using System.Net;
using Blazma.Core.Abstractions;
using Blazma.Core.Analysis;
using Blazma.Core.Settings;
using Blazma.Intelligence.Reputation;
using Blazma.Storage.Secrets;

namespace Blazma.Intelligence.Tests;

public class ReputationProviderTests
{
    private const string Hash = "275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f";
    private const string Key = "SECRET-API-KEY-0123456789abcdef";
    private static readonly ISecretProtector Secrets = new PortableSecretProtector();

    private static IntegrationSettings Settings(bool enabled = true, string? key = Key) => new()
    {
        VirusTotalEnabled = enabled,
        VirusTotalApiKey = key is null ? null : Secrets.Protect(key),
        MalwareBazaarEnabled = enabled,
        MalwareBazaarApiKey = key is null ? null : Secrets.Protect(key),
    };

    private static VirusTotalReputationProvider Vt(FakeHandler handler, IntegrationSettings? settings = null, TimeSpan? timeout = null) =>
        new(handler.Client(), settings ?? Settings(), Secrets, new ReputationProviderOptions { Timeout = timeout ?? TimeSpan.FromSeconds(20) });

    private static MalwareBazaarReputationProvider Mb(FakeHandler handler, IntegrationSettings? settings = null, TimeSpan? timeout = null) =>
        new(handler.Client(), settings ?? Settings(), Secrets, new ReputationProviderOptions { Timeout = timeout ?? TimeSpan.FromSeconds(20) });

    private static string VtReport(int malicious, int suspicious, int undetected = 60, int harmless = 0) => $$"""
        {"data":{"id":"{{Hash}}","type":"file","attributes":{
          "last_analysis_stats":{"malicious":{{malicious}},"suspicious":{{suspicious}},"undetected":{{undetected}},"harmless":{{harmless}},"timeout":2,"confirmed-timeout":0,"failure":1,"type-unsupported":4},
          "popular_threat_classification":{"suggested_threat_label":"trojan.agenttesla/msil","popular_threat_category":[{"value":"trojan","count":20}]},
          "tags":["peexe","assembly","\u202Eevil"],
          "first_submission_date":1592134853 } } }
        """;

    // ---------------- VirusTotal ----------------

    [Fact]
    public async Task VirusTotal_reads_a_report_and_sends_only_the_hash_and_key()
    {
        var handler = FakeHandler.Json(HttpStatusCode.OK, VtReport(40, 2));
        var r = await Vt(handler).LookupAsync(Hash.ToUpperInvariant(), CancellationToken.None);

        Assert.Null(r.Error);
        Assert.Equal(ReputationVerdict.Malicious, r.Verdict);
        Assert.Equal("virustotal", r.ProviderId);
        Assert.Equal(42, r.Detections);
        Assert.Equal(102, r.Engines);
        Assert.Equal("trojan.agenttesla/msil", r.Family);
        Assert.Equal(["peexe", "assembly", "evil"], r.Tags);
        Assert.Equal(DateTimeOffset.FromUnixTimeSeconds(1592134853), r.FirstSeen);
        Assert.Equal($"https://www.virustotal.com/gui/file/{Hash}", r.Link);

        var request = Assert.Single(handler.Requests);
        Assert.Equal(HttpMethod.Get, request.Method);
        Assert.Equal($"https://www.virustotal.com/api/v3/files/{Hash}", request.RequestUri!.ToString());
        Assert.Null(handler.Bodies[0]);
        Assert.Equal(Key, Assert.Single(request.Headers.GetValues("x-apikey")));
        Assert.DoesNotContain(request.Headers, h => h.Key is not ("x-apikey" or "Accept"));
    }

    [Theory]
    [InlineData(5, 0, ReputationVerdict.Malicious)]
    [InlineData(4, 0, ReputationVerdict.Suspicious)]
    [InlineData(1, 0, ReputationVerdict.Suspicious)]
    [InlineData(0, 3, ReputationVerdict.Suspicious)]
    [InlineData(0, 2, ReputationVerdict.Clean)]
    [InlineData(0, 0, ReputationVerdict.Clean)]
    public async Task VirusTotal_verdict_thresholds(int malicious, int suspicious, ReputationVerdict expected)
    {
        var r = await Vt(FakeHandler.Json(HttpStatusCode.OK, VtReport(malicious, suspicious))).LookupAsync(Hash, CancellationToken.None);
        Assert.Equal(expected, r.Verdict);
    }

    [Fact]
    public async Task VirusTotal_is_not_clean_when_no_engine_analyzed_the_file()
    {
        var r = await Vt(FakeHandler.Json(HttpStatusCode.OK, VtReport(0, 0, undetected: 0, harmless: 0))).LookupAsync(Hash, CancellationToken.None);
        Assert.Equal(ReputationVerdict.Unknown, r.Verdict);
        Assert.Equal(0, r.Engines);
    }

    [Fact]
    public async Task VirusTotal_not_found()
    {
        var r = await Vt(FakeHandler.Json(HttpStatusCode.NotFound, """{"error":{"code":"NotFoundError","message":"x"}}""")).LookupAsync(Hash, CancellationToken.None);
        Assert.Equal(ReputationVerdict.NotFound, r.Verdict);
        Assert.Null(r.Error);
    }

    [Theory]
    [InlineData(HttpStatusCode.Unauthorized, "API key rejected")]
    [InlineData(HttpStatusCode.Forbidden, "API key rejected")]
    [InlineData(HttpStatusCode.TooManyRequests, "rate limit / quota reached")]
    [InlineData(HttpStatusCode.ServiceUnavailable, "unavailable")]
    [InlineData(HttpStatusCode.Found, "redirect")]
    [InlineData(HttpStatusCode.BadRequest, "HTTP 400")]
    public async Task VirusTotal_error_statuses(HttpStatusCode status, string expected)
    {
        var r = await Vt(FakeHandler.Status(status)).LookupAsync(Hash, CancellationToken.None);
        Assert.Equal(ReputationVerdict.Unknown, r.Verdict);
        Assert.Contains(expected, r.Error, StringComparison.Ordinal);
        Assert.DoesNotContain(Key, r.Error, StringComparison.Ordinal);
    }

    [Theory]
    [InlineData("not json at all")]
    [InlineData("""{"data":[1,2,3]}""")]
    [InlineData("""{"data":{"attributes":"nope"}}""")]
    [InlineData("[]")]
    [InlineData("""{"data":{"attributes":{"last_analysis_stats":{"malicious":"many"}""")]
    public async Task VirusTotal_malformed_responses_become_errors(string body)
    {
        var r = await Vt(FakeHandler.Json(HttpStatusCode.OK, body)).LookupAsync(Hash, CancellationToken.None);
        Assert.NotNull(r.Error);
        Assert.Equal(ReputationVerdict.Unknown, r.Verdict);
    }

    [Fact]
    public async Task VirusTotal_hostile_values_are_ignored_or_cleaned()
    {
        var body = """
            {"data":{"attributes":{
              "last_analysis_stats":{"malicious":-5,"suspicious":99999999999999,"undetected":"x"},
              "popular_threat_classification":{"suggested_threat_label":42},
              "tags":[1,{"a":1},"ok","ok"],
              "first_submission_date":99999999999999999}}}
            """;
        var r = await Vt(FakeHandler.Json(HttpStatusCode.OK, body)).LookupAsync(Hash, CancellationToken.None);
        Assert.Null(r.Error);
        Assert.Equal(ReputationVerdict.Suspicious, r.Verdict);
        Assert.Null(r.Family);
        Assert.Null(r.FirstSeen);
        Assert.Equal(["ok"], r.Tags);
    }

    [Fact]
    public async Task Deeply_nested_json_is_refused()
    {
        var body = new string('[', 5000) + new string(']', 5000);
        var r = await Vt(FakeHandler.Json(HttpStatusCode.OK, body)).LookupAsync(Hash, CancellationToken.None);
        Assert.NotNull(r.Error);
    }

    [Fact]
    public async Task Oversized_response_with_length_is_refused()
    {
        var handler = FakeHandler.Json(HttpStatusCode.OK, "{\"pad\":\"" + new string('a', 3 * 1024 * 1024) + "\"}");
        var r = await Vt(handler).LookupAsync(Hash, CancellationToken.None);
        Assert.Contains("larger than", r.Error, StringComparison.Ordinal);
    }

    [Fact]
    public async Task Oversized_response_without_length_is_cut_while_reading()
    {
        var r = await Mb(FakeHandler.Endless()).LookupAsync(Hash, CancellationToken.None);
        Assert.Contains("larger than", r.Error, StringComparison.Ordinal);
    }

    [Fact]
    public async Task Timeout_becomes_an_error()
    {
        var r = await Vt(FakeHandler.Hang(), timeout: TimeSpan.FromMilliseconds(100)).LookupAsync(Hash, CancellationToken.None);
        Assert.Contains("did not answer", r.Error, StringComparison.Ordinal);
    }

    [Fact]
    public async Task Caller_cancellation_throws()
    {
        using var cts = new CancellationTokenSource(TimeSpan.FromMilliseconds(100));
        await Assert.ThrowsAnyAsync<OperationCanceledException>(() => Vt(FakeHandler.Hang()).LookupAsync(Hash, cts.Token));
        await Assert.ThrowsAnyAsync<OperationCanceledException>(() => Mb(FakeHandler.Hang()).LookupAsync(Hash, new CancellationToken(true)));
    }

    [Fact]
    public async Task Network_failure_becomes_an_error_without_details()
    {
        var handler = new FakeHandler((_, _) => throw new HttpRequestException($"connect failed key={Key}"));
        var r = await Vt(handler).LookupAsync(Hash, CancellationToken.None);
        Assert.Contains("Could not reach VirusTotal", r.Error, StringComparison.Ordinal);
        Assert.DoesNotContain(Key, r.Error, StringComparison.Ordinal);
    }

    [Fact]
    public async Task Unexpected_handler_exception_never_escapes()
    {
        var handler = new FakeHandler((_, _) => throw new InvalidOperationException(Key));
        var r = await Mb(handler).LookupAsync(Hash, CancellationToken.None);
        Assert.NotNull(r.Error);
        Assert.DoesNotContain(Key, r.Error, StringComparison.Ordinal);
    }

    [Fact]
    public async Task Redirect_to_another_host_is_refused()
    {
        var handler = new FakeHandler((_, _) => Task.FromResult(new HttpResponseMessage(HttpStatusCode.OK)
        {
            Content = new StringContent(VtReport(50, 0)),
            RequestMessage = new HttpRequestMessage(HttpMethod.Get, "https://evil.example/api/v3/files/x"),
        }));
        var r = await Vt(handler).LookupAsync(Hash, CancellationToken.None);
        Assert.Contains("redirect", r.Error, StringComparison.Ordinal);
        Assert.Equal(ReputationVerdict.Unknown, r.Verdict);
    }

    [Theory]
    [InlineData("")]
    [InlineData("abc")]
    [InlineData("275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0")] // 63
    [InlineData("275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f0")] // 65
    [InlineData("zz5a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f")]
    [InlineData("../../../../etc/passwd/89e54d471899f7db9d1663fc695ec2fe2a2c4538aa")]
    [InlineData("275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0\n")]
    [InlineData("C:\\Users\\alice\\Desktop\\invoice.exe")]
    public async Task Invalid_hash_is_refused_with_no_request(string hash)
    {
        var vt = FakeHandler.Json(HttpStatusCode.OK, VtReport(50, 0));
        var mb = FakeHandler.Json(HttpStatusCode.OK, """{"query_status":"ok"}""");
        var r1 = await Vt(vt).LookupAsync(hash, CancellationToken.None);
        var r2 = await Mb(mb).LookupAsync(hash, CancellationToken.None);
        Assert.Contains("Not a valid SHA-256", r1.Error, StringComparison.Ordinal);
        Assert.Contains("Not a valid SHA-256", r2.Error, StringComparison.Ordinal);
        Assert.Empty(vt.Requests);
        Assert.Empty(mb.Requests);
    }

    [Fact]
    public async Task Not_configured_without_key_or_when_disabled_and_sends_nothing()
    {
        var handler = FakeHandler.Json(HttpStatusCode.OK, VtReport(50, 0));
        var noKey = Vt(handler, Settings(key: null));
        var off = Vt(handler, Settings(enabled: false));
        var unreadable = Vt(handler, new IntegrationSettings { VirusTotalEnabled = true, VirusTotalApiKey = "dpapi:AAAA" });
        Assert.False(noKey.IsConfigured);
        Assert.False(off.IsConfigured);
        Assert.False(unreadable.IsConfigured);
        Assert.True(Vt(handler).IsConfigured);
        Assert.True(Vt(handler).IsRemote);
        Assert.NotNull((await noKey.LookupAsync(Hash, CancellationToken.None)).Error);
        Assert.NotNull((await off.LookupAsync(Hash, CancellationToken.None)).Error);
        Assert.Empty(handler.Requests);
    }

    [Fact]
    public async Task Key_with_header_breaking_characters_is_not_sent()
    {
        var handler = FakeHandler.Json(HttpStatusCode.OK, VtReport(50, 0));
        var r = await Vt(handler, Settings(key: "abc\r\nX-Injected: 1")).LookupAsync(Hash, CancellationToken.None);
        Assert.NotNull(r.Error);
        Assert.DoesNotContain("abc", r.Error, StringComparison.Ordinal);
        Assert.Empty(handler.Requests);
    }

    [Fact]
    public async Task Settings_changes_apply_without_recreating_the_provider()
    {
        var settings = Settings(enabled: false);
        var provider = Vt(FakeHandler.Json(HttpStatusCode.OK, VtReport(50, 0)), settings);
        Assert.False(provider.IsConfigured);
        settings.VirusTotalEnabled = true;
        Assert.True(provider.IsConfigured);
        Assert.Equal(ReputationVerdict.Malicious, (await provider.LookupAsync(Hash, CancellationToken.None)).Verdict);
    }

    // ---------------- MalwareBazaar ----------------

    private const string MbHit = $$"""
        {"query_status":"ok","data":[{"sha256_hash":"{{Hash}}","file_name":"x.exe","first_seen":"2020-02-28 05:57:01",
          "signature":"AgentTesla","tags":["exe","AgentTesla"]}]}
        """;

    [Fact]
    public async Task MalwareBazaar_hit_is_malicious_and_sends_only_the_hash_and_key()
    {
        var handler = FakeHandler.Json(HttpStatusCode.OK, MbHit);
        var r = await Mb(handler).LookupAsync(Hash, CancellationToken.None);

        Assert.Null(r.Error);
        Assert.Equal(ReputationVerdict.Malicious, r.Verdict);
        Assert.Equal("malwarebazaar", r.ProviderId);
        Assert.Equal("AgentTesla", r.Family);
        Assert.Equal(["exe", "AgentTesla"], r.Tags);
        Assert.Equal(new DateTimeOffset(2020, 2, 28, 5, 57, 1, TimeSpan.Zero), r.FirstSeen);
        Assert.Equal($"https://bazaar.abuse.ch/sample/{Hash}/", r.Link);

        var request = Assert.Single(handler.Requests);
        Assert.Equal(HttpMethod.Post, request.Method);
        Assert.Equal("https://mb-api.abuse.ch/api/v1/", request.RequestUri!.ToString());
        Assert.Equal($"query=get_info&hash={Hash}", handler.Bodies[0]);
        Assert.Equal(Key, Assert.Single(request.Headers.GetValues("Auth-Key")));
        Assert.DoesNotContain(request.Headers, h => h.Key is not ("Auth-Key" or "Accept"));
    }

    [Fact]
    public async Task MalwareBazaar_not_found()
    {
        var r = await Mb(FakeHandler.Json(HttpStatusCode.OK, """{"query_status":"hash_not_found"}""")).LookupAsync(Hash, CancellationToken.None);
        Assert.Equal(ReputationVerdict.NotFound, r.Verdict);
        Assert.Null(r.Error);
    }

    [Theory]
    [InlineData("""{"query_status":"illegal_hash"}""", "illegal_hash")]
    [InlineData("""{"query_status":"unknown_auth_key"}""", "API key rejected")]
    [InlineData("""{"query_status":"ok","data":[]}""", "could not read")]
    [InlineData("""{"query_status":"ok","data":"x"}""", "could not read")]
    [InlineData("""{"query_status":42}""", "could not read")]
    [InlineData("<html>oops</html>", "could not read")]
    [InlineData("""{"query_status":"ok","data":[{"sha256_hash":"0000000000000000000000000000000000000000000000000000000000000000"}]}""", "different file")]
    public async Task MalwareBazaar_other_answers_are_errors(string body, string expected)
    {
        var r = await Mb(FakeHandler.Json(HttpStatusCode.OK, body)).LookupAsync(Hash, CancellationToken.None);
        Assert.Equal(ReputationVerdict.Unknown, r.Verdict);
        Assert.Contains(expected, r.Error, StringComparison.Ordinal);
    }

    [Theory]
    [InlineData(HttpStatusCode.Unauthorized, "API key rejected")]
    [InlineData(HttpStatusCode.TooManyRequests, "rate limit / quota reached")]
    public async Task MalwareBazaar_http_errors(HttpStatusCode status, string expected)
    {
        var r = await Mb(FakeHandler.Status(status)).LookupAsync(Hash, CancellationToken.None);
        Assert.Contains(expected, r.Error, StringComparison.Ordinal);
    }

    [Fact]
    public async Task Key_echoed_by_the_service_never_reaches_the_error()
    {
        var body = $$"""{"query_status":"{{Key}}<script>\u0007"}""";
        var r = await Mb(FakeHandler.Json(HttpStatusCode.OK, body)).LookupAsync(Hash, CancellationToken.None);
        Assert.NotNull(r.Error);
        Assert.DoesNotContain(Key, r.Error, StringComparison.Ordinal);
        Assert.DoesNotContain("<script>", r.Error, StringComparison.Ordinal);
    }
}
