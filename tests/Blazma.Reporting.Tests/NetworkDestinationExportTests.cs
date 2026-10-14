using System.Text;
using System.Text.Json;
using Blazma.Core.Abstractions;
using Blazma.Core.Analysis;
using Blazma.Reporting.Interop;

namespace Blazma.Reporting.Tests;

/// <summary>The addresses the program tried to reach, attempts included, reach every export.</summary>
public class NetworkDestinationExportTests
{
    private const string Attempted = "192.0.2.77"; // the demo updater's hard-coded server: every attempt failed

    private static async Task<string> Export(IReportExporter exporter, AnalysisResult a, string language = "en")
    {
        using var ms = new MemoryStream();
        await exporter.ExportAsync(a, ms, TestData.Options(language: language), CancellationToken.None);
        return Encoding.UTF8.GetString(ms.ToArray());
    }

    private static AnalysisResult WithLookups()
    {
        var a = TestData.Demo();
        a.HostResolutions = [new HostResolution { Domain = "cdn.contoso-update.example", Status = HostResolutionStatus.Resolved, Addresses = ["198.51.100.8"], Resolver = "cloudflare-dns.com", ResolvedAt = TestData.Start }];
        return a;
    }

    [Theory]
    [InlineData("en", "Addresses the program tried to reach", "Failed or blocked")]
    [InlineData("ar", "العناوين التي حاول البرنامج الوصول إليها", "فشل أو حُظر")]
    public async Task Html_lists_the_destinations_with_status_shapes(string language, string title, string failed)
    {
        var html = await Export(new HtmlReportExporter(), WithLookups(), language);
        Assert.Contains(title, html, StringComparison.Ordinal);
        Assert.Contains(Attempted, html, StringComparison.Ordinal);
        Assert.Contains("✕ " + failed, html, StringComparison.Ordinal);
        Assert.Contains("◆ ", html, StringComparison.Ordinal);           // simulated internet
        Assert.Contains("198.51.100.8", html, StringComparison.Ordinal); // looked up afterwards, labelled as such
        Assert.Contains(language == "ar" ? "بعد انتهاء التحليل" : "after the analysis", html, StringComparison.Ordinal);
    }

    [Fact]
    public async Task Json_carries_destinations_and_the_labelled_lookups()
    {
        var json = await Export(new JsonReportExporter(), WithLookups());
        using var doc = JsonDocument.Parse(json, new JsonDocumentOptions { MaxDepth = 256 });
        var content = doc.RootElement.GetProperty("content");
        var rows = content.GetProperty("networkDestinations").EnumerateArray().ToList();
        var row = Assert.Single(rows, r => r.TryGetProperty("address", out var ip) && ip.GetString() == Attempted);
        Assert.Equal("Failed", row.GetProperty("status").GetString());
        Assert.Equal(6, row.GetProperty("attempts").GetInt32());
        Assert.True(row.GetProperty("directIp").GetBoolean());
        Assert.Contains(rows, r => r.GetProperty("status").GetString() == "Simulated" && r.TryGetProperty("domain", out var name) && name.GetString() == "api.contoso-update.example" && !r.TryGetProperty("address", out _));
        var lookups = content.GetProperty("hostResolutions");
        Assert.Contains("might have received different addresses", lookups.GetProperty("note").GetString(), StringComparison.Ordinal);
        Assert.True(ReportIntegrity.Verify(json));
    }

    [Fact]
    public void Stix_misp_and_indicator_lists_include_the_attempted_address()
    {
        var a = TestData.Demo();
        var stix = new StixExporter().Build(a, TestData.Options());
        Assert.Contains("ipv4-addr", stix, StringComparison.Ordinal);
        Assert.Contains(Attempted, stix, StringComparison.Ordinal);
        Assert.Contains("2001:db8:4b1::25", stix, StringComparison.Ordinal);
        Assert.Contains(Attempted, new MispExporter().Build(a, TestData.Options()), StringComparison.Ordinal);
        Assert.Contains($"IpAddress,{Attempted},", IndicatorExporter.ToCsv(a), StringComparison.Ordinal);
    }

    [Theory]
    [InlineData("en")]
    [InlineData("ar")]
    public async Task Pdf_renders_with_destinations_and_lookups(string language)
    {
        using var ms = new MemoryStream();
        await new PdfReportExporter().ExportAsync(WithLookups(), ms, TestData.Options(language: language), CancellationToken.None);
        Assert.Equal("%PDF-", Encoding.ASCII.GetString(ms.ToArray(), 0, 5));
    }
}
