using System.Text;
using System.Text.Json;
using Blazma.Core.Abstractions;
using Blazma.Core.Indicators;
using Blazma.Reporting;

namespace Blazma.Integration.Tests;

public class ReportingTests
{
    private static ExportOptions Options(string lang = "en", bool redact = false, bool raw = false) => new(lang, redact, raw, true, true, true, 200);

    private static async Task<string> Export(IReportExporter exporter, Core.Analysis.AnalysisResult r, ExportOptions o)
    {
        using var ms = new MemoryStream();
        await exporter.ExportAsync(r, ms, o, CancellationToken.None);
        return Encoding.UTF8.GetString(ms.ToArray());
    }

    [Fact]
    public async Task Json_report_is_machine_readable_and_integrity_protected()
    {
        await using var f = await Fixture.CreateAsync();
        var r = await f.RunDemoAsync();
        var json = await Export(new JsonReportExporter(), r, Options(raw: true));

        using var doc = JsonDocument.Parse(json);
        Assert.Equal("blazma-sandbox-report", doc.RootElement.GetProperty("format").GetString());
        Assert.True(doc.RootElement.GetProperty("demo").GetBoolean());
        var content = doc.RootElement.GetProperty("content");
        Assert.Equal(r.Risk.Score, content.GetProperty("risk").GetProperty("score").GetInt32());
        Assert.Equal(r.Events.Count, content.GetProperty("events").GetArrayLength());
        Assert.True(ReportIntegrity.Verify(json));

        var tampered = json.Replace($"\"score\": {r.Risk.Score}", "\"score\": 1", StringComparison.Ordinal);
        Assert.NotEqual(json, tampered);
        Assert.False(ReportIntegrity.Verify(tampered));
    }

    [Fact]
    public async Task Html_report_encodes_sample_controlled_text_and_has_no_scripts()
    {
        await using var f = await Fixture.CreateAsync();
        var r = await f.RunDemoAsync("<script>alert(1)</script>.exe");
        var html = await Export(new HtmlReportExporter(), r, Options());

        Assert.DoesNotContain("<script>", html, StringComparison.OrdinalIgnoreCase);
        Assert.Contains("&lt;script&gt;", html, StringComparison.Ordinal);
        Assert.Contains("default-src 'none'", html, StringComparison.Ordinal);
        Assert.Contains("DEMO DATA", html, StringComparison.Ordinal);
        Assert.Contains("Why this score?", html, StringComparison.Ordinal);
    }

    [Fact]
    public async Task Arabic_html_report_is_rtl()
    {
        await using var f = await Fixture.CreateAsync();
        var r = await f.RunDemoAsync();
        var html = await Export(new HtmlReportExporter(), r, Options("ar"));
        Assert.Contains("dir=\"rtl\"", html, StringComparison.Ordinal);
        Assert.Contains("لماذا هذه الدرجة؟", html, StringComparison.Ordinal);
    }

    [Fact]
    public async Task Redaction_removes_user_names_from_exports()
    {
        await using var f = await Fixture.CreateAsync();
        var r = await f.RunDemoAsync();
        var redactor = new Redactor(["WDAGUtilityAccount"], ["SANDBOX-PC"]);
        var json = await Export(new JsonReportExporter(_ => redactor), r, Options(redact: true, raw: true));
        Assert.DoesNotContain("WDAGUtilityAccount", json, StringComparison.OrdinalIgnoreCase);
        Assert.Contains(@"C:\\Users\\<user>", json, StringComparison.Ordinal);
    }

    [Fact]
    public async Task Indicator_csv_is_safe_for_spreadsheets()
    {
        await using var f = await Fixture.CreateAsync();
        var r = await f.RunDemoAsync();
        r.Indicators = [.. r.Indicators, new Indicator(IndicatorType.Domain, "=cmd|' /c calc'!A1", IndicatorStatus.Observed, "test", [])];
        var csv = IndicatorExporter.ToCsv(r);
        Assert.StartsWith("type,value,status,source", csv, StringComparison.Ordinal);
        Assert.Contains("'=cmd", csv, StringComparison.Ordinal);
        Assert.Contains("198.51.100.7", csv, StringComparison.Ordinal);
    }
}
