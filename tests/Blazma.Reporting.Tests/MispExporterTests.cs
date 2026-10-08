using System.Text;
using System.Text.Json;
using Blazma.Core.Findings;
using Blazma.Reporting.Interop;

namespace Blazma.Reporting.Tests;

public class MispExporterTests
{
    private static readonly string[] Categories = ["Payload delivery", "Artifacts dropped", "Network activity", "Persistence mechanism", "Other"];

    private static JsonElement Event(string json) => JsonDocument.Parse(json).RootElement.GetProperty("Event");

    private static List<JsonElement> Attributes(JsonElement ev) => ev.GetProperty("Attribute").EnumerateArray().ToList();

    private static JsonElement Attribute(JsonElement ev, string type, string value) =>
        Assert.Single(Attributes(ev), x => x.GetProperty("type").GetString() == type && x.GetProperty("value").GetString() == value);

    [Fact]
    public void Event_is_importable_misp_json()
    {
        var a = TestData.Demo();
        var ev = Event(new MispExporter().Build(a, TestData.Options()));

        Assert.True(Guid.TryParse(ev.GetProperty("uuid").GetString(), out _));
        Assert.StartsWith("[DEMO] Blazma Sandbox analysis of setup.exe: Critical behavior", ev.GetProperty("info").GetString(), StringComparison.Ordinal);
        Assert.Equal("2026-10-07", ev.GetProperty("date").GetString());
        Assert.Equal("1", ev.GetProperty("threat_level_id").GetString());
        Assert.Equal("2", ev.GetProperty("analysis").GetString());
        Assert.Equal("0", ev.GetProperty("distribution").GetString());
        Assert.False(ev.GetProperty("published").GetBoolean());
        Assert.True(long.TryParse(ev.GetProperty("timestamp").GetString(), out _));

        var tags = ev.GetProperty("Tag").EnumerateArray().Select(t => t.GetProperty("name").GetString()).ToList();
        Assert.Equal("tlp:amber", tags[0]);
        Assert.Contains("misp-galaxy:mitre-attack-pattern=\"Registry Run Keys / Startup Folder - T1547.001\"", tags);
        Assert.Contains("misp-galaxy:mitre-attack-pattern=\"PowerShell - T1059.001\"", tags);

        foreach (var attr in Attributes(ev))
        {
            Assert.True(Guid.TryParse(attr.GetProperty("uuid").GetString(), out _));
            Assert.Contains(attr.GetProperty("category").GetString(), Categories);
            Assert.False(string.IsNullOrEmpty(attr.GetProperty("value").GetString()));
            Assert.Equal(JsonValueKind.False, attr.GetProperty("disable_correlation").ValueKind);
        }

        Assert.Equal("Payload delivery", Attribute(ev, "sha256", a.Sample.Sha256).GetProperty("category").GetString());
        Assert.True(Attribute(ev, "sha256", a.Sample.Sha256).GetProperty("to_ids").GetBoolean());
        Assert.Equal("Payload delivery", Attribute(ev, "sha1", a.Sample.Sha1).GetProperty("category").GetString());
        Assert.Equal("Payload delivery", Attribute(ev, "filename", "setup.exe").GetProperty("category").GetString());

        // Observed only: context, not detection.
        var host = Attribute(ev, "hostname", "api.contoso-update.example");
        Assert.Equal("Network activity", host.GetProperty("category").GetString());
        Assert.False(host.GetProperty("to_ids").GetBoolean());

        // Graded by findings: detection-worthy.
        var ip = Attribute(ev, "ip-dst", "198.51.100.7");
        Assert.Equal("Network activity", ip.GetProperty("category").GetString());
        Assert.True(ip.GetProperty("to_ids").GetBoolean());

        var run = Attribute(ev, "regkey|value", @"HKCU\Software\Microsoft\Windows\CurrentVersion\Run\ContosoUpdater|""C:\Users\WDAGUtilityAccount\AppData\Roaming\ContosoUpdate\updater.exe"" /background");
        Assert.Equal("Persistence mechanism", run.GetProperty("category").GetString());

        var task = Attribute(ev, "text", "ContosoUpdateTask");
        Assert.False(task.GetProperty("to_ids").GetBoolean());

        Assert.DoesNotContain(Attributes(ev), x => x.GetProperty("value").GetString() == "powershell.exe");
        Assert.Contains(RiskAssessment.Disclaimer, Assert.Single(Attributes(ev), x => x.GetProperty("type").GetString() == "comment").GetProperty("value").GetString(), StringComparison.Ordinal);
    }

    [Fact]
    public void Low_risk_analysis_is_not_marked_for_detection()
    {
        var a = TestData.Demo("viewer-tool.exe");
        var ev = Event(new MispExporter().Build(a, TestData.Options()));
        Assert.Equal("4", ev.GetProperty("threat_level_id").GetString());
        Assert.All(Attributes(ev), x => Assert.False(x.GetProperty("to_ids").GetBoolean()));
    }

    [Fact]
    public void Tlp_tag_is_configurable()
    {
        var a = TestData.Demo();
        var green = Event(new MispExporter("TLP:GREEN").Build(a, TestData.Options()));
        Assert.Equal("tlp:green", green.GetProperty("Tag")[0].GetProperty("name").GetString());
        var none = Event(new MispExporter(null).Build(a, TestData.Options()));
        Assert.DoesNotContain(none.GetProperty("Tag").EnumerateArray(), t => t.GetProperty("name").GetString()!.StartsWith("tlp:", StringComparison.Ordinal));
        Assert.Throws<ArgumentException>(() => new MispExporter("amber"));
    }

    [Fact]
    public async Task Export_is_byte_identical_and_redacts()
    {
        var exporter = new MispExporter(redactorFactory: _ => new Redactor(["WDAGUtilityAccount"], ["SANDBOX-PC"]));
        Assert.Equal(".misp.json", exporter.FileExtension);
        var first = await Export(exporter, TestData.Demo());
        var second = await Export(exporter, TestData.Demo());
        Assert.Equal(first, second);
        var text = Encoding.UTF8.GetString(first);
        Assert.DoesNotContain("WDAGUtilityAccount", text, StringComparison.OrdinalIgnoreCase);

        // A redacted path no longer matches the real one, so it is never sent to detection.
        var ev = Event(text);
        var dropped = Attribute(ev, "filename", @"C:\Users\<user>\AppData\Roaming\ContosoUpdate\updater.exe");
        Assert.False(dropped.GetProperty("to_ids").GetBoolean());
        Assert.Equal("Artifacts dropped", dropped.GetProperty("category").GetString());
    }

    private static async Task<byte[]> Export(MispExporter exporter, Core.Analysis.AnalysisResult a)
    {
        using var ms = new MemoryStream();
        await exporter.ExportAsync(a, ms, TestData.Options(redact: true), CancellationToken.None);
        return ms.ToArray();
    }
}
