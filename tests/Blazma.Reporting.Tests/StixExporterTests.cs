using System.Text;
using System.Text.Json;
using System.Text.RegularExpressions;
using Blazma.Core.Events;
using Blazma.Core.Findings;
using Blazma.Core.Indicators;
using Blazma.Core.Text;
using Blazma.Reporting.Interop;

namespace Blazma.Reporting.Tests;

public partial class StixExporterTests
{
    private static readonly HashSet<string> Scos = ["file", "domain-name", "ipv4-addr", "ipv6-addr", "url"];

    [GeneratedRegex(@"^[a-z0-9-]+--[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$")]
    private static partial Regex IdRegex();

    [GeneratedRegex(@"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{3}Z$")]
    private static partial Regex TimeRegex();

    private static JsonDocument Parse(string json) => JsonDocument.Parse(json);

    [Fact]
    public void Deterministic_ids_follow_rfc_9562_and_stix_2_9()
    {
        Assert.Equal("886313e1-3b8a-5372-9b90-0c9aee199e5d", DeterministicId.Uuid5("6ba7b810-9dad-11d1-80b4-00c04fd430c8", "python.org"));
        // The STIX 2.1 specification's own example of a deterministic observable ID.
        Assert.Equal("domain-name--bedb4899-d24b-5401-bc86-8f6b4cc18ec7", StixExporter.ObservableId("domain-name", "example.com"));
        Assert.Equal("\"a\\\"b\\\\c\\n\\u0001ع\"", DeterministicId.CanonicalJsonString("a\"b\\c\n\u0001ع"));
    }

    [Fact]
    public void Bundle_has_valid_structure_and_required_properties()
    {
        var a = TestData.Demo();
        using var doc = Parse(new StixExporter().Build(a, TestData.Options()));
        var root = doc.RootElement;
        Assert.Equal("bundle", root.GetProperty("type").GetString());
        Assert.Matches(IdRegex(), root.GetProperty("id").GetString());
        Assert.StartsWith("bundle--", root.GetProperty("id").GetString(), StringComparison.Ordinal);

        var objects = root.GetProperty("objects").EnumerateArray().ToList();
        var ids = objects.Select(o => o.GetProperty("id").GetString()!).ToList();
        Assert.Equal(ids.Count, ids.Distinct().Count());

        foreach (var o in objects)
        {
            var type = o.GetProperty("type").GetString()!;
            var id = o.GetProperty("id").GetString()!;
            Assert.Matches(IdRegex(), id);
            Assert.StartsWith(type + "--", id, StringComparison.Ordinal);
            Assert.Equal("2.1", o.GetProperty("spec_version").GetString());

            if (!Scos.Contains(type))
            {
                Assert.Matches(TimeRegex(), o.GetProperty("created").GetString());
                Assert.Matches(TimeRegex(), o.GetProperty("modified").GetString());
                Assert.True(string.CompareOrdinal(o.GetProperty("created").GetString(), o.GetProperty("modified").GetString()) <= 0);
            }

            // Every reference points at an object in the bundle.
            foreach (var p in o.EnumerateObject())
            {
                if (p.Name.EndsWith("_ref", StringComparison.Ordinal)) Assert.Contains(p.Value.GetString(), ids);
                if (p.Name.EndsWith("_refs", StringComparison.Ordinal)) Assert.All(p.Value.EnumerateArray(), x => Assert.Contains(x.GetString(), ids));
            }

            switch (type)
            {
                case "identity":
                    Assert.Equal("Blazma Sandbox", o.GetProperty("name").GetString());
                    break;
                case "malware-analysis":
                    Assert.Equal("blazma-sandbox", o.GetProperty("product").GetString());
                    Assert.Contains(o.GetProperty("result").GetString(), new[] { "malicious", "suspicious", "unknown" });
                    Assert.Matches(TimeRegex(), o.GetProperty("analysis_started").GetString());
                    Assert.StartsWith("file--", o.GetProperty("sample_ref").GetString(), StringComparison.Ordinal);
                    break;
                case "note":
                    Assert.Contains(RiskAssessment.Disclaimer, o.GetProperty("content").GetString(), StringComparison.Ordinal);
                    Assert.NotEqual(0, o.GetProperty("object_refs").GetArrayLength());
                    break;
                case "indicator":
                    Assert.Equal("stix", o.GetProperty("pattern_type").GetString());
                    Assert.Matches(TimeRegex(), o.GetProperty("valid_from").GetString());
                    Assert.Matches(@"^\[[a-z0-9-]+:.+\]$", o.GetProperty("pattern").GetString());
                    break;
                case "attack-pattern":
                    Assert.False(string.IsNullOrEmpty(o.GetProperty("name").GetString()));
                    Assert.Equal("mitre-attack", o.GetProperty("external_references")[0].GetProperty("source_name").GetString());
                    break;
                case "relationship":
                    Assert.Contains(o.GetProperty("relationship_type").GetString(), new[] { "indicates", "related-to" });
                    if (o.GetProperty("relationship_type").GetString() == "indicates")
                    {
                        Assert.StartsWith("indicator--", o.GetProperty("source_ref").GetString(), StringComparison.Ordinal);
                        Assert.StartsWith("attack-pattern--", o.GetProperty("target_ref").GetString(), StringComparison.Ordinal);
                    }
                    break;
                case "file":
                    Assert.Equal(a.Sample.Sha256, o.GetProperty("hashes").GetProperty("SHA-256").GetString());
                    break;
                case "domain-name" or "ipv4-addr" or "ipv6-addr" or "url":
                    Assert.Equal(StixExporter.ObservableId(type, o.GetProperty("value").GetString()!), id);
                    break;
                default:
                    Assert.Fail("Unexpected object type " + type);
                    break;
            }
        }

        Assert.Contains(objects, o => o.GetProperty("type").GetString() == "domain-name" && o.GetProperty("value").GetString() == "api.contoso-update.example");
        Assert.Contains(objects, o => o.GetProperty("type").GetString() == "ipv4-addr" && o.GetProperty("value").GetString() == "203.0.113.24");
        Assert.Contains(objects, o => o.GetProperty("type").GetString() == "attack-pattern" && o.GetProperty("name").GetString() == "Registry Run Keys / Startup Folder");
        Assert.Contains(objects, o => o.GetProperty("type").GetString() == "relationship" && o.GetProperty("relationship_type").GetString() == "indicates");
    }

    [Fact]
    public void Result_never_claims_benign()
    {
        Assert.Equal("malicious", StixExporter.ResultFor(Verdict.CriticalBehavior));
        Assert.Equal("malicious", StixExporter.ResultFor(Verdict.HighRiskBehavior));
        Assert.Equal("suspicious", StixExporter.ResultFor(Verdict.Suspicious));
        Assert.Equal("unknown", StixExporter.ResultFor(Verdict.LowRisk));

        var quiet = TestData.Demo("viewer-tool.exe");
        Assert.Equal(Verdict.LowRisk, quiet.Risk.Verdict);
        var json = new StixExporter().Build(quiet, TestData.Options());
        Assert.DoesNotContain("benign", json, StringComparison.Ordinal);
        Assert.Contains("\"result\": \"unknown\"", json, StringComparison.Ordinal);
        Assert.Contains("A low score does not prove that a file is safe.", json, StringComparison.Ordinal);
    }

    [Fact]
    public void Only_suspicious_or_higher_indicators_become_patterns()
    {
        var a = TestData.Demo();
        a.Indicators =
        [
            new Indicator(IndicatorType.Domain, "observed.example", IndicatorStatus.Observed, "dns", []),
            new Indicator(IndicatorType.Domain, "bad'quote\\.example", IndicatorStatus.Suspicious, "dns", []),
            new Indicator(IndicatorType.IpAddress, "2001:db8::1", IndicatorStatus.HighRisk, "network", []),
            new Indicator(IndicatorType.IpAddress, "not-an-ip", IndicatorStatus.HighRisk, "network", []),
            new Indicator(IndicatorType.RegistryKey, @"HKCU\Software\Microsoft\Windows\CurrentVersion\Run\ContosoUpdater", IndicatorStatus.HighRisk, "persistence:RunKey", []),
            new Indicator(IndicatorType.PersistenceArtifact, "ContosoUpdateTask", IndicatorStatus.HighRisk, "persistence:ScheduledTask", []),
            new Indicator(IndicatorType.ProcessName, "powershell.exe", IndicatorStatus.HighRisk, "process", []),
        ];
        using var doc = Parse(new StixExporter().Build(a, TestData.Options()));
        var patterns = doc.RootElement.GetProperty("objects").EnumerateArray()
            .Where(o => o.GetProperty("type").GetString() == "indicator").Select(o => o.GetProperty("pattern").GetString()).ToList();

        Assert.Equal(3, patterns.Count);
        Assert.Contains(@"[domain-name:value = 'bad\'quote\\.example']", patterns);
        Assert.Contains("[ipv6-addr:value = '2001:db8::1']", patterns);
        Assert.Contains(@"[windows-registry-key:key = 'HKEY_CURRENT_USER\\Software\\Microsoft\\Windows\\CurrentVersion\\Run' AND windows-registry-key:values[*].name = 'ContosoUpdater']", patterns);
        Assert.DoesNotContain(patterns, p => p!.Contains("observed.example", StringComparison.Ordinal));

        // Observed values are still reported as observables, not as indicators.
        Assert.Contains(doc.RootElement.GetProperty("objects").EnumerateArray(), o => o.GetProperty("type").GetString() == "domain-name" && o.GetProperty("value").GetString() == "observed.example");
        Assert.Contains(doc.RootElement.GetProperty("objects").EnumerateArray(), o => o.GetProperty("type").GetString() == "ipv6-addr");
    }

    [Fact]
    public void Revoked_techniques_are_exported_as_their_replacement_with_a_note()
    {
        var a = TestData.Demo();
        a.Findings =
        [
            .. a.Findings,
            new Finding
            {
                Id = "x", RuleId = "TEST-1", RuleVersion = "1", Title = LocalizedText.Same("t"), Explanation = LocalizedText.Same("e"),
                Category = FindingCategory.DefenseEvasion, Severity = Severity.High, Points = 1, AttackTechniques = ["T1562.001", "T0000"],
                Evidence = [new Evidence { Kind = "k", Description = LocalizedText.Same("d") }],
            },
        ];
        using var doc = Parse(new StixExporter().Build(a, TestData.Options()));
        var patterns = doc.RootElement.GetProperty("objects").EnumerateArray().Where(o => o.GetProperty("type").GetString() == "attack-pattern").ToList();
        var replaced = Assert.Single(patterns, p => p.TryGetProperty("description", out var d) && d.GetString()!.Contains("T1562.001", StringComparison.Ordinal));
        Assert.NotEqual("T1562.001", replaced.GetProperty("external_references")[0].GetProperty("external_id").GetString());
        var unknown = Assert.Single(patterns, p => p.GetProperty("external_references")[0].GetProperty("external_id").GetString() == "T0000");
        Assert.Equal("T0000", unknown.GetProperty("name").GetString());
        Assert.False(unknown.TryGetProperty("kill_chain_phases", out _));
    }

    [Fact]
    public async Task Export_is_byte_identical_and_redacts()
    {
        var exporter = new StixExporter(_ => new Redactor(["WDAGUtilityAccount"], ["SANDBOX-PC"]));
        var first = await Export(exporter, TestData.Demo(), TestData.Options(redact: true));
        var second = await Export(exporter, TestData.Demo(), TestData.Options(redact: true));
        Assert.Equal(first, second);
        Assert.DoesNotContain("WDAGUtilityAccount", Encoding.UTF8.GetString(first), StringComparison.OrdinalIgnoreCase);
        Assert.Equal("STIX 2.1", exporter.Format);
        Assert.Equal(".stix.json", exporter.FileExtension);
    }

    [Fact]
    public void Arabic_note_is_tagged_with_its_language()
    {
        var json = new StixExporter().Build(TestData.Demo(), TestData.Options(language: "ar"));
        Assert.Contains(RiskAssessment.DisclaimerAr, json, StringComparison.Ordinal);
        Assert.Contains("\"lang\": \"ar\"", json, StringComparison.Ordinal);
    }

    private static async Task<byte[]> Export(StixExporter exporter, Core.Analysis.AnalysisResult a, Core.Abstractions.ExportOptions o)
    {
        using var ms = new MemoryStream();
        await exporter.ExportAsync(a, ms, o, CancellationToken.None);
        return ms.ToArray();
    }
}
